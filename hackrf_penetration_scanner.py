#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 script for Linux that wraps `hackrf_sweep`
to scan Sub-GHz human body penetration bands (1-30 MHz, 400-450 MHz, 860-930 MHz)
AND 1-3 GHz (1000-3000 MHz) L/S-Band spectrum for:
  - Pulsed frequencies (beacons, radar, TDMA, telemetry)
  - Mesh network topologies (Meshtastic/LoRa, Zigbee/Thread, Z-Wave, BLE/Wi-Fi Mesh)
  - Round-the-clock (24/7 continuous) transmitters in 1-3 GHz and Sub-GHz
"""

import argparse
import csv
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

# ==============================================================================
# CONFIGURABLE PARAMETERS (Defaults; can also be overridden via CLI flags)
# ==============================================================================

# FFT bin width (frequency resolution) in Hz (valid range: 2445 - 5000000)
FFT_BIN_WIDTH_HZ: int = 50000

# RX LNA (IF) gain in dB (0 - 40 dB, in 8 dB steps)
LNA_GAIN_DB: int = 16

# RX VGA (baseband) gain in dB (0 - 62 dB, in 2 dB steps)
VGA_GAIN_DB: int = 20

# RX RF amplifier toggle (True = Enable / 1, False = Disable / 0)
RF_AMP_ENABLE: bool = False

# Minimum signal power threshold in dB to trigger a hit
DETECTION_THRESHOLD_DB: float = -50.0

# Number of sweeps to perform (0 for continuous live scanning)
SWEEP_COUNT: int = 0

# Scan mode presets:
#   "full"        -> Sub-GHz Penetration + Cellular + 1-3 GHz
#   "cell"        -> Region-Aware Cell Tower Search (auto-tuned to US/UK/EU/AU cellular bands)
#   "cell-pulsed" -> Region-Aware Pulsed Cell Tower Hunter (logs ONLY pulsed hits in cell bands)
#   "pulsed"      -> Pulsed Frequency Hunter (logs ONLY repeating pulsed signals, mutes 24/7/Wi-Fi)
#   "subghz"      -> Sub-GHz Penetration & Low-Band Cellular (1:30,400:450,600:960)
#   "highband"    -> 1-3 GHz (1000:3000) for round-the-clock & 2.4 GHz mesh hunting
#   "mesh"        -> Fast Mesh & Pulsed Hunter (430:440,860:930,2400:2500)
SCAN_MODE_RANGES: Dict[str, str] = {
    "full": "1:30,400:450,600:960,1000:3000",
    "cell": "703:862,880:960,1710:1880,1920:2170,2350:2390,2500:2690",  # Dynamically overridden by region!
    "cell-pulsed": "703:862,880:960,1710:1880,1920:2170,2350:2390,2500:2690",
    "pulsed": "400:450,600:960,1000:2395,2485:3000",
    "subghz": "1:30,400:450,600:960",
    "highband": "1000:3000",
    "mesh": "430:440,860:930,2400:2500",
}
DEFAULT_SCAN_MODE: str = "full"
TARGET_RANGES_CSV: str = SCAN_MODE_RANGES[DEFAULT_SCAN_MODE]
USE_SINGLE_COMMA_SEPARATED_F_ARG: bool = True

# Automatically mute known internal HackRF clock spurs (e.g., 10 MHz & 20 MHz)
# so they don't flood the log file or skew sweep occupancy calculations.
IGNORE_CLOCK_SPURS: bool = True
KNOWN_INTERNAL_SPUR_RANGES_MHZ: List[Tuple[float, float]] = [
    (9.970, 10.030),    # 10.000 MHz internal reference harmonic
    (19.910, 20.110),   # 20.000 MHz internal ADC/sample clock spur
]

# Optional path to log file (always defaults to the script's own directory)
SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH: Optional[str] = os.path.join(SCRIPT_DIR, "penetration_scan_hits.log")

sys.path.insert(0, SCRIPT_DIR)
import cell_tower_intel as cti

# Target Sub-Bands & Tiers: (min_mhz, max_mhz, tier_label, description)
PENETRATION_SUB_BANDS: List[Tuple[float, float, str, str]] = [
    (
        1.0,
        30.0,
        "[DEEP: 1-30 MHz]",
        "Deep / whole-body inductive range (incl. 13.56 MHz ISM)",
    ),
    (
        400.0,
        450.0,
        "[HIGH: 400-450 MHz]",
        "Deep tissue telemetry / MedRadio (401-406 MHz) & 433 MHz ISM/Mesh",
    ),
    (
        600.0,
        860.0,
        "[CELL-LOW: 600-860 MHz]",
        "Low-Band Cellular LTE/5G (600/700/800/850 MHz B71/B12/B13/B20/B28/B5)",
    ),
    (
        860.0,
        960.0,
        "[MODERATE: 860-960 MHz]",
        "Sub-GHz ISM / Mesh & Cellular (B5/B8/E-GSM 900 UL & DL)",
    ),
    (
        1000.0,
        2000.0,
        "[L-BAND: 1-2 GHz]",
        "1-2 GHz L-Band (ADS-B 1090, GNSS, DECT, LTE B3/B2/B1/B4 Cellular)",
    ),
    (
        2000.0,
        3000.0,
        "[S-BAND: 2-3 GHz]",
        "2-3 GHz S-Band (LTE B1/B4/B7/B38/B40/B41 Cellular, 2.4 GHz Mesh/Wi-Fi, Radar)",
    ),
]

# Known Mesh Network Channels for Live Tagging: (low_mhz, high_mhz, label)
MESH_CHANNEL_HINTS: List[Tuple[float, float, str]] = [
    (433.050, 434.790, "MESH/ISM-433 (LoRa/Meshtastic)"),
    (868.000, 868.600, "MESH-EU868 (LoRa/Zigbee/Z-Wave)"),
    (869.400, 869.650, "MESHTASTIC-EU868 (869.525 MHz)"),
    (902.000, 928.000, "MESH-US915 (LoRa/Meshtastic/Z-Wave)"),
    (1880.000, 1900.000, "DECT-1.9G (Pulsed TDMA/Intercom)"),
    (2400.000, 2483.500, "MESH-2.4G (Zigbee/Thread/BLE/WiFi)"),
]


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================


def is_internal_clock_spur(freq_mhz: float) -> bool:
    """
    Return True if `freq_mhz` falls inside a known HackRF internal clock spur window.
    """
    for low_mhz, high_mhz in KNOWN_INTERNAL_SPUR_RANGES_MHZ:
        if low_mhz <= freq_mhz <= high_mhz:
            return True
    return False


def classify_frequency_mhz(
    freq_mhz: float, max_allowed_mhz: float = 3000.0
) -> Optional[str]:
    """
    Check if `freq_mhz` falls within one of the configured target sub-bands
    (1-30 MHz, 400-450 MHz, 860-930 MHz, 1000-2000 MHz, or 2000-3000 MHz).
    Returns the tier label if inside a target band, else None.
    """
    if freq_mhz > max_allowed_mhz or freq_mhz < 1.0:
        return None

    for min_mhz, max_mhz, tier_label, _ in PENETRATION_SUB_BANDS:
        if min_mhz <= freq_mhz <= max_mhz:
            return tier_label

    return None


def get_live_smart_tag(
    freq_mhz: float,
    power_db: float,
    now_ts: float,
    tracker: Dict[float, Dict[str, float]],
) -> str:
    """
    Maintain lightweight live state per 50 kHz bucket to classify hits in real time
    on the console as:
      - [24/7 CARRIER]   (high hit count & continuous presence)
      - [PULSED Δt=..s]  (periodic burst interval detected)
      - [MESH RELAY?]    (known mesh band with varying RSSI levels)
      - [BURST]          (initial or transient hit)
    """
    bucket = round(round(freq_mhz / 0.050) * 0.050, 3)
    state = tracker.get(bucket)
    if state is None:
        tracker[bucket] = {
            "count": 1.0,
            "last_ts": now_ts,
            "last_pri": 0.0,
            "min_db": power_db,
            "max_db": power_db,
            "bursts": 1.0,
        }
        for low_m, high_m, m_label in MESH_CHANNEL_HINTS:
            if low_m <= freq_mhz <= high_m:
                return f"NEW ({m_label})"
        return "NEW BURST"

    dt = now_ts - state["last_ts"]
    state["count"] += 1.0
    if power_db < state["min_db"]:
        state["min_db"] = power_db
    if power_db > state["max_db"]:
        state["max_db"] = power_db

    # Count distinct bursts if separated by > 0.15s
    if dt >= 0.15:
        state["bursts"] += 1.0
        state["last_pri"] = dt
    state["last_ts"] = now_ts

    db_spread = state["max_db"] - state["min_db"]
    in_mesh_band = any(low_m <= freq_mhz <= high_m for low_m, high_m, _ in MESH_CHANNEL_HINTS)

    # Check if continuous / round-the-clock carrier
    if state["count"] >= 12 and dt < 1.5 and db_spread < 6.0:
        if freq_mhz >= 1000.0:
            return "1-3G 24/7 CARRIER"
        return "24/7 CARRIER"

    # Check if multi-node mesh relay (multiple power levels on a mesh channel)
    if in_mesh_band and state["bursts"] >= 3 and db_spread >= 6.0:
        return f"MESH NODE (Δ{db_spread:.0f}dB)"

    # Check if pulsed with measurable interval
    if state["bursts"] >= 2 and state["last_pri"] >= 0.2:
        return f"PULSED (Δt={state['last_pri']:.1f}s)"

    if in_mesh_band:
        return "MESH CH HIT"
    return "ACTIVE SIGNAL"


def build_hackrf_sweep_command(
    use_comma_flag: bool = USE_SINGLE_COMMA_SEPARATED_F_ARG,
    bin_width_hz: int = FFT_BIN_WIDTH_HZ,
    lna_gain_db: int = LNA_GAIN_DB,
    vga_gain_db: int = VGA_GAIN_DB,
    rf_amp: bool = RF_AMP_ENABLE,
    sweep_count: int = SWEEP_COUNT,
    ranges_csv: str = TARGET_RANGES_CSV,
) -> List[str]:
    """
    Construct the `hackrf_sweep` command-line invocation list.
    """
    cmd: List[str] = ["hackrf_sweep"]

    ranges = [r.strip() for r in ranges_csv.split(",") if r.strip()]
    if use_comma_flag:
        cmd.extend(["-f", ",".join(ranges)])
    else:
        for freq_range in ranges:
            cmd.extend(["-f", freq_range])

    cmd.extend(["-w", str(int(bin_width_hz))])
    cmd.extend(["-l", str(int(lna_gain_db))])
    cmd.extend(["-g", str(int(vga_gain_db))])
    cmd.extend(["-a", "1" if rf_amp else "0"])

    if sweep_count > 0:
        cmd.extend(["-N", str(int(sweep_count))])

    return cmd


def passes_target_filters(
    freq_mhz: float,
    region: str,
    only_cell: bool = False,
    exclude_wifi: bool = False,
    exclude_ism: bool = False,
) -> bool:
    """
    Enforce user-requested target pull filters so we only pull frequencies we are looking for.
    """
    if exclude_wifi and (2400.0 <= freq_mhz <= 2483.5):
        return False
    if exclude_ism and cti.is_in_regional_ism(freq_mhz, region) is not None:
        return False
    if only_cell:
        if (
            cti.match_cellular_band(freq_mhz, region) is None
            and cti.match_foreign_cellular_band(freq_mhz, region) is None
        ):
            return False
    return True


def parse_csv_record(
    row: List[str],
    threshold_db: float = DETECTION_THRESHOLD_DB,
    max_allowed_mhz: float = 3000.0,
    ignore_spurs: bool = IGNORE_CLOCK_SPURS,
    region: str = "UK",
    only_cell: bool = False,
    exclude_wifi: bool = False,
    exclude_ism: bool = False,
) -> List[Tuple[str, str, float, float, str]]:
    """
    Parse a single CSV line from `hackrf_sweep` stdout:
        date, time, hz_low, hz_high, hz_bin_width, num_samples, dB, dB, ...

    Calculates the exact frequency in MHz for each FFT bin, filters by active
    target sub-bands, target pull filters (`only_cell`, `exclude_wifi`, `exclude_ism`),
    and `threshold_db`, optionally notches internal clock spurs, and returns a list of hits:
        (date_str, time_str, freq_mhz, power_db, tier_label)
    """
    if len(row) < 7:
        return []

    try:
        date_str = row[0].strip()
        time_str = row[1].strip()
        hz_low = float(row[2].strip())
        hz_high = float(row[3].strip())
        hz_bin_width = float(row[4].strip())
        db_strings = row[6:]
    except ValueError:
        return []

    seg_low_mhz = hz_low / 1e6
    seg_high_mhz = hz_high / 1e6
    if seg_low_mhz > max_allowed_mhz:
        return []

    overlaps_target = any(
        not (seg_high_mhz < min_mhz or seg_low_mhz > max_mhz)
        for min_mhz, max_mhz, _, _ in PENETRATION_SUB_BANDS
        if min_mhz <= max_allowed_mhz
    )
    if not overlaps_target:
        return []

    hits: List[Tuple[str, str, float, float, str]] = []

    for i, db_val_str in enumerate(db_strings):
        db_val_str = db_val_str.strip()
        if not db_val_str:
            continue
        try:
            power_db = float(db_val_str)
        except ValueError:
            continue

        if power_db < threshold_db:
            continue

        bin_center_hz = hz_low + (i + 0.5) * hz_bin_width
        freq_mhz = bin_center_hz / 1e6

        if ignore_spurs and is_internal_clock_spur(freq_mhz):
            continue

        tier_label = classify_frequency_mhz(freq_mhz, max_allowed_mhz=max_allowed_mhz)
        if tier_label is None:
            continue

        if not passes_target_filters(
            freq_mhz=freq_mhz,
            region=region,
            only_cell=only_cell,
            exclude_wifi=exclude_wifi,
            exclude_ism=exclude_ism,
        ):
            continue

        hits.append((date_str, time_str, freq_mhz, power_db, tier_label))

    return hits


def terminate_process_cleanly(proc: Optional[subprocess.Popen]) -> None:
    """
    Gracefully terminate the `hackrf_sweep` subprocess and reap it so no zombie
    processes are left behind.
    """
    if proc is None:
        return

    if proc.poll() is not None:
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        return

    try:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=2.0)
            return
        except subprocess.TimeoutExpired:
            pass

        proc.terminate()
        try:
            proc.wait(timeout=2.0)
            return
        except subprocess.TimeoutExpired:
            pass

        proc.kill()
        proc.wait(timeout=2.0)
    except ProcessLookupError:
        pass
    except Exception as exc:
        sys.stderr.write(f"[!] Warning while terminating subprocess: {exc}\n")


def print_banner(
    cmd: List[str],
    scan_mode: str,
    ranges_csv: str,
    bin_width_hz: int,
    lna_gain_db: int,
    vga_gain_db: int,
    rf_amp: bool,
    threshold_db: float,
    sweep_count: int,
    ignore_spurs: bool,
    log_path: Optional[str],
    region: str = "UK",
    filter_summary: str = "None",
) -> None:
    """
    Print scan configuration and sub-band details to the terminal.
    """
    sep = "=" * 108
    print(sep)
    print(
        " HackRF Smart Spectrum Scanner: Cell Tower Search, Pulsed Hunter, Regional Filter & Distance Estimator"
    )
    print(sep)
    print(" Active Target Sub-Bands:")
    for min_mhz, max_mhz, label, desc in PENETRATION_SUB_BANDS:
        print(f"   * {label:<24} : {min_mhz:>6.1f} - {max_mhz:<6.1f} MHz | {desc}")
    print("-" * 108)
    print(f" Active Region  : {region} ({cti.REGION_LABELS.get(region, region)})")
    print(f" Scan Mode      : {scan_mode.upper()} (Ranges: {ranges_csv} MHz)")
    print(f" Pull Filters   : {filter_summary}")
    print(f" FFT Bin Width  : {bin_width_hz} Hz ({bin_width_hz / 1e3:.1f} kHz)")
    print(f" LNA / VGA Gain : {lna_gain_db} dB / {vga_gain_db} dB")
    print(f" RF Amplifier   : {'ENABLED (1)' if rf_amp else 'DISABLED (0)'}")
    print(f" dB Threshold   : {threshold_db:.1f} dB")
    print(
        f" Clock Spur Mute: {'ENABLED (Notching 10/20 MHz SDR spurs)' if ignore_spurs else 'DISABLED (Logging raw spurs)'}"
    )
    print(
        f" Sweep Count    : {'Continuous (0)' if sweep_count == 0 else sweep_count}"
    )
    if log_path:
        print(f" Log File       : {os.path.abspath(log_path)}")
    print(f" Command        : {' '.join(cmd)}")
    print(sep)
    print(
        f"{'TIMESTAMP':<23} | {'BAND TIER':<23} | {'FREQ (MHz)':>11} | {'POWER':>9} | {'EST DIST':>9} | {'SMART / CELL TAG':<22}"
    )
    print("-" * 108)
    sys.stdout.flush()


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HackRF Smart Scanner: Cell Tower Search, Pulsed Hunter, Regional Pull Filters & 1 MHz - 3 GHz Spectrum"
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["full", "cell", "cell-pulsed", "pulsed", "subghz", "highband", "mesh"],
        default=DEFAULT_SCAN_MODE,
        help="Scan preset: 'full', 'cell' (region-aware cell tower search), 'cell-pulsed' (pulsed cell band hunter), 'pulsed' (pulsed frequencies only), 'subghz', 'highband', or 'mesh'",
    )
    parser.add_argument(
        "--region",
        type=str,
        choices=list(cti.REGION_LABELS.keys()),
        default=None,
        help="Location/Region profile for cellular bands & ISM filtering (US, UK, EU, AU, GLOBAL). Defaults to scanner_config.json",
    )
    parser.add_argument(
        "--only-cell",
        action="store_true",
        default=False,
        help="Pull ONLY cellular-band frequencies (local or foreign cellular bands)",
    )
    parser.add_argument(
        "--only-pulsed",
        action="store_true",
        default=False,
        help="Pull ONLY frequencies confirmed as repeating pulsed bursts (suppresses single blips and 24/7 continuous noise)",
    )
    parser.add_argument(
        "--exclude-wifi",
        action="store_true",
        default=False,
        help="Exclude 2400-2483.5 MHz Wi-Fi/BLE band clutter",
    )
    parser.add_argument(
        "--exclude-ism",
        action="store_true",
        default=False,
        help="Exclude regional unlicensed ISM bands (433, 868/915, 2.4 GHz)",
    )
    parser.add_argument(
        "--ranges",
        type=str,
        default=None,
        help="Custom comma-separated MHz ranges for hackrf_sweep -f (overrides --mode)",
    )
    parser.add_argument(
        "-w",
        "--bin-width",
        type=int,
        default=FFT_BIN_WIDTH_HZ,
        help=f"FFT bin width in Hz (default: {FFT_BIN_WIDTH_HZ})",
    )
    parser.add_argument(
        "-l",
        "--lna-gain",
        type=int,
        default=LNA_GAIN_DB,
        help=f"RX LNA gain 0-40 dB in 8 dB steps (default: {LNA_GAIN_DB})",
    )
    parser.add_argument(
        "-g",
        "--vga-gain",
        type=int,
        default=VGA_GAIN_DB,
        help=f"RX VGA gain 0-62 dB in 2 dB steps (default: {VGA_GAIN_DB})",
    )
    parser.add_argument(
        "-a",
        "--amp",
        action="store_true",
        default=RF_AMP_ENABLE,
        help="Enable RX RF amplifier (default: disabled)",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=DETECTION_THRESHOLD_DB,
        help=f"Detection threshold in dB (default: {DETECTION_THRESHOLD_DB})",
    )
    parser.add_argument(
        "-N",
        "--sweeps",
        type=int,
        default=SWEEP_COUNT,
        help=f"Number of sweeps (0 for continuous, default: {SWEEP_COUNT})",
    )
    parser.add_argument(
        "--multi-f",
        action="store_true",
        default=not USE_SINGLE_COMMA_SEPARATED_F_ARG,
        help="Pass multiple -f flags instead of comma-separated",
    )
    parser.add_argument(
        "--include-spurs",
        action="store_true",
        default=False,
        help="Include internal 10/20 MHz HackRF clock spurs instead of auto-notching them",
    )
    parser.add_argument(
        "-o",
        "--log-file",
        type=str,
        default=LOG_FILE_PATH,
        help=f"Log file path (default: {LOG_FILE_PATH})",
    )
    return parser.parse_args()


# ==============================================================================
# MAIN SCANNER LOOP
# ==============================================================================


def main() -> int:
    args = parse_cli_args()

    if shutil.which("hackrf_sweep") is None:
        sys.stderr.write(
            "[ERROR] `hackrf_sweep` binary not found in PATH.\n"
            "        Run `./auto_scanner.sh --install-deps` or `sudo apt install hackrf`.\n"
        )
        return 1

    cfg = cti.load_config()
    region = args.region or cfg.get("region", "UK")
    cfg["region"] = region
    cfg["lna_gain_db"] = args.lna_gain
    cfg["vga_gain_db"] = args.vga_gain
    cfg["rf_amp"] = args.amp

    only_cell = args.only_cell or args.mode in ("cell", "cell-pulsed")
    only_pulsed = args.only_pulsed or args.mode in ("cell-pulsed", "pulsed")
    exclude_wifi = args.exclude_wifi or args.mode in ("cell", "cell-pulsed", "pulsed")
    exclude_ism = args.exclude_ism

    if args.ranges:
        ranges_csv = args.ranges
    elif args.mode in ("cell", "cell-pulsed"):
        ranges_csv = cti.get_cell_sweep_ranges(region, include_uplinks=True)
    else:
        ranges_csv = SCAN_MODE_RANGES[args.mode]

    max_allowed_mhz = 1000.0 if args.mode == "subghz" and not args.ranges else 3000.0
    ignore_spurs = not args.include_spurs

    active_filters: List[str] = []
    if only_cell:
        active_filters.append("CELLULAR-ONLY")
    if only_pulsed:
        active_filters.append("PULSED-ONLY (muting 24/7 & single noise)")
    if exclude_wifi:
        active_filters.append("EXCLUDE-WIFI (2.4G muted)")
    if exclude_ism:
        active_filters.append(f"EXCLUDE-{region}-ISM")
    filter_summary = ", ".join(active_filters) if active_filters else "All Active Sub-Bands"

    use_comma_flag = not args.multi_f
    cmd = build_hackrf_sweep_command(
        use_comma_flag=use_comma_flag,
        bin_width_hz=args.bin_width,
        lna_gain_db=args.lna_gain,
        vga_gain_db=args.vga_gain,
        rf_amp=args.amp,
        sweep_count=args.sweeps,
        ranges_csv=ranges_csv,
    )
    print_banner(
        cmd=cmd,
        scan_mode=args.mode,
        ranges_csv=ranges_csv,
        bin_width_hz=args.bin_width,
        lna_gain_db=args.lna_gain,
        vga_gain_db=args.vga_gain,
        rf_amp=args.amp,
        threshold_db=args.threshold,
        sweep_count=args.sweeps,
        ignore_spurs=ignore_spurs,
        log_path=args.log_file,
        region=region,
        filter_summary=filter_summary,
    )

    proc: Optional[subprocess.Popen] = None
    log_file = None
    total_hits = 0
    tier_counts: Dict[str, int] = {label: 0 for _, _, label, _ in PENETRATION_SUB_BANDS}
    live_tracker: Dict[float, Dict[str, float]] = {}
    start_time = time.time()

    def handle_sigterm(signum: int, frame: object) -> None:
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        if args.log_file:
            log_file = open(args.log_file, mode="a", encoding="utf-8", buffering=1)
            log_file.write(
                f"# --- Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"Mode: {args.mode} | Region: {region} | Filters: {filter_summary} | Command: {' '.join(cmd)} ---\n"
            )

        for attempt in range(2):
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            assert proc.stdout is not None
            csv_reader = csv.reader(proc.stdout)
            got_rows = False

            for row in csv_reader:
                if not row:
                    continue
                got_rows = True

                hits = parse_csv_record(
                    row,
                    threshold_db=args.threshold,
                    max_allowed_mhz=max_allowed_mhz,
                    ignore_spurs=ignore_spurs,
                    region=region,
                    only_cell=only_cell,
                    exclude_wifi=exclude_wifi,
                    exclude_ism=exclude_ism,
                )
                now_ts = time.time()
                for date_str, time_str, freq_mhz, power_db, tier_label in hits:
                    timestamp = f"{date_str} {time_str}"
                    smart_tag = get_live_smart_tag(
                        freq_mhz=freq_mhz,
                        power_db=power_db,
                        now_ts=now_ts,
                        tracker=live_tracker,
                    )

                    # If user enabled `--only-pulsed`, only pull/log confirmed pulsed bursts!
                    if only_pulsed and (
                        "CARRIER" in smart_tag or smart_tag.startswith("NEW")
                    ):
                        continue

                    cell_b = cti.match_cellular_band(freq_mhz, region)
                    if cell_b is not None:
                        tag_prefix = f"{cell_b['band'].split()[0]} {cell_b['direction'][:2]}"
                        display_tag = f"{tag_prefix} | {smart_tag}"
                        sig_kind = "macro_cell" if cell_b["direction"] in ("DOWNLINK", "TDD") else "portable_cell"
                    else:
                        f_cell = cti.match_foreign_cellular_band(freq_mhz, region)
                        if f_cell is not None:
                            display_tag = f"FOREIGN-{f_cell[0]}! | {smart_tag}"
                            sig_kind = "portable_cell"
                        else:
                            display_tag = smart_tag
                            sig_kind = "auto"

                    dist_est = cti.estimate_distance_from_db(
                        freq_mhz, power_db, config=cfg, signal_kind=sig_kind
                    )

                    total_hits += 1
                    tier_counts[tier_label] = tier_counts.get(tier_label, 0) + 1

                    line = (
                        f"{timestamp:<23} | "
                        f"{tier_label:<23} | "
                        f"{freq_mhz:>9.4f} M | "
                        f"{power_db:>6.2f} dB | "
                        f"{dist_est['primary_dist_str']:>9} | "
                        f"{display_tag}"
                    )
                    print(line, flush=True)

                    if log_file is not None:
                        log_file.write(
                            f"{timestamp},{tier_label},{freq_mhz:.6f},{power_db:.2f}\n"
                        )

            return_code = proc.wait()
            if return_code == 0:
                break

            stderr_output = ""
            if proc.stderr is not None:
                stderr_output = proc.stderr.read().strip()

            # Auto-fallback if comma-separated `-f` caused an argument error
            if (
                attempt == 0
                and use_comma_flag
                and not got_rows
                and (
                    "argument error" in stderr_output.lower()
                    or "usage:" in stderr_output.lower()
                )
            ):
                sys.stderr.write(
                    "[*] Local `hackrf_sweep` requires repeated `-f` flags; "
                    f"auto-retrying with expanded `-f` arguments for {ranges_csv}...\n"
                )
                use_comma_flag = False
                cmd = build_hackrf_sweep_command(
                    use_comma_flag=False,
                    bin_width_hz=args.bin_width,
                    lna_gain_db=args.lna_gain,
                    vga_gain_db=args.vga_gain,
                    rf_amp=args.amp,
                    sweep_count=args.sweeps,
                    ranges_csv=ranges_csv,
                )
                continue

            sys.stderr.write(
                f"\n[!] `hackrf_sweep` exited with code {return_code}.\n"
            )
            if stderr_output:
                sys.stderr.write(f"    stderr: {stderr_output}\n")
            return return_code

    except KeyboardInterrupt:
        print("\n[!] Signal detected. Stopping hackrf_sweep gracefully...", flush=True)
    finally:
        terminate_process_cleanly(proc)
        elapsed = time.time() - start_time
        print("-" * 96)
        print(
            f"[+] Scan terminated cleanly. Elapsed: {elapsed:.1f}s | Total Hits: {total_hits}"
        )
        for _, _, label, _ in PENETRATION_SUB_BANDS:
            print(f"    {label:<24}: {tier_counts.get(label, 0)} hits")
        print("=" * 96, flush=True)

        if log_file is not None:
            try:
                log_file.write(
                    f"# --- Scan ended at {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                    f"Total hits: {total_hits} ---\n"
                )
                log_file.close()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
