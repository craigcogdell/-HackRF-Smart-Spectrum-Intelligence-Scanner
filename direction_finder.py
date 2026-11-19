#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 RF Direction Finder & Multi-Point Triangulator
(`direction_finder.py`).

Uses a HackRF One with a directional antenna (Yagi / Log-Periodic / Cantenna) or
body-shielding nulling to determine the compass bearing (direction) and estimated
distance of any target cell tower or pulsed frequency.

Capabilities:
  1. Live Narrowband Heading Sampler (`sample_live_bearing`):
     Runs a fast `hackrf_sweep` window around `freq_mhz +/- span_mhz` (25 kHz bins)
     for a few sweeps and extracts peak & average dB at the user's current compass heading.
  2. Circular Vector Bearing Estimator (`compute_bearing_summary`):
     Computes weighted circular vector mean azimuth (0-359°), 16-point cardinal heading,
     Front-to-Back ratio (dB), signal null direction, confidence level, and dB-based
     distance estimate (both Macro Cell Tower & Portable/Fake BTS models).
  3. Multi-Point GPS Triangulation (`triangulate_bearings`):
     Intersects 2+ compass bearings recorded from different GPS coordinates to estimate
     the transmitter's geographic Latitude & Longitude.
  4. Persistent storage (`df_bearings.json`) automatically linked into `cell_tower_intel.py`
     and the interactive Web Dashboard Polar Radar!
"""

import argparse
import csv
import json
import math
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import cell_tower_intel as cti

DF_BEARINGS_FILE = cti.DF_BEARINGS_FILE


def _freq_key(freq_mhz: float) -> str:
    return f"{round(float(freq_mhz), 3):.3f}"


def load_bearings_db() -> Dict[str, Any]:
    return cti.load_df_bearings()


def save_bearings_db(db: Dict[str, Any]) -> None:
    with open(DF_BEARINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def compute_bearing_summary(
    freq_mhz: float,
    samples: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Calculate the best estimated Direction of Arrival (Azimuth° + Cardinal),
    Front-to-Back ratio, Null Bearing, Confidence, and dB-based Distance Estimate
    from a list of compass heading samples:
        [{"heading_deg": 45.0, "power_db": -22.4, ...}, ...]
    """
    cfg = config or cti.load_config()
    if not samples:
        return {
            "freq_mhz": round(freq_mhz, 4),
            "sample_count": 0,
            "peak_bearing_deg": None,
            "cardinal": "N/A",
            "null_bearing_deg": None,
            "peak_db": None,
            "min_db": None,
            "front_to_back_db": 0.0,
            "confidence": "NONE",
            "distance": None,
            "heading_bins": [],
        }

    # Aggregate multiple samples at the same heading into average/max per heading
    by_heading: Dict[float, List[float]] = {}
    for s in samples:
        h = round(float(s["heading_deg"]) % 360.0, 1)
        p = float(s["power_db"])
        by_heading.setdefault(h, []).append(p)

    heading_bins: List[Dict[str, Any]] = []
    for h, powers in sorted(by_heading.items()):
        heading_bins.append(
            {
                "heading_deg": h,
                "cardinal": cti.deg_to_cardinal(h),
                "max_db": round(max(powers), 2),
                "avg_db": round(sum(powers) / len(powers), 2),
                "count": len(powers),
            }
        )

    peak_bin = max(heading_bins, key=lambda b: b["max_db"])
    min_bin = min(heading_bins, key=lambda b: b["max_db"])
    peak_db = peak_bin["max_db"]
    min_db = min_bin["max_db"]
    fb_ratio = round(peak_db - min_db, 2)

    # Weighted circular vector mean using relative linear power above (min_db - 2 dB)
    # Using power weight w = 10^((dB - peak_db)/10) focuses the vector toward the main lobe
    sum_sin = 0.0
    sum_cos = 0.0
    for b in heading_bins:
        weight = 10.0 ** ((b["max_db"] - peak_db) / 10.0)
        rad = math.radians(b["heading_deg"])
        sum_sin += weight * math.sin(rad)
        sum_cos += weight * math.cos(rad)

    if abs(sum_sin) < 1e-9 and abs(sum_cos) < 1e-9:
        est_deg = peak_bin["heading_deg"]
    else:
        est_deg = (math.degrees(math.atan2(sum_sin, sum_cos)) + 360.0) % 360.0
    est_deg = round(est_deg, 1)

    # Confidence scoring based on angular coverage & front-to-back dynamic range
    n_headings = len(heading_bins)
    if n_headings >= 6 and fb_ratio >= 8.0:
        confidence = "HIGH"
    elif n_headings >= 4 and fb_ratio >= 5.0:
        confidence = "MEDIUM"
    elif n_headings >= 2 and fb_ratio >= 3.0:
        confidence = "LOW-MEDIUM"
    else:
        confidence = "LOW (Collect more compass headings)"

    # Determine signal class for primary distance display
    region = cfg.get("region", "UK")
    cell_b = cti.match_cellular_band(freq_mhz, region)
    sig_kind = (
        "macro_cell"
        if (cell_b and cell_b["direction"] in ("DOWNLINK", "TDD"))
        else ("portable_cell" if cell_b else "auto")
    )
    dist = cti.estimate_distance_from_db(freq_mhz, peak_db, config=cfg, signal_kind=sig_kind)

    return {
        "freq_mhz": round(freq_mhz, 4),
        "sample_count": len(samples),
        "unique_headings": n_headings,
        "peak_bearing_deg": est_deg,
        "peak_heading_raw_deg": peak_bin["heading_deg"],
        "cardinal": cti.deg_to_cardinal(est_deg),
        "null_bearing_deg": min_bin["heading_deg"],
        "null_cardinal": cti.deg_to_cardinal(min_bin["heading_deg"]),
        "peak_db": peak_db,
        "min_db": min_db,
        "front_to_back_db": fb_ratio,
        "confidence": confidence,
        "distance": dist,
        "heading_bins": heading_bins,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def record_bearing_sample(
    freq_mhz: float,
    heading_deg: float,
    power_db: float,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    note: str = "",
    source: str = "MANUAL",
) -> Dict[str, Any]:
    """
    Append a compass bearing measurement for `freq_mhz` and recompute its DF summary.
    """
    db = load_bearings_db()
    key = _freq_key(freq_mhz)
    entry = db.get(
        key,
        {
            "freq_mhz": round(float(freq_mhz), 4),
            "samples": [],
            "summary": {},
        },
    )
    sample = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "heading_deg": round(float(heading_deg) % 360.0, 1),
        "power_db": round(float(power_db), 2),
        "lat": float(lat) if lat not in (None, "") else None,
        "lon": float(lon) if lon not in (None, "") else None,
        "note": str(note or "").strip(),
        "source": source,
    }
    entry["samples"].append(sample)
    entry["summary"] = compute_bearing_summary(float(freq_mhz), entry["samples"])
    db[key] = entry
    save_bearings_db(db)
    return entry


def clear_bearing_samples(freq_mhz: float) -> Dict[str, Any]:
    db = load_bearings_db()
    key = _freq_key(freq_mhz)
    if key in db:
        del db[key]
        save_bearings_db(db)
    return {"cleared": key, "remaining_targets": len(db)}


def sample_live_bearing(
    freq_mhz: float,
    heading_deg: float,
    span_mhz: float = 1.0,
    sweeps: int = 3,
    bin_width_hz: int = 25000,
    record: bool = True,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    note: str = "",
) -> Dict[str, Any]:
    """
    Perform a fast narrowband HackRF sweep around `freq_mhz` at `heading_deg` to
    measure the live signal power in that compass direction.
    """
    if shutil.which("hackrf_sweep") is None:
        return {
            "ok": False,
            "error": "`hackrf_sweep` is not installed in PATH.",
        }

    cfg = cti.load_config()
    lna = int(cfg.get("lna_gain_db", 16))
    vga = int(cfg.get("vga_gain_db", 20))
    amp = 1 if cfg.get("rf_amp", False) else 0

    lo = max(1, int(math.floor(freq_mhz - max(1.0, span_mhz))))
    hi = min(6000, int(math.ceil(freq_mhz + max(1.0, span_mhz))))
    if hi <= lo:
        hi = lo + 2

    cmd = [
        "hackrf_sweep",
        "-f",
        f"{lo}:{hi}",
        "-w",
        str(int(bin_width_hz)),
        "-l",
        str(lna),
        "-g",
        str(vga),
        "-a",
        str(amp),
        "-N",
        str(max(1, int(sweeps))),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=12.0,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Timed out waiting for HackRF sweep. Ensure no other scanner is holding the HackRF USB device."}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to invoke hackrf_sweep: {exc}"}

    if proc.returncode != 0:
        err_msg = (proc.stderr or proc.stdout or "").strip()
        return {
            "ok": False,
            "error": f"hackrf_sweep error (code {proc.returncode}): {err_msg or 'No HackRF connected or device busy (stop background scanner first).'}",
        }

    # Extract bins within +/- 0.25 MHz of target frequency
    target_powers: List[float] = []
    window_half_mhz = max(0.15, min(0.5, span_mhz * 0.3))
    for row in csv.reader(proc.stdout.splitlines()):
        if len(row) < 7:
            continue
        try:
            hz_low = float(row[2].strip())
            hz_bin = float(row[4].strip())
            dbs = row[6:]
        except ValueError:
            continue
        for i, db_s in enumerate(dbs):
            try:
                p_db = float(db_s.strip())
            except ValueError:
                continue
            f_m = (hz_low + (i + 0.5) * hz_bin) / 1e6
            if abs(f_m - freq_mhz) <= window_half_mhz:
                target_powers.append(p_db)

    if not target_powers:
        return {
            "ok": False,
            "error": f"No FFT bins matched {freq_mhz:.3f} MHz in range {lo}:{hi} MHz.",
        }

    peak_db = round(max(target_powers), 2)
    avg_db = round(sum(target_powers) / len(target_powers), 2)

    entry = None
    if record:
        entry = record_bearing_sample(
            freq_mhz=freq_mhz,
            heading_deg=heading_deg,
            power_db=peak_db,
            lat=lat if lat is not None else cfg.get("latitude"),
            lon=lon if lon is not None else cfg.get("longitude"),
            note=note or f"Live HackRF ({sweeps} sweeps, avg {avg_db} dB)",
            source="LIVE_HACKRF",
        )

    return {
        "ok": True,
        "freq_mhz": round(freq_mhz, 4),
        "heading_deg": round(float(heading_deg) % 360.0, 1),
        "peak_db": peak_db,
        "avg_db": avg_db,
        "bins_measured": len(target_powers),
        "entry": entry,
    }


def triangulate_bearings(observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Given 2 or more bearing lines from distinct GPS coordinates:
        [{"lat": 51.500, "lon": -0.120, "bearing_deg": 45.0}, ...]
    compute the least-squares intersection point in local tangent-plane (ENU) meters
    and convert back to (est_lat, est_lon).
    """
    valid: List[Tuple[float, float, float]] = []
    for obs in observations:
        try:
            lat = float(obs["lat"])
            lon = float(obs["lon"])
            brg = float(obs["bearing_deg"]) % 360.0
            valid.append((lat, lon, brg))
        except (KeyError, TypeError, ValueError):
            continue

    if len(valid) < 2:
        return {
            "ok": False,
            "error": "Provide at least 2 bearing observations from different GPS coordinates.",
        }

    # Local ENU projection centered at mean lat/lon
    ref_lat = sum(v[0] for v in valid) / len(valid)
    ref_lon = sum(v[1] for v in valid) / len(valid)
    m_per_deg_lat = 111132.92
    m_per_deg_lon = 111412.84 * math.cos(math.radians(ref_lat))

    # Each bearing ray from (x_i, y_i) with direction (sin(az), cos(az)) has normal
    # n_i = (cos(az), -sin(az)), satisfying n_i . p = n_i . p_i.
    # Solve 2x2 normal equations A * [x, y]^T = b.
    a00 = a01 = a11 = b0 = b1 = 0.0
    rays = []
    for lat, lon, az in valid:
        xi = (lon - ref_lon) * m_per_deg_lon
        yi = (lat - ref_lat) * m_per_deg_lat
        rad = math.radians(az)
        dx = math.sin(rad)
        dy = math.cos(rad)
        nx = dy
        ny = -dx
        c = nx * xi + ny * yi
        a00 += nx * nx
        a01 += nx * ny
        a11 += ny * ny
        b0 += nx * c
        b1 += ny * c
        rays.append((xi, yi, dx, dy))

    det = a00 * a11 - a01 * a01
    if abs(det) < 1e-6:
        return {
            "ok": False,
            "error": "Bearing lines are nearly parallel — move to a wider baseline angle and re-measure.",
        }

    est_x = (a11 * b0 - a01 * b1) / det
    est_y = (-a01 * b0 + a00 * b1) / det

    # Check if intersection lies in front of the rays (positive dot product)
    forward_count = sum(
        1 for xi, yi, dx, dy in rays if ((est_x - xi) * dx + (est_y - yi) * dy) > 0
    )

    est_lat = round(ref_lat + (est_y / m_per_deg_lat), 6)
    est_lon = round(ref_lon + (est_x / m_per_deg_lon), 6)

    dist_from_first, brg_from_first, card_first = cti.haversine_and_bearing(
        valid[0][0], valid[0][1], est_lat, est_lon
    )

    warning = None
    if forward_count < len(valid):
        warning = "Warning: Bearing rays diverge behind one or more stations; verify compass calibration or multipath reflections."

    return {
        "ok": True,
        "estimated_lat": est_lat,
        "estimated_lon": est_lon,
        "distance_from_point1_m": dist_from_first,
        "distance_from_point1_str": cti.format_distance_m(dist_from_first),
        "bearing_from_point1": f"{card_first} {brg_from_first}°",
        "stations_used": len(valid),
        "warning": warning,
        "maps_url": f"https://www.openstreetmap.org/?mlat={est_lat}&mlon={est_lon}#map=16/{est_lat}/{est_lon}",
    }


def run_interactive_cli(freq_mhz: float) -> int:
    sep = "=" * 84
    print(sep)
    print(f" HACKRF INTERACTIVE COMPASS DIRECTION FINDER — TARGET: {freq_mhz:.4f} MHz")
    print(sep)
    print(" Point your directional antenna (or use body-shielding with a whip antenna)")
    print(" toward each compass heading (0=N, 45=NE, 90=E, 135=SE, 180=S, 225=SW, 270=W, 315=NW).")
    print(" Commands: enter heading degrees (e.g. '45') to run a live HackRF sample,")
    print("           '45 -24.5' to log a manual dB reading, 'clear' to reset, 'q' to quit.")
    print(sep)

    while True:
        try:
            raw = input("\nHeading deg [0-359] (or 'deg dB' / 'clear' / 'q'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting Direction Finder.")
            break
        if not raw or raw.lower() in ("q", "quit", "exit"):
            break
        if raw.lower() == "clear":
            clear_bearing_samples(freq_mhz)
            print(f"[+] Cleared bearing samples for {freq_mhz:.3f} MHz.")
            continue

        parts = raw.split()
        try:
            hdg = float(parts[0])
        except ValueError:
            print("[!] Invalid heading. Enter degrees 0-359 (e.g. 90 for East).")
            continue

        if len(parts) >= 2:
            try:
                pwr = float(parts[1])
            except ValueError:
                print("[!] Invalid dB power value.")
                continue
            entry = record_bearing_sample(freq_mhz, hdg, pwr, source="CLI_MANUAL")
            summary = entry["summary"]
            print(f"[+] Recorded manual sample: {hdg:.0f}° ({cti.deg_to_cardinal(hdg)}) -> {pwr:.2f} dB")
        else:
            print(f"[*] Sampling live HackRF power around {freq_mhz:.3f} MHz at {hdg:.0f}° ({cti.deg_to_cardinal(hdg)})...")
            res = sample_live_bearing(freq_mhz, hdg)
            if not res.get("ok"):
                print(f"[!] {res.get('error')}")
                continue
            summary = res["entry"]["summary"]
            print(f"[+] Live sample: Peak {res['peak_db']:.2f} dB (Avg {res['avg_db']:.2f} dB)")

        dist = summary.get("distance") or {}
        print("-" * 84)
        print(
            f" ESTIMATED DIRECTION : {summary['cardinal']} {summary['peak_bearing_deg']:.1f}° "
            f"(Front/Back: {summary['front_to_back_db']:.1f} dB | Confidence: {summary['confidence']})"
        )
        print(
            f" SIGNAL NULL (BACK)  : {summary['null_cardinal']} {summary['null_bearing_deg']:.1f}° ({summary['min_db']:.1f} dB)"
        )
        if dist:
            print(
                f" EST. DISTANCE (dB)  : Macro Tower {dist['macro_tower_str']} | "
                f"Portable/Fake BTS {dist['portable_bts_str']}"
            )
        print("-" * 84)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="HackRF Compass Direction Finder & Distance Estimator")
    parser.add_argument("--freq", type=float, required=True, help="Target frequency in MHz (e.g. 890.25)")
    parser.add_argument("--heading", type=float, default=None, help="Single heading in degrees (0-359) to sample and exit")
    parser.add_argument("--db", type=float, default=None, help="Optional manual dB reading to log with --heading")
    args = parser.parse_args()

    if args.heading is not None:
        if args.db is not None:
            entry = record_bearing_sample(args.freq, args.heading, args.db, source="CLI_MANUAL")
            print(json.dumps(entry["summary"], indent=2))
            return 0
        res = sample_live_bearing(args.freq, args.heading)
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    return run_interactive_cli(args.freq)


if __name__ == "__main__":
    sys.exit(main())
