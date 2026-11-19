#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 Signal Intelligence Analyzer for HackRF scans.
Reads `penetration_scan_hits.log`, separates internal SDR clock spurs, and performs:
  1. Pulsed Frequency Profiling (Inter-Arrival Time / PRI, jitter, cadence, & device inference)
  2. Mesh Network Topology Detection (Multi-node RSSI clustering, store-and-forward relay echoes,
     Zigbee/Thread/Matter, Meshtastic/LoRa, Z-Wave, BLE Mesh, Wi-Fi 802.11s Mesh)
  3. 1-3 GHz & Sub-GHz Round-the-Clock (24/7 Continuous Carrier) Transmitter Hunting
"""

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_FILE = os.path.join(SCRIPT_DIR, "penetration_scan_hits.log")

# Internal HackRF clock spurs to separate so they don't skew real signal duty-cycle math
INTERNAL_SPUR_WINDOWS_MHZ: List[Tuple[float, float, str]] = [
    (9.970, 10.030, "10.00 MHz HackRF Internal TCXO Reference Spur"),
    (19.910, 20.110, "20.00 MHz HackRF Internal ADC Sample Clock Spur"),
]

# Known Sub-GHz & 1-3 GHz frequency signatures
KNOWN_BAND_SIGNATURES: List[Tuple[float, float, str]] = [
    # --- 1 - 30 MHz (Deep Inductive / HF) ---
    (1.800, 2.000, "160m Amateur / Inductive HF"),
    (3.500, 4.000, "80m Amateur / Shortwave HF"),
    (6.750, 6.810, "6.78 MHz ISM (Magnetic Resonance Wireless Power / Inductive)"),
    (7.000, 7.300, "40m Amateur / Shortwave"),
    (13.540, 13.580, "13.56 MHz ISM (NFC / RFID / Deep Inductive Medical Telemetry)"),
    (14.000, 14.350, "20m Amateur / HF Utility Band"),
    (26.957, 27.283, "27.12 MHz ISM (Diathermy / Medical RF / CB)"),
    (28.000, 29.700, "10m Amateur Band"),
    # --- 400 - 450 MHz (High Penetration / Telemetry / UHF Mesh) ---
    (401.000, 402.000, "MedRadio Wing Band (401-402 MHz Medical Implant/Body-Worn)"),
    (402.000, 405.000, "MICS / MedRadio Core (402-405 MHz Cardiac/Implant Telemetry)"),
    (405.000, 406.000, "MedRadio Wing Band (405-406 MHz Medical Telemetry)"),
    (406.000, 406.100, "Emergency Distress Beacon (COSPAS-SARSAT 50s Pulse)"),
    (410.000, 430.000, "UHF Land Mobile / Trunked Radio (TETRA / P25 / DMR TDMA)"),
    (433.050, 434.790, "433 MHz ISM (LoRa/Meshtastic 433 Mesh / Sensors / Keyfobs / TPMS)"),
    (430.000, 440.000, "70cm Amateur / UHF Telemetry"),
    (446.000, 446.200, "PMR446 UHF Personal Radio"),
    # --- 600 - 860 MHz (Sub-GHz Cellular LTE/5G Bands 71, 12, 13, 14, 28, 20, 5) ---
    (617.000, 652.000, "600 MHz 5G/LTE Band 71 Downlink (US) / UHF TV (UK/EU)"),
    (703.000, 748.000, "700 MHz LTE/5G Band 28 Uplink (UK/EU/AU) / Band 12 Downlink (US)"),
    (746.000, 768.000, "700 MHz LTE Band 13/14 Downlink (US) / Band 28 Downlink (UK/EU/AU)"),
    (758.000, 803.000, "700 MHz LTE/5G Band 28 Downlink (UK/EU/AU)"),
    (791.000, 821.000, "800 MHz LTE Band 20 Cellular Base Station Downlink (UK/EU 24/7 Carrier)"),
    (824.000, 862.000, "800/850 MHz LTE Band 20/5 Cellular Mobile Uplink"),
    # --- 860 - 960 MHz (Sub-GHz Mesh / Telemetry / Cellular) ---
    (863.000, 868.000, "863-868 MHz Europe SRD / Wireless Audio / Walkie-Talkie / Mesh"),
    (868.000, 868.600, "868 MHz Core ISM (LoRaWAN EU868 / Zigbee 868 Mesh / Smart Meters)"),
    (868.350, 868.500, "Z-Wave EU Mesh Channel (868.42 MHz Home Automation Mesh)"),
    (869.400, 869.650, "Meshtastic EU868 Mesh (869.525 MHz High-Power LoRa Mesh) / Alarms"),
    (869.700, 870.000, "Z-Wave EU High Channel (869.85 MHz) / SRD Telemetry"),
    (870.000, 880.000, "870-876 MHz Short-Range Devices / Smart Grid Mesh (or US/AU B5 Cellular DL)"),
    (880.000, 915.000, "E-GSM 900 / LTE Band 8 Uplink (UK/EU) OR US Band 5 DL (869-894) / US915 ISM"),
    (906.500, 907.200, "Meshtastic US915 Default Mesh Channel (906.875 MHz) / E-GSM Uplink"),
    (908.300, 908.550, "Z-Wave US Mesh Channel (908.42 MHz) / E-GSM Uplink"),
    (915.000, 925.000, "915 MHz ISM Mesh (US/AU LoRa / Zigbee / Z-Wave) OR UK/EU GSM-R Railway"),
    (925.000, 960.000, "E-GSM 900 / LTE Band 8 Cellular Base Station Downlink (UK/EU/AU 24/7 Carrier)"),
    # --- 1000 - 2000 MHz (L-Band: Aviation, GNSS, DECT, Cellular 24/7 Downlinks) ---
    (1029.000, 1031.000, "1030 MHz Aviation SSR / TCAS Radar Interrogation Pulses"),
    (1089.000, 1091.000, "1090 MHz ADS-B / Mode-S Aircraft Transponder Pulses"),
    (1164.000, 1250.000, "GNSS L5/L2 / Aviation DME Pulsed Navigation Transponders"),
    (1525.000, 1626.500, "L-Band Satellite (Inmarsat/Iridium) & GPS L1 (1575.42 MHz)"),
    (1710.000, 1785.000, "LTE Band 3 / DCS-1800 Cellular Mobile Uplink"),
    (1805.000, 1880.000, "LTE Band 3 / DCS-1800 Cellular Base Station Downlink (24/7 Carrier)"),
    (1880.000, 1900.000, "DECT Cordless Phone / Wireless Intercom / Baby Monitor (10ms TDMA Pulses)"),
    (1920.000, 1980.000, "LTE Band 1 / UMTS 2100 Cellular Mobile Uplink"),
    # --- 2000 - 3000 MHz (S-Band: 2.4 GHz Mesh/ISM, LTE/5G 24/7 Carriers, Radar) ---
    (2110.000, 2170.000, "LTE Band 1 / UMTS 2100 Cellular Base Station Downlink (24/7 Carrier)"),
    (2300.000, 2400.000, "LTE Band 40 (2.3 GHz TDD Cellular Base Station) / Amateur 13cm"),
    (2400.000, 2483.500, "2.4 GHz ISM (Zigbee/Thread Mesh, Wi-Fi Mesh, BLE Mesh, Video/Drone Links)"),
    (2483.500, 2500.000, "2.48 GHz Satellite S-Band / Industrial Telemetry"),
    (2500.000, 2570.000, "LTE Band 7 Uplink / Band 41 TDD Cellular"),
    (2570.000, 2620.000, "LTE Band 38 / Band 41 TDD Cellular Base Station (24/7 Carrier)"),
    (2620.000, 2690.000, "LTE Band 7 Cellular Base Station Downlink (24/7 Carrier)"),
    (2700.000, 3000.000, "S-Band Airport / Weather Surveillance Radar (2.7-3.0 GHz Pulsed)"),
]

# Known Mesh-Capable Frequency Ranges: (low_mhz, high_mhz, protocol_name)
MESH_PROTOCOL_BANDS: List[Tuple[float, float, str]] = [
    (433.050, 434.790, "LoRa 433 / Meshtastic 433 MHz Mesh"),
    (863.000, 868.000, "Sub-GHz SRD / 802.15.4g Smart Grid Mesh"),
    (868.000, 868.600, "EU868 LoRa Mesh / Zigbee 868 (802.15.4)"),
    (868.350, 868.500, "Z-Wave EU Mesh (868.42 MHz)"),
    (869.400, 869.650, "Meshtastic EU868 Mesh (869.525 MHz)"),
    (869.700, 870.000, "Z-Wave EU High-Speed Mesh (869.85 MHz)"),
    (902.000, 928.000, "US915 Meshtastic / LoRa / Z-Wave / Zigbee 915 Mesh"),
    (2400.000, 2483.500, "2.4 GHz Mesh (Zigbee / Thread / Matter / BLE Mesh / Wi-Fi 802.11s)"),
]


def is_internal_spur(freq_mhz: float) -> Optional[str]:
    for low_m, high_m, desc in INTERNAL_SPUR_WINDOWS_MHZ:
        if low_m <= freq_mhz <= high_m:
            return desc
    return None


def identify_24ghz_channel_detail(freq_mhz: float) -> Optional[str]:
    """
    Pinpoint exact BLE Advertising, Zigbee/Thread (Ch 11-26), or Wi-Fi (Ch 1-13)
    channels inside 2400 - 2483.5 MHz.
    """
    if not (2400.0 <= freq_mhz <= 2485.0):
        return None

    details: List[str] = []
    # BLE Advertising channels: 37 (2402 MHz), 38 (2426 MHz), 39 (2480 MHz)
    for ch, ble_f in [(37, 2402.0), (38, 2426.0), (39, 2480.0)]:
        if abs(freq_mhz - ble_f) <= 1.0:
            details.append(f"BLE Mesh/Beacon Adv Ch {ch} ({ble_f:.0f} MHz)")

    # Zigbee / Thread / Matter IEEE 802.15.4 Channels 11..26: Fc = 2405 + 5*(k-11)
    for zb_ch in range(11, 27):
        zb_center = 2405.0 + 5.0 * (zb_ch - 11)
        if abs(freq_mhz - zb_center) <= 1.2:
            pref = " [Primary Non-WiFi Mesh Ch]" if zb_ch in (11, 15, 20, 25, 26) else ""
            details.append(f"Zigbee/Thread Mesh Ch {zb_ch} ({zb_center:.0f} MHz){pref}")
            break

    # Wi-Fi 802.11b/g/n/ax Channels 1..13: Fc = 2412 + 5*(k-1)
    for wf_ch in (1, 6, 11):
        wf_center = 2412.0 + 5.0 * (wf_ch - 1)
        if abs(freq_mhz - wf_center) <= 2.5:
            details.append(f"Wi-Fi Center Ch {wf_ch} ({wf_center:.0f} MHz)")
            break

    return " | ".join(details) if details else None


def identify_signature(freq_mhz: float) -> str:
    """
    Match a frequency (MHz) against known Sub-GHz and 1-3 GHz allocations.
    """
    ch_24 = identify_24ghz_channel_detail(freq_mhz)
    matches: List[str] = []
    for low_mhz, high_mhz, desc in KNOWN_BAND_SIGNATURES:
        if low_mhz <= freq_mhz <= high_mhz:
            matches.append(desc)

    base = matches[0] if matches else ""
    if not base:
        if 1.0 <= freq_mhz <= 30.0:
            base = "HF Deep Inductive / Shortwave Utility"
        elif 400.0 <= freq_mhz <= 450.0:
            base = "UHF Sub-Band (Telemetry / Land Mobile)"
        elif 860.0 <= freq_mhz <= 930.0:
            base = "Sub-GHz UHF (Cellular / Telemetry / Mesh)"
        elif 1000.0 <= freq_mhz <= 2000.0:
            base = "L-Band (1-2 GHz Microwave / Satellite / Cellular / Aviation)"
        elif 2000.0 <= freq_mhz <= 3000.0:
            base = "S-Band (2-3 GHz Wireless / Radar / Cellular / ISM)"
        else:
            base = "Unclassified RF Signal"

    if ch_24:
        return f"{base} -> {ch_24}"
    return base


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    ts_str = ts_str.strip()
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def load_log_hits(
    log_path: str,
    min_db: Optional[float] = None,
    tier_filter: Optional[str] = None,
) -> List[Tuple[str, Optional[datetime], str, float, float]]:
    """
    Read hits from `penetration_scan_hits.log`.
    """
    records: List[Tuple[str, Optional[datetime], str, float, float]] = []
    if not os.path.exists(log_path):
        return records

    with open(log_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            first_col = row[0].strip()
            if not first_col or first_col.startswith("#"):
                continue
            if len(row) < 4:
                continue
            try:
                ts_str = first_col
                tier_label = row[1].strip()
                freq_mhz = float(row[2].strip())
                power_db = float(row[3].strip())
            except ValueError:
                continue

            if min_db is not None and power_db < min_db:
                continue
            if tier_filter and tier_filter.lower() not in tier_label.lower():
                continue

            dt = parse_timestamp(ts_str)
            records.append((ts_str, dt, tier_label, freq_mhz, power_db))

    return records


def analyze_pulse_and_mesh_characteristics(
    events: List[Tuple[float, float]],
    center_mhz: float,
    occupancy_pct: float,
) -> Dict[str, Any]:
    """
    Given chronological `(epoch_sec, peak_db)` events for a frequency cluster:
      1. Group same-sweep samples (`dt < 0.12s`) into discrete burst events.
      2. Compute Pulse Repetition Interval (PRI / inter-arrival times), median PRI,
         PRI jitter (std dev), and Coefficient of Variation (CV).
      3. Identify what type of pulsed device it likely is.
      4. Detect Mesh Network behavior:
         - Multi-node RSSI levels (distinct power clusters separated by >= 5.5 dB)
         - Store-and-forward relay echoes (bursts separated by 0.05s..3.0s with |ΔdB| >= 5.0 dB)
    """
    if not events:
        return {}

    sorted_ev = sorted(events, key=lambda x: x[0])

    # Coalesce hits within 0.12s into discrete burst events (timestamp, max_db)
    bursts: List[Tuple[float, float]] = []
    for t_sec, db in sorted_ev:
        if not bursts:
            bursts.append((t_sec, db))
            continue
        prev_t, prev_db = bursts[-1]
        if (t_sec - prev_t) < 0.12:
            bursts[-1] = (prev_t, max(prev_db, db))
        else:
            bursts.append((t_sec, db))

    burst_count = len(bursts)
    intervals: List[float] = []
    relay_echoes = 0

    for i in range(1, burst_count):
        dt = bursts[i][0] - bursts[i - 1][0]
        db_diff = abs(bursts[i][1] - bursts[i - 1][1])
        # Only count intervals within the same continuous scanning session (< 1800s)
        if 0.12 <= dt <= 1800.0:
            intervals.append(dt)
        # Store-and-forward mesh relay echo: immediate retransmission (0.05s - 3.5s)
        # at a distinctly different RSSI (another node further/closer away)
        if 0.05 <= dt <= 3.5 and db_diff >= 5.0:
            relay_echoes += 1

    # Estimate distinct RSSI power nodes (greedy 6 dB mode clustering)
    burst_dbs = sorted([b[1] for b in bursts], reverse=True)
    node_power_centers: List[float] = []
    for db_val in burst_dbs:
        if not any(abs(db_val - c) < 5.5 for c in node_power_centers):
            node_power_centers.append(round(db_val, 1))
    estimated_nodes = len(node_power_centers)

    # Pulse interval statistics
    mean_pri = 0.0
    median_pri = 0.0
    std_pri = 0.0
    cv_pri = 0.0
    pulse_class = "SINGLE TRANSIENT BURST"

    if intervals:
        s_int = sorted(intervals)
        n_int = len(s_int)
        mean_pri = sum(s_int) / n_int
        if n_int % 2 == 1:
            median_pri = s_int[n_int // 2]
        else:
            median_pri = 0.5 * (s_int[n_int // 2 - 1] + s_int[n_int // 2])
        var_pri = sum((x - mean_pri) ** 2 for x in s_int) / n_int
        std_pri = math.sqrt(var_pri)
        cv_pri = (std_pri / mean_pri) if mean_pri > 0 else 0.0

        if occupancy_pct >= 65.0:
            pulse_class = "CONTINUOUS / 24-7 CARRIER"
        elif median_pri < 1.0:
            pulse_class = f"RAPID PULSE TRAIN (PRI ~{median_pri*1000:.0f} ms)"
        elif cv_pri <= 0.25 and n_int >= 2:
            pulse_class = f"STRICT PERIODIC BEACON (Every {median_pri:.1f}s)"
        elif cv_pri <= 0.65 and n_int >= 2:
            pulse_class = f"SCHEDULED / QUASI-PERIODIC PULSE (~{median_pri:.1f}s)"
        else:
            pulse_class = f"BURSTY / EVENT-DRIVEN PULSES (Med Δt={median_pri:.1f}s)"
    elif burst_count >= 2:
        pulse_class = "INTERMITTENT MULTI-SESSION BURSTS"

    # Probable Pulsed Device Identification
    probable_pulsed_source = infer_pulsed_device(
        center_mhz=center_mhz,
        burst_count=burst_count,
        median_pri=median_pri,
        cv_pri=cv_pri,
        occupancy_pct=occupancy_pct,
    )

    # Mesh Network Scoring & Classification
    mesh_proto = None
    for low_m, high_m, proto_desc in MESH_PROTOCOL_BANDS:
        if low_m <= center_mhz <= high_m:
            mesh_proto = proto_desc
            break

    mesh_score = 0
    mesh_reasons: List[str] = []
    if mesh_proto:
        mesh_score += 25
        mesh_reasons.append(f"Operates in known mesh band ({mesh_proto})")
    if estimated_nodes >= 3:
        mesh_score += 40
        mesh_reasons.append(
            f"Multi-node RSSI signature: {estimated_nodes} distinct power tiers ({', '.join(f'{p:.1f}dB' for p in node_power_centers[:4])})"
        )
    elif estimated_nodes == 2 and burst_count >= 2:
        mesh_score += 25
        mesh_reasons.append(
            f"Dual-node RSSI levels detected ({node_power_centers[0]:.1f} dB & {node_power_centers[1]:.1f} dB)"
        )
    if relay_echoes >= 1:
        mesh_score += 35
        mesh_reasons.append(
            f"{relay_echoes} store-and-forward relay echo(es) (bursts <3.5s apart with >=5 dB power step)"
        )

    if mesh_score >= 60:
        mesh_status = "[CONFIRMED MESH NETWORK]"
    elif mesh_score >= 45:
        mesh_status = "[PROBABLE MESH / MULTI-NODE RELAY]"
    elif mesh_proto and burst_count >= 2:
        mesh_status = "[MESH-CAPABLE CHANNEL ACTIVE]"
    else:
        mesh_status = "NONE"

    return {
        "burst_count": burst_count,
        "mean_pri_sec": round(mean_pri, 3),
        "median_pri_sec": round(median_pri, 3),
        "pri_jitter_sec": round(std_pri, 3),
        "cv_pri": round(cv_pri, 2),
        "pulse_class": pulse_class,
        "probable_pulsed_source": probable_pulsed_source,
        "mesh_status": mesh_status,
        "mesh_score": min(100, mesh_score),
        "mesh_protocol": mesh_proto or "Non-standard / Custom Mesh",
        "estimated_mesh_nodes": estimated_nodes,
        "node_power_tiers_db": node_power_centers,
        "relay_echoes": relay_echoes,
        "mesh_reasons": mesh_reasons,
    }


def infer_pulsed_device(
    center_mhz: float,
    burst_count: int,
    median_pri: float,
    cv_pri: float,
    occupancy_pct: float,
) -> str:
    """
    Determine what a pulsed signal is based on its frequency band and pulse cadence.
    """
    if occupancy_pct >= 65.0:
        if center_mhz >= 1000.0:
            return "Continuous 1-3 GHz Carrier (Base Station Downlink / Continuous Video / Beacon)"
        return "Continuous Sub-GHz Carrier / Persistent Transmitter"

    if 401.0 <= center_mhz <= 406.0:
        return "MedRadio Medical Implant Telemetry Burst (Pacemaker / ICD / Body Sensor)"
    if 406.0 < center_mhz <= 406.1:
        return "COSPAS-SARSAT Distress Beacon (50s Period Pulse)"
    if 433.05 <= center_mhz <= 434.79:
        if 20.0 <= median_pri <= 120.0 and cv_pri <= 0.35:
            return "433 MHz Periodic Sensor Beacon (Weather Station / TPMS / Temperature Probe)"
        if burst_count >= 3 and median_pri < 10.0:
            return "LoRa 433 / Meshtastic Node or Security Sensor Burst Train"
        return "433 MHz ISM Remote Keyfob / Wireless Sensor Packet"
    if 863.0 <= center_mhz <= 870.0:
        if 868.35 <= center_mhz <= 868.50 or 869.70 <= center_mhz <= 870.00:
            return "Z-Wave EU Smart Home Mesh Packet / Routed Ack"
        if 869.40 <= center_mhz <= 869.65:
            return "Meshtastic EU868 LoRa Mesh Beacon / High-Power Telemetry"
        if 5.0 <= median_pri <= 300.0 and cv_pri <= 0.40:
            return "868 MHz Wireless M-Bus Smart Utility Meter / LoRaWAN Periodic Beacon"
        return "868 MHz SRD Telemetry / Alarm / LoRa Packet Burst"
    if 880.0 <= center_mhz <= 915.0:
        if median_pri > 0 and median_pri < 2.0:
            return "GSM/LTE Band 8 TDMA Handset Uplink Burst Train (or US915 FHSS Mesh)"
        return "Mobile Phone / Cellular IoT Modem Uplink Burst (or US915 LoRa/Z-Wave)"
    if 1029.0 <= center_mhz <= 1091.0:
        return "Aviation Mode-S / ADS-B / TCAS Pulsed Transponder"
    if 1880.0 <= center_mhz <= 1900.0:
        return "DECT Cordless Phone / Wireless Intercom TDMA Beacon Pulses"
    if 2400.0 <= center_mhz <= 2483.5:
        ch_detail = identify_24ghz_channel_detail(center_mhz)
        if ch_detail and "Zigbee/Thread" in ch_detail:
            return f"IEEE 802.15.4 Pulsed Mesh Traffic ({ch_detail})"
        if ch_detail and "BLE" in ch_detail:
            return f"Bluetooth Low Energy (BLE) Advertising / Mesh Pulse ({ch_detail})"
        return "2.4 GHz Wi-Fi / Zigbee / FHSS Drone or IoT Packet Bursts"
    if 2700.0 <= center_mhz <= 3000.0:
        return "S-Band Pulsed Surveillance / Weather Radar"

    if median_pri > 0 and cv_pri <= 0.30:
        return f"Automated Periodic Telemetry Beacon (Fires every ~{median_pri:.1f}s)"
    return "Intermittent Digital Packet / Telemetry Transmitter"


def analyze_records(
    records: List[Tuple[str, Optional[datetime], str, float, float]],
    cluster_step_mhz: float = 0.050,
    hide_spurs: bool = True,
) -> Dict[str, Any]:
    """
    Aggregate raw hit records into:
      - Per-tier sweep counts (ignoring internal clock spurs so real signals get accurate occupancy)
      - 60-second time slices per tier to detect true Round-the-Clock (24/7) persistence
      - Frequency cluster analysis with Pulsed PRI profiling and Mesh topology detection
    """
    if not records:
        return {}

    timestamps_set = set()
    all_timestamps_by_tier: Dict[str, set] = {}
    external_timestamps_by_tier: Dict[str, set] = {}
    external_time_windows_by_tier: Dict[str, set] = {}
    valid_dts: List[datetime] = []

    tier_stats: Dict[str, Dict[str, Any]] = {}
    clusters: Dict[Tuple[str, float], Dict[str, Any]] = {}
    spur_hits_count = 0

    for ts_str, dt, tier, freq_mhz, power_db in records:
        all_timestamps_by_tier.setdefault(tier, set()).add(ts_str)
        spur_desc = is_internal_spur(freq_mhz)
        if spur_desc and hide_spurs:
            spur_hits_count += 1
            continue

        timestamps_set.add(ts_str)
        epoch_s = dt.timestamp() if dt is not None else 0.0
        time_slice_id = int(epoch_s // 60) if epoch_s > 0 else 0

        if dt is not None:
            valid_dts.append(dt)

        if not spur_desc:
            if tier not in external_timestamps_by_tier:
                external_timestamps_by_tier[tier] = set()
                external_time_windows_by_tier[tier] = set()
            external_timestamps_by_tier[tier].add(ts_str)
            if time_slice_id > 0:
                external_time_windows_by_tier[tier].add(time_slice_id)

        if tier not in tier_stats:
            tier_stats[tier] = {
                "count": 0,
                "max_db": -999.0,
                "min_db": 999.0,
                "sum_db": 0.0,
                "strongest_freq_mhz": 0.0,
            }
        t_stat = tier_stats[tier]
        t_stat["count"] += 1
        t_stat["sum_db"] += power_db
        if power_db > t_stat["max_db"]:
            t_stat["max_db"] = power_db
            t_stat["strongest_freq_mhz"] = freq_mhz
        if power_db < t_stat["min_db"]:
            t_stat["min_db"] = power_db

        bucket_mhz = round(round(freq_mhz / cluster_step_mhz) * cluster_step_mhz, 4)
        key = (tier, bucket_mhz)
        if key not in clusters:
            clusters[key] = {
                "tier": tier,
                "center_mhz": bucket_mhz,
                "count": 0,
                "max_db": -999.0,
                "min_db": 999.0,
                "sum_db": 0.0,
                "sum_sq_db": 0.0,
                "first_seen": ts_str,
                "last_seen": ts_str,
                "unique_sweeps": set(),
                "time_windows": set(),
                "events": [],
                "is_spur": bool(spur_desc),
            }
        c = clusters[key]
        c["count"] += 1
        c["sum_db"] += power_db
        c["sum_sq_db"] += power_db * power_db
        if power_db > c["max_db"]:
            c["max_db"] = power_db
        if power_db < c["min_db"]:
            c["min_db"] = power_db
        c["last_seen"] = ts_str
        c["unique_sweeps"].add(ts_str)
        if time_slice_id > 0:
            c["time_windows"].add(time_slice_id)
        if epoch_s > 0:
            c["events"].append((epoch_s, power_db))

    total_unique_timestamps = max(len(timestamps_set), 1)

    # Finalize cluster metrics
    cluster_list: List[Dict[str, Any]] = []
    for (_, _), c in clusters.items():
        n = c["count"]
        tier = c["tier"]
        avg_db = c["sum_db"] / n
        variance = max(0.0, (c["sum_sq_db"] / n) - (avg_db * avg_db))
        std_db = math.sqrt(variance)

        tier_sweeps = max(
            len(all_timestamps_by_tier.get(tier, set())),
            len(external_timestamps_by_tier.get(tier, set())),
            1,
        )
        if c["is_spur"]:
            occupancy_pct = min(
                100.0, (len(c["unique_sweeps"]) / total_unique_timestamps) * 100.0
            )
        else:
            occupancy_pct = min(
                100.0, (len(c["unique_sweeps"]) / tier_sweeps) * 100.0
            )

        tier_windows = max(len(external_time_windows_by_tier.get(tier, set())), 1)
        window_persistence_pct = min(
            100.0, (len(c["time_windows"]) / tier_windows) * 100.0
        )

        # Round-the-clock (24/7) detection: high occupancy OR present across multiple time windows continuously
        is_round_the_clock = (
            not c["is_spur"]
            and (
                (occupancy_pct >= 50.0 and n >= 5)
                or (window_persistence_pct >= 75.0 and len(c["time_windows"]) >= 2 and n >= 10)
            )
        )

        pulse_mesh = analyze_pulse_and_mesh_characteristics(
            events=c["events"],
            center_mhz=c["center_mhz"],
            occupancy_pct=occupancy_pct,
        )

        if c["is_spur"]:
            behavior = "INTERNAL SDR CLOCK SPUR"
        elif is_round_the_clock:
            behavior = "24/7 ROUND-THE-CLOCK CARRIER"
        elif pulse_mesh.get("mesh_status", "NONE") in (
            "[CONFIRMED MESH NETWORK]",
            "[PROBABLE MESH / MULTI-NODE RELAY]",
        ):
            behavior = "MESH NETWORK RELAY"
        elif pulse_mesh.get("burst_count", 0) >= 2:
            behavior = "REPEATING / PULSED"
        else:
            behavior = "TRANSIENT / BURST"

        cluster_list.append(
            {
                "tier": tier,
                "center_mhz": c["center_mhz"],
                "hits": n,
                "avg_db": round(avg_db, 2),
                "max_db": round(c["max_db"], 2),
                "min_db": round(c["min_db"], 2),
                "std_db": round(std_db, 2),
                "occupancy_pct": round(occupancy_pct, 1),
                "window_persistence_pct": round(window_persistence_pct, 1),
                "is_round_the_clock": is_round_the_clock,
                "behavior": behavior,
                "first_seen": c["first_seen"],
                "last_seen": c["last_seen"],
                "signature": identify_signature(c["center_mhz"]),
                "burst_count": pulse_mesh.get("burst_count", 1),
                "mean_pri_sec": pulse_mesh.get("mean_pri_sec", 0.0),
                "median_pri_sec": pulse_mesh.get("median_pri_sec", 0.0),
                "pri_jitter_sec": pulse_mesh.get("pri_jitter_sec", 0.0),
                "pulse_class": pulse_mesh.get("pulse_class", ""),
                "probable_pulsed_source": pulse_mesh.get("probable_pulsed_source", ""),
                "mesh_status": pulse_mesh.get("mesh_status", "NONE"),
                "mesh_score": pulse_mesh.get("mesh_score", 0),
                "mesh_protocol": pulse_mesh.get("mesh_protocol", ""),
                "estimated_mesh_nodes": pulse_mesh.get("estimated_mesh_nodes", 1),
                "node_power_tiers_db": pulse_mesh.get("node_power_tiers_db", []),
                "relay_echoes": pulse_mesh.get("relay_echoes", 0),
                "mesh_reasons": pulse_mesh.get("mesh_reasons", []),
            }
        )

    # Boost mesh score if multiple distinct channels in the same mesh band are active
    mesh_band_channels: Dict[str, List[Dict[str, Any]]] = {}
    for item in cluster_list:
        if item["mesh_status"] != "NONE" or any(
            low_m <= item["center_mhz"] <= high_m
            for low_m, high_m, _ in MESH_PROTOCOL_BANDS
        ):
            proto = item["mesh_protocol"]
            mesh_band_channels.setdefault(proto, []).append(item)

    for proto, items in mesh_band_channels.items():
        if len(items) >= 2:
            for item in items:
                item["mesh_score"] = min(100, item["mesh_score"] + 15)
                item["mesh_reasons"].append(
                    f"Coordinated multi-channel activity: {len(items)} active frequency channels in {proto}"
                )
                if item["mesh_score"] >= 60:
                    item["mesh_status"] = "[CONFIRMED MESH NETWORK]"
                elif item["mesh_score"] >= 40:
                    item["mesh_status"] = "[PROBABLE MESH / MULTI-NODE RELAY]"

    cluster_list.sort(key=lambda item: (item["max_db"], item["hits"]), reverse=True)

    first_ts = records[0][0]
    last_ts = records[-1][0]
    duration_sec = 0.0
    if len(valid_dts) >= 2:
        duration_sec = (max(valid_dts) - min(valid_dts)).total_seconds()

    return {
        "total_hits": sum(t["count"] for t in tier_stats.values()),
        "raw_records_count": len(records),
        "filtered_clock_spur_hits": spur_hits_count,
        "unique_timestamps": len(timestamps_set),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration_seconds": duration_sec,
        "tier_stats": tier_stats,
        "clusters": cluster_list,
    }


def make_ascii_bar(
    db_value: float, floor_db: float = -70.0, ceil_db: float = -10.0, width: int = 14
) -> str:
    clamped = max(floor_db, min(ceil_db, db_value))
    ratio = (clamped - floor_db) / (ceil_db - floor_db)
    filled = int(round(ratio * width))
    return "#" * filled + "." * (width - filled)


def print_report(
    summary: Dict[str, Any], top_n: int = 25, log_path: str = DEFAULT_LOG_FILE
) -> None:
    sep = "=" * 100
    subsep = "-" * 100
    print(sep)
    print(
        " HACKRF SMART SPECTRUM INTELLIGENCE REPORT (PULSED SIGNALS, MESH NETWORKS & 1-3 GHz 24/7)"
    )
    print(sep)
    print(f" Source Log File      : {os.path.abspath(log_path)}")
    print(
        f" External Signal Hits : {summary['total_hits']} "
        f"(Filtered {summary.get('filtered_clock_spur_hits', 0)} internal 10/20 MHz SDR clock spur hits)"
    )
    print(f" First Hit Recorded   : {summary['first_timestamp']}")
    print(f" Last Hit Recorded    : {summary['last_timestamp']}")
    print(
        f" Active Time Span     : {summary['duration_seconds']:.1f} seconds "
        f"({summary['unique_timestamps']} active external signal sweeps)"
    )
    print(subsep)

    # 1. Band Tier Summary
    print(" 1. SPECTRUM TIER SUMMARY (1 MHz - 3 GHz)")
    print(subsep)
    print(
        f" {'SPECTRUM TIER':<24} | {'HITS':>8} | {'SHARE':>7} | {'AVG dB':>9} | {'PEAK dB':>9} | {'STRONGEST FREQ':>15}"
    )
    print(" " + "-" * 98)

    total_hits = max(summary["total_hits"], 1)
    for tier, t_stat in sorted(summary["tier_stats"].items()):
        count = t_stat["count"]
        share = (count / total_hits) * 100.0
        avg_db = t_stat["sum_db"] / count
        max_db = t_stat["max_db"]
        strongest_f = t_stat["strongest_freq_mhz"]
        print(
            f" {tier:<24} | {count:>8} | {share:>6.1f}% | {avg_db:>6.2f} dB | {max_db:>6.2f} dB | {strongest_f:>11.4f} MHz"
        )

    print(subsep)

    clusters = summary["clusters"]

    # Helper to deduplicate adjacent 50 kHz bins of the same wideband emission
    def deduplicate_adjacent_peaks(
        items: List[Dict[str, Any]], min_sep_mhz: float = 0.25
    ) -> List[Dict[str, Any]]:
        selected: List[Dict[str, Any]] = []
        for item in items:
            if not any(
                s["tier"] == item["tier"]
                and abs(s["center_mhz"] - item["center_mhz"]) <= min_sep_mhz
                for s in selected
            ):
                selected.append(item)
        return selected

    # 2. Pulsed Frequency Analysis Section
    raw_pulsed = [
        c
        for c in clusters
        if c["burst_count"] >= 2 and not c.get("is_round_the_clock", False)
    ]
    pulsed_clusters = deduplicate_adjacent_peaks(raw_pulsed, min_sep_mhz=0.25)
    print(
        f" 2. PULSED & REPEATING FREQUENCY INTELLIGENCE ({len(pulsed_clusters)} Distinct Pulsed Signals)"
    )
    print(subsep)
    if pulsed_clusters:
        for p in pulsed_clusters[:15]:
            pri_str = (
                f"Median Δt={p['median_pri_sec']:.2f}s (Mean {p['mean_pri_sec']:.2f}s, Jitter ±{p['pri_jitter_sec']:.2f}s)"
                if p["median_pri_sec"] > 0
                else "Multi-session bursts"
            )
            print(
                f" * {p['center_mhz']:>9.4f} MHz | {p['tier']:<23} | Peak: {p['max_db']:>6.2f} dB | "
                f"Bursts: {p['burst_count']:>3} | {p['pulse_class']}"
            )
            print(f"     +-> Pulse Timing    : {pri_str}")
            print(f"     +-> Probable Source : {p['probable_pulsed_source']}")
            print(f"     +-> Band Allocation : {p['signature']}")
    else:
        print(
            " [i] No multi-burst pulsed signals recorded yet (run scan longer to capture pulse intervals)."
        )
    print(subsep)

    # 3. Mesh Network Detection Section
    raw_mesh = [c for c in clusters if c["mesh_status"] != "NONE"]
    raw_mesh.sort(key=lambda x: (x["mesh_score"], x["max_db"]), reverse=True)
    mesh_clusters = deduplicate_adjacent_peaks(raw_mesh, min_sep_mhz=0.25)
    print(
        f" 3. MESH NETWORK TOPOLOGY & MULTI-NODE RELAY DETECTION ({len(mesh_clusters)} Distinct Mesh Channels)"
    )
    print(subsep)
    if mesh_clusters:
        for m in mesh_clusters[:15]:
            tiers_str = ", ".join(f"{db:.1f} dB" for db in m["node_power_tiers_db"][:5])
            print(
                f" * {m['center_mhz']:>9.4f} MHz | {m['mesh_status']:<34} | Score: {m['mesh_score']:>3}/100 | "
                f"Est. Nodes: ~{m['estimated_mesh_nodes']} ({tiers_str})"
            )
            print(
                f"     +-> Protocol / Band : {m['mesh_protocol']} | Relay Echoes: {m['relay_echoes']} | Bursts: {m['burst_count']}"
            )
            for reason in m["mesh_reasons"]:
                print(f"     +-> Mesh Evidence   : {reason}")
    else:
        print(" [i] No multi-node mesh network activity detected in the current log.")
    print(subsep)

    # 4. 1-3 GHz & Sub-GHz Round-the-Clock (24/7 Continuous) Transmitters
    highband_24_7 = [
        c
        for c in clusters
        if c["center_mhz"] >= 1000.0 and c.get("is_round_the_clock", False)
    ]
    subghz_24_7 = [
        c
        for c in clusters
        if c["center_mhz"] < 1000.0 and c.get("is_round_the_clock", False)
    ]
    highband_all = [c for c in clusters if c["center_mhz"] >= 1000.0]

    print(" 4. 1-3 GHz & SUB-GHZ ROUND-THE-CLOCK (24/7 CONTINUOUS) TRANSMITTERS")
    print(subsep)
    if highband_24_7:
        print(
            f" [!] 1-3 GHz Round-the-Clock Transmitters Found: {len(highband_24_7)} frequency bin(s)"
        )
        for c in highband_24_7[:15]:
            print(
                f"     - {c['center_mhz']:>9.4f} MHz ({c['tier']}) | Peak: {c['max_db']:>6.2f} dB | "
                f"Occupancy: {c['occupancy_pct']:>5.1f}% | Window Persistence: {c['window_persistence_pct']:>5.1f}% | {c['signature']}"
            )
    elif highband_all:
        print(
            f" [i] {len(highband_all)} signal(s) detected in 1-3 GHz, but none met 24/7 continuous carrier criteria:"
        )
        for c in highband_all[:10]:
            print(
                f"     - {c['center_mhz']:>9.4f} MHz ({c['tier']}) | Peak: {c['max_db']:>6.2f} dB | "
                f"Hits: {c['hits']} ({c['occupancy_pct']:.1f}% occ) | {c['behavior']} | {c['signature']}"
            )
    else:
        print(
            " [i] No 1-3 GHz hits recorded in log yet. Run `./auto_scanner.sh --run --mode highband` "
            "or `./auto_scanner.sh --run --mode full` to scan 1000-3000 MHz!"
        )

    if subghz_24_7:
        print(
            f"\n [!] Sub-GHz Round-the-Clock Carriers Found: {len(subghz_24_7)} external frequency bin(s)"
        )
        for c in subghz_24_7[:10]:
            print(
                f"     - {c['center_mhz']:>9.4f} MHz ({c['tier']}) | Peak: {c['max_db']:>6.2f} dB | "
                f"Occupancy: {c['occupancy_pct']:>5.1f}% | Hits: {c['hits']} | {c['signature']}"
            )
    print(subsep)

    # 5. Top Detected Hotspots Table
    shown = clusters[:top_n]
    print(
        f" 5. TOP {len(shown)} EXTERNAL FREQUENCY HOTSPOTS (Ranked by Peak Power & Persistence)"
    )
    print(subsep)
    print(
        f" {'FREQ (MHz)':>11} | {'TIER':<22} | {'HITS':>5} | {'PEAK dB':>8} | {'OCC %':>6} | {'STRENGTH':<16} | {'BEHAVIOR':<24}"
    )
    print(" " + "-" * 98)

    for c in shown:
        bar = make_ascii_bar(c["max_db"])
        print(
            f" {c['center_mhz']:>11.4f} | {c['tier']:<22} | {c['hits']:>5} | "
            f"{c['max_db']:>8.2f} | {c['occupancy_pct']:>5.1f}% | [{bar}] | {c['behavior']:<24}"
        )
        print(
            f"             +-> Allocation : {c['signature']} "
            f"(First: {c['first_seen']} | Last: {c['last_seen']})"
        )

    print(sep)


def export_csv(clusters: List[Dict[str, Any]], csv_path: str) -> None:
    fieldnames = [
        "center_mhz",
        "tier",
        "hits",
        "burst_count",
        "max_db",
        "avg_db",
        "min_db",
        "std_db",
        "occupancy_pct",
        "window_persistence_pct",
        "is_round_the_clock",
        "behavior",
        "pulse_class",
        "median_pri_sec",
        "mean_pri_sec",
        "pri_jitter_sec",
        "probable_pulsed_source",
        "mesh_status",
        "mesh_score",
        "mesh_protocol",
        "estimated_mesh_nodes",
        "relay_echoes",
        "signature",
        "first_seen",
        "last_seen",
    ]
    with open(csv_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for c in clusters:
            writer.writerow(c)
    print(
        f"[+] Exported {len(clusters)} aggregated frequency clusters to CSV: {os.path.abspath(csv_path)}"
    )


def export_json(summary: Dict[str, Any], json_path: str) -> None:
    with open(json_path, mode="w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Exported full analysis report to JSON: {os.path.abspath(json_path)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze HackRF Scan Logs for Pulsed Signals, Mesh Networks, and 1-3 GHz 24/7 Carriers"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=DEFAULT_LOG_FILE,
        help=f"Path to scan log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top frequency hotspots to display (default: 20)",
    )
    parser.add_argument(
        "--min-db",
        type=float,
        default=None,
        help="Filter out hits weaker than this dB value during analysis",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default=None,
        help="Filter by tier keyword (e.g., DEEP, HIGH, MODERATE, L-BAND, S-BAND)",
    )
    parser.add_argument(
        "--bin-step",
        type=float,
        default=0.050,
        help="Frequency clustering step in MHz (default: 0.050 MHz = 50 kHz)",
    )
    parser.add_argument(
        "--show-spurs",
        action="store_true",
        default=False,
        help="Include internal 10/20 MHz HackRF clock spurs in hotspot rankings",
    )
    parser.add_argument(
        "--export-csv",
        type=str,
        default=None,
        help="Export aggregated frequency table to a CSV file",
    )
    parser.add_argument(
        "--export-json",
        type=str,
        default=None,
        help="Export full analysis summary to a JSON file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not os.path.exists(args.file):
        sys.stderr.write(
            f"[!] Log file not found: {os.path.abspath(args.file)}\n"
            f"    Run a scan first (`./auto_scanner.sh --run` or `--daemon`) to generate hits.\n"
        )
        return 1

    records = load_log_hits(args.file, min_db=args.min_db, tier_filter=args.tier)
    if not records:
        print(f"[i] Log file '{args.file}' exists but contains no matching RF hits yet.")
        return 0

    summary = analyze_records(
        records, cluster_step_mhz=args.bin_step, hide_spurs=not args.show_spurs
    )
    print_report(summary, top_n=args.top, log_path=args.file)

    if args.export_csv:
        export_csv(summary["clusters"], args.export_csv)
    if args.export_json:
        export_json(summary, args.export_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
