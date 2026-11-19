#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 Flagged Frequency Sentinel & Characteristic
Pattern Matcher (`monitor_flagged.py`).

Capabilities:
  1. Auto-extracts all Flagged Frequencies from `penetration_scan_hits.log`:
     - 1-3 GHz & Sub-GHz 24/7 Round-the-Clock Continuous Transmitters
     - Confirmed & Probable Mesh Network Channels
     - Repeating Pulsed Signals (with consistent Pulse Repetition Interval Δt)
     - Suspicious / Non-Compliant / Bandwidth or Duty-Cycle Anomaly Signals
  2. Builds a persistent Characteristic Fingerprint (`flagged_watchlist.json`) for
     every flagged signal (Bandwidth, Pulse Interval Δt, Jitter, Duty Cycle,
     Amplitude Envelope StdDev, and Multi-Node RSSI Spread).
  3. Cross-Spectrum Characteristic Matcher:
     Scans all other detected frequencies across 1 MHz - 3 GHz to find any signal
     that shares the behavioral characteristics of a flagged frequency (detecting
     frequency-hopping devices, cloned transmitters, or sibling mesh nodes on
     different channels).
  4. High-Speed Targeted Lock-On Monitor (`--live`):
     Constructs tight narrowband `hackrf_sweep` windows around flagged frequencies
     for 10-25x faster revisit rates, tracking power trends (Approaching vs Receding),
     frequency drift/hopping, and real-time characteristic clone alerts.
"""

import argparse
import csv
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import analyze_scan_data as analyzer
import verify_rf_devices as verifier

DEFAULT_LOG_FILE = os.path.join(SCRIPT_DIR, "penetration_scan_hits.log")
WATCHLIST_JSON = os.path.join(SCRIPT_DIR, "flagged_watchlist.json")
ALERTS_LOG = os.path.join(SCRIPT_DIR, "flagged_alerts.log")


# ==============================================================================
# 1. FLAGGED SIGNAL EXTRACTION & CHARACTERISTIC FINGERPRINTING
# ==============================================================================


def build_characteristic_fingerprint(
    cluster: Dict[str, Any], emission_map: Dict[float, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Create a quantitative behavioral fingerprint for a frequency cluster so we
    can monitor it and match other frequencies with similar characteristics.
    """
    c_mhz = cluster["center_mhz"]
    # Find closest merged emission from verify_rf_devices for accurate occupied bandwidth
    matched_em = None
    best_dist = 999.0
    for em_mhz, em in emission_map.items():
        dist = abs(em_mhz - c_mhz)
        if dist <= 0.35 and dist < best_dist:
            best_dist = dist
            matched_em = em

    est_bw_khz = matched_em["est_bw_khz"] if matched_em else 50.0
    verdict = matched_em["verdict"] if matched_em else "[ACTIVE SIGNAL]"
    span_mhz = matched_em["span_mhz"] if matched_em else f"{c_mhz - 0.025:.3f} - {c_mhz + 0.025:.3f} MHz"

    # Determine why this frequency is flagged
    flag_reasons: List[str] = []
    flag_types: List[str] = []

    if cluster.get("is_round_the_clock", False) or "24/7" in verdict:
        flag_types.append("24/7_CONTINUOUS")
        flag_reasons.append(
            f"Round-the-Clock 24/7 Carrier ({cluster['occupancy_pct']:.1f}% occupancy, {cluster.get('window_persistence_pct', 0):.0f}% window persistence)"
        )

    if cluster.get("mesh_status", "NONE") in (
        "[CONFIRMED MESH NETWORK]",
        "[PROBABLE MESH / MULTI-NODE RELAY]",
    ):
        flag_types.append("MESH_TOPOLOGY")
        flag_reasons.append(
            f"{cluster['mesh_status']} (Score {cluster['mesh_score']}/100, ~{cluster['estimated_mesh_nodes']} nodes)"
        )

    if cluster.get("burst_count", 0) >= 2 and not cluster.get("is_round_the_clock", False):
        flag_types.append("PULSED_SIGNAL")
        pri = cluster.get("median_pri_sec", 0.0)
        if pri > 0:
            flag_reasons.append(
                f"Pulsed Cadence: {cluster['pulse_class']} (Median Δt={pri:.2f}s, {cluster['burst_count']} bursts)"
            )
        else:
            flag_reasons.append(
                f"Repeating Multi-Session Bursts ({cluster['burst_count']} bursts)"
            )

    if any(k in verdict for k in ("ILLEGAL", "SUSPICIOUS", "VIOLATION", "ANOMALY")):
        flag_types.append("COMPLIANCE_ALERT")
        flag_reasons.append(f"Regulatory/Technical Flag: {verdict}")

    primary_flag = flag_types[0] if flag_types else "MONITORED"

    # Compute monitoring guard window (MHz) around the target
    guard_half_mhz = max(1.0, (est_bw_khz / 1000.0) * 2.0)
    mon_low_mhz = max(1.0, int(math.floor(c_mhz - guard_half_mhz)))
    mon_high_mhz = min(3000, int(math.ceil(c_mhz + guard_half_mhz)))
    if mon_high_mhz <= mon_low_mhz:
        mon_high_mhz = mon_low_mhz + 2

    return {
        "center_mhz": c_mhz,
        "span_mhz": span_mhz,
        "tier": cluster["tier"],
        "primary_flag": primary_flag,
        "flag_types": flag_types,
        "flag_reasons": flag_reasons,
        "verdict": verdict,
        "signature": cluster["signature"],
        "probable_device": cluster.get("probable_pulsed_source", ""),
        "monitor_window_mhz": f"{mon_low_mhz}:{mon_high_mhz}",
        "characteristics": {
            "est_bw_khz": est_bw_khz,
            "peak_db": cluster["max_db"],
            "avg_db": cluster["avg_db"],
            "std_db": cluster["std_db"],
            "occupancy_pct": cluster["occupancy_pct"],
            "window_persistence_pct": cluster.get("window_persistence_pct", 0.0),
            "burst_count": cluster.get("burst_count", 1),
            "median_pri_sec": cluster.get("median_pri_sec", 0.0),
            "mean_pri_sec": cluster.get("mean_pri_sec", 0.0),
            "pri_jitter_sec": cluster.get("pri_jitter_sec", 0.0),
            "estimated_mesh_nodes": cluster.get("estimated_mesh_nodes", 1),
            "node_power_tiers_db": cluster.get("node_power_tiers_db", []),
            "relay_echoes": cluster.get("relay_echoes", 0),
        },
        "first_seen": cluster["first_seen"],
        "last_seen": cluster["last_seen"],
    }


def compute_characteristic_similarity(
    target_fp: Dict[str, Any],
    candidate_cluster: Dict[str, Any],
    candidate_bw_khz: float,
) -> Tuple[float, List[str]]:
    """
    Compare a candidate signal's measured RF characteristics against a Flagged
    Signal's fingerprint to detect:
      - Frequency-hopping transmitters (same PRI / BW / power envelope on a new frequency)
      - Cloned / identical devices operating on another channel
      - Sibling mesh nodes sharing identical packet bandwidth & cadence
    Returns (similarity_score_0_to_100, matching_traits_list).
    """
    t_char = target_fp["characteristics"]
    t_mhz = target_fp["center_mhz"]
    c_mhz = candidate_cluster["center_mhz"]

    # Skip comparing a signal with itself or within the same wideband channel
    min_freq_sep = 2.5 if (t_mhz >= 1000.0 and c_mhz >= 1000.0) else 0.50
    if abs(t_mhz - c_mhz) <= min_freq_sep:
        return (0.0, [])

    score = 0.0
    traits: List[str] = []

    # 1. Pulse Repetition Interval (PRI / Δt) Similarity (up to 45 pts)
    t_pri = t_char.get("median_pri_sec", 0.0)
    c_pri = candidate_cluster.get("median_pri_sec", 0.0)
    if t_pri > 0.1 and c_pri > 0.1:
        rel_diff = abs(t_pri - c_pri) / max(t_pri, c_pri)
        if rel_diff <= 0.08:
            score += 45.0
            traits.append(
                f"Identical Pulse Cadence: Δt={c_pri:.2f}s matches target Δt={t_pri:.2f}s ({100*(1-rel_diff):.1f}% timing match)"
            )
        elif rel_diff <= 0.22:
            score += 28.0
            traits.append(
                f"Similar Pulse Interval: Δt={c_pri:.2f}s vs target Δt={t_pri:.2f}s"
            )
        # Check harmonic / 2x interval (e.g. missed every second pulse while sweeping)
        elif abs(max(t_pri, c_pri) / min(t_pri, c_pri) - 2.0) <= 0.12:
            score += 25.0
            traits.append(
                f"Harmonic 2x Pulse Cadence: Δt={c_pri:.2f}s is 2x/0.5x of target Δt={t_pri:.2f}s"
            )

    # 2. Continuous / 24-7 Persistence Similarity (up to 40 pts if both are continuous)
    t_occ = t_char.get("occupancy_pct", 0.0)
    c_occ = candidate_cluster.get("occupancy_pct", 0.0)
    if t_occ >= 50.0 and c_occ >= 50.0:
        score += 40.0
        traits.append(
            f"Matching 24/7 Continuous Carrier Profile ({c_occ:.1f}% vs {t_occ:.1f}% occupancy)"
        )

    # 3. Occupied Bandwidth Similarity (up to 25 pts)
    t_bw = t_char.get("est_bw_khz", 50.0)
    bw_ratio = min(t_bw, candidate_bw_khz) / max(t_bw, candidate_bw_khz, 1.0)
    if bw_ratio >= 0.80:
        score += 25.0
        traits.append(
            f"Matching Channel Bandwidth (~{candidate_bw_khz:.0f} kHz vs target ~{t_bw:.0f} kHz)"
        )
    elif bw_ratio >= 0.50:
        score += 12.0
        traits.append(
            f"Comparable Bandwidth (~{candidate_bw_khz:.0f} kHz vs ~{t_bw:.0f} kHz)"
        )

    # 4. Amplitude Envelope & Modulation Variance (StdDev dB & Peak dB) (up to 20 pts)
    t_std = t_char.get("std_db", 0.0)
    c_std = candidate_cluster.get("std_db", 0.0)
    if abs(t_std - c_std) <= 1.8 and (t_std > 0.2 or c_std > 0.2 or t_occ >= 50.0):
        score += 12.0
        traits.append(
            f"Matching Amplitude Envelope Variance (StdDev {c_std:.2f} dB vs {t_std:.2f} dB)"
        )

    t_peak = t_char.get("peak_db", -50.0)
    c_peak = candidate_cluster.get("max_db", -50.0)
    if abs(t_peak - c_peak) <= 3.5:
        score += 8.0
        traits.append(
            f"Similar Transmitter RSSI Level (Peak {c_peak:.1f} dB vs {t_peak:.1f} dB -> likely same distance/source)"
        )

    # 5. Same Mesh Protocol or Band Tier Family (up to 15 pts)
    if candidate_cluster.get("tier") == target_fp.get("tier"):
        score += 10.0
        traits.append(f"Operates in same spectrum tier ({candidate_cluster.get('tier')})")
    if (
        candidate_cluster.get("mesh_status", "NONE") != "NONE"
        and "MESH_TOPOLOGY" in target_fp.get("flag_types", [])
    ):
        score += 10.0
        traits.append(
            f"Shared Mesh Network Behavior ({candidate_cluster.get('mesh_protocol')})"
        )

    return (min(100.0, round(score, 1)), traits)


def analyze_flagged_and_matches(
    log_path: str = DEFAULT_LOG_FILE,
    min_match_score: float = 55.0,
    precomputed_analysis: Optional[Dict[str, Any]] = None,
    precomputed_compliance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    1. Load all records from `penetration_scan_hits.log` (or reuse precomputed analysis).
    2. Identify all Flagged Frequencies (24/7 carriers, Confirmed/High-Score Mesh,
       Repeating Pulsed Signals, and Compliance Anomalies).
    3. Deduplicate adjacent bins so each flagged transmitter has one canonical profile.
    4. Cross-match every detected signal across the spectrum against each Flagged
       Target's characteristic fingerprint to find clones, hoppers, and sibling nodes.
    5. Generate an optimized `hackrf_sweep -f` watchlist command string for high-speed
       targeted monitoring.
    """
    if precomputed_analysis is not None and precomputed_compliance is not None:
        analysis = precomputed_analysis
        compliance = precomputed_compliance
        if not analysis.get("clusters"):
            return {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "flagged_targets": [],
                "characteristic_matches": [],
                "recommended_sweep_ranges": "",
                "recommended_monitor_cmd": "",
            }
    else:
        records = analyzer.load_log_hits(log_path)
        if not records:
            return {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "flagged_targets": [],
                "characteristic_matches": [],
                "recommended_sweep_ranges": "",
                "recommended_monitor_cmd": "",
            }

        analysis = analyzer.analyze_records(records, hide_spurs=True)
        compliance = verifier.group_contiguous_signals(records)

    clusters = analysis.get("clusters", [])
    emissions = compliance.get("emissions", [])

    emission_map: Dict[float, Dict[str, Any]] = {
        e["center_mhz"]: e for e in emissions
    }

    # Select raw flagged clusters
    raw_flagged: List[Dict[str, Any]] = []
    for c in clusters:
        em = emission_map.get(c["center_mhz"])
        verdict = em["verdict"] if em else ""
        is_flagged = (
            c.get("is_round_the_clock", False)
            or c.get("mesh_status", "NONE") == "[CONFIRMED MESH NETWORK]"
            or (c.get("burst_count", 0) >= 2 and not c.get("is_round_the_clock", False))
            or any(k in verdict for k in ("ILLEGAL", "SUSPICIOUS", "24/7", "MESH"))
        )
        if is_flagged:
            raw_flagged.append(c)

    # Deduplicate adjacent bins (0.50 MHz for Sub-GHz, 3.0 MHz for 1-3 GHz)
    dedup_flagged_clusters: List[Dict[str, Any]] = []
    for c in raw_flagged:
        sep_req = 3.0 if c["center_mhz"] >= 1000.0 else 0.50
        if not any(
            s["tier"] == c["tier"] and abs(s["center_mhz"] - c["center_mhz"]) <= sep_req
            for s in dedup_flagged_clusters
        ):
            dedup_flagged_clusters.append(c)

    flagged_targets: List[Dict[str, Any]] = [
        build_characteristic_fingerprint(c, emission_map)
        for c in dedup_flagged_clusters
    ]

    # Deduplicate candidate clusters for cross-spectrum characteristic matching
    dedup_candidates: List[Dict[str, Any]] = []
    for c in clusters:
        sep_req = 2.0 if c["center_mhz"] >= 1000.0 else 0.40
        if not any(
            s["tier"] == c["tier"] and abs(s["center_mhz"] - c["center_mhz"]) <= sep_req
            for s in dedup_candidates
        ):
            dedup_candidates.append(c)

    best_match_per_candidate: Dict[float, Dict[str, Any]] = {}

    for target in flagged_targets:
        t_mhz = target["center_mhz"]
        for cand in dedup_candidates:
            c_mhz = cand["center_mhz"]

            cand_em = None
            for em_mhz, em in emission_map.items():
                if abs(em_mhz - c_mhz) <= 0.35:
                    cand_em = em
                    break
            cand_bw = cand_em["est_bw_khz"] if cand_em else 50.0

            sim_score, traits = compute_characteristic_similarity(
                target_fp=target,
                candidate_cluster=cand,
                candidate_bw_khz=cand_bw,
            )
            if sim_score >= min_match_score and len(traits) >= 2:
                freq_sep = abs(c_mhz - t_mhz)
                if freq_sep <= 15.0:
                    rel_type = "ADJACENT CHANNEL HOP / SIBLING NODE"
                elif cand["tier"] == target["tier"]:
                    rel_type = "IN-BAND CLONE / FREQUENCY HOPPER"
                else:
                    rel_type = "CROSS-BAND CHARACTERISTIC MATCH"

                entry = {
                    "candidate_mhz": c_mhz,
                    "candidate_tier": cand["tier"],
                    "candidate_peak_db": cand["max_db"],
                    "candidate_bw_khz": cand_bw,
                    "candidate_pri_sec": cand.get("median_pri_sec", 0.0),
                    "candidate_occupancy_pct": cand.get("occupancy_pct", 0.0),
                    "candidate_signature": cand["signature"],
                    "matched_target_mhz": t_mhz,
                    "matched_target_flag": target["primary_flag"],
                    "similarity_pct": sim_score,
                    "relationship": rel_type,
                    "matching_traits": traits,
                    "first_seen": cand["first_seen"],
                    "last_seen": cand["last_seen"],
                }
                prev = best_match_per_candidate.get(c_mhz)
                if prev is None or sim_score > prev["similarity_pct"]:
                    best_match_per_candidate[c_mhz] = entry

    characteristic_matches: List[Dict[str, Any]] = list(
        best_match_per_candidate.values()
    )

    characteristic_matches.sort(
        key=lambda x: (x["similarity_pct"], x["candidate_peak_db"]), reverse=True
    )

    # Merge overlapping narrowband monitor windows (`low:high`) for fast lock-on scanning
    raw_windows: List[Tuple[int, int]] = []
    for t in flagged_targets:
        parts = t["monitor_window_mhz"].split(":")
        raw_windows.append((int(parts[0]), int(parts[1])))
    for m in characteristic_matches:
        c_int = int(round(m["candidate_mhz"]))
        raw_windows.append((max(1, c_int - 2), min(3000, c_int + 2)))

    raw_windows.sort(key=lambda x: x[0])
    merged_windows: List[Tuple[int, int]] = []
    for w_low, w_high in raw_windows:
        if not merged_windows:
            merged_windows.append((w_low, w_high))
        else:
            p_low, p_high = merged_windows[-1]
            if w_low <= p_high + 5:
                merged_windows[-1] = (p_low, max(p_high, w_high))
            else:
                merged_windows.append((w_low, w_high))

    ranges_str = ",".join(f"{lo}:{hi}" for lo, hi in merged_windows)
    monitor_cmd = (
        f"python3 hackrf_penetration_scanner.py --ranges {ranges_str} -w 25000"
        if ranges_str
        else ""
    )

    result = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_flagged_targets": len(flagged_targets),
        "total_characteristic_matches": len(characteristic_matches),
        "recommended_sweep_ranges": ranges_str,
        "recommended_monitor_cmd": monitor_cmd,
        "flagged_targets": flagged_targets,
        "characteristic_matches": characteristic_matches,
    }

    try:
        with open(WATCHLIST_JSON, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return result


# ==============================================================================
# 2. TERMINAL REPORT & LIVE LOCK-ON SENTINEL MONITOR
# ==============================================================================


def print_watchlist_report(data: Dict[str, Any]) -> None:
    sep = "=" * 100
    subsep = "-" * 100
    targets = data.get("flagged_targets", [])
    matches = data.get("characteristic_matches", [])

    print(sep)
    print(
        " HACKRF FLAGGED FREQUENCY WATCHLIST & CHARACTERISTIC CLONE / HOPPER DETECTOR"
    )
    print(sep)
    print(f" Generated At               : {data.get('generated_at')}")
    print(f" Flagged Watchlist Targets  : {len(targets)} distinct flagged transmitter(s)")
    print(
        f" Characteristic Matches     : {len(matches)} signal(s) matching flagged characteristics"
    )
    if data.get("recommended_sweep_ranges"):
        print(
            f" Narrowband Lock-On Ranges  : {data['recommended_sweep_ranges']} MHz (25 kHz high-res FFT)"
        )
        print(f" Lock-On Command            : {data['recommended_monitor_cmd']}")
    print(subsep)

    print(" 1. FLAGGED TARGET WATCHLIST (FINGERPRINTED SIGNALS)")
    print(subsep)
    if targets:
        for idx, t in enumerate(targets, start=1):
            ch = t["characteristics"]
            pri_str = (
                f"Δt={ch['median_pri_sec']:.2f}s (±{ch['pri_jitter_sec']:.2f}s)"
                if ch["median_pri_sec"] > 0
                else "N/A"
            )
            print(
                f" TARGET #{idx}: {t['center_mhz']:>9.4f} MHz ({t['span_mhz']}) | "
                f"Flag: [{t['primary_flag']}] | Lock Window: {t['monitor_window_mhz']} MHz"
            )
            print(
                f"   Fingerprint : BW ~{ch['est_bw_khz']:.0f} kHz | Peak {ch['peak_db']:.2f} dB "
                f"(StdDev {ch['std_db']:.2f} dB) | Occ {ch['occupancy_pct']:.1f}% | Pulse {pri_str} | Nodes: ~{ch['estimated_mesh_nodes']}"
            )
            for r in t["flag_reasons"]:
                print(f"   Flag Reason : {r}")
            print(f"   Allocation  : {t['signature']}")
            print(" " + "-" * 98)
    else:
        print(" [i] No flagged frequencies found yet.")
    print(subsep)

    print(
        " 2. FREQUENCIES MATCHING CHARACTERISTICS OF FLAGGED TARGETS (HOPPERS / CLONES / SIBLING NODES)"
    )
    print(subsep)
    if matches:
        for m in matches[:25]:
            print(
                f" * {m['candidate_mhz']:>9.4f} MHz ({m['candidate_tier']}) "
                f"<== [{m['similarity_pct']:.0f}% MATCH to Flagged {m['matched_target_mhz']:.4f} MHz ({m['matched_target_flag']})]"
            )
            print(
                f"     +-> Relationship    : {m['relationship']} | Peak: {m['candidate_peak_db']:.2f} dB | "
                f"Est. BW: ~{m['candidate_bw_khz']:.0f} kHz"
            )
            for tr in m["matching_traits"]:
                print(f"     +-> Matching Trait  : {tr}")
            print(f"     +-> Band Allocation : {m['candidate_signature']}")
    else:
        print(" [i] No cross-frequency characteristic clones above threshold yet.")
    print(sep)


def run_live_targeted_monitor(
    data: Dict[str, Any],
    log_path: str = DEFAULT_LOG_FILE,
    threshold_db: float = -50.0,
    bin_width_hz: int = 25000,
) -> int:
    """
    Launch `hackrf_sweep` focused strictly on the narrowband windows around
    Flagged Targets + Characteristic Matches, and compare every incoming hit in
    real time against the Flagged Fingerprints!
    """
    if shutil.which("hackrf_sweep") is None:
        sys.stderr.write("[ERROR] `hackrf_sweep` not found in PATH.\n")
        return 1

    ranges_csv = data.get("recommended_sweep_ranges", "")
    if not ranges_csv:
        ranges_csv = "400:450,860:930,1000:3000"

    targets = data.get("flagged_targets", [])
    cmd = ["hackrf_sweep"]
    for r in ranges_csv.split(","):
        if r.strip():
            cmd.extend(["-f", r.strip()])
    cmd.extend(["-w", str(bin_width_hz), "-l", "16", "-g", "20", "-a", "0"])

    sep = "=" * 100
    print(sep)
    print(" LIVE LOCK-ON SENTINEL: MONITORING FLAGGED FREQUENCIES & CHARACTERISTIC MATCHES")
    print(sep)
    print(f" Monitored Windows : {ranges_csv} MHz (Resolution: {bin_width_hz/1000:.1f} kHz)")
    print(f" Active Watchlist  : {len(targets)} Flagged Target Fingerprint(s)")
    print(f" Alerts Log File   : {os.path.abspath(ALERTS_LOG)}")
    print(sep)
    print(
        f"{'TIMESTAMP':<23} | {'FREQ (MHz)':>11} | {'POWER':>9} | {'TARGET / CHARACTERISTIC MATCH STATUS':<50}"
    )
    print("-" * 100)
    sys.stdout.flush()

    live_state: Dict[float, Dict[str, float]] = {}
    proc: Optional[subprocess.Popen] = None

    def handle_sigterm(signum: int, frame: object) -> None:
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        with open(log_path, "a", encoding="utf-8", buffering=1) as lf, open(
            ALERTS_LOG, "a", encoding="utf-8", buffering=1
        ) as af:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            reader = csv.reader(proc.stdout)

            for row in reader:
                if len(row) < 7:
                    continue
                try:
                    date_s = row[0].strip()
                    time_s = row[1].strip()
                    hz_low = float(row[2].strip())
                    hz_bin = float(row[4].strip())
                    dbs = row[6:]
                except ValueError:
                    continue

                now_t = time.time()
                for i, db_s in enumerate(dbs):
                    try:
                        p_db = float(db_s.strip())
                    except ValueError:
                        continue
                    if p_db < threshold_db:
                        continue

                    f_mhz = (hz_low + (i + 0.5) * hz_bin) / 1e6
                    if analyzer.is_internal_spur(f_mhz):
                        continue

                    # Track live PRI & power delta on this bin
                    b_mhz = round(round(f_mhz / 0.050) * 0.050, 3)
                    st = live_state.get(b_mhz)
                    if st is None:
                        st = {
                            "last_t": now_t,
                            "pri": 0.0,
                            "prev_db": p_db,
                            "hits": 1.0,
                        }
                        live_state[b_mhz] = st
                    else:
                        dt = now_t - st["last_t"]
                        if dt >= 0.15:
                            st["pri"] = dt
                        st["hits"] += 1.0
                        st["last_t"] = now_t

                    db_delta = p_db - st["prev_db"]
                    st["prev_db"] = p_db
                    trend = (
                        f"▲+{db_delta:.1f}dB"
                        if db_delta >= 2.0
                        else (f"▼{db_delta:.1f}dB" if db_delta <= -2.0 else "STEADY")
                    )

                    # Check if direct hit on a Flagged Target OR a Characteristic Match!
                    status_msg = ""
                    for t in targets:
                        dist = abs(f_mhz - t["center_mhz"])
                        t_pri = t["characteristics"].get("median_pri_sec", 0.0)
                        if dist <= 0.25:
                            status_msg = f"[LOCKED TARGET {t['center_mhz']:.3f}M | {t['primary_flag']} | {trend}]"
                            break
                        elif (
                            t_pri > 0.2
                            and st["pri"] > 0.2
                            and abs(st["pri"] - t_pri) / max(t_pri, st["pri"]) <= 0.15
                        ):
                            status_msg = f"[CHAR MATCH -> {t['center_mhz']:.3f}M | Same Δt={st['pri']:.2f}s]"
                            break
                        elif (
                            abs(p_db - t["characteristics"]["peak_db"]) <= 3.0
                            and abs(f_mhz - t["center_mhz"]) <= 5.0
                        ):
                            status_msg = f"[NEARBY HOP? -> {t['center_mhz']:.3f}M | Δf={f_mhz - t['center_mhz']:+.2f}M]"
                            break

                    if not status_msg:
                        status_msg = f"[NEW WATCHBAND SIGNAL | {trend}]"

                    ts = f"{date_s} {time_s}"
                    line = f"{ts:<23} | {f_mhz:>10.4f} MHz | {p_db:>6.2f} dB | {status_msg}"
                    print(line, flush=True)

                    tier_label = (
                        "[L-BAND: 1-2 GHz]"
                        if 1000 <= f_mhz < 2000
                        else (
                            "[S-BAND: 2-3 GHz]"
                            if f_mhz >= 2000
                            else "[MODERATE: 860-930 MHz]"
                        )
                    )
                    lf.write(f"{ts},{tier_label},{f_mhz:.6f},{p_db:.2f}\n")
                    af.write(f"{ts},{f_mhz:.6f},{p_db:.2f},{status_msg}\n")

    except KeyboardInterrupt:
        print("\n[+] Stopping Live Lock-On Sentinel gracefully...", flush=True)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monitor Flagged Frequencies & Detect Signals Matching Flagged Characteristics"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=DEFAULT_LOG_FILE,
        help=f"Path to scan log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=55.0,
        help="Minimum characteristic similarity score (0-100) to report a clone/hopper match (default: 55)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Start live narrowband HackRF Lock-On Sentinel monitoring the flagged frequencies",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=-50.0,
        help="Power threshold in dB for live lock-on monitor (default: -50.0)",
    )
    args = parser.parse_args()

    data = analyze_flagged_and_matches(
        log_path=args.file, min_match_score=args.min_score
    )
    print_watchlist_report(data)

    if args.live:
        return run_live_targeted_monitor(
            data=data, log_path=args.file, threshold_db=args.threshold
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
