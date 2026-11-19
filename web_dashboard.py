#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 Web Dashboard & Static HTML Report Generator
for the HackRF Smart Spectrum & Cell Tower Intelligence Suite (1 MHz - 3 GHz).

Features:
  1. Cell Tower Search & Real-vs-Fake Cell Tower (Rogue BTS / IMSI-Catcher) Detector
  2. Location-Aware Regional Frequency Allocation Audit (What Belongs vs. What Doesn't)
  3. Calibrated dB-Based Distance Estimator (Macro Tower vs. Portable/Fake BTS vs. IoT)
  4. Interactive 360° Polar Compass Direction Finder (DF) & Multi-Point GPS Triangulator
  5. Real Flag Triage & Research Dossier (Separates Real Research Flags from Benign Noise)
  6. Targeted Pull Scanner Controls (Search Cell Towers, Pulsed Only, Exclude Wi-Fi/ISM)
  7. Generates self-contained `scan_dashboard.html` AND runs live server (`http://127.0.0.1:8080`).
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import analyze_scan_data as analyzer
import cell_tower_intel as cti
import direction_finder as df_engine
import monitor_flagged as watchlist_engine
import verify_rf_devices as verifier

DEFAULT_LOG_FILE = os.path.join(SCRIPT_DIR, "penetration_scan_hits.log")
DEFAULT_HTML_OUT = os.path.join(SCRIPT_DIR, "scan_dashboard.html")
PID_FILE = os.path.join(SCRIPT_DIR, ".hackrf_scanner.pid")
SCANNER_PY = os.path.join(SCRIPT_DIR, "hackrf_penetration_scanner.py")
MONITOR_PY = os.path.join(SCRIPT_DIR, "monitor_flagged.py")

# Fast mtime cache so live auto-refresh doesn't re-parse a large log unless it changed
_RAW_PARSE_CACHE: Dict[str, Any] = {
    "key": None,
    "analysis": None,
    "compliance": None,
    "watchlist": None,
}


def get_scanner_status() -> Dict[str, Any]:
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r", encoding="utf-8") as f:
                pid_str = f.read().strip()
            pid = int(pid_str)
            os.kill(pid, 0)
            return {"running": True, "pid": pid}
        except Exception:
            pass
    return {"running": False, "pid": None}


def _file_sig(path: str) -> Tuple[float, int]:
    try:
        st = os.stat(path)
        return (st.st_mtime, st.st_size)
    except OSError:
        return (0.0, 0)


def build_combined_payload(log_path: str = DEFAULT_LOG_FILE) -> Dict[str, Any]:
    """
    Load `penetration_scan_hits.log` (using fast mtime caching for the heavy CSV parse)
    and run Signal Intelligence, Device Compliance, Watchlist, Cell Tower Authenticity,
    Regional Belonging, dB Distance Estimation, and Direction Finding integration.
    """
    cfg = cti.load_config()
    region = cfg.get("region", "UK")

    log_sig = (os.path.abspath(log_path), _file_sig(log_path))
    if _RAW_PARSE_CACHE["key"] == log_sig and _RAW_PARSE_CACHE["analysis"] is not None:
        analysis = _RAW_PARSE_CACHE["analysis"]
        compliance = _RAW_PARSE_CACHE["compliance"]
        watchlist_data = _RAW_PARSE_CACHE["watchlist"]
    else:
        raw_records = analyzer.load_log_hits(log_path)
        analysis = analyzer.analyze_records(raw_records, hide_spurs=True) if raw_records else {}
        compliance = verifier.group_contiguous_signals(raw_records) if raw_records else {}
        watchlist_data = watchlist_engine.analyze_flagged_and_matches(
            log_path=log_path,
            precomputed_analysis=analysis,
            precomputed_compliance=compliance,
        )
        _RAW_PARSE_CACHE["key"] = log_sig
        _RAW_PARSE_CACHE["analysis"] = analysis
        _RAW_PARSE_CACHE["compliance"] = compliance
        _RAW_PARSE_CACHE["watchlist"] = watchlist_data

    clusters = analysis.get("clusters", [])
    emissions = compliance.get("emissions", [])

    # Always recompute lightweight regional/distance/DF intelligence dynamically so config or DF changes show instantly
    full_intel = cti.build_full_intel(emissions=emissions, clusters=clusters, config=cfg)
    cell_intel = full_intel["cell_towers"]
    flag_triage = full_intel["flag_triage"]
    df_bearings = full_intel["df_bearings"]

    # Enrich clusters with lightweight regional belonging, distance & DF bearing
    enriched_clusters = []
    for c in clusters:
        c_copy = dict(c)
        c_mhz = float(c["center_mhz"])
        cell_b = cti.match_cellular_band(c_mhz, region)
        sig_kind = (
            "macro_cell"
            if (cell_b and cell_b["direction"] in ("DOWNLINK", "TDD"))
            else ("portable_cell" if cell_b else "auto")
        )
        c_copy["belonging"] = cti.evaluate_location_belonging(
            freq_mhz=c_mhz,
            region=region,
            occupancy_pct=float(c.get("occupancy_pct", 0.0)),
            burst_count=int(c.get("burst_count", 1)),
        )
        c_copy["distance"] = cti.estimate_distance_from_db(
            freq_mhz=c_mhz, peak_db=float(c["max_db"]), config=cfg, signal_kind=sig_kind
        )
        c_copy["is_cellular"] = (
            cell_b is not None or cti.match_foreign_cellular_band(c_mhz, region) is not None
        )
        c_copy["is_wifi"] = 2400.0 <= c_mhz <= 2483.5
        c_copy["is_regional_ism"] = cti.is_in_regional_ism(c_mhz, region) is not None
        c_copy["df_bearing"] = cti.find_measured_bearing(c_mhz, df_bearings)
        enriched_clusters.append(c_copy)

    def dedup_peaks(items, min_sep=0.25):
        out = []
        for it in items:
            if not any(
                s["tier"] == it["tier"]
                and abs(s["center_mhz"] - it["center_mhz"]) <= min_sep
                for s in out
            ):
                out.append(it)
        return out

    pulsed_list = dedup_peaks(
        [
            c
            for c in enriched_clusters
            if c.get("burst_count", 0) >= 2 and not c.get("is_round_the_clock", False)
        ],
        0.25,
    )
    mesh_raw = [c for c in enriched_clusters if c.get("mesh_status", "NONE") != "NONE"]
    mesh_raw.sort(key=lambda x: (x.get("mesh_score", 0), x.get("max_db", -999)), reverse=True)
    mesh_list = dedup_peaks(mesh_raw, 0.25)

    continuous_1_3ghz = [
        c
        for c in enriched_clusters
        if c.get("center_mhz", 0) >= 1000.0 and c.get("is_round_the_clock", False)
    ]
    continuous_subghz = [
        c
        for c in enriched_clusters
        if c.get("center_mhz", 0) < 1000.0 and c.get("is_round_the_clock", False)
    ]
    all_1_3ghz = [c for c in enriched_clusters if c.get("center_mhz", 0) >= 1000.0]

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log_file": os.path.abspath(log_path),
        "scanner": get_scanner_status(),
        "config": cfg,
        "region_labels": cti.REGION_LABELS,
        "summary": {
            "total_external_hits": analysis.get("total_hits", 0),
            "filtered_spur_hits": analysis.get("filtered_clock_spur_hits", 0),
            "unique_sweeps": analysis.get("unique_timestamps", 0),
            "total_sweeps_with_spurs": compliance.get("total_sweeps", 0),
            "duration_seconds": round(analysis.get("duration_seconds", 0.0), 1),
            "first_timestamp": analysis.get("first_timestamp", "N/A"),
            "last_timestamp": analysis.get("last_timestamp", "N/A"),
            "distinct_emissions": len(
                [e for e in emissions if "HARDWARE SPUR" not in e.get("verdict", "")]
            ),
            "pulsed_count": len(pulsed_list),
            "mesh_count": len(mesh_list),
            "continuous_1_3ghz_count": len(continuous_1_3ghz),
            "continuous_subghz_count": len(continuous_subghz),
            "highband_total_count": len(all_1_3ghz),
            "flagged_targets_count": len(watchlist_data.get("flagged_targets", [])),
            "characteristic_matches_count": len(
                watchlist_data.get("characteristic_matches", [])
            ),
            "cell_total": cell_intel["total_cellular_emitters"],
            "cell_suspected_fake": cell_intel["counts"]["suspected_fake"],
            "cell_pulsed_verify": cell_intel["counts"]["pulsed_verify"],
            "cell_likely_real": cell_intel["counts"]["likely_real"],
            "cell_uplinks": cell_intel["counts"]["uplink_device"],
            "real_flags_critical": flag_triage["critical_count"],
            "real_flags_investigate": flag_triage["investigate_count"],
            "benign_filtered": flag_triage["benign_filtered_count"],
            "df_targets_measured": sum(
                1
                for v in df_bearings.values()
                if v.get("summary", {}).get("sample_count", 0) > 0
            ),
        },
        "tier_stats": analysis.get("tier_stats", {}),
        "cell_towers": cell_intel,
        "flag_triage": flag_triage,
        "df_bearings": df_bearings,
        "known_towers": full_intel["known_towers"],
        "clusters": enriched_clusters,
        "pulsed_signals": pulsed_list,
        "mesh_networks": mesh_list,
        "continuous_1_3ghz": continuous_1_3ghz,
        "continuous_subghz": continuous_subghz,
        "all_1_3ghz": all_1_3ghz,
        "emissions": emissions,
        "watchlist": watchlist_data,
    }


DASHBOARD_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HackRF Cell Tower, Direction Finder & Spectrum Intelligence Center</title>
<style>
  :root {
    --bg-dark: #0b0f19;
    --bg-card: #111827;
    --bg-card-hover: #1a2333;
    --bg-header: #0f172a;
    --border: #1e293b;
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
    --accent-cyan: #06b6d4;
    --accent-blue: #3b82f6;
    --accent-green: #10b981;
    --accent-amber: #f59e0b;
    --accent-red: #ef4444;
    --accent-purple: #a855f7;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text-main);
    line-height: 1.5;
    padding-bottom: 56px;
  }
  .topbar {
    background: linear-gradient(90deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 4px 20px rgba(0,0,0,0.45);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-icon {
    width: 40px; height: 40px; border-radius: 10px;
    background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 16px; color: #fff;
    box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
  }
  .brand h1 { font-size: 1.15rem; font-weight: 700; letter-spacing: 0.2px; }
  .brand p { font-size: 0.77rem; color: var(--text-muted); }
  .controls-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 5px 12px; border-radius: 999px; font-size: 0.78rem; font-weight: 600;
    background: rgba(148, 163, 184, 0.12); border: 1px solid var(--border);
  }
  .status-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--text-muted); }
  .status-dot.live { background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .btn {
    background: #1e293b; color: var(--text-main); border: 1px solid #334155;
    padding: 6px 12px; border-radius: 8px; font-size: 0.8rem; font-weight: 600;
    cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 5px;
  }
  .btn:hover { background: #334155; border-color: #475569; }
  .btn-primary { background: var(--accent-blue); border-color: var(--accent-blue); color: #fff; }
  .btn-primary:hover { background: #2563eb; }
  .btn-cyan { background: rgba(6,182,212,0.18); border-color: var(--accent-cyan); color: #67e8f9; }
  .btn-cyan:hover { background: rgba(6,182,212,0.32); }
  .btn-amber { background: rgba(245,158,11,0.18); border-color: var(--accent-amber); color: #fcd34d; }
  .btn-amber:hover { background: rgba(245,158,11,0.32); }
  .btn-green { background: rgba(16,185,129,0.18); border-color: var(--accent-green); color: #6ee7b7; }
  .btn-green:hover { background: rgba(16,185,129,0.32); }
  .btn-danger { background: rgba(239,68,68,0.18); border-color: var(--accent-red); color: #fca5a5; }
  .btn-danger:hover { background: rgba(239,68,68,0.32); }
  .btn-sm { padding: 4px 9px; font-size: 0.74rem; border-radius: 6px; }

  /* Location & Calibration Bar */
  .config-strip {
    background: #0f172a;
    border-bottom: 1px solid var(--border);
    padding: 10px 24px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    font-size: 0.8rem;
  }
  .config-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .config-group label { color: var(--text-muted); font-weight: 600; font-size: 0.75rem; }
  .inp, .sel {
    background: #0b1220; color: var(--text-main); border: 1px solid #334155;
    padding: 5px 9px; border-radius: 6px; font-size: 0.8rem;
  }
  .inp-sm { width: 88px; }
  .inp-md { width: 175px; }

  .container { max-width: 1520px; margin: 20px auto; padding: 0 22px; }

  /* Targeted Scan Pull Bar */
  .pull-bar {
    background: linear-gradient(135deg, rgba(15,23,42,0.95), rgba(30,27,75,0.55));
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 14px 18px;
    margin-bottom: 20px;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }
  .pull-check { display: inline-flex; align-items: center; gap: 5px; font-size: 0.8rem; color: #cbd5e1; cursor: pointer; }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(215px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
  }
  .kpi-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px 18px; position: relative; overflow: hidden;
  }
  .kpi-card::before { content: ""; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent-cyan); }
  .kpi-card.purple::before { background: var(--accent-purple); }
  .kpi-card.amber::before { background: var(--accent-amber); }
  .kpi-card.green::before { background: var(--accent-green); }
  .kpi-card.red::before { background: var(--accent-red); }
  .kpi-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-muted); font-weight: 700; }
  .kpi-value { font-size: 1.75rem; font-weight: 800; margin: 4px 0 3px; }
  .kpi-sub { font-size: 0.76rem; color: var(--text-muted); }

  .tabs {
    display: flex; gap: 6px; border-bottom: 1px solid var(--border);
    margin-bottom: 18px; overflow-x: auto; padding-bottom: 8px;
  }
  .tab-btn {
    background: transparent; color: var(--text-muted); border: 1px solid transparent;
    padding: 8px 14px; border-radius: 8px; font-size: 0.84rem; font-weight: 600;
    cursor: pointer; white-space: nowrap; transition: all 0.15s;
  }
  .tab-btn:hover { color: var(--text-main); background: rgba(255,255,255,0.04); }
  .tab-btn.active { color: #fff; background: rgba(59, 130, 246, 0.22); border-color: var(--accent-blue); }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  .panel {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 18px; margin-bottom: 18px;
  }
  .panel-header {
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 10px; margin-bottom: 14px; padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .panel-title { font-size: 1.02rem; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  th, td { padding: 10px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th {
    background: rgba(15, 23, 42, 0.75); color: var(--text-muted);
    font-weight: 600; text-transform: uppercase; font-size: 0.71rem; letter-spacing: 0.5px;
  }
  tr:hover td { background: var(--bg-card-hover); }
  .mono { font-family: "JetBrains Mono", "Fira Code", ui-monospace, monospace; }

  .badge {
    display: inline-block; padding: 3px 8px; border-radius: 6px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.25px; white-space: nowrap;
  }
  .badge-cyan { background: rgba(6, 182, 212, 0.16); color: #67e8f9; border: 1px solid rgba(6,182,212,0.35); }
  .badge-purple { background: rgba(168, 85, 247, 0.18); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.4); }
  .badge-amber { background: rgba(245, 158, 11, 0.18); color: #fcd34d; border: 1px solid rgba(245,158,11,0.4); }
  .badge-green { background: rgba(16, 185, 129, 0.16); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.35); }
  .badge-red { background: rgba(239, 68, 68, 0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
  .badge-muted { background: rgba(148, 163, 184, 0.14); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.3); }

  .meter-wrap { display: flex; align-items: center; gap: 8px; }
  .meter-bar { width: 82px; height: 8px; background: #1e293b; border-radius: 4px; overflow: hidden; }
  .meter-fill { height: 100%; border-radius: 4px; }

  .cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(430px, 1fr)); gap: 14px; }
  .detail-card {
    background: #0f172a; border: 1px solid var(--border); border-radius: 10px; padding: 15px 17px;
  }
  .detail-card.danger { border-color: rgba(239,68,68,0.5); box-shadow: inset 0 0 0 1px rgba(239,68,68,0.15); }
  .detail-card.warn { border-color: rgba(245,158,11,0.45); }
  .detail-card.ok { border-color: rgba(16,185,129,0.35); }
  .detail-card-head {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;
    margin-bottom: 10px; padding-bottom: 9px; border-bottom: 1px solid var(--border);
  }
  .freq-title { font-size: 1.1rem; font-weight: 800; color: #fff; }
  .detail-list { list-style: none; font-size: 0.81rem; color: #cbd5e1; }
  .detail-list li { margin-bottom: 5px; padding-left: 13px; position: relative; }
  .detail-list li::before { content: "•"; position: absolute; left: 0; color: var(--accent-cyan); }
  .code-cmd {
    display: block; background: #070b14; border: 1px solid #1e293b; border-radius: 6px;
    padding: 5px 8px; margin-top: 4px; font-size: 0.74rem; color: #67e8f9; overflow-x: auto;
  }

  .df-grid { display: grid; grid-template-columns: 380px 1fr; gap: 18px; align-items: start; }
  @media (max-width: 960px) { .df-grid { grid-template-columns: 1fr; } }
  .radar-box {
    background: #070b14; border: 1px solid #1e293b; border-radius: 12px;
    padding: 12px; display: flex; flex-direction: column; align-items: center;
  }
  .compass-btns {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin: 10px 0;
  }
  .chart-box {
    width: 100%; height: 270px; background: #090d16;
    border: 1px solid var(--border); border-radius: 10px; padding: 12px; position: relative;
  }
  canvas { display: block; }
  .empty-state {
    padding: 24px; text-align: center; color: var(--text-muted);
    background: rgba(15, 23, 42, 0.5); border-radius: 8px; border: 1px dashed #334155;
  }
  .toast {
    position: fixed; bottom: 20px; right: 20px; background: #1e293b; color: #fff;
    border: 1px solid var(--accent-cyan); border-radius: 10px; padding: 10px 16px;
    font-size: 0.84rem; font-weight: 600; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    z-index: 999; display: none;
  }
  textarea.inp { width: 100%; min-height: 78px; font-family: monospace; font-size: 0.77rem; }
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <div class="brand-icon">RF</div>
    <div>
      <h1>HackRF Cell Tower, Direction Finder & Spectrum Intelligence Center</h1>
      <p id="subtitle-meta">Real vs. Fake Cell Towers • Pulsed Signal Pull Filters • Compass DF & dB Distance • Location Allocation Audit</p>
    </div>
  </div>
  <div class="controls-bar">
    <div class="status-pill" id="scanner-status-pill">
      <span class="status-dot" id="scanner-dot"></span>
      <span id="scanner-status-text">Static Report Mode</span>
    </div>
    <button class="btn btn-cyan" id="btn-start-cell" style="display:none;" onclick="startCellTowerSearch()">📡 Search Cell Towers</button>
    <button class="btn btn-amber" id="btn-start-cell-pulsed" style="display:none;" onclick="controlScanner('start', 'cell-pulsed')">⚡ Pulsed Cell Hunter</button>
    <button class="btn btn-primary" id="btn-start-full" style="display:none;" onclick="controlScanner('start', 'full')">▶ Full Scan</button>
    <button class="btn" id="btn-start-watchlist" style="display:none;" onclick="controlScanner('start', 'watchlist')">🎯 Lock-On</button>
    <button class="btn btn-danger" id="btn-stop" style="display:none;" onclick="controlScanner('stop', '')">■ Stop Scan</button>
    <button class="btn" onclick="exportCurrentJson()">⬇ Export JSON</button>
  </div>
</header>

<!-- Location, Region & dB Calibration Bar -->
<section class="config-strip">
  <div class="config-group">
    <label for="cfg-region">📍 Your Location / Region:</label>
    <select id="cfg-region" class="sel">
      <option value="UK">United Kingdom (Ofcom / ITU R1)</option>
      <option value="US">United States & Canada (FCC / ITU R2)</option>
      <option value="EU">European Union (ETSI / ITU R1)</option>
      <option value="AU">Australia & New Zealand (ACMA / ITU R3)</option>
      <option value="GLOBAL">Global / Multi-Region</option>
    </select>
    <label for="cfg-lat">Lat:</label>
    <input type="text" id="cfg-lat" class="inp inp-sm" placeholder="e.g. 51.507">
    <label for="cfg-lon">Lon:</label>
    <input type="text" id="cfg-lon" class="inp inp-sm" placeholder="e.g. -0.128">
    <label for="cfg-env">dB Distance Model:</label>
    <select id="cfg-env" class="sel">
      <option value="suburban">Suburban / Mixed (n=2.8)</option>
      <option value="outdoor_los">Outdoor Line-of-Sight (n=2.2)</option>
      <option value="urban_indoor">Urban / Indoor Walls (n=3.5)</option>
    </select>
    <label for="cfg-cal">Cal Offset (dB):</label>
    <input type="number" step="1" id="cfg-cal" class="inp" style="width:68px;" value="0">
    <button class="btn btn-green btn-sm" onclick="saveUserConfig()">💾 Save Location & Re-Evaluate</button>
  </div>
  <div class="config-group" style="color:var(--text-muted);">
    <span>Regional Cell Bands: <code id="cfg-cell-ranges" class="mono" style="color:#67e8f9;">—</code></span>
  </div>
</section>

<main class="container">
  <!-- Targeted Pull Scanner Controls (Only Pull Frequencies We Are Looking For) -->
  <section class="pull-bar" id="targeted-pull-bar">
    <div style="display:flex; flex-direction:column; gap:4px;">
      <strong style="font-size:0.86rem; color:#67e8f9;">🎯 Targeted Frequency Pull Filter (Pull ONLY What You Are Looking For)</strong>
      <div style="display:flex; gap:14px; flex-wrap:wrap; align-items:center;">
        <label class="pull-check"><input type="checkbox" id="pull-only-cell" checked> Cellular Bands Only</label>
        <label class="pull-check"><input type="checkbox" id="pull-only-pulsed"> Pulsed Signals Only (Ignore 24/7 & Blips)</label>
        <label class="pull-check"><input type="checkbox" id="pull-exclude-wifi" checked> Exclude 2.4 GHz Wi-Fi/BLE</label>
        <label class="pull-check"><input type="checkbox" id="pull-exclude-ism"> Exclude Regional ISM</label>
      </div>
    </div>
    <div class="filter-bar">
      <input type="text" id="pull-custom-ranges" class="inp inp-md mono" placeholder="Custom MHz e.g. 869:894,925:960">
      <input type="number" id="pull-threshold" class="inp" style="width:84px;" value="-50" title="dB Threshold">
      <button class="btn btn-primary" id="btn-run-filtered" onclick="startFilteredScan()">▶ Start Filtered Scan</button>
    </div>
  </section>

  <!-- KPI Summary Row -->
  <section class="kpi-grid">
    <div class="kpi-card red">
      <div class="kpi-label">Cell Towers (Real vs. Fake)</div>
      <div class="kpi-value mono" id="kpi-cell-summary">0 / 0</div>
      <div class="kpi-sub" id="kpi-cell-sub">0 suspected fake • 0 pulsed/verify • 0 real</div>
    </div>
    <div class="kpi-card amber">
      <div class="kpi-label">Real Research Flags</div>
      <div class="kpi-value mono" id="kpi-real-flags">0</div>
      <div class="kpi-sub" id="kpi-benign-sub">0 benign / expected signals filtered out</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Pulsed Frequencies</div>
      <div class="kpi-value mono" id="kpi-pulsed">0</div>
      <div class="kpi-sub">Repeating burst / beacon channels</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-label">DF Bearings Measured</div>
      <div class="kpi-value mono" id="kpi-df-count">0</div>
      <div class="kpi-sub" id="kpi-region-sub">Region: UK</div>
    </div>
    <div class="kpi-card purple">
      <div class="kpi-label">External RF Hits</div>
      <div class="kpi-value mono" id="kpi-hits">0</div>
      <div class="kpi-sub" id="kpi-timespan">Updated: —</div>
    </div>
  </section>

  <!-- Navigation Tabs -->
  <nav class="tabs">
    <button class="tab-btn active" data-tab="cells" onclick="switchTab('cells', this)">1. 📡 Cell Tower Search & Fake Detector (<span id="tab-count-cells">0</span>)</button>
    <button class="tab-btn" data-tab="df" onclick="switchTab('df', this)">2. 🧭 Direction Finder & Distance Radar</button>
    <button class="tab-btn" data-tab="flags" onclick="switchTab('flags', this)">3. 🚨 Real Flags & Location Audit (<span id="tab-count-flags">0</span>)</button>
    <button class="tab-btn" data-tab="pulsed" onclick="switchTab('pulsed', this)">4. ⚡ Pulsed Frequencies (<span id="tab-count-pulsed">0</span>)</button>
    <button class="tab-btn" data-tab="overview" onclick="switchTab('overview', this)">5. 📊 Spectrum Map & All Hits</button>
    <button class="tab-btn" data-tab="mesh" onclick="switchTab('mesh', this)">6. 🕸 Mesh Radar (<span id="tab-count-mesh">0</span>)</button>
    <button class="tab-btn" data-tab="continuous" onclick="switchTab('continuous', this)">7. 24/7 Carriers (<span id="tab-count-247">0</span>)</button>
    <button class="tab-btn" data-tab="watchlist" onclick="switchTab('watchlist', this)">8. 🎯 Watchlist & Audit</button>
  </nav>

  <!-- TAB 1: CELL TOWER SEARCH & FAKE TOWER DETECTOR -->
  <section id="tab-cells" class="tab-panel active">
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">📡 Cell Tower Authenticity Analyzer (Real Cell Towers vs. Fake / Rogue Base Stations)</div>
          <div style="font-size:0.79rem; color:var(--text-muted); margin-top:2px;">
            Evaluates regional 3GPP bands, Downlink vs. Uplink direction, channel width (wideband LTE/NR vs. sunset 2G narrowband), pulsed anomalies, dB distance (Macro vs. Portable BTS), and compass bearings.
          </div>
        </div>
        <div class="filter-bar">
          <input type="text" id="cell-search" class="inp inp-md" placeholder="Search MHz, band, carrier..." oninput="renderCellTowersTab()">
          <select id="cell-verdict-filter" class="sel" onchange="renderCellTowersTab()">
            <option value="ALL">All Cellular Emitters</option>
            <option value="suspected_fake">🚨 Suspected Fake / Rogue Only</option>
            <option value="pulsed_verify">⚡ Pulsed / Verify Cellular Only</option>
            <option value="likely_real">✅ Likely Real Cell Towers Only</option>
            <option value="uplink_device">📱 Mobile Uplinks / IoT Only</option>
          </select>
          <label class="pull-check"><input type="checkbox" id="cell-pulsed-only" onchange="renderCellTowersTab()"> Pulsed Only</label>
        </div>
      </div>

      <div class="table-wrap" style="margin-bottom:18px;">
        <table>
          <thead>
            <tr>
              <th>Frequency & Band</th>
              <th>Verdict (Real vs. Fake)</th>
              <th>Auth / Fake Risk</th>
              <th>Power & Est. Distance (dB)</th>
              <th>Direction / Bearing</th>
              <th>Pulse / Stability</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="cell-table-body"></tbody>
        </table>
      </div>

      <h3 style="margin:12px 0; font-size:0.95rem; color:#67e8f9;">Detailed Cell Tower Evidence & Research Steps</h3>
      <div id="cell-cards-container" class="cards-grid"></div>
    </div>

    <!-- Known Real Tower Cross-Reference Panel -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">📍 Known Real Cell Tower Cross-Reference Database (<span id="known-tower-count">0</span> Loaded)</div>
          <div style="font-size:0.78rem; color:var(--text-muted);">Add real local towers or paste OpenCelliD / FCC CSV rows to automatically compute exact distance & compass bearing to legitimate macro towers!</div>
        </div>
        <button class="btn btn-danger btn-sm" onclick="clearKnownTowers()">Clear Tower DB</button>
      </div>
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap:16px;">
        <div class="detail-card">
          <strong style="display:block; margin-bottom:8px; font-size:0.86rem;">Add Single Verified Real Tower</strong>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
            <input id="kt-label" class="inp" placeholder="Label (e.g. North Mast)">
            <input id="kt-carrier" class="inp" placeholder="Carrier (e.g. O2 / AT&T)">
            <input id="kt-band" class="inp" placeholder="Band (e.g. B8 / B5)">
            <input id="kt-freq" class="inp" placeholder="Freq MHz (optional)">
            <input id="kt-lat" class="inp" placeholder="Tower Lat">
            <input id="kt-lon" class="inp" placeholder="Tower Lon">
          </div>
          <button class="btn btn-green btn-sm" style="margin-top:10px;" onclick="addKnownTower()">+ Add Real Tower Pin</button>
        </div>
        <div class="detail-card">
          <strong style="display:block; margin-bottom:8px; font-size:0.86rem;">Import OpenCelliD / Custom CSV</strong>
          <textarea id="kt-csv" class="inp" placeholder="Paste OpenCelliD CSV (radio,mcc,net,area,cell,unit,lon,lat,range) or custom CSV (label,carrier,radio,band,freq_mhz,lat,lon)"></textarea>
          <button class="btn btn-cyan btn-sm" style="margin-top:8px;" onclick="importTowersCsv()">⬆ Import CSV Towers</button>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 2: DIRECTION FINDER & DISTANCE RADAR -->
  <section id="tab-df" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">🧭 Compass Direction Finder (DF) & dB Distance Estimator</div>
          <div style="font-size:0.79rem; color:var(--text-muted);">
            Lock onto any cell tower or pulsed frequency, rotate your directional antenna (or use body-shielding null method) across compass headings, and capture readings to pinpoint incoming signal direction & distance.
          </div>
        </div>
        <div class="filter-bar">
          <select id="df-target-select" class="sel" onchange="selectDfTargetFromDropdown()">
            <option value="">— Quick Pick Detected Target —</option>
          </select>
          <input type="number" step="0.001" id="df-freq-input" class="inp inp-sm mono" value="890.250" oninput="renderDfTab()">
          <span style="font-size:0.8rem; color:var(--text-muted);">MHz</span>
          <button class="btn btn-danger btn-sm" onclick="clearDfSamples()">🗑 Clear Target</button>
        </div>
      </div>

      <div class="df-grid">
        <div class="radar-box">
          <canvas id="dfRadarCanvas" width="350" height="350"></canvas>
          <div id="df-bearing-readout" style="text-align:center; margin-top:8px;"></div>
        </div>

        <div>
          <div class="detail-card" style="margin-bottom:14px;">
            <strong style="display:block; margin-bottom:8px; color:#67e8f9;">Step 1: Aim Antenna at Compass Heading & Capture Signal Power</strong>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
              <label style="font-size:0.8rem;">Heading (°):</label>
              <input type="number" id="df-heading-input" class="inp inp-sm mono" min="0" max="359" value="0">
              <button class="btn btn-cyan" onclick="captureLiveDf()">📡 Live HackRF Sample</button>
              <span style="color:var(--text-muted); font-size:0.78rem;">OR Manual dB:</span>
              <input type="number" step="0.1" id="df-manual-db" class="inp inp-sm mono" placeholder="-24.5">
              <button class="btn btn-green" onclick="recordManualDf()">+ Log Reading</button>
            </div>
            <div style="font-size:0.76rem; color:var(--text-muted); margin-bottom:6px;">Quick Compass Headings (click to set heading, or use live capture):</div>
            <div class="compass-btns">
              <button class="btn btn-sm" onclick="setHeading(0)">N (0°)</button>
              <button class="btn btn-sm" onclick="setHeading(45)">NE (45°)</button>
              <button class="btn btn-sm" onclick="setHeading(90)">E (90°)</button>
              <button class="btn btn-sm" onclick="setHeading(135)">SE (135°)</button>
              <button class="btn btn-sm" onclick="setHeading(180)">S (180°)</button>
              <button class="btn btn-sm" onclick="setHeading(225)">SW (225°)</button>
              <button class="btn btn-sm" onclick="setHeading(270)">W (270°)</button>
              <button class="btn btn-sm" onclick="setHeading(315)">NW (315°)</button>
            </div>
            <div id="df-live-status" style="font-size:0.78rem; color:#fcd34d; margin-top:6px;"></div>
          </div>

          <div class="detail-card" style="margin-bottom:14px;">
            <strong style="display:block; margin-bottom:8px; color:#6ee7b7;">Step 2: dB-Based Distance Estimate (Live & Peak)</strong>
            <div id="df-distance-panel" style="font-size:0.82rem; color:#cbd5e1;"></div>
          </div>

          <div class="detail-card">
            <strong style="display:block; margin-bottom:8px; color:#d8b4fe;">Step 3: Multi-Point GPS Triangulation (Intersect 2+ Bearings)</strong>
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:8px; margin-bottom:8px;">
              <input id="tri-lat1" class="inp" placeholder="Point 1 Lat">
              <input id="tri-lon1" class="inp" placeholder="Point 1 Lon">
              <input id="tri-brg1" class="inp" placeholder="Point 1 Bearing°">
              <input id="tri-lat2" class="inp" placeholder="Point 2 Lat">
              <input id="tri-lon2" class="inp" placeholder="Point 2 Lon">
              <input id="tri-brg2" class="inp" placeholder="Point 2 Bearing°">
            </div>
            <button class="btn btn-primary btn-sm" onclick="runTriangulation()">📐 Calculate Intersection Coordinates</button>
            <div id="tri-result" style="margin-top:8px; font-size:0.82rem;"></div>
          </div>
        </div>
      </div>

      <div style="margin-top:16px;">
        <strong style="font-size:0.86rem; display:block; margin-bottom:8px;">Recorded Compass Samples for Selected Frequency</strong>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Timestamp</th><th>Heading</th><th>Power (dB)</th><th>Source</th><th>Notes</th></tr></thead>
            <tbody id="df-samples-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 3: REAL FLAGS & LOCATION ALLOCATION AUDIT -->
  <section id="tab-flags" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">🚨 Real Research Flags vs. Benign Local Noise (Location-Aware Triage)</div>
          <div style="font-size:0.79rem; color:var(--text-muted);">
            Identifies which frequencies BELONG at your location, which DO NOT BELONG (out-of-region / protected band / fake tower), and which flags are REAL anomalies worth deeper research.
          </div>
        </div>
        <div class="filter-bar">
          <select id="flag-tier-filter" class="sel" onchange="renderRealFlagsTab()">
            <option value="REAL_ONLY">🚨 Real Research Flags Only (Critical + Investigate)</option>
            <option value="CRITICAL">🔥 CRITICAL Flags Only</option>
            <option value="INVESTIGATE">⚠️ Investigate (Medium) Only</option>
            <option value="BENIGN">✅ Filtered Benign / Expected Signals</option>
            <option value="ALL">Show Everything</option>
          </select>
          <select id="flag-belong-filter" class="sel" onchange="renderRealFlagsTab()">
            <option value="ALL">All Belonging Statuses</option>
            <option value="DOES_NOT_BELONG">❌ Does NOT Belong Here</option>
            <option value="VERIFY_CONTEXT">❓ Verify License / Context</option>
            <option value="BELONGS">✅ Belongs in Region</option>
          </select>
          <input type="text" id="flag-search" class="inp inp-md" placeholder="Search MHz, reason..." oninput="renderRealFlagsTab()">
        </div>
      </div>
      <div id="flags-container" class="cards-grid"></div>
    </div>
  </section>

  <!-- TAB 4: PULSED FREQUENCIES (FILTERABLE) -->
  <section id="tab-pulsed" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">⚡ Pulsed & Repeating Frequency Intelligence (Filtered Pull View)</div>
          <div style="font-size:0.79rem; color:var(--text-muted);">Filter to pull only the pulsed frequencies you want (cellular-band pulses, non-WiFi/non-ISM, specific PRI intervals).</div>
        </div>
        <div class="filter-bar">
          <input type="text" id="pulsed-search" class="inp inp-md" placeholder="Search MHz, band, source..." oninput="renderPulsedCards()">
          <label class="pull-check"><input type="checkbox" id="pulsed-cell-only" onchange="renderPulsedCards()"> Cellular Only</label>
          <label class="pull-check"><input type="checkbox" id="pulsed-hide-wifi" checked onchange="renderPulsedCards()"> Hide 2.4G Wi-Fi</label>
          <label class="pull-check"><input type="checkbox" id="pulsed-hide-ism" onchange="renderPulsedCards()"> Hide Regional ISM</label>
          <label class="pull-check"><input type="checkbox" id="pulsed-not-belong" onchange="renderPulsedCards()"> Out-of-Region Only</label>
        </div>
      </div>
      <div id="pulsed-container" class="cards-grid"></div>
    </div>
  </section>

  <!-- TAB 5: OVERVIEW & SPECTRUM MAP -->
  <section id="tab-overview" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Interactive Peak Power Spectrum (1 MHz – 3000 MHz)</div>
        <div style="font-size:0.78rem;">
          <span class="badge badge-red">24/7 Carrier</span>
          <span class="badge badge-purple">Mesh Network</span>
          <span class="badge badge-amber">Pulsed Signal</span>
          <span class="badge badge-cyan">Transient</span>
        </div>
      </div>
      <div class="chart-box"><canvas id="spectrumCanvas"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">All Detected External Frequency Clusters</div>
        <div class="filter-bar">
          <input type="text" id="cluster-search" class="inp inp-md" placeholder="Search MHz, band, allocation..." oninput="renderClustersTable()">
          <select id="cluster-tier-filter" class="sel" onchange="renderClustersTable()">
            <option value="ALL">All Spectrum Tiers</option>
            <option value="CELL-LOW">600–860 MHz (Low Cellular)</option>
            <option value="MODERATE">860–960 MHz (Sub-GHz / Cellular)</option>
            <option value="L-BAND">1–2 GHz (L-Band)</option>
            <option value="S-BAND">2–3 GHz (S-Band)</option>
            <option value="HIGH">400–450 MHz</option>
            <option value="DEEP">1–30 MHz</option>
          </select>
          <label class="pull-check"><input type="checkbox" id="cluster-hide-wifi" checked onchange="renderClustersTable()"> Hide 2.4G Wi-Fi</label>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Freq (MHz)</th>
              <th>Location Status</th>
              <th>Peak Power</th>
              <th>Est. Distance (dB)</th>
              <th>Bursts / Occ</th>
              <th>Behavior</th>
              <th>Regional Allocation</th>
              <th>DF</th>
            </tr>
          </thead>
          <tbody id="clusters-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 6: MESH NETWORKS -->
  <section id="tab-mesh" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🕸 Mesh Network Topology & Multi-Node Relay Detector</div>
      </div>
      <div id="mesh-container" class="cards-grid"></div>
    </div>
  </section>

  <!-- TAB 7: 24/7 CARRIERS -->
  <section id="tab-continuous" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">1–3 GHz & Sub-GHz Round-the-Clock (24/7 Continuous) Transmitters</div>
      </div>
      <div id="continuous-container"></div>
    </div>
  </section>

  <!-- TAB 8: WATCHLIST & COMPLIANCE AUDIT -->
  <section id="tab-watchlist" class="tab-panel">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🎯 Targeted Lock-On Watchlist & Cross-Spectrum Characteristic Clones</div>
      </div>
      <div id="watchlist-banner" style="background:#0f172a; border:1px solid #334155; border-radius:10px; padding:12px 16px; margin-bottom:16px;"></div>
      <h3 style="margin-bottom:10px; color:#fcd34d; font-size:0.95rem;">1. Flagged Target Fingerprints</h3>
      <div id="watchlist-targets-container" class="cards-grid" style="margin-bottom:20px;"></div>
      <h3 style="margin-bottom:10px; color:#67e8f9; font-size:0.95rem;">2. Characteristic Clones / Hoppers</h3>
      <div id="watchlist-matches-container" class="cards-grid"></div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Raw RF Compliance Audit (<span id="tab-count-audit">0</span> Emissions)</div>
        <input type="text" id="audit-search" class="inp inp-md" placeholder="Filter emissions..." oninput="renderComplianceCards()">
      </div>
      <div id="compliance-container" class="cards-grid"></div>
    </div>
  </section>
</main>

<div id="toast" class="toast"></div>

<script>
let REPORT_DATA = __INITIAL_PAYLOAD_JSON__;
const IS_LIVE_SERVER = window.location.protocol.startsWith("http");
let configInitialized = false;

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { t.style.display = 'none'; }, 3500);
}

function switchTab(tabId, btnEl) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  if (btnEl) {
    btnEl.classList.add('active');
  } else {
    const match = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (match) match.classList.add('active');
  }
  if (tabId === 'overview') drawSpectrumChart();
  if (tabId === 'df') renderDfTab();
}

function jumpToDirectionFinder(freqMhz) {
  document.getElementById('df-freq-input').value = Number(freqMhz).toFixed(3);
  switchTab('df', null);
  renderDfTab();
  showToast(`Direction Finder locked onto ${Number(freqMhz).toFixed(3)} MHz`);
}

function dbToPercent(db) {
  const clamped = Math.max(-70, Math.min(-5, db));
  return Math.round(((clamped + 70) / 65) * 100);
}

function dbToColor(db) {
  if (db >= -18) return '#ef4444';
  if (db >= -32) return '#f59e0b';
  if (db >= -44) return '#06b6d4';
  return '#3b82f6';
}

function belongingBadge(b) {
  if (!b) return `<span class="badge badge-muted">UNKNOWN</span>`;
  if (b.status === 'DOES_NOT_BELONG') return `<span class="badge badge-red">❌ ${b.badge}</span>`;
  if (b.status === 'VERIFY_CONTEXT') return `<span class="badge badge-amber">❓ ${b.badge}</span>`;
  return `<span class="badge badge-green">✅ ${b.badge}</span>`;
}

function cellVerdictBadge(t) {
  if (t.verdict_key === 'suspected_fake') return `<span class="badge badge-red">🚨 ${t.tower_verdict}</span>`;
  if (t.verdict_key === 'pulsed_verify') return `<span class="badge badge-amber">⚡ ${t.tower_verdict}</span>`;
  if (t.verdict_key === 'likely_real') return `<span class="badge badge-green">✅ ${t.tower_verdict}</span>`;
  return `<span class="badge badge-cyan">📱 ${t.tower_verdict}</span>`;
}

function behaviorBadge(c) {
  const b = c.behavior || '';
  if (b.includes('24/7')) return `<span class="badge badge-red">${b}</span>`;
  if (b.includes('MESH') || (c.mesh_status && c.mesh_status !== 'NONE')) return `<span class="badge badge-purple">${c.mesh_status !== 'NONE' ? c.mesh_status : b}</span>`;
  if (b.includes('PULSED')) return `<span class="badge badge-amber">${b}</span>`;
  return `<span class="badge badge-cyan">${b}</span>`;
}

function syncConfigInputs() {
  const cfg = REPORT_DATA.config || {};
  if (!configInitialized) {
    document.getElementById('cfg-region').value = cfg.region || 'UK';
    document.getElementById('cfg-lat').value = cfg.latitude !== null && cfg.latitude !== undefined ? cfg.latitude : '';
    document.getElementById('cfg-lon').value = cfg.longitude !== null && cfg.longitude !== undefined ? cfg.longitude : '';
    document.getElementById('cfg-env').value = cfg.environment || 'suburban';
    document.getElementById('cfg-cal').value = cfg.cal_offset_db || 0;
    if (cfg.latitude !== null && cfg.latitude !== undefined) {
      document.getElementById('tri-lat1').value = cfg.latitude;
      document.getElementById('tri-lon1').value = cfg.longitude;
    }
    configInitialized = true;
  }
  const ct = REPORT_DATA.cell_towers || {};
  document.getElementById('cfg-cell-ranges').textContent = (ct.recommended_cell_ranges || '—') + ' MHz';
}

function renderDashboard() {
  syncConfigInputs();
  const s = REPORT_DATA.summary || {};
  const cfg = REPORT_DATA.config || {};

  document.getElementById('kpi-cell-summary').textContent = `${s.cell_likely_real || 0} Real / ${s.cell_suspected_fake || 0} Fake`;
  document.getElementById('kpi-cell-sub').textContent = `${s.cell_suspected_fake || 0} suspected fake • ${s.cell_pulsed_verify || 0} pulsed/verify • ${s.cell_uplinks || 0} uplinks`;
  document.getElementById('kpi-real-flags').textContent = `${(s.real_flags_critical || 0) + (s.real_flags_investigate || 0)}`;
  document.getElementById('kpi-benign-sub').textContent = `${s.real_flags_critical || 0} critical • ${s.real_flags_investigate || 0} investigate • ${s.benign_filtered || 0} benign filtered`;
  document.getElementById('kpi-pulsed').textContent = s.pulsed_count || 0;
  document.getElementById('kpi-df-count').textContent = s.df_targets_measured || 0;
  document.getElementById('kpi-region-sub').textContent = `Region: ${cfg.region || 'UK'} (${(cfg.environment || 'suburban').replace('_', ' ')})`;
  document.getElementById('kpi-hits').textContent = (s.total_external_hits || 0).toLocaleString();
  document.getElementById('kpi-timespan').textContent = `Updated: ${REPORT_DATA.generated_at || ''} (${(s.filtered_spur_hits || 0).toLocaleString()} spurs muted)`;

  document.getElementById('tab-count-cells').textContent = s.cell_total || 0;
  document.getElementById('tab-count-flags').textContent = (s.real_flags_critical || 0) + (s.real_flags_investigate || 0);
  document.getElementById('tab-count-pulsed').textContent = s.pulsed_count || 0;
  document.getElementById('tab-count-mesh').textContent = s.mesh_count || 0;
  document.getElementById('tab-count-247').textContent = (s.continuous_1_3ghz_count || 0) + (s.continuous_subghz_count || 0);
  document.getElementById('tab-count-audit').textContent = (REPORT_DATA.emissions || []).length;
  document.getElementById('known-tower-count').textContent = (REPORT_DATA.known_towers || []).length;

  if (IS_LIVE_SERVER) {
    const sc = REPORT_DATA.scanner || {};
    const dot = document.getElementById('scanner-dot');
    const txt = document.getElementById('scanner-status-text');
    ['btn-start-cell', 'btn-start-cell-pulsed', 'btn-start-full', 'btn-start-watchlist'].forEach(id => {
      document.getElementById(id).style.display = sc.running ? 'none' : 'inline-flex';
    });
    document.getElementById('btn-stop').style.display = sc.running ? 'inline-flex' : 'none';
    if (sc.running) {
      dot.classList.add('live');
      txt.textContent = `Scanner RUNNING (PID ${sc.pid}) • Live Auto-Refresh`;
    } else {
      dot.classList.remove('live');
      txt.textContent = `Scanner Idle • Live Server Ready`;
    }
  } else {
    document.getElementById('btn-run-filtered').disabled = true;
    document.getElementById('btn-run-filtered').title = 'Launch live server (`./auto_scanner.sh --web`) to start scans from browser';
  }

  renderCellTowersTab();
  populateDfDropdown();
  renderDfTab();
  renderRealFlagsTab();
  renderPulsedCards();
  renderClustersTable();
  renderMeshCards();
  renderContinuousSection();
  renderWatchlistTab();
  renderComplianceCards();
  if (document.getElementById('tab-overview').classList.contains('active')) {
    drawSpectrumChart();
  }
}

/* ==================== TAB 1: CELL TOWERS ==================== */
function renderCellTowersTab() {
  const ct = REPORT_DATA.cell_towers || {};
  const all = ct.towers || [];
  const q = (document.getElementById('cell-search').value || '').toLowerCase();
  const vf = document.getElementById('cell-verdict-filter').value;
  const pulsedOnly = document.getElementById('cell-pulsed-only').checked;

  const filtered = all.filter(t => {
    if (vf !== 'ALL' && t.verdict_key !== vf) return false;
    if (pulsedOnly && !t.is_pulsed) return false;
    if (!q) return true;
    const hay = `${t.center_mhz} ${t.band_3gpp} ${t.carriers} ${t.direction} ${t.tower_verdict} ${t.earfcn_arfcn}`.toLowerCase();
    return hay.includes(q);
  });

  const tbody = document.getElementById('cell-table-body');
  const cards = document.getElementById('cell-cards-container');

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:22px;">No matching cellular-band emitters yet. Click <strong>📡 Search Cell Towers</strong> above (or run <code>./auto_scanner.sh --cell</code>) to scan your region's cellular bands!</td></tr>`;
    cards.innerHTML = `<div class="empty-state">No cellular emitters match current filter.</div>`;
    return;
  }

  tbody.innerHTML = filtered.map(t => {
    const d = t.distance || {};
    const pulseTxt = t.is_continuous
      ? `<span class="badge badge-green">24/7 Steady (${t.duty_cycle_pct.toFixed(0)}%)</span>`
      : `<span class="badge badge-amber">Pulsed (${t.pulses}x${t.median_pri_sec > 0 ? ', Δt=' + t.median_pri_sec.toFixed(1) + 's' : ''})</span>`;
    return `<tr>
      <td>
        <div class="mono" style="font-weight:800; color:#fff;">${t.center_mhz.toFixed(3)} MHz</div>
        <div style="font-size:0.74rem; color:var(--text-muted);">${t.band_3gpp} • <strong>${t.direction}</strong> • ~${t.est_bw_khz} kHz</div>
        <div style="font-size:0.72rem; color:#67e8f9;">${t.carriers}</div>
      </td>
      <td>${cellVerdictBadge(t)}</td>
      <td class="mono" style="font-size:0.78rem;">
        <div>Real: <strong style="color:#6ee7b7;">${t.authenticity_score}</strong>/100</div>
        <div>Fake Risk: <strong style="color:${t.fake_risk_score >= 55 ? '#fca5a5' : '#fcd34d'};">${t.fake_risk_score}</strong>/100</div>
      </td>
      <td>
        <div class="mono" style="font-weight:700; color:${dbToColor(t.peak_db)};">${t.peak_db.toFixed(1)} dB <span style="font-size:0.72rem; color:var(--text-muted);">(~${d.est_rx_dbm} dBm)</span></div>
        <div style="font-size:0.73rem;">Macro Tower: <strong>${d.macro_tower_str || '—'}</strong></div>
        <div style="font-size:0.73rem; color:#fcd34d;">If Portable/Fake BTS: <strong>${d.portable_bts_str || '—'}</strong></div>
      </td>
      <td style="font-size:0.78rem;">${t.bearing_display}</td>
      <td>${pulseTxt}</td>
      <td><button class="btn btn-cyan btn-sm" onclick="jumpToDirectionFinder(${t.center_mhz})">🧭 Find Direction</button></td>
    </tr>`;
  }).join('');

  cards.innerHTML = filtered.map(t => {
    const cls = t.verdict_key === 'suspected_fake' ? 'danger' : (t.verdict_key === 'pulsed_verify' ? 'warn' : 'ok');
    const d = t.distance || {};
    const fakeLi = (t.fake_indicators || []).map(x => `<li style="color:#fca5a5;"><strong>[!] Risk:</strong> ${x}</li>`).join('');
    const realLi = (t.real_indicators || []).map(x => `<li style="color:#6ee7b7;"><strong>[+] Real Match:</strong> ${x}</li>`).join('');
    const stepsLi = (t.research_steps || []).map(x => `<li><span style="color:#94a3b8;">Research:</span> <span class="mono" style="font-size:0.76rem; color:#67e8f9;">${x}</span></li>`).join('');
    return `<div class="detail-card ${cls}">
      <div class="detail-card-head">
        <div>
          <div class="freq-title mono">${t.center_mhz.toFixed(4)} MHz <span style="font-size:0.78rem; color:var(--text-muted);">(${t.band_3gpp} ${t.direction})</span></div>
          <div style="font-size:0.76rem; color:var(--text-muted);">${t.carriers} • ${t.earfcn_arfcn} • Est. BW ~${t.est_bw_khz} kHz</div>
        </div>
        <div style="text-align:right;">
          ${cellVerdictBadge(t)}
          <div style="margin-top:6px;"><button class="btn btn-cyan btn-sm" onclick="jumpToDirectionFinder(${t.center_mhz})">🧭 Find Direction</button></div>
        </div>
      </div>
      <ul class="detail-list">
        <li><strong>Distance from dB (${t.peak_db.toFixed(1)} dB):</strong> Macro Tower <strong>${d.macro_tower_str}</strong> | Portable/Fake BTS <strong style="color:#fcd34d;">${d.portable_bts_str}</strong> | Handset/IoT <strong>${d.low_power_tx_str}</strong></li>
        <li><strong>Direction / Bearing:</strong> ${t.bearing_display}</li>
        ${fakeLi}
        ${realLi}
        ${stepsLi}
      </ul>
    </div>`;
  }).join('');
}

/* ==================== TAB 2: DIRECTION FINDER ==================== */
function populateDfDropdown() {
  const sel = document.getElementById('df-target-select');
  const prev = sel.value;
  const opts = [`<option value="">— Quick Pick Detected Target —</option>`];
  const seen = new Set();

  (REPORT_DATA.cell_towers?.towers || []).forEach(t => {
    const k = t.center_mhz.toFixed(3);
    if (!seen.has(k)) {
      seen.add(k);
      opts.push(`<option value="${k}">[CELL] ${k} MHz — ${t.band_3gpp} (${t.tower_verdict})</option>`);
    }
  });
  (REPORT_DATA.flag_triage?.critical_flags || []).forEach(f => {
    const k = f.center_mhz.toFixed(3);
    if (!seen.has(k)) {
      seen.add(k);
      opts.push(`<option value="${k}">[CRITICAL FLAG] ${k} MHz — ${f.belonging.badge}</option>`);
    }
  });
  (REPORT_DATA.pulsed_signals || []).slice(0, 20).forEach(p => {
    const k = p.center_mhz.toFixed(3);
    if (!seen.has(k)) {
      seen.add(k);
      opts.push(`<option value="${k}">[PULSED] ${k} MHz — ${p.max_db.toFixed(1)} dB</option>`);
    }
  });
  sel.innerHTML = opts.join('');
  if (prev) sel.value = prev;
}

function selectDfTargetFromDropdown() {
  const v = document.getElementById('df-target-select').value;
  if (v) {
    document.getElementById('df-freq-input').value = v;
    renderDfTab();
  }
}

function setHeading(deg) {
  document.getElementById('df-heading-input').value = deg;
}

function getSelectedDfEntry() {
  const freq = parseFloat(document.getElementById('df-freq-input').value) || 890.25;
  const db = REPORT_DATA.df_bearings || {};
  const exactKey = freq.toFixed(3);
  if (db[exactKey]) return { freq, entry: db[exactKey] };
  // Fuzzy match within +/- 0.5 MHz
  let best = null, bestDiff = 0.5;
  Object.values(db).forEach(e => {
    const diff = Math.abs((e.freq_mhz || -999) - freq);
    if (diff <= bestDiff) { bestDiff = diff; best = e; }
  });
  return { freq, entry: best };
}

function renderDfTab() {
  const { freq, entry } = getSelectedDfEntry();
  const summary = entry?.summary || null;
  const samples = entry?.samples || [];

  drawDfPolarRadar(freq, summary);

  const readout = document.getElementById('df-bearing-readout');
  const distPanel = document.getElementById('df-distance-panel');
  const tbody = document.getElementById('df-samples-tbody');

  if (summary && summary.sample_count > 0) {
    readout.innerHTML = `
      <div style="font-size:1.25rem; font-weight:800; color:#67e8f9;" class="mono">🧭 ${summary.cardinal} ${summary.peak_bearing_deg.toFixed(1)}°</div>
      <div style="font-size:0.78rem; color:var(--text-muted);">Peak ${summary.peak_db.toFixed(1)} dB • Front/Back ${summary.front_to_back_db.toFixed(1)} dB • Null: ${summary.null_cardinal} ${summary.null_bearing_deg.toFixed(0)}°</div>
      <div style="margin-top:4px;"><span class="badge ${summary.confidence === 'HIGH' ? 'badge-green' : 'badge-amber'}">DF Confidence: ${summary.confidence} (${summary.unique_headings} headings)</span></div>
    `;
    const d = summary.distance || {};
    distPanel.innerHTML = `
      <div style="margin-bottom:6px;">Based on Peak Bearing Power <strong class="mono" style="color:#6ee7b7;">${summary.peak_db.toFixed(2)} dB</strong> (Est. ${d.est_rx_dbm} dBm @ ${d.environment_label}):</div>
      <ul class="detail-list">
        <li><strong>If Real Macro Cell Tower (~58 dBm EIRP):</strong> <strong style="color:#67e8f9;">${d.macro_tower_str}</strong></li>
        <li><strong>If Portable / Fake Cell Tower / Femtocell (~28 dBm):</strong> <strong style="color:#fcd34d;">${d.portable_bts_str}</strong></li>
        <li><strong>If Mobile Handset / Pulsed Sensor / IoT (~18 dBm):</strong> <strong style="color:#d8b4fe;">${d.low_power_tx_str}</strong></li>
      </ul>
    `;
  } else {
    readout.innerHTML = `<div style="color:var(--text-muted); font-size:0.84rem;">No compass samples recorded for <strong class="mono">${freq.toFixed(3)} MHz</strong> yet.<br>Aim your directional antenna at N/E/S/W headings and capture readings!</div>`;
    // Show distance estimate from scan log if present
    const cl = (REPORT_DATA.clusters || []).find(c => Math.abs(c.center_mhz - freq) <= 0.35);
    if (cl && cl.distance) {
      const d = cl.distance;
      distPanel.innerHTML = `
        <div style="margin-bottom:6px;">Latest Logged Power for <strong class="mono">${cl.center_mhz.toFixed(3)} MHz</strong>: <strong>${cl.max_db.toFixed(1)} dB</strong> (Est. ${d.est_rx_dbm} dBm):</div>
        <ul class="detail-list">
          <li><strong>If Real Macro Cell Tower (~58 dBm):</strong> <strong style="color:#67e8f9;">${d.macro_tower_str}</strong></li>
          <li><strong>If Portable / Fake BTS (~28 dBm):</strong> <strong style="color:#fcd34d;">${d.portable_bts_str}</strong></li>
          <li><strong>If Handset / Pulsed IoT (~18 dBm):</strong> <strong style="color:#d8b4fe;">${d.low_power_tx_str}</strong></li>
        </ul>`;
    } else {
      distPanel.innerHTML = `<span style="color:var(--text-muted);">Capture a live HackRF reading or log a manual dB value to compute estimated distance.</span>`;
    }
  }

  if (!samples.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px;">No compass samples recorded for ${freq.toFixed(3)} MHz yet.</td></tr>`;
  } else {
    tbody.innerHTML = samples.slice().reverse().map(s => `<tr>
      <td class="mono">${s.timestamp}</td>
      <td class="mono"><strong>${s.heading_deg.toFixed(1)}°</strong></td>
      <td class="mono" style="color:${dbToColor(s.power_db)}; font-weight:700;">${s.power_db.toFixed(2)} dB</td>
      <td><span class="badge badge-muted">${s.source}</span></td>
      <td style="font-size:0.78rem; color:var(--text-muted);">${s.note || ''}</td>
    </tr>`).join('');
  }
}

function drawDfPolarRadar(freqMhz, summary) {
  const canvas = document.getElementById('dfRadarCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 32;

  ctx.clearRect(0, 0, W, H);

  // Concentric rings
  [0.25, 0.5, 0.75, 1.0].forEach(frac => {
    ctx.beginPath();
    ctx.arc(cx, cy, R * frac, 0, Math.PI * 2);
    ctx.strokeStyle = frac === 1.0 ? '#334155' : '#1e293b';
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // Radial lines & compass labels
  const cardinals = [
    [0, 'N'], [45, 'NE'], [90, 'E'], [135, 'SE'],
    [180, 'S'], [225, 'SW'], [270, 'W'], [315, 'NW']
  ];
  ctx.font = 'bold 12px monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  cardinals.forEach(([deg, lbl]) => {
    const rad = (deg - 90) * Math.PI / 180;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + R * Math.cos(rad), cy + R * Math.sin(rad));
    ctx.strokeStyle = '#1e293b';
    ctx.stroke();

    ctx.fillStyle = lbl === 'N' ? '#ef4444' : '#94a3b8';
    ctx.fillText(lbl, cx + (R + 16) * Math.cos(rad), cy + (R + 16) * Math.sin(rad));
  });

  // Plot measured heading polygon
  const bins = summary?.heading_bins || [];
  if (bins.length > 0) {
    const minDb = Math.min(-65, (summary.min_db || -60) - 6);
    const maxDb = Math.max(summary.peak_db || -10, minDb + 10);

    ctx.beginPath();
    bins.forEach((b, i) => {
      const norm = Math.max(0.12, (b.max_db - minDb) / (maxDb - minDb));
      const rad = (b.heading_deg - 90) * Math.PI / 180;
      const x = cx + R * norm * Math.cos(rad);
      const y = cy + R * norm * Math.sin(rad);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    if (bins.length >= 3) ctx.closePath();
    ctx.fillStyle = 'rgba(6, 182, 212, 0.25)';
    ctx.fill();
    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Sample dots
    bins.forEach(b => {
      const norm = Math.max(0.12, (b.max_db - minDb) / (maxDb - minDb));
      const rad = (b.heading_deg - 90) * Math.PI / 180;
      const x = cx + R * norm * Math.cos(rad);
      const y = cy + R * norm * Math.sin(rad);
      ctx.beginPath();
      ctx.arc(x, y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = '#67e8f9';
      ctx.fill();
    });

    // Peak Bearing Vector Arrow
    if (summary.peak_bearing_deg !== null && summary.peak_bearing_deg !== undefined) {
      const pRad = (summary.peak_bearing_deg - 90) * Math.PI / 180;
      const ex = cx + R * 0.96 * Math.cos(pRad);
      const ey = cy + R * 0.96 * Math.sin(pRad);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(ex, ey);
      ctx.strokeStyle = '#f59e0b';
      ctx.lineWidth = 3;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(ex, ey, 6, 0, Math.PI * 2);
      ctx.fillStyle = '#f59e0b';
      ctx.fill();
    }
  } else {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px sans-serif';
    ctx.fillText(`${freqMhz.toFixed(3)} MHz`, cx, cy - 8);
    ctx.fillText('Awaiting DF Samples', cx, cy + 10);
  }
}

/* ==================== TAB 3: REAL FLAGS & LOCATION AUDIT ==================== */
function renderRealFlagsTab() {
  const ft = REPORT_DATA.flag_triage || {};
  const tierSel = document.getElementById('flag-tier-filter').value;
  const belSel = document.getElementById('flag-belong-filter').value;
  const q = (document.getElementById('flag-search').value || '').toLowerCase();

  let items = [];
  if (tierSel === 'CRITICAL') items = ft.critical_flags || [];
  else if (tierSel === 'INVESTIGATE') items = ft.investigate_flags || [];
  else if (tierSel === 'BENIGN') items = ft.benign_expected || [];
  else if (tierSel === 'ALL') items = [...(ft.critical_flags || []), ...(ft.investigate_flags || []), ...(ft.benign_expected || [])];
  else items = [...(ft.critical_flags || []), ...(ft.investigate_flags || [])];

  const filtered = items.filter(f => {
    if (belSel !== 'ALL' && f.belonging?.status !== belSel) return false;
    if (!q) return true;
    const hay = `${f.center_mhz} ${f.belonging?.local_allocation} ${f.belonging?.badge} ${(f.reasons || []).join(' ')} ${f.original_verdict}`.toLowerCase();
    return hay.includes(q);
  });

  const box = document.getElementById('flags-container');
  if (!filtered.length) {
    box.innerHTML = `<div class="empty-state">No signals match this Real Flag / Location Belonging filter.</div>`;
    return;
  }

  box.innerHTML = filtered.map(f => {
    const cls = f.triage_tier === 'CRITICAL_REAL_FLAG' ? 'danger' : (f.triage_tier === 'INVESTIGATE_MEDIUM' ? 'warn' : 'ok');
    const tierBadge = f.triage_tier === 'CRITICAL_REAL_FLAG'
      ? `<span class="badge badge-red">🔥 CRITICAL REAL FLAG (${f.research_score}/100)</span>`
      : (f.triage_tier === 'INVESTIGATE_MEDIUM'
        ? `<span class="badge badge-amber">⚠️ INVESTIGATE (${f.research_score}/100)</span>`
        : `<span class="badge badge-green">✅ BENIGN / EXPECTED</span>`);
    const d = f.distance || {};
    const bearingTxt = f.bearing ? `🧭 ${f.bearing.cardinal} ${f.bearing.peak_bearing_deg.toFixed(0)}° (${f.bearing.confidence})` : 'Unmeasured';
    const reasonsHtml = (f.reasons || []).map(r => `<li>${r}</li>`).join('');
    const stepsHtml = (f.next_steps || []).map(st => `<li><strong>Next Step:</strong> <code class="code-cmd">${st}</code></li>`).join('');

    return `<div class="detail-card ${cls}">
      <div class="detail-card-head">
        <div>
          <div class="freq-title mono">${f.center_mhz.toFixed(4)} MHz <span style="font-size:0.78rem; color:var(--text-muted);">(${f.span_mhz} • ~${f.est_bw_khz} kHz)</span></div>
          <div style="margin-top:4px; display:flex; gap:6px; flex-wrap:wrap;">
            ${tierBadge}
            ${belongingBadge(f.belonging)}
          </div>
        </div>
        <button class="btn btn-cyan btn-sm" onclick="jumpToDirectionFinder(${f.center_mhz})">🧭 Find Direction</button>
      </div>
      <ul class="detail-list">
        <li><strong>Local Allocation (${ft.region}):</strong> ${f.belonging?.local_allocation || 'Unknown'}</li>
        <li><strong>Power & Distance (dB):</strong> Peak <strong class="mono">${f.peak_db.toFixed(1)} dB</strong> | Est. Dist: <strong>${d.primary_dist_str}</strong> (${d.primary_range_str}) | Direction: <strong>${bearingTxt}</strong></li>
        <li><strong>Activity:</strong> ${f.pulses} burst(s), ${f.duty_cycle_pct.toFixed(1)}% occ${f.median_pri_sec > 0 ? `, Median PRI Δt=${f.median_pri_sec.toFixed(2)}s` : ''}</li>
        ${reasonsHtml}
        ${stepsHtml}
      </ul>
    </div>`;
  }).join('');
}

/* ==================== TAB 4: PULSED SIGNALS ==================== */
function renderPulsedCards() {
  const list = REPORT_DATA.pulsed_signals || [];
  const q = (document.getElementById('pulsed-search').value || '').toLowerCase();
  const cellOnly = document.getElementById('pulsed-cell-only').checked;
  const hideWifi = document.getElementById('pulsed-hide-wifi').checked;
  const hideIsm = document.getElementById('pulsed-hide-ism').checked;
  const notBelong = document.getElementById('pulsed-not-belong').checked;

  const filtered = list.filter(p => {
    if (cellOnly && !p.is_cellular) return false;
    if (hideWifi && p.is_wifi) return false;
    if (hideIsm && p.is_regional_ism) return false;
    if (notBelong && p.belonging?.status !== 'DOES_NOT_BELONG') return false;
    if (!q) return true;
    const hay = `${p.center_mhz} ${p.tier} ${p.probable_pulsed_source} ${p.signature} ${p.belonging?.local_allocation}`.toLowerCase();
    return hay.includes(q);
  });

  const box = document.getElementById('pulsed-container');
  if (!filtered.length) {
    box.innerHTML = `<div class="empty-state">No pulsed signals match your active pull filters. Adjust checkboxes or run a live pulsed scan.</div>`;
    return;
  }

  box.innerHTML = filtered.slice(0, 80).map(p => {
    const priText = p.median_pri_sec > 0
      ? `Median Δt = <strong>${p.median_pri_sec.toFixed(2)}s</strong> (Mean ${p.mean_pri_sec.toFixed(2)}s, Jitter ±${p.pri_jitter_sec.toFixed(2)}s)`
      : `Intermittent bursts across separate sessions`;
    const d = p.distance || {};
    const brg = p.df_bearing ? `🧭 ${p.df_bearing.cardinal} ${p.df_bearing.peak_bearing_deg.toFixed(0)}°` : 'Unmeasured';
    return `<div class="detail-card">
      <div class="detail-card-head">
        <div>
          <div class="freq-title mono">${p.center_mhz.toFixed(4)} MHz</div>
          <div style="margin-top:4px; display:flex; gap:6px; flex-wrap:wrap;">
            ${belongingBadge(p.belonging)}
            <span class="badge badge-amber">${p.pulse_class}</span>
          </div>
        </div>
        <button class="btn btn-cyan btn-sm" onclick="jumpToDirectionFinder(${p.center_mhz})">🧭 Find Direction</button>
      </div>
      <ul class="detail-list">
        <li><strong>Regional Allocation:</strong> ${p.belonging?.local_allocation || p.signature}</li>
        <li><strong>Pulse Cadence (PRI):</strong> ${priText}</li>
        <li><strong>Power, Distance & Direction:</strong> Peak <strong>${p.max_db.toFixed(1)} dB</strong> | Est. Dist: <strong>${d.primary_dist_str}</strong> (${d.primary_range_str}) | Direction: <strong>${brg}</strong></li>
        <li><strong>Probable Source:</strong> <span style="color:#fcd34d;">${p.probable_pulsed_source}</span></li>
        <li><strong>Bursts & Span:</strong> ${p.burst_count} bursts (${p.first_seen} → ${p.last_seen})</li>
      </ul>
    </div>`;
  }).join('');
}

/* ==================== TAB 5: OVERVIEW & CLUSTERS ==================== */
function renderClustersTable() {
  const q = (document.getElementById('cluster-search').value || '').toLowerCase();
  const tierFilter = document.getElementById('cluster-tier-filter').value;
  const hideWifi = document.getElementById('cluster-hide-wifi').checked;
  const clusters = REPORT_DATA.clusters || [];
  const tbody = document.getElementById('clusters-tbody');

  const filtered = clusters.filter(c => {
    if (hideWifi && c.is_wifi) return false;
    if (tierFilter !== 'ALL' && !(c.tier || '').includes(tierFilter)) return false;
    if (!q) return true;
    const hay = `${c.center_mhz} ${c.tier} ${c.behavior} ${c.signature} ${c.belonging?.local_allocation}`.toLowerCase();
    return hay.includes(q);
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">No matching frequency clusters.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 150).map(c => {
    const pct = dbToPercent(c.max_db);
    const col = dbToColor(c.max_db);
    const d = c.distance || {};
    return `<tr>
      <td class="mono" style="font-weight:700; color:#fff;">${c.center_mhz.toFixed(3)} MHz</td>
      <td>${belongingBadge(c.belonging)}</td>
      <td>
        <div class="meter-wrap">
          <span class="mono" style="font-weight:700; width:64px;">${c.max_db.toFixed(1)} dB</span>
          <div class="meter-bar"><div class="meter-fill" style="width:${pct}%; background:${col};"></div></div>
        </div>
      </td>
      <td class="mono" style="font-size:0.78rem;">${d.primary_dist_str || '—'}</td>
      <td class="mono" style="font-size:0.78rem;">${c.burst_count || 1}b (${c.occupancy_pct.toFixed(1)}%)</td>
      <td>${behaviorBadge(c)}</td>
      <td style="max-width:300px; font-size:0.77rem;">${c.belonging?.local_allocation || c.signature}</td>
      <td><button class="btn btn-cyan btn-sm" onclick="jumpToDirectionFinder(${c.center_mhz})">🧭</button></td>
    </tr>`;
  }).join('');
}

/* ==================== TAB 6, 7, 8 ==================== */
function renderMeshCards() {
  const list = REPORT_DATA.mesh_networks || [];
  const box = document.getElementById('mesh-container');
  if (!list.length) {
    box.innerHTML = `<div class="empty-state">No mesh network channels detected yet.</div>`;
    return;
  }
  box.innerHTML = list.slice(0, 50).map(m => {
    const tiers = (m.node_power_tiers_db || []).map(d => `${d.toFixed(1)} dB`).join(', ');
    const reasons = (m.mesh_reasons || []).map(r => `<li>${r}</li>`).join('');
    return `<div class="detail-card">
      <div class="detail-card-head">
        <div>
          <div class="freq-title mono">${m.center_mhz.toFixed(4)} MHz</div>
          <div style="font-size:0.76rem; color:var(--text-muted);">${m.belonging?.local_allocation || m.mesh_protocol}</div>
        </div>
        <span class="badge badge-purple">${m.mesh_status} (${m.mesh_score}/100)</span>
      </div>
      <ul class="detail-list">
        <li><strong>Nodes & Relay Echoes:</strong> ~${m.estimated_mesh_nodes} tier(s) [${tiers}] • ${m.relay_echoes} relay echo(es)</li>
        <li><strong>Est. Distance:</strong> ${m.distance?.primary_dist_str || '—'} (${m.distance?.primary_range_str || ''})</li>
        ${reasons}
      </ul>
    </div>`;
  }).join('');
}

function renderContinuousSection() {
  const c13 = REPORT_DATA.continuous_1_3ghz || [];
  const cSub = REPORT_DATA.continuous_subghz || [];
  const box = document.getElementById('continuous-container');
  const all = [...c13, ...cSub];
  if (!all.length) {
    box.innerHTML = `<div class="empty-state">No round-the-clock (24/7) continuous carriers detected yet.</div>`;
    return;
  }
  box.innerHTML = `<div class="cards-grid">` + all.slice(0, 50).map(c => `
    <div class="detail-card">
      <div class="detail-card-head">
        <div class="freq-title mono">${c.center_mhz.toFixed(4)} MHz</div>
        ${belongingBadge(c.belonging)}
      </div>
      <ul class="detail-list">
        <li><strong>Occupancy:</strong> ${c.occupancy_pct.toFixed(1)}% | Window Persistence: ${c.window_persistence_pct.toFixed(1)}%</li>
        <li><strong>Power & Distance:</strong> Peak ${c.max_db.toFixed(1)} dB | Est. Dist: ${c.distance?.primary_dist_str || '—'}</li>
        <li><strong>Allocation:</strong> ${c.belonging?.local_allocation || c.signature}</li>
      </ul>
    </div>`).join('') + `</div>`;
}

function renderWatchlistTab() {
  const wl = REPORT_DATA.watchlist || {};
  const targets = wl.flagged_targets || [];
  const matches = wl.characteristic_matches || [];
  document.getElementById('watchlist-banner').innerHTML = `
    <div class="mono" style="font-size:0.86rem; color:#67e8f9;">Narrowband Lock-On Ranges: <strong>${wl.recommended_sweep_ranges || 'N/A'} MHz</strong></div>
    <div class="mono" style="font-size:0.76rem; color:var(--text-muted); margin-top:3px;">CLI: <code>./auto_scanner.sh --monitor</code></div>
  `;
  document.getElementById('watchlist-targets-container').innerHTML = targets.length
    ? targets.slice(0, 30).map((t, i) => `
      <div class="detail-card">
        <div class="detail-card-head">
          <div class="freq-title mono">#${i+1}: ${t.center_mhz.toFixed(3)} MHz</div>
          <span class="badge badge-amber">${t.primary_flag}</span>
        </div>
        <ul class="detail-list">
          <li>BW ~${t.characteristics?.est_bw_khz} kHz | Peak ${t.characteristics?.peak_db?.toFixed(1)} dB | Lock: ${t.monitor_window_mhz} MHz</li>
          ${(t.flag_reasons || []).map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>`).join('')
    : `<div class="empty-state">No watchlist targets yet.</div>`;

  document.getElementById('watchlist-matches-container').innerHTML = matches.length
    ? matches.slice(0, 24).map(m => `
      <div class="detail-card">
        <div class="detail-card-head">
          <div class="freq-title mono">${m.candidate_mhz.toFixed(3)} MHz ⇄ ${m.matched_target_mhz.toFixed(3)} MHz</div>
          <span class="badge badge-cyan">${m.similarity_pct.toFixed(0)}% MATCH</span>
        </div>
        <ul class="detail-list">
          <li>${m.relationship} | Peak ${m.candidate_peak_db.toFixed(1)} dB</li>
          ${(m.matching_traits || []).map(tr => `<li>${tr}</li>`).join('')}
        </ul>
      </div>`).join('')
    : `<div class="empty-state">No characteristic clones matched yet.</div>`;
}

function renderComplianceCards() {
  const q = (document.getElementById('audit-search').value || '').toLowerCase();
  const emissions = (REPORT_DATA.emissions || []).filter(e => {
    if (!q) return true;
    return `${e.center_mhz} ${e.band_name} ${e.verdict} ${e.typical_devices}`.toLowerCase().includes(q);
  });
  const box = document.getElementById('compliance-container');
  box.innerHTML = emissions.length
    ? emissions.slice(0, 60).map((e, idx) => `
      <div class="detail-card">
        <div class="detail-card-head">
          <div>
            <div class="freq-title mono">#${idx+1}: ${e.center_mhz.toFixed(3)} MHz (~${e.est_bw_khz} kHz)</div>
            <div style="font-size:0.76rem; color:var(--text-muted);">${e.band_name}</div>
          </div>
          <span class="badge badge-muted">${e.verdict}</span>
        </div>
        <ul class="detail-list">
          <li>Peak ${e.peak_db.toFixed(1)} dB | Pulses ${e.coalesced_pulses || e.unique_bursts} (${e.duty_cycle_pct.toFixed(1)}% occ)</li>
          ${(e.audit_reasons || []).map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>`).join('')
    : `<div class="empty-state">No emissions match filter.</div>`;
}

function drawSpectrumChart() {
  const canvas = document.getElementById('spectrumCanvas');
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = Math.max(600, rect.width - 24);
  canvas.height = Math.max(220, rect.height - 24);
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  const padL = 52, padR = 20, padT = 18, padB = 34;
  const plotW = W - padL - padR, plotH = H - padT - padB;

  ctx.strokeStyle = '#1e293b'; ctx.fillStyle = '#64748b'; ctx.font = '11px monospace';
  for (let db = 0; db >= -60; db -= 10) {
    const y = padT + ((db - 0) / (-60)) * plotH;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillText(`${db} dB`, 6, y + 4);
  }
  const clusters = (REPORT_DATA.clusters || []).slice().sort((a, b) => a.center_mhz - b.center_mhz);
  if (!clusters.length) return;
  const n = clusters.length, stepX = plotW / Math.max(n, 1);
  const barW = Math.max(3, Math.min(20, stepX * 0.65));
  clusters.forEach((c, i) => {
    const x = padL + i * stepX + stepX / 2;
    const clamped = Math.max(-60, Math.min(0, c.max_db));
    const y = padT + ((clamped - 0) / (-60)) * plotH;
    const barH = (padT + plotH) - y;
    let color = '#06b6d4';
    if (c.belonging?.status === 'DOES_NOT_BELONG') color = '#ef4444';
    else if (c.is_cellular) color = '#10b981';
    else if ((c.behavior || '').includes('PULSED')) color = '#f59e0b';
    ctx.fillStyle = color;
    ctx.fillRect(x - barW / 2, y, barW, barH);
    if (n <= 35 || i % Math.ceil(n / 18) === 0) {
      ctx.fillStyle = '#94a3b8'; ctx.font = '10px monospace'; ctx.textAlign = 'center';
      ctx.fillText(`${c.center_mhz.toFixed(0)}M`, x, H - 6);
    }
  });
}

/* ==================== API ACTIONS ==================== */
async function saveUserConfig() {
  if (!IS_LIVE_SERVER) { showToast('Run `./auto_scanner.sh --web` to save config live.'); return; }
  const payload = {
    region: document.getElementById('cfg-region').value,
    latitude: document.getElementById('cfg-lat').value.trim(),
    longitude: document.getElementById('cfg-lon').value.trim(),
    environment: document.getElementById('cfg-env').value,
    cal_offset_db: parseFloat(document.getElementById('cfg-cal').value) || 0,
  };
  const r = await fetch('/api/config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  if (r.ok) {
    configInitialized = false;
    await fetchLiveReport();
    showToast(`Location updated to ${payload.region} — all frequencies & distances re-evaluated!`);
  }
}

async function startCellTowerSearch() {
  await controlScanner('start', 'cell', { exclude_wifi: true, only_cell: true });
  showToast('Started Region-Aware Cell Tower Search!');
}

async function startFilteredScan() {
  if (!IS_LIVE_SERVER) { showToast('Start live server (`./auto_scanner.sh --web`) to run scans.'); return; }
  const onlyCell = document.getElementById('pull-only-cell').checked;
  const onlyPulsed = document.getElementById('pull-only-pulsed').checked;
  const excludeWifi = document.getElementById('pull-exclude-wifi').checked;
  const excludeIsm = document.getElementById('pull-exclude-ism').checked;
  const ranges = document.getElementById('pull-custom-ranges').value.trim();
  const threshold = document.getElementById('pull-threshold').value.trim() || '-50';
  const mode = onlyCell ? (onlyPulsed ? 'cell-pulsed' : 'cell') : (onlyPulsed ? 'pulsed' : 'full');
  await controlScanner('start', mode, {
    only_cell: onlyCell,
    only_pulsed: onlyPulsed,
    exclude_wifi: excludeWifi,
    exclude_ism: excludeIsm,
    ranges,
    threshold,
  });
  showToast(`Started Targeted Filtered Scan (${mode.toUpperCase()})!`);
}

async function controlScanner(action, mode, opts = {}) {
  if (!IS_LIVE_SERVER) return;
  const params = new URLSearchParams({ action, mode });
  Object.entries(opts).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  });
  await fetch(`/api/control?${params.toString()}`, { method: 'POST' });
  setTimeout(fetchLiveReport, 700);
}

async function captureLiveDf() {
  if (!IS_LIVE_SERVER) { showToast('Launch live web server to sample HackRF live.'); return; }
  const freq = parseFloat(document.getElementById('df-freq-input').value);
  const heading = parseFloat(document.getElementById('df-heading-input').value) || 0;
  const st = document.getElementById('df-live-status');
  st.textContent = `⏳ Sampling live HackRF power around ${freq.toFixed(3)} MHz at heading ${heading}°...`;
  const r = await fetch('/api/df/sample', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ freq_mhz: freq, heading_deg: heading })
  });
  const data = await r.json();
  if (data.ok) {
    st.textContent = `✅ Captured ${heading}° -> Peak ${data.peak_db.toFixed(2)} dB (Avg ${data.avg_db.toFixed(2)} dB)`;
    await fetchLiveReport();
  } else {
    st.textContent = `❌ ${data.error || 'Failed to sample HackRF'}`;
  }
}

async function recordManualDf() {
  if (!IS_LIVE_SERVER) { showToast('Launch live web server to log bearing samples.'); return; }
  const freq = parseFloat(document.getElementById('df-freq-input').value);
  const heading = parseFloat(document.getElementById('df-heading-input').value) || 0;
  const db = parseFloat(document.getElementById('df-manual-db').value);
  if (isNaN(db)) { showToast('Enter a valid dB reading (e.g. -24.5)'); return; }
  const r = await fetch('/api/df/record', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ freq_mhz: freq, heading_deg: heading, power_db: db })
  });
  if (r.ok) {
    showToast(`Logged ${heading}° -> ${db.toFixed(1)} dB for ${freq.toFixed(3)} MHz`);
    await fetchLiveReport();
  }
}

async function clearDfSamples() {
  if (!IS_LIVE_SERVER) return;
  const freq = parseFloat(document.getElementById('df-freq-input').value);
  await fetch('/api/df/clear', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ freq_mhz: freq })
  });
  showToast(`Cleared DF samples for ${freq.toFixed(3)} MHz`);
  await fetchLiveReport();
}

async function runTriangulation() {
  if (!IS_LIVE_SERVER) { showToast('Launch live web server to triangulate.'); return; }
  const obs = [
    { lat: document.getElementById('tri-lat1').value, lon: document.getElementById('tri-lon1').value, bearing_deg: document.getElementById('tri-brg1').value },
    { lat: document.getElementById('tri-lat2').value, lon: document.getElementById('tri-lon2').value, bearing_deg: document.getElementById('tri-brg2').value },
  ];
  const r = await fetch('/api/df/triangulate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ observations: obs })
  });
  const res = await r.json();
  const el = document.getElementById('tri-result');
  if (!res.ok) {
    el.innerHTML = `<span style="color:#fca5a5;">❌ ${res.error}</span>`;
    return;
  }
  el.innerHTML = `<div style="color:#6ee7b7;">
    ✅ Estimated Transmitter Location: <strong class="mono">${res.estimated_lat}, ${res.estimated_lon}</strong>
    (${res.distance_from_point1_str} ${res.bearing_from_point1} from Point 1)
    &nbsp;<a href="${res.maps_url}" target="_blank" style="color:#67e8f9;">Open on Map ↗</a>
    ${res.warning ? `<div style="color:#fcd34d; margin-top:4px;">⚠️ ${res.warning}</div>` : ''}
  </div>`;
}

async function addKnownTower() {
  if (!IS_LIVE_SERVER) { showToast('Launch live web server to add towers.'); return; }
  const payload = {
    label: document.getElementById('kt-label').value,
    carrier: document.getElementById('kt-carrier').value,
    band: document.getElementById('kt-band').value,
    freq_mhz: document.getElementById('kt-freq').value,
    lat: document.getElementById('kt-lat').value,
    lon: document.getElementById('kt-lon').value,
  };
  const r = await fetch('/api/towers/add', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  if (r.ok) { showToast('Added verified real tower!'); await fetchLiveReport(); }
  else { showToast('Enter valid Tower Lat & Lon coordinates.'); }
}

async function importTowersCsv() {
  if (!IS_LIVE_SERVER) { showToast('Launch live web server to import CSV.'); return; }
  const csvText = document.getElementById('kt-csv').value;
  const r = await fetch('/api/towers/import', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ csv_text: csvText }) });
  const data = await r.json();
  showToast(`Imported ${data.added || 0} known towers (Total: ${data.total || 0})`);
  await fetchLiveReport();
}

async function clearKnownTowers() {
  if (!IS_LIVE_SERVER) return;
  await fetch('/api/towers/clear', { method: 'POST' });
  showToast('Cleared known tower database.');
  await fetchLiveReport();
}

async function fetchLiveReport() {
  if (!IS_LIVE_SERVER) return;
  try {
    const resp = await fetch('/api/report');
    if (resp.ok) {
      REPORT_DATA = await resp.json();
      renderDashboard();
    }
  } catch (e) {}
}

function exportCurrentJson() {
  const blob = new Blob([JSON.stringify(REPORT_DATA, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `hackrf_cell_and_spectrum_intel_${Date.now()}.json`;
  a.click();
}

window.addEventListener('resize', () => {
  if (document.getElementById('tab-overview').classList.contains('active')) drawSpectrumChart();
});
renderDashboard();
if (IS_LIVE_SERVER) {
  setInterval(fetchLiveReport, 4000);
}
</script>
</body>
</html>
"""


def generate_static_html(
    log_path: str = DEFAULT_LOG_FILE, html_out: str = DEFAULT_HTML_OUT
) -> str:
    payload = build_combined_payload(log_path)
    json_str = json.dumps(payload)
    page_html = DASHBOARD_HTML_TEMPLATE.replace("__INITIAL_PAYLOAD_JSON__", json_str)
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(page_html)
    return os.path.abspath(html_out)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    log_path: str = DEFAULT_LOG_FILE

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/report":
            self._send_json(build_combined_payload(self.log_path))
            return
        if parsed.path == "/api/config":
            self._send_json(cti.load_config())
            return

        payload = build_combined_payload(self.log_path)
        page_html = DASHBOARD_HTML_TEMPLATE.replace(
            "__INITIAL_PAYLOAD_JSON__", json.dumps(payload)
        )
        body = page_html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/config":
            body = self._read_json_body()
            updated = cti.save_config(body)
            self._send_json({"ok": True, "config": updated})
            return

        if parsed.path == "/api/df/sample":
            body = self._read_json_body()
            try:
                freq = float(body["freq_mhz"])
                hdg = float(body.get("heading_deg", 0.0))
            except (KeyError, ValueError, TypeError):
                self._send_json({"ok": False, "error": "Invalid freq_mhz or heading_deg"}, 400)
                return
            res = df_engine.sample_live_bearing(freq_mhz=freq, heading_deg=hdg)
            self._send_json(res)
            return

        if parsed.path == "/api/df/record":
            body = self._read_json_body()
            try:
                freq = float(body["freq_mhz"])
                hdg = float(body.get("heading_deg", 0.0))
                pwr = float(body["power_db"])
            except (KeyError, ValueError, TypeError):
                self._send_json({"ok": False, "error": "Invalid DF parameters"}, 400)
                return
            entry = df_engine.record_bearing_sample(
                freq_mhz=freq,
                heading_deg=hdg,
                power_db=pwr,
                note=str(body.get("note", "Web Manual Entry")),
                source="WEB_MANUAL",
            )
            self._send_json({"ok": True, "entry": entry})
            return

        if parsed.path == "/api/df/clear":
            body = self._read_json_body()
            try:
                freq = float(body["freq_mhz"])
            except (KeyError, ValueError, TypeError):
                self._send_json({"ok": False, "error": "Invalid freq_mhz"}, 400)
                return
            self._send_json(df_engine.clear_bearing_samples(freq))
            return

        if parsed.path == "/api/df/triangulate":
            body = self._read_json_body()
            res = df_engine.triangulate_bearings(body.get("observations", []))
            self._send_json(res)
            return

        if parsed.path == "/api/towers/add":
            body = self._read_json_body()
            try:
                towers = cti.add_known_tower(body)
                self._send_json({"ok": True, "total": len(towers)})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, 400)
            return

        if parsed.path == "/api/towers/import":
            body = self._read_json_body()
            cfg = cti.load_config()
            res = cti.import_opencellid_csv_text(
                csv_text=str(body.get("csv_text", "")),
                user_lat=cfg.get("latitude"),
                user_lon=cfg.get("longitude"),
            )
            self._send_json({"ok": True, **res})
            return

        if parsed.path == "/api/towers/clear":
            cti.save_known_towers([])
            self._send_json({"ok": True, "total": 0})
            return

        if parsed.path == "/api/control":
            qs = urllib.parse.parse_qs(parsed.query)
            action = qs.get("action", [""])[0]
            mode = qs.get("mode", ["full"])[0]
            valid_modes = (
                "full", "cell", "cell-pulsed", "pulsed", "highband", "mesh", "subghz", "watchlist"
            )
            if mode not in valid_modes:
                mode = "full"

            status = get_scanner_status()
            if action == "stop" and status["running"] and status["pid"]:
                try:
                    os.kill(status["pid"], signal.SIGINT)
                except Exception:
                    pass
                try:
                    if os.path.exists(PID_FILE):
                        os.remove(PID_FILE)
                except Exception:
                    pass
            elif action == "start" and not status["running"]:
                stdout_log = os.path.join(SCRIPT_DIR, "scanner_stdout.log")
                out_f = open(stdout_log, "a", encoding="utf-8")
                cfg = cti.load_config()
                if mode == "watchlist":
                    cmd_list = [sys.executable, MONITOR_PY, "--live", "-f", self.log_path]
                else:
                    cmd_list = [
                        sys.executable,
                        SCANNER_PY,
                        "--mode",
                        mode,
                        "--region",
                        cfg.get("region", "UK"),
                        "-o",
                        self.log_path,
                    ]
                    if qs.get("only_cell", [""])[0].lower() == "true":
                        cmd_list.append("--only-cell")
                    if qs.get("only_pulsed", [""])[0].lower() == "true":
                        cmd_list.append("--only-pulsed")
                    if qs.get("exclude_wifi", [""])[0].lower() == "true":
                        cmd_list.append("--exclude-wifi")
                    if qs.get("exclude_ism", [""])[0].lower() == "true":
                        cmd_list.append("--exclude-ism")
                    custom_ranges = qs.get("ranges", [""])[0].strip()
                    if custom_ranges:
                        cmd_list.extend(["--ranges", custom_ranges])
                    thresh = qs.get("threshold", [""])[0].strip()
                    if thresh:
                        try:
                            float(thresh)
                            cmd_list.extend(["-t", thresh])
                        except ValueError:
                            pass

                proc = subprocess.Popen(
                    cmd_list,
                    stdout=out_f,
                    stderr=out_f,
                    start_new_session=True,
                )
                with open(PID_FILE, "w", encoding="utf-8") as pf:
                    pf.write(str(proc.pid))

            self._send_json(get_scanner_status())
            return

        self.send_response(404)
        self.end_headers()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HackRF Cell Tower, Direction Finder & Spectrum Web Dashboard"
    )
    parser.add_argument("-f", "--file", type=str, default=DEFAULT_LOG_FILE)
    parser.add_argument("-o", "--html-out", type=str, default=DEFAULT_HTML_OUT)
    parser.add_argument("--serve", action="store_true", default=False)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--open-browser", action="store_true", default=False)
    args = parser.parse_args()

    out_path = generate_static_html(log_path=args.file, html_out=args.html_out)
    print(f"[+] Generated standalone interactive HTML dashboard: {out_path}")

    if not args.serve:
        if args.open_browser:
            webbrowser.open(f"file://{out_path}")
        return 0

    DashboardRequestHandler.log_path = args.file
    server_addr = ("127.0.0.1", args.port)
    httpd = HTTPServer(server_addr, DashboardRequestHandler)
    url = f"http://127.0.0.1:{args.port}"
    print("=" * 88)
    print(f" HackRF Cell Tower & Spectrum Intelligence Web Server Running at: {url}")
    print("   - Live auto-refreshing from:", os.path.abspath(args.file))
    print("   - Includes Cell Tower Search, Fake Tower Detector, Compass DF & Real Flag Triage")
    print("   - Press Ctrl+C to stop the web server")
    print("=" * 88)

    if args.open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down web dashboard server cleanly.")
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
