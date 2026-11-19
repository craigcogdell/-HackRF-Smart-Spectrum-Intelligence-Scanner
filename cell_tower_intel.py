#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 Cell Tower Authenticity, Regional Allocation,
dB-Based Distance Estimator & Real Flag Research Triage Engine (`cell_tower_intel.py`).

Capabilities:
  1. Location & Regional Spectrum Profiles (US/Canada, UK, EU, Australia/NZ, Global):
     - Auto-maps GPS latitude/longitude to the right ITU Region & Country profile.
     - Knows exact 3GPP cellular Downlink vs. Uplink bands, duplex spacing, channel
       bandwidths, EARFCN/ARFCN calculations, 2G/3G sunset status, and licensed carriers.
     - Evaluates EVERY detected signal for whether it BELONGS or DOES NOT BELONG at
       the user's location (e.g., flags EU 868 MHz / GSM-900 in US, or US 915 ISM in UK/EU).
  2. Real Cell Tower vs. Fake Cell Tower (Rogue BTS / IMSI-Catcher / Stingray) Classifier:
     - Scores cellular-band emissions using spectral mask / channel width, duplex direction,
       2G/3G sunset status, temporal persistence (24/7 macro vs. transient pop-up),
       pulsed anomalies, extreme close-range RSSI overpowering, and optional Known Real
       Tower database cross-reference (OpenCelliD / FCC / manual CSV).
  3. Calibrated dB-Based Distance Estimator (FSPL + Log-Distance Path Loss Model):
     - Estimates probable distance from HackRF dB reading for Macro Cell Towers (~58 dBm EIRP),
       Portable/Fake Base Stations (~27 dBm EIRP), and Low-Power Pulsed/IoT Emitters (~17 dBm).
  4. Real Flag Research Triage Engine:
     - Separates genuinely suspicious / actionable REAL FLAGS (worth deeper RF research)
       from expected local benign signals (Wi-Fi Ch 1/6/11, BLE, legal regional ISM,
       verified macro cell towers, internal SDR spurs).
     - Generates concrete next-step research actions & SDR verification commands.
"""

import argparse
import csv
import json
import math
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "scanner_config.json")
KNOWN_TOWERS_FILE = os.path.join(SCRIPT_DIR, "known_towers.json")
DF_BEARINGS_FILE = os.path.join(SCRIPT_DIR, "df_bearings.json")
DEFAULT_LOG_FILE = os.path.join(SCRIPT_DIR, "penetration_scan_hits.log")


# ==============================================================================
# 1. PERSISTENT USER LOCATION, CALIBRATION & FILTER CONFIGURATION
# ==============================================================================

DEFAULT_CONFIG: Dict[str, Any] = {
    "region": "UK",
    "location_label": "United Kingdom (ITU Region 1)",
    "latitude": None,
    "longitude": None,
    "environment": "suburban",  # outdoor_los (n=2.2), suburban (n=2.8), urban_indoor (n=3.5)
    "lna_gain_db": 16,
    "vga_gain_db": 20,
    "rf_amp": False,
    "antenna_gain_dbi": 2.0,
    "cal_offset_db": 0.0,
    "default_filters": {
        "only_cell": False,
        "only_pulsed": False,
        "exclude_wifi": True,
        "exclude_ism": False,
        "min_db": -50.0,
    },
}

REGION_LABELS: Dict[str, str] = {
    "US": "United States & Canada (FCC / ITU Region 2)",
    "UK": "United Kingdom (Ofcom / ITU Region 1)",
    "EU": "European Union (ETSI / CEPT / ITU Region 1)",
    "AU": "Australia & New Zealand (ACMA / ITU Region 3)",
    "GLOBAL": "Global / Multi-Region Fallback",
}

ENVIRONMENT_EXPONENTS: Dict[str, Tuple[float, str]] = {
    "outdoor_los": (2.2, "Outdoor / Open Line-of-Sight (n=2.2)"),
    "suburban": (2.8, "Suburban / Mixed Outdoor-Indoor (n=2.8)"),
    "urban_indoor": (3.5, "Dense Urban / Indoor Wall Attenuation (n=3.5)"),
}


def infer_region_from_coords(lat: Optional[float], lon: Optional[float]) -> Optional[str]:
    """
    Coarse geographic bounding-box lookup to map GPS lat/lon to a spectrum region.
    """
    if lat is None or lon is None:
        return None
    # United Kingdom & Ireland
    if 49.5 <= lat <= 61.0 and -10.8 <= lon <= 2.2:
        return "UK"
    # North America (US & Canada)
    if 24.0 <= lat <= 72.0 and -168.0 <= lon <= -52.0:
        return "US"
    # Australia & New Zealand
    if -48.0 <= lat <= -10.0 and 112.0 <= lon <= 180.0:
        return "AU"
    # Continental Europe
    if 35.0 <= lat <= 71.5 and -10.0 <= lon <= 40.0:
        return "EU"
    return "GLOBAL"


def load_config() -> Dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                for k, v in saved.items():
                    if k == "default_filters" and isinstance(v, dict):
                        cfg["default_filters"].update(v)
                    else:
                        cfg[k] = v
        except Exception:
            pass
    if cfg.get("region") not in REGION_LABELS:
        cfg["region"] = "UK"
    if not cfg.get("location_label"):
        cfg["location_label"] = REGION_LABELS[cfg["region"]]
    return cfg


def save_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    cfg = load_config()
    for k, v in updates.items():
        if k == "default_filters" and isinstance(v, dict):
            cfg["default_filters"].update(v)
        elif k in ("latitude", "longitude"):
            if v is None or v == "":
                cfg[k] = None
            else:
                try:
                    cfg[k] = float(v)
                except (ValueError, TypeError):
                    pass
        elif k in ("lna_gain_db", "vga_gain_db"):
            try:
                cfg[k] = int(v)
            except (ValueError, TypeError):
                pass
        elif k in ("antenna_gain_dbi", "cal_offset_db"):
            try:
                cfg[k] = float(v)
            except (ValueError, TypeError):
                pass
        elif k == "rf_amp":
            cfg[k] = bool(v)
        else:
            cfg[k] = v

    # Auto-infer region if coordinates were explicitly updated without an explicit region override
    if (
        "latitude" in updates
        and "longitude" in updates
        and "region" not in updates
        and cfg["latitude"] is not None
        and cfg["longitude"] is not None
    ):
        inferred = infer_region_from_coords(cfg["latitude"], cfg["longitude"])
        if inferred:
            cfg["region"] = inferred

    if cfg.get("region") not in REGION_LABELS:
        cfg["region"] = "UK"
    if "location_label" not in updates or not updates.get("location_label"):
        cfg["location_label"] = REGION_LABELS[cfg["region"]]

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return cfg


# ==============================================================================
# 2. REGIONAL CELLULAR & SPECTRUM ALLOCATION DATABASE (3GPP + ITU REGIONS)
# ==============================================================================

# Each cellular band entry:
#   band: 3GPP band name (e.g. "B8 (900 MHz)")
#   direction: "DOWNLINK" | "UPLINK" | "TDD"
#   low_mhz, high_mhz: float
#   tech: str (e.g. "4G LTE / 5G NR / 2G GSM")
#   legacy_2g_sunset: bool (True if 2G GSM has been shut down on major carriers in this region)
#   duplex_mhz: float (DL - UL spacing for FDD, 0 for TDD)
#   std_bw_khz: Tuple[float, float] (min..max typical real base-station BW in kHz)
#   carriers: str
#   earfcn_base: Optional[Tuple[int, float]] -> (N_offs, F_low_mhz) where EARFCN = N_offs + 10*(F - F_low)

REGIONAL_CELLULAR_BANDS: Dict[str, List[Dict[str, Any]]] = {
    "US": [
        {
            "band": "B71 / n71 (600 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 617.0,
            "high_mhz": 652.0,
            "tech": "5G NR / 4G LTE",
            "legacy_2g_sunset": True,
            "duplex_mhz": -46.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "T-Mobile, Dish Wireless, UScellular",
            "earfcn_base": (68586, 617.0),
        },
        {
            "band": "B71 / n71 (600 MHz)",
            "direction": "UPLINK",
            "low_mhz": 663.0,
            "high_mhz": 698.0,
            "tech": "5G NR / 4G LTE Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": -46.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (T-Mobile / Dish)",
            "earfcn_base": (133122, 663.0),
        },
        {
            "band": "B12 / B17 (700 MHz Lower)",
            "direction": "DOWNLINK",
            "low_mhz": 729.0,
            "high_mhz": 746.0,
            "tech": "4G LTE",
            "legacy_2g_sunset": True,
            "duplex_mhz": 30.0,
            "std_bw_khz": (4500.0, 10000.0),
            "carriers": "AT&T, T-Mobile, UScellular",
            "earfcn_base": (5010, 729.0),
        },
        {
            "band": "B13 (700 MHz Upper C)",
            "direction": "DOWNLINK",
            "low_mhz": 746.0,
            "high_mhz": 756.0,
            "tech": "4G LTE",
            "legacy_2g_sunset": True,
            "duplex_mhz": -31.0,
            "std_bw_khz": (4500.0, 10000.0),
            "carriers": "Verizon Wireless",
            "earfcn_base": (5180, 746.0),
        },
        {
            "band": "B14 (700 MHz FirstNet)",
            "direction": "DOWNLINK",
            "low_mhz": 758.0,
            "high_mhz": 768.0,
            "tech": "4G LTE Public Safety",
            "legacy_2g_sunset": True,
            "duplex_mhz": -30.0,
            "std_bw_khz": (4500.0, 10000.0),
            "carriers": "AT&T FirstNet Public Safety",
            "earfcn_base": (5280, 758.0),
        },
        {
            "band": "B12 / B13 / B14 (700 MHz)",
            "direction": "UPLINK",
            "low_mhz": 699.0,
            "high_mhz": 798.0,  # Guard/UL gaps outside DL ranges (checked after DL)
            "tech": "4G LTE Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 30.0,
            "std_bw_khz": (180.0, 10000.0),
            "carriers": "Mobile Devices (AT&T / Verizon / T-Mobile)",
            "earfcn_base": None,
        },
        {
            "band": "B5 / B26 (850 MHz CLR)",
            "direction": "UPLINK",
            "low_mhz": 814.0,
            "high_mhz": 849.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (180.0, 10000.0),
            "carriers": "Mobile Devices (AT&T / Verizon / UScellular)",
            "earfcn_base": (20400, 824.0),
        },
        {
            "band": "B5 / B26 (850 MHz CLR)",
            "direction": "DOWNLINK",
            "low_mhz": 859.0,
            "high_mhz": 894.0,
            "tech": "4G LTE / 5G NR (2G/3G Sunset)",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (1400.0, 15000.0),
            "carriers": "AT&T, Verizon, UScellular, Dish (B26)",
            "earfcn_base": (2400, 869.0),
        },
        {
            "band": "B4 / B66 (AWS-1/3)",
            "direction": "UPLINK",
            "low_mhz": 1710.0,
            "high_mhz": 1780.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 400.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (AT&T / Verizon / T-Mobile / Dish)",
            "earfcn_base": (131972, 1710.0),
        },
        {
            "band": "B2 / B25 (1900 MHz PCS)",
            "direction": "UPLINK",
            "low_mhz": 1850.0,
            "high_mhz": 1915.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 80.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (AT&T / Verizon / T-Mobile)",
            "earfcn_base": (18600, 1850.0),
        },
        {
            "band": "B2 / B25 (1900 MHz PCS)",
            "direction": "DOWNLINK",
            "low_mhz": 1930.0,
            "high_mhz": 1995.0,
            "tech": "4G LTE / 5G NR (T-Mobile Legacy GSM Sunset)",
            "legacy_2g_sunset": True,
            "duplex_mhz": 80.0,
            "std_bw_khz": (1400.0, 20000.0),
            "carriers": "AT&T, Verizon, T-Mobile, Dish",
            "earfcn_base": (600, 1930.0),
        },
        {
            "band": "B4 / B66 (AWS-1/3)",
            "direction": "DOWNLINK",
            "low_mhz": 2110.0,
            "high_mhz": 2200.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": True,
            "duplex_mhz": 400.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "AT&T, Verizon, T-Mobile, Dish",
            "earfcn_base": (66436, 2110.0),
        },
        {
            "band": "B30 (2300 MHz WCS)",
            "direction": "DOWNLINK",
            "low_mhz": 2350.0,
            "high_mhz": 2360.0,
            "tech": "4G LTE",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (4500.0, 10000.0),
            "carriers": "AT&T",
            "earfcn_base": (9770, 2350.0),
        },
        {
            "band": "B41 / n41 (2.5 GHz BRS/EBS)",
            "direction": "TDD",
            "low_mhz": 2496.0,
            "high_mhz": 2690.0,
            "tech": "5G NR / 4G LTE TDD",
            "legacy_2g_sunset": True,
            "duplex_mhz": 0.0,
            "std_bw_khz": (4500.0, 40000.0),
            "carriers": "T-Mobile 5G Ultra Capacity",
            "earfcn_base": (39650, 2496.0),
        },
    ],
    "UK": [
        {
            "band": "B28 / n28 (700 MHz)",
            "direction": "UPLINK",
            "low_mhz": 703.0,
            "high_mhz": 733.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": 55.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (EE / O2 / Vodafone / Three)",
            "earfcn_base": (27210, 703.0),
        },
        {
            "band": "B28 / n28 (700 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 758.0,
            "high_mhz": 788.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": False,
            "duplex_mhz": 55.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "EE, O2 (VMO2), Three, Vodafone",
            "earfcn_base": (9210, 758.0),
        },
        {
            "band": "B20 (800 MHz Digital Dividend)",
            "direction": "DOWNLINK",
            "low_mhz": 791.0,
            "high_mhz": 821.0,
            "tech": "4G LTE",
            "legacy_2g_sunset": False,
            "duplex_mhz": -41.0,
            "std_bw_khz": (4500.0, 15000.0),
            "carriers": "O2 (VMO2), Vodafone, EE, Three",
            "earfcn_base": (6150, 791.0),
        },
        {
            "band": "B20 (800 MHz Digital Dividend)",
            "direction": "UPLINK",
            "low_mhz": 832.0,
            "high_mhz": 862.0,
            "tech": "4G LTE Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": -41.0,
            "std_bw_khz": (180.0, 15000.0),
            "carriers": "Mobile Devices (O2 / Vodafone / EE / Three)",
            "earfcn_base": (24150, 832.0),
        },
        {
            "band": "B8 / E-GSM 900",
            "direction": "UPLINK",
            "low_mhz": 880.0,
            "high_mhz": 915.0,
            "tech": "2G GSM / 4G LTE / NB-IoT Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": 45.0,
            "std_bw_khz": (150.0, 10000.0),
            "carriers": "Mobile Devices & Cellular IoT (O2 / Vodafone)",
            "earfcn_base": (21450, 880.0),
        },
        {
            "band": "B8 / E-GSM 900",
            "direction": "DOWNLINK",
            "low_mhz": 925.0,
            "high_mhz": 960.0,
            "tech": "2G GSM / 4G LTE / NB-IoT Base Station",
            "legacy_2g_sunset": False,
            "duplex_mhz": 45.0,
            "std_bw_khz": (180.0, 10000.0),
            "carriers": "O2 (VMO2), Vodafone UK",
            "earfcn_base": (3450, 925.0),
        },
        {
            "band": "B3 / DCS-1800",
            "direction": "UPLINK",
            "low_mhz": 1710.0,
            "high_mhz": 1785.0,
            "tech": "4G LTE / 2G GSM Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": 95.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (EE / Three / O2 / Vodafone)",
            "earfcn_base": (19200, 1710.0),
        },
        {
            "band": "B3 / DCS-1800",
            "direction": "DOWNLINK",
            "low_mhz": 1805.0,
            "high_mhz": 1880.0,
            "tech": "4G LTE / 5G NR / 2G GSM Base Station",
            "legacy_2g_sunset": False,
            "duplex_mhz": 95.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "EE, Three UK, O2, Vodafone",
            "earfcn_base": (1200, 1805.0),
        },
        {
            "band": "B1 / n1 (2100 MHz)",
            "direction": "UPLINK",
            "low_mhz": 1920.0,
            "high_mhz": 1980.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": 190.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (EE / Three / O2 / Vodafone)",
            "earfcn_base": (18000, 1920.0),
        },
        {
            "band": "B1 / n1 (2100 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 2110.0,
            "high_mhz": 2170.0,
            "tech": "4G LTE / 5G NR Base Station",
            "legacy_2g_sunset": False,
            "duplex_mhz": 190.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "EE, Three UK, O2, Vodafone",
            "earfcn_base": (0, 2110.0),
        },
        {
            "band": "B40 (2300 MHz TDD)",
            "direction": "TDD",
            "low_mhz": 2350.0,
            "high_mhz": 2390.0,
            "tech": "4G LTE TDD",
            "legacy_2g_sunset": False,
            "duplex_mhz": 0.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "O2 (VMO2)",
            "earfcn_base": (38650, 2300.0),
        },
        {
            "band": "B7 (2600 MHz FDD)",
            "direction": "UPLINK",
            "low_mhz": 2500.0,
            "high_mhz": 2570.0,
            "tech": "4G LTE Handset Uplink",
            "legacy_2g_sunset": False,
            "duplex_mhz": 120.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (EE / Vodafone)",
            "earfcn_base": (20750, 2500.0),
        },
        {
            "band": "B38 (2600 MHz TDD)",
            "direction": "TDD",
            "low_mhz": 2570.0,
            "high_mhz": 2620.0,
            "tech": "4G LTE TDD",
            "legacy_2g_sunset": False,
            "duplex_mhz": 0.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Vodafone UK / EE",
            "earfcn_base": (37750, 2570.0),
        },
        {
            "band": "B7 (2600 MHz FDD)",
            "direction": "DOWNLINK",
            "low_mhz": 2620.0,
            "high_mhz": 2690.0,
            "tech": "4G LTE Base Station",
            "legacy_2g_sunset": False,
            "duplex_mhz": 120.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "EE, Vodafone UK",
            "earfcn_base": (2750, 2620.0),
        },
    ],
    "AU": [
        {
            "band": "B28 / n28 (700 MHz APT)",
            "direction": "UPLINK",
            "low_mhz": 703.0,
            "high_mhz": 748.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 55.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (Telstra / Optus / Vodafone)",
            "earfcn_base": (27210, 703.0),
        },
        {
            "band": "B28 / n28 (700 MHz APT)",
            "direction": "DOWNLINK",
            "low_mhz": 758.0,
            "high_mhz": 803.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": True,
            "duplex_mhz": 55.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Telstra, Optus, Vodafone AU",
            "earfcn_base": (9210, 758.0),
        },
        {
            "band": "B5 / B26 (850 MHz)",
            "direction": "UPLINK",
            "low_mhz": 825.0,
            "high_mhz": 845.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (180.0, 15000.0),
            "carriers": "Mobile Devices (Telstra / Vodafone)",
            "earfcn_base": (20400, 824.0),
        },
        {
            "band": "B5 / B26 (850 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 870.0,
            "high_mhz": 890.0,
            "tech": "4G LTE / 5G NR (2G/3G Sunset)",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (4500.0, 15000.0),
            "carriers": "Telstra, Vodafone AU",
            "earfcn_base": (2400, 869.0),
        },
        {
            "band": "B8 (900 MHz)",
            "direction": "UPLINK",
            "low_mhz": 890.0,
            "high_mhz": 915.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (180.0, 10000.0),
            "carriers": "Mobile Devices (Optus / Telstra)",
            "earfcn_base": (21450, 880.0),
        },
        {
            "band": "B8 (900 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 935.0,
            "high_mhz": 960.0,
            "tech": "4G LTE / 5G NR (2G/3G Sunset)",
            "legacy_2g_sunset": True,
            "duplex_mhz": 45.0,
            "std_bw_khz": (4500.0, 10000.0),
            "carriers": "Optus, Telstra, Vodafone AU",
            "earfcn_base": (3450, 925.0),
        },
        {
            "band": "B3 (1800 MHz)",
            "direction": "UPLINK",
            "low_mhz": 1710.0,
            "high_mhz": 1785.0,
            "tech": "4G LTE / 5G NR Handset Uplink",
            "legacy_2g_sunset": True,
            "duplex_mhz": 95.0,
            "std_bw_khz": (180.0, 20000.0),
            "carriers": "Mobile Devices (Telstra / Optus / Vodafone)",
            "earfcn_base": (19200, 1710.0),
        },
        {
            "band": "B3 (1800 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 1805.0,
            "high_mhz": 1880.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": True,
            "duplex_mhz": 95.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Telstra, Optus, Vodafone AU",
            "earfcn_base": (1200, 1805.0),
        },
        {
            "band": "B1 (2100 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 2110.0,
            "high_mhz": 2170.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": True,
            "duplex_mhz": 190.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Telstra, Optus, Vodafone AU",
            "earfcn_base": (0, 2110.0),
        },
        {
            "band": "B40 (2300 MHz TDD)",
            "direction": "TDD",
            "low_mhz": 2302.0,
            "high_mhz": 2400.0,
            "tech": "4G LTE / 5G NR TDD",
            "legacy_2g_sunset": True,
            "duplex_mhz": 0.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Optus, NBN Fixed Wireless",
            "earfcn_base": (38650, 2300.0),
        },
        {
            "band": "B7 (2600 MHz)",
            "direction": "DOWNLINK",
            "low_mhz": 2620.0,
            "high_mhz": 2690.0,
            "tech": "4G LTE / 5G NR",
            "legacy_2g_sunset": True,
            "duplex_mhz": 120.0,
            "std_bw_khz": (4500.0, 20000.0),
            "carriers": "Telstra, Optus",
            "earfcn_base": (2750, 2620.0),
        },
    ],
}
# EU shares the same ITU Region 1 3GPP band plan as UK with EU carrier labels
REGIONAL_CELLULAR_BANDS["EU"] = [
    dict(b, carriers=b["carriers"].replace("EE, O2 (VMO2), Three, Vodafone", "European MNOs (Vodafone / Orange / DT / Telefonica)")
         .replace("O2 (VMO2), Vodafone, EE, Three", "European MNOs (Vodafone / Orange / DT / Telefonica)")
         .replace("O2 (VMO2), Vodafone UK", "European MNOs (B8 900 MHz Carriers)")
         .replace("EE, Three UK, O2, Vodafone", "European MNOs (B3/B1 Carriers)")
         .replace("O2 (VMO2)", "European MNOs (B40 TDD)")
         .replace("EE, Vodafone UK", "European MNOs (B7 2600 MHz)"))
    for b in REGIONAL_CELLULAR_BANDS["UK"]
]
REGIONAL_CELLULAR_BANDS["GLOBAL"] = REGIONAL_CELLULAR_BANDS["UK"] + [
    b for b in REGIONAL_CELLULAR_BANDS["US"]
    if b["band"] in ("B71 / n71 (600 MHz)", "B5 / B26 (850 MHz CLR)", "B2 / B25 (1900 MHz PCS)")
]

# Regional Unlicensed ISM / SRD / DECT Bands (used to verify whether a frequency BELONGS in your region!)
REGIONAL_ISM_BANDS: Dict[str, List[Tuple[float, float, str]]] = {
    "US": [
        (6.765, 6.795, "6.78 MHz ISM"),
        (13.553, 13.567, "13.56 MHz ISM (NFC/RFID)"),
        (26.957, 27.283, "27.12 MHz ISM / CB"),
        (433.050, 434.790, "433 MHz FCC Part 15.231 / Amateur"),
        (902.000, 928.000, "US 902-928 MHz ISM (LoRa US915 / Z-Wave 908.42 / Smart Meters)"),
        (1920.000, 1930.000, "US DECT 6.0 (UPCS Cordless Phone)"),
        (2400.000, 2483.500, "2.4 GHz ISM (Wi-Fi / BLE / Zigbee / Thread)"),
    ],
    "UK": [
        (6.765, 6.795, "6.78 MHz ISM"),
        (13.553, 13.567, "13.56 MHz ISM (NFC/RFID)"),
        (26.957, 27.283, "27.12 MHz ISM / CB"),
        (433.050, 434.790, "433 MHz UK/EU LPD433 ISM"),
        (446.000, 446.200, "PMR446 License-Free Radio"),
        (863.000, 870.000, "UK/EU 863-870 MHz SRD/ISM (LoRa EU868 / Z-Wave 868.42 / Smart Meters)"),
        (870.000, 876.000, "UK/EU 870-876 MHz SRD / Smart Grid Telemetry"),
        (1880.000, 1900.000, "UK/EU DECT 1.88-1.90 GHz Cordless / Intercom"),
        (2400.000, 2483.500, "2.4 GHz ISM (Wi-Fi / BLE / Zigbee / Thread)"),
    ],
    "EU": [
        (6.765, 6.795, "6.78 MHz ISM"),
        (13.553, 13.567, "13.56 MHz ISM (NFC/RFID)"),
        (26.957, 27.283, "27.12 MHz ISM / CB"),
        (433.050, 434.790, "433 MHz EU LPD433 ISM"),
        (446.000, 446.200, "PMR446 License-Free Radio"),
        (863.000, 870.000, "EU 863-870 MHz SRD/ISM (LoRa EU868 / Z-Wave 868.42 / Smart Meters)"),
        (870.000, 876.000, "EU 870-876 MHz SRD / Smart Grid"),
        (1880.000, 1900.000, "EU DECT 1.88-1.90 GHz Cordless / Intercom"),
        (2400.000, 2483.500, "2.4 GHz ISM (Wi-Fi / BLE / Zigbee / Thread)"),
    ],
    "AU": [
        (6.765, 6.795, "6.78 MHz ISM"),
        (13.553, 13.567, "13.56 MHz ISM (NFC/RFID)"),
        (26.957, 27.283, "27.12 MHz ISM"),
        (433.050, 434.790, "433 MHz AU LIPD ISM"),
        (915.000, 928.000, "AU 915-928 MHz ISM (LoRa AU915 / Z-Wave 921.4 / Mesh)"),
        (1880.000, 1900.000, "AU DECT 1.88-1.90 GHz Cordless / Intercom"),
        (2400.000, 2483.500, "2.4 GHz ISM (Wi-Fi / BLE / Zigbee / Thread)"),
    ],
    "GLOBAL": [
        (6.765, 6.795, "6.78 MHz ISM"),
        (13.553, 13.567, "13.56 MHz ISM"),
        (26.957, 27.283, "27.12 MHz ISM"),
        (433.050, 434.790, "433 MHz ISM"),
        (863.000, 870.000, "EU868 SRD/ISM"),
        (902.000, 928.000, "US/AU 915 ISM"),
        (1880.000, 1900.000, "DECT"),
        (2400.000, 2483.500, "2.4 GHz ISM"),
    ],
}

# Strictly Protected / Safety-of-Life Bands (worldwide)
PROTECTED_BANDS: List[Tuple[float, float, str, str]] = [
    (401.000, 406.000, "MedRadio / MICS Medical Implants", "Reserved strictly for cardiac pacemakers, ICDs & body telemetry."),
    (406.000, 406.100, "COSPAS-SARSAT Emergency Distress", "Protected international satellite search & rescue beacon band."),
    (1029.000, 1031.000, "1030 MHz Aviation SSR / TCAS Radar", "Protected aviation transponder interrogation band."),
    (1089.000, 1091.000, "1090 MHz ADS-B / Mode-S Aviation", "Protected aircraft transponder reply band."),
    (1164.000, 1300.000, "GNSS L5/L2 & Aviation DME (1164-1300 MHz)", "Protected satellite navigation (GPS L2 1227.6 MHz) & aviation DME."),
    (1559.000, 1610.000, "GNSS L1 / Galileo E1 / GLONASS (1559-1610 MHz)", "Protected GPS L1 (1575.42 MHz). Real GPS is below noise floor; strong signals indicate jammer/spoofer/interference!"),
    (2700.000, 3000.000, "S-Band Aviation & Weather Radar", "Protected radiolocation radar spectrum."),
]

# Foreign/Wrong-Region signature traps (explicitly catch cross-region anomalies)
FOREIGN_BAND_TRAPS: Dict[str, List[Tuple[float, float, str]]] = {
    "US": [
        (863.0, 868.99, "EU868 / UK SRD Band (Not unlicensed in US — overlaps US Public Safety / 850 MHz boundary)"),
        (928.1, 960.0, "EU/UK/AU GSM-900 / LTE B8 Downlink (925-960 MHz is NOT a US cellular band; US uses 928-960 for fixed utility/STL/paging)"),
        (1805.0, 1849.9, "EU/UK DCS-1800 / LTE B3 Downlink (Not a US cellular band — US PCS starts at 1850 MHz)"),
        (1880.0, 1900.0, "EU DECT 1.88-1.90 GHz (Overlaps US PCS Band 2 Uplink 1850-1910 MHz!)"),
    ],
    "UK": [
        (617.0, 652.0, "US 600 MHz Band 71 Cellular (In UK this is UHF TV Broadcast, NOT cellular)"),
        (869.0, 869.4, "US Band 5 Cellular edge / UK SRD sub-band"),
        (902.0, 915.0, "US 915 MHz ISM Device Operating Inside UK/EU Licensed E-GSM 900 / B8 Uplink!"),
        (915.0, 925.0, "US/AU 915 MHz ISM Operating in UK GSM-R Railway / RFID Band (915-925 MHz)!"),
        (1930.0, 1980.0, "US PCS Band 2 Downlink (In UK/EU 1920-1980 MHz is LTE Band 1 UPLINK, not downlink!)"),
    ],
    "EU": [
        (617.0, 652.0, "US 600 MHz Band 71 Cellular (In EU this is UHF Broadcast TV, NOT cellular)"),
        (902.0, 915.0, "US 915 MHz ISM Device Operating Inside EU Licensed E-GSM 900 / B8 Uplink!"),
        (915.0, 925.0, "US/AU 915 MHz ISM Operating in EU GSM-R Railway / RFID Band!"),
        (1930.0, 1980.0, "US PCS Band 2 Downlink (In EU 1920-1980 MHz is LTE Band 1 UPLINK, not downlink!)"),
    ],
    "AU": [
        (791.0, 821.0, "EU Band 20 Downlink (In AU 803-825 MHz is outside B28 DL)"),
        (863.0, 869.9, "EU868 SRD Band (Not AU ISM — AU ISM is 915-928 MHz)"),
        (1930.0, 1980.0, "US PCS Band 2 Downlink (In AU 1920-1980 MHz is Band 1 UPLINK)"),
    ],
}


def get_cell_sweep_ranges(region: str = "UK", include_uplinks: bool = True) -> str:
    """
    Build an optimized comma-separated `hackrf_sweep -f` range list covering ONLY
    the real cellular bands for the user's selected region.
    """
    bands = REGIONAL_CELLULAR_BANDS.get(region, REGIONAL_CELLULAR_BANDS["UK"])
    raw_ranges: List[Tuple[int, int]] = []
    for b in bands:
        if not include_uplinks and b["direction"] == "UPLINK":
            continue
        lo = max(1, int(math.floor(b["low_mhz"])))
        hi = min(3000, int(math.ceil(b["high_mhz"])))
        raw_ranges.append((lo, hi))

    raw_ranges.sort(key=lambda x: x[0])
    merged: List[Tuple[int, int]] = []
    for lo, hi in raw_ranges:
        if not merged:
            merged.append((lo, hi))
        else:
            plo, phi = merged[-1]
            if lo <= phi + 4:
                merged[-1] = (plo, max(phi, hi))
            else:
                merged.append((lo, hi))
    return ",".join(f"{lo}:{hi}" for lo, hi in merged)


def match_cellular_band(freq_mhz: float, region: str = "UK") -> Optional[Dict[str, Any]]:
    """
    Match a frequency against the region's licensed 3GPP cellular bands.
    Prefers exact Downlink/TDD bands before broad uplink ranges.
    """
    bands = REGIONAL_CELLULAR_BANDS.get(region, REGIONAL_CELLULAR_BANDS["UK"])
    # First check Downlink and TDD (exact base station bands)
    for b in bands:
        if b["direction"] in ("DOWNLINK", "TDD") and b["low_mhz"] <= freq_mhz <= b["high_mhz"]:
            return b
    # Then check Uplink
    for b in bands:
        if b["direction"] == "UPLINK" and b["low_mhz"] <= freq_mhz <= b["high_mhz"]:
            return b
    return None


def match_foreign_cellular_band(freq_mhz: float, user_region: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Check if a frequency belongs to a DIFFERENT region's cellular downlink plan
    (e.g., an EU GSM-900 / B8 downlink running in the US, or a US PCS downlink running in UK/EU),
    EXCLUDING frequencies that are already legal local ISM / SRD / DECT bands in `user_region`
    (for example, 863-876 MHz is legal UK/EU SRD/ISM, NOT a rogue US Band 5 tower!).
    """
    if is_in_regional_ism(freq_mhz, user_region) is not None:
        return None
    for other_reg in ("US", "UK", "AU"):
        if other_reg == user_region or (user_region == "EU" and other_reg == "UK"):
            continue
        for b in REGIONAL_CELLULAR_BANDS.get(other_reg, []):
            if b["direction"] in ("DOWNLINK", "TDD") and b["low_mhz"] <= freq_mhz <= b["high_mhz"]:
                return (other_reg, b)
    return None


def compute_earfcn_arfcn(freq_mhz: float, band_info: Dict[str, Any]) -> str:
    """
    Compute approximate 3GPP EARFCN (and GSM ARFCN where applicable).
    """
    parts: List[str] = []
    eb = band_info.get("earfcn_base")
    if eb is not None:
        n_offs, f_low = eb
        if freq_mhz >= f_low:
            earfcn = int(round(n_offs + 10.0 * (freq_mhz - f_low)))
            parts.append(f"EARFCN ~{earfcn}")
    # GSM ARFCN calculations for 900 MHz (B8) and 1800 MHz (B3)
    if 935.0 <= freq_mhz <= 960.0:
        arfcn = int(round((freq_mhz - 935.0) / 0.2))
        parts.append(f"GSM-900 ARFCN {arfcn}")
    elif 925.0 <= freq_mhz < 935.0:
        arfcn = int(round(1024 + (freq_mhz - 935.0) / 0.2))
        parts.append(f"E-GSM ARFCN {arfcn}")
    elif 890.0 <= freq_mhz <= 915.0:
        arfcn = int(round((freq_mhz - 890.0) / 0.2))
        parts.append(f"GSM-900 UL ARFCN {arfcn}")
    elif 880.0 <= freq_mhz < 890.0:
        arfcn = int(round(1024 + (freq_mhz - 890.0) / 0.2))
        parts.append(f"E-GSM UL ARFCN {arfcn}")
    elif 1805.2 <= freq_mhz <= 1879.8:
        arfcn = int(round(512 + (freq_mhz - 1805.2) / 0.2))
        parts.append(f"DCS-1800 ARFCN {arfcn}")
    elif 869.0 <= freq_mhz <= 894.0:
        arfcn = int(round(128 + (freq_mhz - 869.2) / 0.2))
        if 128 <= arfcn <= 251:
            parts.append(f"GSM-850 ARFCN {arfcn}")
    return " / ".join(parts) if parts else "N/A"


def is_in_regional_ism(freq_mhz: float, region: str = "UK") -> Optional[str]:
    for lo, hi, label in REGIONAL_ISM_BANDS.get(region, REGIONAL_ISM_BANDS["GLOBAL"]):
        if lo <= freq_mhz <= hi:
            return label
    return None


def is_in_protected_band(freq_mhz: float) -> Optional[Tuple[str, str]]:
    for lo, hi, name, desc in PROTECTED_BANDS:
        if lo <= freq_mhz <= hi:
            return (name, desc)
    return None


# ==============================================================================
# 3. CALIBRATED dB-TO-DISTANCE ESTIMATOR (FSPL + LOG-DISTANCE PATH LOSS)
# ==============================================================================


def format_distance_m(dist_m: float) -> str:
    if dist_m < 1.0:
        return "<1 m"
    if dist_m < 1000.0:
        return f"{dist_m:.0f} m"
    if dist_m < 10000.0:
        return f"{dist_m / 1000.0:.2f} km"
    return f"{dist_m / 1000.0:.1f} km"


def hackrf_db_to_rx_dbm(
    sweep_db: float,
    lna_gain_db: int = 16,
    vga_gain_db: int = 20,
    rf_amp: bool = False,
    cal_offset_db: float = 0.0,
) -> float:
    """
    Convert `hackrf_sweep` relative FFT bin power (dB / dBFS) into approximate
    antenna-port received power P_rx (dBm).

    Empirical HackRF One calibration baseline:
      At LNA=16 dB, VGA=20 dB, AMP=0, a 0 dBFS reading corresponds roughly to
      -26 dBm at the SMA port (full-scale front-end compression around -20 to -26 dBm
      for total IF+BB gain 36 dB). Higher gain lowers the full-scale input dBm 1:1.
    """
    amp_gain = 14.0 if rf_amp else 0.0
    total_gain_db = float(lna_gain_db) + float(vga_gain_db) + amp_gain
    # Reference full-scale input at 0 dB gain is ~ +10 dBm (conservative HackRF max input)
    full_scale_dbm = 10.0 - total_gain_db
    return round(sweep_db + full_scale_dbm + float(cal_offset_db), 2)


def _solve_log_distance_m(
    freq_mhz: float,
    rx_dbm: float,
    tx_eirp_dbm: float,
    rx_antenna_gain_dbi: float,
    path_loss_exp: float,
) -> float:
    """
    Log-Distance Path Loss Model:
      PL(d) = FSPL(1m) + 10 * n * log10(d)
      FSPL(1m) = 20 * log10(freq_MHz) - 27.55
      PL_measured = tx_eirp_dbm + rx_antenna_gain_dbi - rx_dbm
      d = 10 ^ ((PL_measured - FSPL(1m)) / (10 * n))
    """
    f_clamped = max(1.0, float(freq_mhz))
    fspl_1m = 20.0 * math.log10(f_clamped) - 27.55
    path_loss_db = (tx_eirp_dbm + rx_antenna_gain_dbi) - rx_dbm
    exponent = (path_loss_db - fspl_1m) / (10.0 * max(1.8, path_loss_exp))
    # Clamp distance between 1 meter and 50 km for numerical sanity
    exponent = max(0.0, min(4.7, exponent))
    return 10.0 ** exponent


def estimate_distance_from_db(
    freq_mhz: float,
    peak_db: float,
    config: Optional[Dict[str, Any]] = None,
    signal_kind: str = "auto",
) -> Dict[str, Any]:
    """
    Compute estimated transmitter distance based on measured HackRF dB power,
    frequency, gain calibration, and environment path-loss exponent.

    Returns distance ranges for three transmitter power classes so operators can
    immediately compare "How far if it's a Real Macro Cell Tower?" vs
    "How close if it's a Portable Fake Tower / Stingray / Handset?".
    """
    cfg = config or load_config()
    env_key = cfg.get("environment", "suburban")
    n_exp, env_label = ENVIRONMENT_EXPONENTS.get(env_key, ENVIRONMENT_EXPONENTS["suburban"])

    rx_dbm = hackrf_db_to_rx_dbm(
        sweep_db=peak_db,
        lna_gain_db=int(cfg.get("lna_gain_db", 16)),
        vga_gain_db=int(cfg.get("vga_gain_db", 20)),
        rf_amp=bool(cfg.get("rf_amp", False)),
        cal_offset_db=float(cfg.get("cal_offset_db", 0.0)),
    )
    ant_gain = float(cfg.get("antenna_gain_dbi", 2.0))

    # Macro Cell Tower (~55-62 dBm EIRP -> center 58 dBm)
    macro_mid = _solve_log_distance_m(freq_mhz, rx_dbm, 58.0, ant_gain, n_exp)
    macro_min = _solve_log_distance_m(freq_mhz, rx_dbm + 4.0, 54.0, ant_gain, n_exp + 0.25)
    macro_max = _solve_log_distance_m(freq_mhz, rx_dbm - 4.0, 62.0, ant_gain, max(2.0, n_exp - 0.25))

    # Portable / Fake Cell Tower / Femtocell / Stingray (~23-33 dBm EIRP -> center 28 dBm)
    port_mid = _solve_log_distance_m(freq_mhz, rx_dbm, 28.0, ant_gain, n_exp)
    port_min = _solve_log_distance_m(freq_mhz, rx_dbm + 4.0, 23.0, ant_gain, n_exp + 0.25)
    port_max = _solve_log_distance_m(freq_mhz, rx_dbm - 4.0, 33.0, ant_gain, max(2.0, n_exp - 0.25))

    # Low-Power Handset / Pulsed IoT / Mesh / Sensor (~14-23 dBm EIRP -> center 18 dBm)
    low_mid = _solve_log_distance_m(freq_mhz, rx_dbm, 18.0, ant_gain, n_exp)
    low_min = _solve_log_distance_m(freq_mhz, rx_dbm + 4.0, 12.0, ant_gain, n_exp + 0.25)
    low_max = _solve_log_distance_m(freq_mhz, rx_dbm - 4.0, 23.0, ant_gain, max(2.0, n_exp - 0.25))

    if signal_kind == "macro_cell":
        primary_m = macro_mid
        primary_range = f"{format_distance_m(macro_min)} – {format_distance_m(macro_max)}"
        primary_model = "Macro Cell Tower (~58 dBm EIRP)"
    elif signal_kind == "portable_cell":
        primary_m = port_mid
        primary_range = f"{format_distance_m(port_min)} – {format_distance_m(port_max)}"
        primary_model = "Portable BTS / Small Cell (~28 dBm EIRP)"
    else:
        primary_m = low_mid
        primary_range = f"{format_distance_m(low_min)} – {format_distance_m(low_max)}"
        primary_model = "Handset / IoT / Pulsed TX (~18 dBm EIRP)"

    if primary_m <= 30.0:
        prox_zone = "IMMEDIATE (<30 m)"
    elif primary_m <= 150.0:
        prox_zone = "VERY CLOSE (30–150 m)"
    elif primary_m <= 600.0:
        prox_zone = "NEAR (150–600 m)"
    elif primary_m <= 2500.0:
        prox_zone = "LOCAL (0.6–2.5 km)"
    else:
        prox_zone = "DISTANT (>2.5 km)"

    return {
        "est_rx_dbm": rx_dbm,
        "environment": env_key,
        "environment_label": env_label,
        "path_loss_exp": n_exp,
        "primary_dist_m": round(primary_m, 1),
        "primary_dist_str": format_distance_m(primary_m),
        "primary_range_str": primary_range,
        "primary_model": primary_model,
        "proximity_zone": prox_zone,
        "macro_tower_m": round(macro_mid, 1),
        "macro_tower_str": f"~{format_distance_m(macro_mid)} ({format_distance_m(macro_min)}–{format_distance_m(macro_max)})",
        "portable_bts_m": round(port_mid, 1),
        "portable_bts_str": f"~{format_distance_m(port_mid)} ({format_distance_m(port_min)}–{format_distance_m(port_max)})",
        "low_power_tx_m": round(low_mid, 1),
        "low_power_tx_str": f"~{format_distance_m(low_mid)} ({format_distance_m(low_min)}–{format_distance_m(low_max)})",
    }


# ==============================================================================
# 4. GEODESY & KNOWN REAL CELL TOWER CROSS-REFERENCE (OpenCelliD / Manual)
# ==============================================================================


def deg_to_cardinal(deg: float) -> str:
    dirs = [
        "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
        "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW",
    ]
    idx = int(round((deg % 360.0) / 22.5)) % 16
    return dirs[idx]


def haversine_and_bearing(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> Tuple[float, float, str]:
    """
    Compute Great-Circle distance (meters) and initial compass bearing (0-359.9 deg + cardinal)
    from (lat1, lon1) to (lat2, lon2).
    """
    r_earth = 6371000.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)

    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    dist_m = 2.0 * r_earth * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))

    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    bearing_deg = (math.degrees(math.atan2(y, x)) + 360.0) % 360.0
    return (round(dist_m, 1), round(bearing_deg, 1), deg_to_cardinal(bearing_deg))


def load_known_towers() -> List[Dict[str, Any]]:
    if not os.path.exists(KNOWN_TOWERS_FILE):
        return []
    try:
        with open(KNOWN_TOWERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_known_towers(towers: List[Dict[str, Any]]) -> None:
    with open(KNOWN_TOWERS_FILE, "w", encoding="utf-8") as f:
        json.dump(towers, f, indent=2)


def add_known_tower(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    towers = load_known_towers()
    cleaned = {
        "label": str(entry.get("label", "Known Tower")).strip() or "Known Tower",
        "carrier": str(entry.get("carrier", "Unknown")).strip() or "Unknown",
        "radio": str(entry.get("radio", "LTE")).strip().upper(),
        "band": str(entry.get("band", "")).strip(),
        "freq_mhz": float(entry["freq_mhz"]) if entry.get("freq_mhz") not in (None, "") else None,
        "cell_id": str(entry.get("cell_id", "")).strip(),
        "lat": float(entry["lat"]),
        "lon": float(entry["lon"]),
        "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    towers.append(cleaned)
    save_known_towers(towers)
    return towers


def import_opencellid_csv_text(
    csv_text: str,
    user_lat: Optional[float] = None,
    user_lon: Optional[float] = None,
    max_radius_km: float = 15.0,
) -> Dict[str, Any]:
    """
    Import towers from an OpenCelliD / Mozilla Location Service / Custom CSV snippet.
    Supports either:
      - OpenCelliD columns: radio,mcc,net,area,cell,unit,lon,lat,range,...
      - Custom CSV with headers: label,carrier,radio,band,freq_mhz,lat,lon,cell_id
    """
    towers = load_known_towers()
    added = 0
    skipped = 0
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    if not lines:
        return {"added": 0, "skipped": 0, "total": len(towers)}

    first_lower = lines[0].lower()
    has_header = any(k in first_lower for k in ("lat", "lon", "radio", "mcc", "carrier"))

    if has_header:
        reader = csv.DictReader(lines)
        for row in reader:
            row_l = {str(k).strip().lower(): (str(v).strip() if v is not None else "") for k, v in row.items()}
            try:
                lat = float(row_l.get("lat") or row_l.get("latitude"))
                lon = float(row_l.get("lon") or row_l.get("lng") or row_l.get("longitude"))
            except (ValueError, TypeError):
                skipped += 1
                continue
            if user_lat is not None and user_lon is not None:
                d_m, _, _ = haversine_and_bearing(user_lat, user_lon, lat, lon)
                if d_m > max_radius_km * 1000.0:
                    skipped += 1
                    continue
            freq_val = None
            if row_l.get("freq_mhz"):
                try:
                    freq_val = float(row_l["freq_mhz"])
                except ValueError:
                    pass
            mcc = row_l.get("mcc", "")
            mnc = row_l.get("net") or row_l.get("mnc", "")
            cid = row_l.get("cell") or row_l.get("cell_id", "")
            radio = (row_l.get("radio") or "LTE").upper()
            carrier = row_l.get("carrier") or (f"MCC {mcc} / MNC {mnc}" if mcc else "Registered MNO")
            label = row_l.get("label") or f"{radio} Cell {cid or 'Tower'}"
            towers.append(
                {
                    "label": label,
                    "carrier": carrier,
                    "radio": radio,
                    "band": row_l.get("band", ""),
                    "freq_mhz": freq_val,
                    "cell_id": cid,
                    "lat": lat,
                    "lon": lon,
                    "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            added += 1
    else:
        # Raw OpenCelliD headerless format: radio,mcc,net,area,cell,unit,lon,lat,range,...
        for row in csv.reader(lines):
            if len(row) < 8:
                skipped += 1
                continue
            try:
                radio = row[0].strip().upper()
                mcc = row[1].strip()
                mnc = row[2].strip()
                cid = row[4].strip()
                lon = float(row[6].strip())
                lat = float(row[7].strip())
            except (ValueError, IndexError):
                skipped += 1
                continue
            if user_lat is not None and user_lon is not None:
                d_m, _, _ = haversine_and_bearing(user_lat, user_lon, lat, lon)
                if d_m > max_radius_km * 1000.0:
                    skipped += 1
                    continue
            towers.append(
                {
                    "label": f"{radio} Cell {cid}",
                    "carrier": f"MCC {mcc} / MNC {mnc}",
                    "radio": radio,
                    "band": "",
                    "freq_mhz": None,
                    "cell_id": cid,
                    "lat": lat,
                    "lon": lon,
                    "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            added += 1

    # Cap stored towers to 500 closest to keep JSON lightweight
    if user_lat is not None and user_lon is not None and len(towers) > 500:
        towers.sort(key=lambda t: haversine_and_bearing(user_lat, user_lon, t["lat"], t["lon"])[0])
        towers = towers[:500]
    save_known_towers(towers)
    return {"added": added, "skipped": skipped, "total": len(towers)}


def load_df_bearings() -> Dict[str, Any]:
    if not os.path.exists(DF_BEARINGS_FILE):
        return {}
    try:
        with open(DF_BEARINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def find_measured_bearing(freq_mhz: float, bearings_db: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    best = None
    best_diff = 1.0  # Match within +/- 1.0 MHz
    for _, entry in bearings_db.items():
        try:
            f_b = float(entry.get("freq_mhz", -999.0))
        except (TypeError, ValueError):
            continue
        diff = abs(f_b - freq_mhz)
        if diff <= best_diff and entry.get("summary") and entry["summary"].get("sample_count", 0) > 0:
            best_diff = diff
            best = entry["summary"]
    return best


def find_nearest_known_tower(
    freq_mhz: float,
    band_name: str,
    known_towers: List[Dict[str, Any]],
    user_lat: Optional[float],
    user_lon: Optional[float],
) -> Optional[Dict[str, Any]]:
    if not known_towers or user_lat is None or user_lon is None:
        return None
    candidates: List[Tuple[float, Dict[str, Any]]] = []
    for t in known_towers:
        d_m, az, card = haversine_and_bearing(user_lat, user_lon, t["lat"], t["lon"])
        freq_match = t.get("freq_mhz") is not None and abs(float(t["freq_mhz"]) - freq_mhz) <= 5.0
        band_match = bool(t.get("band")) and t["band"].lower() in band_name.lower()
        score_penalty = 0.0 if freq_match else (500.0 if band_match else 2000.0)
        candidates.append(
            (
                d_m + score_penalty,
                {
                    "label": t["label"],
                    "carrier": t["carrier"],
                    "radio": t["radio"],
                    "cell_id": t.get("cell_id", ""),
                    "distance_m": d_m,
                    "distance_str": format_distance_m(d_m),
                    "bearing_deg": az,
                    "cardinal": card,
                    "exact_freq_match": freq_match,
                },
            )
        )
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0])
    best = candidates[0][1]
    if best["distance_m"] <= 15000.0:
        return best
    return None


# ==============================================================================
# 5. LOCATION BELONGING EVALUATOR (WHAT BELONGS VS. WHAT DOESN'T)
# ==============================================================================


def evaluate_location_belonging(
    freq_mhz: float,
    region: str,
    est_bw_khz: float = 50.0,
    occupancy_pct: float = 0.0,
    burst_count: int = 1,
) -> Dict[str, Any]:
    """
    Determine whether a detected frequency BELONGS at the user's location/region
    or DOES NOT BELONG (wrong-region frequency, restricted band intrusion, or
    unauthorized continuous carrier).
    """
    # 1. Protected safety-of-life / GNSS / Aviation / MedRadio bands
    prot = is_in_protected_band(freq_mhz)
    if prot is not None:
        p_name, p_desc = prot
        # Real ADS-B (1090), SSR (1030), and S-band Radar (2700-3000) are normal if pulsed
        if (1029.0 <= freq_mhz <= 1091.0 or 2700.0 <= freq_mhz <= 3000.0) and occupancy_pct < 30.0:
            return {
                "status": "BELONGS",
                "badge": "PROTECTED PULSED (EXPECTED)",
                "local_allocation": p_name,
                "reason": f"Expected pulsed aviation/radar transponder inside {p_name}. {p_desc}",
            }
        return {
            "status": "DOES_NOT_BELONG",
            "badge": "PROTECTED BAND ALERT",
            "local_allocation": p_name,
            "reason": f"Signal detected inside restricted {p_name}! {p_desc}",
        }

    # 2. Check regional cellular bands first
    cell = match_cellular_band(freq_mhz, region)
    if cell is not None:
        if cell["direction"] in ("DOWNLINK", "TDD"):
            return {
                "status": "BELONGS",
                "badge": f"REGIONAL CELL {cell['direction']}",
                "local_allocation": f"{cell['band']} {cell['direction']} ({cell['carriers']})",
                "reason": f"Valid {region} licensed cellular base station band ({cell['tech']}).",
            }
        else:
            # Uplink band!
            # Check if a foreign ISM trap overlaps this uplink band (e.g. US 915 MHz ISM in UK 880-915 UL)
            for t_lo, t_hi, t_desc in FOREIGN_BAND_TRAPS.get(region, []):
                if t_lo <= freq_mhz <= t_hi and occupancy_pct >= 35.0:
                    return {
                        "status": "DOES_NOT_BELONG",
                        "badge": "WRONG-REGION / UPLINK VIOLATION",
                        "local_allocation": f"{cell['band']} UPLINK (Trap: {t_desc})",
                        "reason": f"Persistent transmission in {region} Cellular Uplink — {t_desc}",
                    }
            if occupancy_pct >= 50.0 and burst_count >= 8:
                return {
                    "status": "DOES_NOT_BELONG",
                    "badge": "ABNORMAL CONTINUOUS UPLINK",
                    "local_allocation": f"{cell['band']} UPLINK ({cell['carriers']})",
                    "reason": f"{freq_mhz:.3f} MHz is a {region} mobile UPLINK band; continuous 24/7 tower-like carriers do NOT belong here (possible rogue BTS, repeater, or jammer).",
                }
            return {
                "status": "BELONGS",
                "badge": "REGIONAL CELL UPLINK",
                "local_allocation": f"{cell['band']} UPLINK ({cell['carriers']})",
                "reason": f"Valid {region} mobile handset/IoT uplink band — intermittent bursts indicate a nearby phone, cellular alarm, or smart meter talking to a tower.",
            }

    # 3. Check Regional Unlicensed ISM / SRD / DECT
    ism = is_in_regional_ism(freq_mhz, region)
    if ism is not None:
        if 2400.0 <= freq_mhz <= 2483.5:
            return {
                "status": "BELONGS",
                "badge": "LOCAL ISM / WI-FI / BLE",
                "local_allocation": ism,
                "reason": f"Standard worldwide 2.4 GHz ISM band ({ism}).",
            }
        return {
            "status": "BELONGS",
            "badge": f"REGIONAL ISM ({region})",
            "local_allocation": ism,
            "reason": f"Legal unlicensed ISM/SRD allocation for {region} ({ism}).",
        }

    # 4. Check explicit Foreign / Wrong-Region Band Traps
    for t_lo, t_hi, t_desc in FOREIGN_BAND_TRAPS.get(region, []):
        if t_lo <= freq_mhz <= t_hi:
            return {
                "status": "DOES_NOT_BELONG",
                "badge": f"OUT-OF-REGION FOR {region}",
                "local_allocation": f"Foreign Band Trap: {t_desc}",
                "reason": f"Does NOT match standard {region} unlicensed/cellular allocations: {t_desc}",
            }

    # 5. Check if it falls in ANOTHER country's cellular downlink
    foreign_cell = match_foreign_cellular_band(freq_mhz, region)
    if foreign_cell is not None:
        f_reg, f_band = foreign_cell
        return {
            "status": "DOES_NOT_BELONG",
            "badge": f"FOREIGN CELL BAND ({f_reg})",
            "local_allocation": f"{f_reg} {f_band['band']} {f_band['direction']} (Not {region} Cellular)",
            "reason": f"Frequency matches {f_reg} cellular {f_band['band']} rather than {region} cellular bands — verify if foreign hardware, licensed utility, or rogue emitter!",
        }

    # 6. General licensed / amateur / utility spectrum
    if 1.0 <= freq_mhz <= 30.0:
        return {
            "status": "VERIFY_CONTEXT",
            "badge": "HF SHORTWAVE / UTILITY",
            "local_allocation": "HF 1–30 MHz (Shortwave / Amateur / SMPS Harmonic)",
            "reason": "Outside HF ISM spots (6.78/13.56/27.12 MHz); verify if amateur radio, shortwave, or local power-supply noise.",
        }
    if 410.0 <= freq_mhz <= 430.0:
        return {
            "status": "VERIFY_CONTEXT",
            "badge": "LICENSED UHF / TETRA / LMR",
            "local_allocation": "410–430 MHz Licensed UHF Trunked / Emergency / SCADA",
            "reason": "Licensed land mobile / TETRA / utility radio spectrum; expected if official base station, illegal if unlicensed.",
        }

    return {
        "status": "VERIFY_CONTEXT",
        "badge": f"UNASSIGNED / LICENSED ({region})",
        "local_allocation": f"Non-ISM / Non-Cellular Spectrum in {region}",
        "reason": f"Outside standard {region} cellular & ISM bands — research local regulator ({'FCC' if region == 'US' else 'Ofcom' if region == 'UK' else 'ACMA' if region == 'AU' else 'ETSI'}) license database.",
    }


# ==============================================================================
# 6. REAL CELL TOWER VS. FAKE CELL TOWER (ROGUE BTS / IMSI-CATCHER) ENGINE
# ==============================================================================


def analyze_cell_towers(
    emissions: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Identify all cellular-band (and foreign-cellular-band) emitters from grouped
    RF emissions and score each one as:
      - [LIKELY REAL CELL TOWER]
      - [PULSED / VERIFY CELLULAR EMITTER]
      - [CELLULAR UPLINK / NEARBY HANDSET OR IOT]
      - [SUSPECTED FAKE / ROGUE CELL TOWER]
    Includes dB-based distance estimates (both Macro Tower & Portable Stingray models)
    and Compass Direction (from DF bearings or Known Tower database).
    """
    cfg = config or load_config()
    region = cfg.get("region", "UK")
    user_lat = cfg.get("latitude")
    user_lon = cfg.get("longitude")
    known_towers = load_known_towers()
    bearings_db = load_df_bearings()

    # Build quick lookup of cluster pulse metadata near each emission center
    cluster_by_mhz = {round(c["center_mhz"], 2): c for c in clusters}

    towers_out: List[Dict[str, Any]] = []
    counts = {
        "likely_real": 0,
        "pulsed_verify": 0,
        "uplink_device": 0,
        "suspected_fake": 0,
    }

    for em in emissions:
        if "HARDWARE SPUR" in em.get("verdict", ""):
            continue
        c_mhz = float(em["center_mhz"])

        local_cell = match_cellular_band(c_mhz, region)
        foreign_cell = match_foreign_cellular_band(c_mhz, region) if local_cell is None else None

        # Only evaluate signals inside a local cellular band OR a foreign cellular downlink band
        if local_cell is None and foreign_cell is None:
            continue

        is_foreign = local_cell is None and foreign_cell is not None
        band_info = local_cell if local_cell is not None else foreign_cell[1]
        foreign_reg = foreign_cell[0] if foreign_cell is not None else None

        est_bw_khz = float(em.get("est_bw_khz", 50.0))
        peak_db = float(em.get("peak_db", -50.0))
        avg_db = float(em.get("avg_db", -50.0))
        std_db = float(em.get("std_db", 0.0))
        duty_pct = float(em.get("duty_cycle_pct", 0.0))
        win_pct = float(em.get("window_persistence_pct", 0.0))
        pulses = int(em.get("coalesced_pulses", em.get("unique_bursts", 1)))
        med_pri = float(em.get("median_pri_sec", 0.0))
        pri_jitter = float(em.get("pri_jitter_sec", 0.0))
        direction = band_info["direction"]

        # Pull pulse_class from closest cluster if available
        cl_match = cluster_by_mhz.get(round(c_mhz, 2))
        pulse_class = cl_match.get("pulse_class", "") if cl_match else ""

        is_continuous = (duty_pct >= 45.0 and pulses >= 6) or (win_pct >= 70.0 and pulses >= 12)
        is_pulsed = pulses >= 2 and not is_continuous

        # Distance estimates under BOTH Macro Tower & Portable/Fake BTS assumptions
        sig_kind = "macro_cell" if (direction in ("DOWNLINK", "TDD") and not is_foreign) else "portable_cell"
        dist_info = estimate_distance_from_db(c_mhz, peak_db, config=cfg, signal_kind=sig_kind)

        # Bearing from live DF measurements or Known Real Tower database
        df_bearing = find_measured_bearing(c_mhz, bearings_db)
        known_match = find_nearest_known_tower(c_mhz, band_info["band"], known_towers, user_lat, user_lon)

        # ---- AUTHENTICITY & FAKE/ROGUE RISK SCORING ----
        auth_score = 50
        fake_risk = 10
        real_indicators: List[str] = []
        fake_indicators: List[str] = []
        research_steps: List[str] = []

        earfcn_str = compute_earfcn_arfcn(c_mhz, band_info)

        # Criterion 1: Regional Band & Duplex Direction
        if is_foreign:
            auth_score -= 40
            fake_risk += 55
            fake_indicators.append(
                f"WRONG-REGION CELLULAR BAND: {c_mhz:.3f} MHz belongs to {foreign_reg} {band_info['band']} "
                f"{direction}, NOT {region} licensed cellular spectrum!"
            )
            research_steps.append(
                f"Verify with directional antenna & SDR waterfall: foreign {foreign_reg} cellular band active in {region} is a prime rogue BTS / misconfigured SDR / imported repeater indicator."
            )
        elif direction in ("DOWNLINK", "TDD"):
            auth_score += 20
            real_indicators.append(
                f"Valid {region} licensed cellular {direction} band: {band_info['band']} ({band_info['carriers']})."
            )
        else:
            # UPLINK band
            if is_continuous:
                auth_score -= 35
                fake_risk += 50
                fake_indicators.append(
                    f"TOWER-LIKE CONTINUOUS CARRIER IN UPLINK BAND ({band_info['band']} UL): "
                    "Mobile handsets burst intermittently; a 24/7 carrier here indicates a rogue repeater, jammer, or misconfigured fake BTS!"
                )
            else:
                real_indicators.append(
                    f"Operates in {region} Cellular UPLINK band ({band_info['band']} UL): intermittent bursts are typical of a nearby mobile phone, cellular alarm, or smart meter transmitting TO a real tower."
                )
                # Check if extraordinarily strong (device is right next to HackRF!)
                if peak_db >= -15.0:
                    real_indicators.append(
                        f"Very strong uplink RSSI ({peak_db:.1f} dB -> {dist_info['low_power_tx_str']}): transmitting phone/IoT modem is likely inside your building/room!"
                    )

        # Criterion 2: Bandwidth & Spectral Mask (Wideband LTE/5G vs Narrowband 2G/Anomalous Spike)
        min_std_bw, max_std_bw = band_info["std_bw_khz"]
        if direction in ("DOWNLINK", "TDD") and not is_foreign:
            if est_bw_khz >= 1400.0:
                auth_score += 20
                fake_risk -= 5
                real_indicators.append(
                    f"Wideband 4G LTE / 5G NR spectral plateau (~{est_bw_khz / 1000.0:.2f} MHz BW) matches legitimate macro/small-cell OFDM carrier."
                )
            elif 150.0 <= est_bw_khz <= 450.0:
                if band_info.get("legacy_2g_sunset", False):
                    auth_score -= 25
                    fake_risk += 35
                    fake_indicators.append(
                        f"SUNSET-2G NARROWBAND CARRIER (~{est_bw_khz:.0f} kHz BW) in {region} {band_info['band']}: "
                        "2G GSM is shut down on major carriers here — a lone 200 kHz GSM-width carrier is a classic IMSI-catcher / Stingray 2G downgrade signature!"
                    )
                else:
                    real_indicators.append(
                        f"Narrowband ~{est_bw_khz:.0f} kHz width matches 2G GSM BCCH (200 kHz) or NB-IoT carrier (still active on {region} {band_info['band']})."
                    )
            else:
                auth_score -= 10
                fake_risk += 20
                fake_indicators.append(
                    f"Unusual channel width (~{est_bw_khz:.0f} kHz) for {band_info['band']} (expected {min_std_bw:.0f}–{max_std_bw:.0f} kHz)."
                )

        # Criterion 3: Temporal Stability vs. Pulsed / Pop-Up Behavior in Downlink Band
        if direction in ("DOWNLINK", "TDD"):
            if is_continuous and std_db <= 4.5:
                auth_score += 20
                real_indicators.append(
                    f"Steady round-the-clock base station stability ({duty_pct:.1f}% occupancy, low power variance ±{std_db:.1f} dB)."
                )
            elif is_pulsed:
                auth_score -= 15
                fake_risk += 25
                pri_desc = f"every ~{med_pri:.1f}s (±{pri_jitter:.1f}s)" if med_pri > 0 else "intermittently"
                fake_indicators.append(
                    f"PULSED / INTERMITTENT DOWNLINK ACTIVITY ({pulses} bursts, {pri_desc}, StdDev {std_db:.1f} dB): "
                    "Real macro cell towers broadcast continuous 24/7 sync signals; pulsed spikes inside a DL band warrant investigation (possible portable BTS, bursty small cell, or non-cellular interference)."
                )
                if std_db >= 7.0:
                    fake_risk += 15
                    fake_indicators.append(
                        f"High RSSI fluctuation (StdDev {std_db:.1f} dB) suggests a moving transmitter (vehicle/portable) or multipath burst hopping rather than a fixed macro tower."
                    )

        # Criterion 4: Close-Range Power Overpowering Anomaly
        if direction in ("DOWNLINK", "TDD") and peak_db >= -18.0:
            fake_risk += 20
            fake_indicators.append(
                f"EXTREMELY STRONG DOWNLINK SIGNAL ({peak_db:.1f} dB / est. {dist_info['est_rx_dbm']} dBm): "
                f"If portable/fake BTS -> {dist_info['portable_bts_str']}; if real macro tower -> {dist_info['macro_tower_str']}. "
                "IMSI-catchers intentionally overpower nearby macro towers to force phone reselection!"
            )

        # Criterion 5: Known Real Tower Database Cross-Reference
        if known_match is not None and direction in ("DOWNLINK", "TDD") and not is_foreign:
            if known_match["distance_m"] <= 3000.0:
                auth_score += 18
                fake_risk = max(0, fake_risk - 15)
                real_indicators.append(
                    f"Correlates with registered local tower '{known_match['label']}' ({known_match['carrier']}) "
                    f"at {known_match['distance_str']} bearing {known_match['cardinal']} {known_match['bearing_deg']}°."
                )

        # Criterion 6: Check Paired Duplex Uplink/Downlink Activity in the Same Scan!
        duplex_mhz = float(band_info.get("duplex_mhz", 0.0))
        paired_partner_mhz = None
        if duplex_mhz != 0.0:
            expected_partner = (c_mhz - duplex_mhz) if direction == "DOWNLINK" else (c_mhz + duplex_mhz)
            for other_em in emissions:
                if abs(float(other_em["center_mhz"]) - expected_partner) <= 2.0:
                    paired_partner_mhz = round(float(other_em["center_mhz"]), 3)
                    break
            if paired_partner_mhz is not None:
                auth_score += 10
                real_indicators.append(
                    f"Active FDD duplex pair detected at {paired_partner_mhz:.3f} MHz (exact {abs(duplex_mhz):.0f} MHz spacing)."
                )

        auth_score = max(0, min(100, auth_score))
        fake_risk = max(0, min(100, fake_risk))

        # Final Cell Tower Verdict
        if direction == "UPLINK" and not is_foreign:
            if is_continuous or fake_risk >= 55:
                verdict = "[SUSPECTED FAKE / ROGUE UPLINK TX]"
                verdict_key = "suspected_fake"
                counts["suspected_fake"] += 1
            else:
                verdict = "[CELLULAR UPLINK / HANDSET OR IOT]"
                verdict_key = "uplink_device"
                counts["uplink_device"] += 1
        elif is_foreign or fake_risk >= 55:
            verdict = "[SUSPECTED FAKE / ROGUE CELL TOWER]"
            verdict_key = "suspected_fake"
            counts["suspected_fake"] += 1
        elif is_pulsed or fake_risk >= 35 or auth_score < 65:
            verdict = "[PULSED / VERIFY CELLULAR EMITTER]"
            verdict_key = "pulsed_verify"
            counts["pulsed_verify"] += 1
        else:
            verdict = "[LIKELY REAL CELL TOWER]"
            verdict_key = "likely_real"
            counts["likely_real"] += 1

        # Actionable Research & Protocol Decode Commands
        lock_lo = max(1, int(math.floor(c_mhz - 1)))
        lock_hi = min(3000, int(math.ceil(c_mhz + 1)))
        research_steps.append(
            f"Lock-on high-res sweep: python3 hackrf_penetration_scanner.py --ranges {lock_lo}:{lock_hi} -w 25000 -t -55"
        )
        research_steps.append(
            f"Run Compass Direction Finder: python3 direction_finder.py --freq {c_mhz:.3f}"
        )
        if direction in ("DOWNLINK", "TDD"):
            research_steps.append(
                f"Decode real Cell ID / MCC / MNC / LAC / SIB1 to confirm authenticity: "
                f"use `gr-gsm` / `kal -s GSM900` (2G) or `LTE-Cell-Scanner` / `srsRAN cell_search` tuned to {c_mhz:.3f} MHz ({earfcn_str}), "
                "then verify MCC/MNC/CellID against CellMapper.net or OpenCelliD.org."
            )
        else:
            research_steps.append(
                f"This is a mobile UPLINK channel ({c_mhz:.3f} MHz). To confirm if it's your own phone/smart-meter/alarm pulsing every ~{med_pri:.0f}s, "
                "temporarily put nearby phones in Airplane Mode while watching the live lock-on monitor."
            )

        # Summarize Direction / Bearing string
        if df_bearing is not None:
            bearing_display = f"🧭 {df_bearing['cardinal']} {df_bearing['peak_bearing_deg']:.0f}° (Measured DF • {df_bearing['confidence']})"
            bearing_deg = df_bearing["peak_bearing_deg"]
            bearing_source = "MEASURED_DF"
        elif known_match is not None:
            bearing_display = f"📍 {known_match['cardinal']} {known_match['bearing_deg']:.0f}° (Known Tower {known_match['distance_str']})"
            bearing_deg = known_match["bearing_deg"]
            bearing_source = "KNOWN_TOWER_DB"
        else:
            bearing_display = "Unmeasured — Click 'Find Direction'"
            bearing_deg = None
            bearing_source = "NONE"

        towers_out.append(
            {
                "center_mhz": round(c_mhz, 4),
                "span_mhz": em.get("span_mhz", ""),
                "est_bw_khz": est_bw_khz,
                "band_3gpp": band_info["band"],
                "direction": "OUT-OF-REGION" if is_foreign else direction,
                "tech": band_info["tech"],
                "carriers": f"Foreign ({foreign_reg}): {band_info['carriers']}" if is_foreign else band_info["carriers"],
                "earfcn_arfcn": earfcn_str,
                "tower_verdict": verdict,
                "verdict_key": verdict_key,
                "authenticity_score": auth_score,
                "fake_risk_score": fake_risk,
                "is_pulsed": is_pulsed,
                "is_continuous": is_continuous,
                "pulse_class": pulse_class,
                "pulses": pulses,
                "median_pri_sec": med_pri,
                "pri_jitter_sec": pri_jitter,
                "duty_cycle_pct": duty_pct,
                "peak_db": peak_db,
                "avg_db": avg_db,
                "std_db": std_db,
                "distance": dist_info,
                "bearing_display": bearing_display,
                "bearing_deg": bearing_deg,
                "bearing_source": bearing_source,
                "df_bearing": df_bearing,
                "known_tower_match": known_match,
                "paired_duplex_mhz": paired_partner_mhz,
                "real_indicators": real_indicators,
                "fake_indicators": fake_indicators,
                "research_steps": research_steps,
                "first_seen": em.get("first_seen", ""),
                "last_seen": em.get("last_seen", ""),
            }
        )

    # Sort suspected fake & pulsed cellular emitters first, then strongest power
    priority_rank = {"suspected_fake": 0, "pulsed_verify": 1, "likely_real": 2, "uplink_device": 3}
    towers_out.sort(key=lambda t: (priority_rank.get(t["verdict_key"], 9), -t["fake_risk_score"], -t["peak_db"]))

    return {
        "region": region,
        "region_label": REGION_LABELS.get(region, region),
        "recommended_cell_ranges": get_cell_sweep_ranges(region, include_uplinks=True),
        "recommended_dl_only_ranges": get_cell_sweep_ranges(region, include_uplinks=False),
        "counts": counts,
        "total_cellular_emitters": len(towers_out),
        "known_towers_loaded": len(known_towers),
        "towers": towers_out,
    }


# ==============================================================================
# 7. REAL FLAG TRIAGE & RESEARCH PRIORITY ENGINE
# ==============================================================================


def triage_real_flags(
    emissions: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    cell_intel: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Separate EVERY detected emission into:
      1. CRITICAL_REAL_FLAG  — Genuine high-priority anomaly worth deep research
         (Suspected fake/rogue tower, out-of-region frequency, protected GNSS/MedRadio/SARSAT
         intrusion, continuous carrier in forbidden/uplink band)
      2. INVESTIGATE_MEDIUM  — Real unexplained pulsed signal, tight periodic beacon in
         non-ISM band, or unverified pulsed cellular emitter
      3. BENIGN_EXPECTED     — Likely false positive / expected local RF for user's location
         (Standard 2.4 GHz Wi-Fi / BLE, legal regional ISM sensors/Z-Wave/DECT, verified
         macro cellular downlinks, normal nearby phone uplinks, HackRF internal spurs)
    """
    cfg = config or load_config()
    region = cfg.get("region", "UK")
    bearings_db = load_df_bearings()

    tower_by_mhz = {round(t["center_mhz"], 2): t for t in cell_intel.get("towers", [])}
    cluster_by_mhz = {round(c["center_mhz"], 2): c for c in clusters}

    critical_flags: List[Dict[str, Any]] = []
    investigate_flags: List[Dict[str, Any]] = []
    benign_expected: List[Dict[str, Any]] = []

    for em in emissions:
        c_mhz = float(em["center_mhz"])
        peak_db = float(em.get("peak_db", -50.0))
        std_db = float(em.get("std_db", 0.0))
        est_bw_khz = float(em.get("est_bw_khz", 50.0))
        duty_pct = float(em.get("duty_cycle_pct", 0.0))
        pulses = int(em.get("coalesced_pulses", em.get("unique_bursts", 1)))
        med_pri = float(em.get("median_pri_sec", 0.0))
        verdict = em.get("verdict", "")

        belonging = evaluate_location_belonging(
            freq_mhz=c_mhz,
            region=region,
            est_bw_khz=est_bw_khz,
            occupancy_pct=duty_pct,
            burst_count=pulses,
        )
        tower_info = tower_by_mhz.get(round(c_mhz, 2))
        cl_info = cluster_by_mhz.get(round(c_mhz, 2))
        df_b = find_measured_bearing(c_mhz, bearings_db)

        sig_kind = (
            "macro_cell"
            if (tower_info and tower_info["direction"] in ("DOWNLINK", "TDD"))
            else ("portable_cell" if tower_info else "auto")
        )
        dist_info = estimate_distance_from_db(c_mhz, peak_db, config=cfg, signal_kind=sig_kind)

        # Decide Triage Tier & Research Score (0-100)
        tier = "BENIGN_EXPECTED"
        research_score = 10
        why_real_or_benign: List[str] = []
        next_steps: List[str] = []

        # Case A: Internal Hardware Clock Spur (False Positive)
        if "HARDWARE SPUR" in verdict:
            tier = "BENIGN_EXPECTED"
            research_score = 0
            why_real_or_benign.append("Internal HackRF 10/20 MHz sample/reference clock spur (hardware artifact, not an external signal).")
        # Case B: Standard 2.4 GHz Wi-Fi / BLE / Zigbee (Common False Positive for '24/7 Illegal'!)
        elif 2400.0 <= c_mhz <= 2483.5 and est_bw_khz >= 800.0 and belonging["status"] == "BELONGS":
            tier = "BENIGN_EXPECTED"
            research_score = 15
            why_real_or_benign.append(
                f"Standard 2.4 GHz ISM wireless traffic (~{est_bw_khz / 1000.0:.1f} MHz BW, Wi-Fi router / BLE / Zigbee). "
                "Busy Wi-Fi access points often trigger high-occupancy '24/7' alerts even though they are completely normal."
            )
            next_steps.append("Use '--exclude-wifi' when scanning to hide 2.4 GHz Wi-Fi clutter and focus on target frequencies.")
        # Case C: Suspected Fake / Rogue Cell Tower
        elif tower_info and tower_info["verdict_key"] == "suspected_fake":
            tier = "CRITICAL_REAL_FLAG"
            research_score = max(80, tower_info["fake_risk_score"])
            why_real_or_benign.extend(tower_info["fake_indicators"])
            next_steps.extend(tower_info["research_steps"])
        # Case D: Protected Band or Wrong-Region Frequency (Does Not Belong!)
        elif belonging["status"] == "DOES_NOT_BELONG":
            tier = "CRITICAL_REAL_FLAG"
            research_score = 88
            why_real_or_benign.append(belonging["reason"])
            if 1164.0 <= c_mhz <= 1610.0:
                why_real_or_benign.append(
                    "Note: Disconnect antenna briefly to verify this isn't a local USB/PC clock harmonic or HackRF image; "
                    "if it remains with antenna attached and changes with direction, it is a genuine L-band / GNSS-adjacent emitter!"
                )
            lock_lo = max(1, int(math.floor(c_mhz - 1)))
            lock_hi = min(3000, int(math.ceil(c_mhz + 1)))
            next_steps.append(f"Narrowband lock-on check: python3 hackrf_penetration_scanner.py --ranges {lock_lo}:{lock_hi} -w 25000")
            next_steps.append(f"Find direction: python3 direction_finder.py --freq {c_mhz:.3f}")
        # Case E: Pulsed / Unverified Cellular Band Emitter
        elif tower_info and tower_info["verdict_key"] == "pulsed_verify":
            tier = "INVESTIGATE_MEDIUM"
            research_score = max(55, tower_info["fake_risk_score"] + 15)
            why_real_or_benign.extend(tower_info["fake_indicators"] or [belonging["reason"]])
            next_steps.extend(tower_info["research_steps"])
        # Case F: Very Strong Pulsed Cellular Uplink (Worth confirming what local device is pulsing!)
        elif tower_info and tower_info["verdict_key"] == "uplink_device":
            if peak_db >= -15.0 and pulses >= 5 and med_pri > 0:
                tier = "INVESTIGATE_MEDIUM"
                research_score = 62
                why_real_or_benign.append(
                    f"Very strong pulsed signal ({peak_db:.1f} dB, {pulses} bursts every ~{med_pri:.1f}s) in {region} {tower_info['band_3gpp']} UPLINK."
                )
                why_real_or_benign.append(
                    f"NOT a macro cell tower (it's on the Uplink frequency) — estimated distance {dist_info['low_power_tx_str']}. "
                    "Likely a very close phone, cellular smart meter, burglar alarm dialer, or GPS tracker transmitting periodically."
                )
                next_steps.append(
                    f"Run Direction Finder (`python3 direction_finder.py --freq {c_mhz:.3f}`) inside/around your location to locate the physical transmitting device."
                )
                next_steps.append(
                    "Toggle Airplane Mode on nearby personal phones to rule them out vs. a hidden cellular IoT/tracker module."
                )
            else:
                tier = "BENIGN_EXPECTED"
                research_score = 22
                why_real_or_benign.append(
                    f"Normal intermittent mobile phone / IoT uplink bursts in {region} {tower_info['band_3gpp']} Uplink."
                )
        # Case G: Verified Likely Real Macro Cell Tower
        elif tower_info and tower_info["verdict_key"] == "likely_real":
            tier = "BENIGN_EXPECTED"
            research_score = 18
            why_real_or_benign.append(
                f"Matches expected {region} licensed macro cell tower downlink ({tower_info['band_3gpp']} — {tower_info['carriers']})."
            )
        # Case H: Legal Regional ISM / SRD (433, 868 in UK/EU, 915 in US/AU, DECT)
        elif belonging["status"] == "BELONGS" and is_in_regional_ism(c_mhz, region):
            if "ILLEGAL" in verdict or duty_pct >= 50.0:
                tier = "INVESTIGATE_MEDIUM"
                research_score = 58
                why_real_or_benign.append(
                    f"Operates inside legal {region} ISM band ({belonging['local_allocation']}), BUT high duty cycle ({duty_pct:.1f}%) violates intermittent burst rules."
                )
                next_steps.append(f"Locate source with Direction Finder: python3 direction_finder.py --freq {c_mhz:.3f}")
            else:
                tier = "BENIGN_EXPECTED"
                research_score = 20
                why_real_or_benign.append(
                    f"Expected unlicensed {region} ISM/SRD device ({belonging['local_allocation']}) — e.g., smart meter, Z-Wave, LoRa sensor, keyfob, or DECT."
                )
        # Case I: Unclassified / Licensed Non-ISM Spectrum with Strong or Repeating Activity
        else:
            if pulses >= 3 or peak_db >= -25.0 or "ILLEGAL" in verdict or "SUSPICIOUS" in verdict:
                tier = "INVESTIGATE_MEDIUM"
                research_score = 55
                why_real_or_benign.append(belonging["reason"])
                why_real_or_benign.append(
                    f"Active transmitter: Peak {peak_db:.1f} dB (~{est_bw_khz:.0f} kHz BW), {pulses} burst(s), PRI {med_pri:.1f}s."
                )
                next_steps.append(
                    f"Inspect modulation in GQRX/SDR++ at {c_mhz:.3f} MHz and check national license database ({'FCC ULS' if region == 'US' else 'Ofcom WTR' if region == 'UK' else 'ACMA RRL' if region == 'AU' else 'National NRA'})."
                )
                next_steps.append(f"Find direction: python3 direction_finder.py --freq {c_mhz:.3f}")
            else:
                tier = "BENIGN_EXPECTED"
                research_score = 25
                why_real_or_benign.append(f"Low-count transient hit in {belonging['local_allocation']}.")

        item = {
            "center_mhz": round(c_mhz, 4),
            "span_mhz": em.get("span_mhz", ""),
            "est_bw_khz": est_bw_khz,
            "tier": em.get("tier", ""),
            "triage_tier": tier,
            "research_score": research_score,
            "belonging": belonging,
            "peak_db": peak_db,
            "avg_db": float(em.get("avg_db", -50.0)),
            "std_db": std_db,
            "pulses": pulses,
            "median_pri_sec": med_pri,
            "duty_cycle_pct": duty_pct,
            "pulse_class": cl_info.get("pulse_class", "") if cl_info else "",
            "original_verdict": verdict,
            "cell_tower_verdict": tower_info["tower_verdict"] if tower_info else None,
            "distance": dist_info,
            "bearing": df_b,
            "reasons": why_real_or_benign,
            "next_steps": next_steps,
            "first_seen": em.get("first_seen", ""),
            "last_seen": em.get("last_seen", ""),
        }

        if tier == "CRITICAL_REAL_FLAG":
            critical_flags.append(item)
        elif tier == "INVESTIGATE_MEDIUM":
            investigate_flags.append(item)
        else:
            benign_expected.append(item)

    critical_flags.sort(key=lambda x: (x["research_score"], x["peak_db"]), reverse=True)
    investigate_flags.sort(key=lambda x: (x["research_score"], x["peak_db"]), reverse=True)
    benign_expected.sort(key=lambda x: x["peak_db"], reverse=True)

    return {
        "region": region,
        "region_label": REGION_LABELS.get(region, region),
        "critical_count": len(critical_flags),
        "investigate_count": len(investigate_flags),
        "benign_filtered_count": len(benign_expected),
        "real_flags_total": len(critical_flags) + len(investigate_flags),
        "critical_flags": critical_flags,
        "investigate_flags": investigate_flags,
        "benign_expected": benign_expected,
    }


def build_full_intel(
    emissions: List[Dict[str, Any]],
    clusters: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cfg = config or load_config()
    cell_intel = analyze_cell_towers(emissions, clusters, config=cfg)
    flag_triage = triage_real_flags(emissions, clusters, cell_intel, config=cfg)
    return {
        "config": cfg,
        "cell_towers": cell_intel,
        "flag_triage": flag_triage,
        "known_towers": load_known_towers(),
        "df_bearings": load_df_bearings(),
    }


# ==============================================================================
# 8. CLI REPORT
# ==============================================================================


def print_intel_report(intel: Dict[str, Any]) -> None:
    cfg = intel["config"]
    ct = intel["cell_towers"]
    ft = intel["flag_triage"]
    sep = "=" * 102
    sub = "-" * 102

    print(sep)
    print(" HACKRF CELL TOWER AUTHENTICITY, LOCATION ALLOCATION & REAL FLAG RESEARCH REPORT")
    print(sep)
    print(f" Active Region / Location : {cfg['region']} — {cfg['location_label']}")
    if cfg.get("latitude") is not None and cfg.get("longitude") is not None:
        print(f" GPS Coordinates          : {cfg['latitude']:.5f}, {cfg['longitude']:.5f}")
    print(f" Path-Loss Environment    : {ENVIRONMENT_EXPONENTS.get(cfg.get('environment', 'suburban'))[1]}")
    print(f" Cell Tower Scan Ranges   : {ct['recommended_cell_ranges']} MHz")
    print(sub)
    print(
        f" CELLULAR SUMMARY : {ct['counts']['suspected_fake']} Suspected Fake/Rogue | "
        f"{ct['counts']['pulsed_verify']} Pulsed/Verify | "
        f"{ct['counts']['likely_real']} Likely Real Towers | "
        f"{ct['counts']['uplink_device']} Mobile Uplinks"
    )
    print(
        f" FLAG TRIAGE      : {ft['critical_count']} CRITICAL Real Flags | "
        f"{ft['investigate_count']} Medium Investigate | "
        f"{ft['benign_filtered_count']} Benign/Expected Filtered Out"
    )
    print(sub)

    print(" 1. CELL TOWER REAL vs. FAKE ANALYSIS")
    print(sub)
    if not ct["towers"]:
        print(" [i] No cellular-band transmitters recorded yet. Run `./auto_scanner.sh --cell` to scan cell towers.")
    for t in ct["towers"][:20]:
        print(
            f" * {t['center_mhz']:>8.3f} MHz ({t['band_3gpp']} {t['direction']}) -> {t['tower_verdict']}"
        )
        print(
            f"     Auth: {t['authenticity_score']}/100 | Fake Risk: {t['fake_risk_score']}/100 | "
            f"Peak: {t['peak_db']:.1f} dB (BW ~{t['est_bw_khz']:.0f} kHz, {t['earfcn_arfcn']})"
        )
        print(
            f"     Distance (from dB) : Macro Tower {t['distance']['macro_tower_str']} | "
            f"Portable/Fake BTS {t['distance']['portable_bts_str']}"
        )
        print(f"     Direction / Bearing: {t['bearing_display']}")
        for fi in t["fake_indicators"]:
            print(f"     [!] Risk Note      : {fi}")
        for ri in t["real_indicators"][:2]:
            print(f"     [+] Real Match     : {ri}")

    print(sub)
    print(" 2. REAL FLAGS WORTH DEEPER RESEARCH (FILTERED FROM BENIGN LOCAL NOISE)")
    print(sub)
    real_all = ft["critical_flags"] + ft["investigate_flags"]
    if not real_all:
        print(" [i] No critical or medium real flags detected for your configured location.")
    for f in real_all[:20]:
        print(
            f" * [{f['triage_tier']}] {f['center_mhz']:>8.3f} MHz | Score {f['research_score']}/100 | "
            f"{f['belonging']['badge']} | Peak {f['peak_db']:.1f} dB | Est. Dist: {f['distance']['primary_dist_str']}"
        )
        for r in f["reasons"][:3]:
            print(f"     Why Real   : {r}")
        for step in f["next_steps"][:2]:
            print(f"     Next Step  : {step}")
    print(sep)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cell Tower Real-vs-Fake Analyzer, Regional Belonging Audit & Real Flag Triage"
    )
    parser.add_argument("-f", "--file", default=DEFAULT_LOG_FILE, help="Scan log file")
    parser.add_argument("--region", choices=list(REGION_LABELS.keys()), default=None, help="Set/override region (US, UK, EU, AU, GLOBAL)")
    parser.add_argument("--lat", type=float, default=None, help="Set user latitude")
    parser.add_argument("--lon", type=float, default=None, help="Set user longitude")
    parser.add_argument("--env", choices=list(ENVIRONMENT_EXPONENTS.keys()), default=None, help="Path-loss environment")
    parser.add_argument("--save-config", action="store_true", help="Persist region/lat/lon/env settings to scanner_config.json")
    parser.add_argument("--print-cell-ranges", action="store_true", help="Print optimal cellular sweep ranges for the active region and exit")
    args = parser.parse_args()

    cfg = load_config()
    updates: Dict[str, Any] = {}
    if args.region:
        updates["region"] = args.region
    if args.lat is not None:
        updates["latitude"] = args.lat
    if args.lon is not None:
        updates["longitude"] = args.lon
    if args.env:
        updates["environment"] = args.env

    if updates:
        if args.save_config:
            cfg = save_config(updates)
        else:
            cfg.update(updates)
            if args.region:
                cfg["location_label"] = REGION_LABELS[args.region]

    if args.print_cell_ranges:
        print(get_cell_sweep_ranges(cfg["region"], include_uplinks=True))
        return 0

    sys.path.insert(0, SCRIPT_DIR)
    import analyze_scan_data as analyzer
    import verify_rf_devices as verifier

    records = analyzer.load_log_hits(args.file)
    if not records:
        print(f"[i] No hits found in {args.file}.")
        return 0

    analysis = analyzer.analyze_records(records, hide_spurs=True)
    compliance = verifier.group_contiguous_signals(records)
    intel = build_full_intel(compliance.get("emissions", []), analysis.get("clusters", []), config=cfg)
    print_intel_report(intel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
