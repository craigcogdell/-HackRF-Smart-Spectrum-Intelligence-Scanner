#!/usr/bin/env python3
"""
Standalone, zero-dependency Python 3 RF Device Fingerprinter & Compliance Auditor
(1 MHz - 3 GHz: Sub-GHz Penetration Bands + L-Band & S-Band 1-3 GHz).

Reads `penetration_scan_hits.log`, groups contiguous FFT bins into discrete RF
transmissions, and audits each emission for:
  1. Pulsed Signal Signature (Pulse Repetition Interval / PRI, jitter, burst cadence)
  2. Mesh Network Topology (Multi-node RSSI tiers, store-and-forward relay echoes,
     Meshtastic/LoRa, Z-Wave, Zigbee/Thread Ch 11-26, BLE Mesh, Wi-Fi Mesh)
  3. 1-3 GHz & Sub-GHz Round-the-Clock (24/7 Continuous) Carrier Detection
  4. Regulatory & Technical Compliance Verdict:
     - [HARDWARE SPUR / SDR CLOCK]  (Internal HackRF 10/20 MHz clock harmonic)
     - [COMPLIANT / TRUE DEVICE]    (Matches legal device parameters for that band)
     - [CONFIRMED MESH NETWORK]     (Verified multi-node relay / mesh topology)
     - [24/7 CONTINUOUS TRANSMITTER](Round-the-clock persistent carrier in 1-3 GHz / Sub-GHz)
     - [SUSPICIOUS / NON-STANDARD]  (Deviates from expected duty cycle or bandwidth)
     - [ILLEGAL / ROGUE ANOMALY]    (Operates in restricted spectrum or violates continuous carrier rules)
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


# ==============================================================================
# RF DEVICE & REGULATORY KNOWLEDGE BASE (1 MHz - 3000 MHz / 3 GHz)
# ==============================================================================


class BandProfile:
    def __init__(
        self,
        low_mhz: float,
        high_mhz: float,
        band_name: str,
        typical_devices: str,
        expected_modulation: str,
        max_duty_cycle_pct: float,
        min_bw_khz: float,
        max_bw_khz: float,
        allow_continuous_carrier: bool,
        legal_notes: str,
        is_hardware_spur: bool = False,
        is_mesh_band: bool = False,
    ) -> None:
        self.low_mhz = low_mhz
        self.high_mhz = high_mhz
        self.band_name = band_name
        self.typical_devices = typical_devices
        self.expected_modulation = expected_modulation
        self.max_duty_cycle_pct = max_duty_cycle_pct
        self.min_bw_khz = min_bw_khz
        self.max_bw_khz = max_bw_khz
        self.allow_continuous_carrier = allow_continuous_carrier
        self.legal_notes = legal_notes
        self.is_hardware_spur = is_hardware_spur
        self.is_mesh_band = is_mesh_band


DEVICE_PROFILES: List[BandProfile] = [
    # --- Known HackRF Internal Clock Spurs (10 MHz, 20 MHz) ---
    BandProfile(
        low_mhz=19.900,
        high_mhz=20.150,
        band_name="20.000 MHz HackRF ADC/TCXO Clock Harmonic (or WWV Time Standard)",
        typical_devices="HackRF Internal 20 Msps Sample Clock Spur (Local LO Leakage)",
        expected_modulation="Unmodulated Continuous Wave (CW) Clock Spur",
        max_duty_cycle_pct=100.0,
        min_bw_khz=25.0,
        max_bw_khz=300.0,
        allow_continuous_carrier=True,
        legal_notes="Internal SDR receiver clock artifact at 20.000 MHz (not an external transmitter unless confirmed with antenna disconnected).",
        is_hardware_spur=True,
    ),
    BandProfile(
        low_mhz=9.950,
        high_mhz=10.050,
        band_name="10.000 MHz Reference Clock / WWV Time Standard",
        typical_devices="10 MHz TCXO Reference Oscillator / HF Time Signal",
        expected_modulation="CW / AM Time Code",
        max_duty_cycle_pct=100.0,
        min_bw_khz=25.0,
        max_bw_khz=150.0,
        allow_continuous_carrier=True,
        legal_notes="Often local 10 MHz reference harmonic or standard time broadcast.",
        is_hardware_spur=True,
    ),
    # --- 1 MHz - 30 MHz (DEEP / WHOLE-BODY INDUCTIVE) ---
    BandProfile(
        low_mhz=6.765,
        high_mhz=6.795,
        band_name="6.78 MHz ISM Band (Inductive / Magnetic Resonance)",
        typical_devices="AirFuel Wireless Power Chargers, Inductive Medical Implants, HF Industrial Heating",
        expected_modulation="Continuous Inductive Carrier / Load Modulation",
        max_duty_cycle_pct=100.0,
        min_bw_khz=10.0,
        max_bw_khz=100.0,
        allow_continuous_carrier=True,
        legal_notes="ITU ISM band; narrowband inductive carrier permitted within 6.765-6.795 MHz.",
    ),
    BandProfile(
        low_mhz=13.553,
        high_mhz=13.567,
        band_name="13.56 MHz Worldwide ISM Band (NFC / RFID / Deep Inductive Telemetry)",
        typical_devices="NFC Readers, ISO 14443/15693 Smartcards, Implantable Inductive Telemetry, Access Badges",
        expected_modulation="ASK / OOK / Load Modulation (106-848 kbps)",
        max_duty_cycle_pct=100.0,
        min_bw_khz=10.0,
        max_bw_khz=200.0,
        allow_continuous_carrier=True,
        legal_notes="Strict fundamental mask (13.553-13.567 MHz); sidebands up to +/-800 kHz at lower power.",
    ),
    BandProfile(
        low_mhz=26.957,
        high_mhz=27.283,
        band_name="27.12 MHz ISM / Citizens Band (CB / Medical Diathermy)",
        typical_devices="RF Medical Diathermy/Hyperthermia Equipment, 27 MHz RC Toys, Wireless Pagers, CB Radio",
        expected_modulation="AM / FM / FSK / Pulsed RF",
        max_duty_cycle_pct=100.0,
        min_bw_khz=10.0,
        max_bw_khz=350.0,
        allow_continuous_carrier=True,
        legal_notes="Permitted for ISM medical diathermy and unlicensed 27 MHz telemetry/CB.",
    ),
    # --- 400 MHz - 450 MHz (HIGH PENETRATION / DEEP TISSUE TELEMETRY / UHF MESH) ---
    BandProfile(
        low_mhz=401.000,
        high_mhz=406.000,
        band_name="MedRadio / MICS (401-406 MHz Medical Implant Communication Service)",
        typical_devices="Cardiac Pacemakers, Implantable Defibrillators (ICDs), Insulin Pumps, Capsule Endoscopes",
        expected_modulation="FSK / GFSK Low-Duty-Cycle Telemetry Bursts",
        max_duty_cycle_pct=1.0,
        min_bw_khz=25.0,
        max_bw_khz=300.0,
        allow_continuous_carrier=False,
        legal_notes="Strictly reserved for medical implants/body-worn telemetry. Continuous carriers or high-duty-cycle jamming (>1%) are ILLEGAL.",
    ),
    BandProfile(
        low_mhz=406.000,
        high_mhz=406.100,
        band_name="406 MHz COSPAS-SARSAT Emergency Distress Band",
        typical_devices="EPIRB / ELT / PLB Satellite Emergency Beacons",
        expected_modulation="BPSK 400 bps Short 0.5s Bursts every 50s",
        max_duty_cycle_pct=2.0,
        min_bw_khz=25.0,
        max_bw_khz=100.0,
        allow_continuous_carrier=False,
        legal_notes="PROTECTED SATELLITE DISTRESS BAND. Any non-emergency or continuous transmission here is strictly ILLEGAL.",
    ),
    BandProfile(
        low_mhz=433.050,
        high_mhz=434.790,
        band_name="433 MHz ISM / LPD433 Band (Sensors, Keyfobs & LoRa/Meshtastic 433 Mesh)",
        typical_devices="Meshtastic/LoRa 433 Mesh Nodes, Weather Stations, TPMS, Car Keyfobs, Home Security Sensors",
        expected_modulation="OOK / ASK / FSK / LoRa CSS Packet Bursts",
        max_duty_cycle_pct=10.0,
        min_bw_khz=25.0,
        max_bw_khz=500.0,
        allow_continuous_carrier=False,
        legal_notes="Unlicensed SRD/ISM band requires periodic bursts (typically <=10% duty cycle). Continuous unmodulated carriers violate ISM sharing rules.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=446.000,
        high_mhz=446.200,
        band_name="PMR446 License-Free Walkie-Talkie Band",
        typical_devices="PMR446 Analog FM / Digital dPMR / DMR Tier I Handheld Radios",
        expected_modulation="NFM (12.5 kHz) / 4FSK Voice Push-to-Talk",
        max_duty_cycle_pct=50.0,
        min_bw_khz=25.0,
        max_bw_khz=150.0,
        allow_continuous_carrier=False,
        legal_notes="Push-to-talk voice only (max 500 mW ERP); unattended continuous beacons/transmitters are prohibited.",
    ),
    BandProfile(
        low_mhz=410.000,
        high_mhz=430.000,
        band_name="410-430 MHz Licensed UHF Land Mobile / Emergency Services / Trunked Radio",
        typical_devices="TETRA (Airwave/Emergency Services), DMR Tier II/III, P25, Utility SCADA Telemetry",
        expected_modulation="TETRA pi/4-DQPSK (25 kHz) / DMR 2-slot TDMA / NFM",
        max_duty_cycle_pct=100.0,
        min_bw_khz=25.0,
        max_bw_khz=250.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed spectrum (base stations may transmit continuous control channels; unlicensed devices are ILLEGAL here).",
    ),
    # --- 860 MHz - 930 MHz (SUB-GHZ MESH, TELEMETRY & CELLULAR) ---
    BandProfile(
        low_mhz=868.350,
        high_mhz=868.500,
        band_name="868.42 MHz Z-Wave EU Mesh & LoRaWAN EU868 Band",
        typical_devices="Z-Wave Smart Home Mesh Nodes (Locks, Switches, Sensors), LoRaWAN EU868 Devices, Zigbee 868",
        expected_modulation="FSK / GFSK (40/100 kbps Z-Wave Mesh) / LoRa CSS",
        max_duty_cycle_pct=10.0,
        min_bw_khz=25.0,
        max_bw_khz=500.0,
        allow_continuous_carrier=False,
        legal_notes="ETSI EN 300 220 <=1% or <=10% duty cycle. Multi-hop store-and-forward mesh bursts are normal; continuous carriers are illegal.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=869.400,
        high_mhz=869.650,
        band_name="869.525 MHz High-Power EU868 Band (Meshtastic LoRa Mesh / Smart Grid)",
        typical_devices="Meshtastic EU868 LoRa Mesh Routers/Nodes, High-Power Sub-GHz Telemetry, Alarm Systems",
        expected_modulation="LoRa Chirp Spread Spectrum (125/250 kHz) / GFSK",
        max_duty_cycle_pct=10.0,
        min_bw_khz=25.0,
        max_bw_khz=600.0,
        allow_continuous_carrier=False,
        legal_notes="High-power SRD sub-band (up to 500 mW ERP, <=10% duty cycle) — primary European frequency for Meshtastic LoRa mesh networks.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=863.000,
        high_mhz=870.000,
        band_name="863-870 MHz European SRD / ISM / Sub-GHz Mesh Band",
        typical_devices="LoRaWAN (EU868), Sigfox, Wireless M-Bus Smart Meters, Z-Wave (869.85 MHz), Zigbee 868 Mesh, Intruder Alarms",
        expected_modulation="LoRa CSS / GFSK / BPSK Short Telemetry & Mesh Bursts",
        max_duty_cycle_pct=10.0,
        min_bw_khz=25.0,
        max_bw_khz=600.0,
        allow_continuous_carrier=False,
        legal_notes="Strict ETSI EN 300 220 duty cycle limits (0.1% to 10%). Continuous transmission (>10% occupancy) without LBT/AFA is non-compliant/illegal.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=880.000,
        high_mhz=915.000,
        band_name="E-GSM 900 / LTE Band 8 Cellular Uplink (880-915 MHz) & Region 2 US915 Mesh",
        typical_devices="Mobile Phones (GSM/LTE Band 8 Uplink Handsets), Cellular IoT Modems, OR US915 Meshtastic (906.875 MHz) / Z-Wave (908.42 MHz)",
        expected_modulation="TDMA GSM Bursts / SC-FDMA LTE Uplink / LoRa CSS",
        max_duty_cycle_pct=25.0,
        min_bw_khz=50.0,
        max_bw_khz=5000.0,
        allow_continuous_carrier=False,
        legal_notes="In Region 1 (UK/EU), 880-915 MHz is licensed Cellular Uplink; a continuous fixed carrier here is an illegal jammer/repeater. In Region 2 (Americas), 902-928 MHz is unlicensed ISM/Mesh.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=915.000,
        high_mhz=925.000,
        band_name="915-925 MHz (GSM-R Railway / RFID / Region 2 902-928 MHz ISM Mesh)",
        typical_devices="Americas 915 MHz ISM Mesh (LoRa/Meshtastic, Z-Wave 916 MHz, Zigbee 915) OR Region 1 GSM-R / UHF RFID (915-921 MHz)",
        expected_modulation="FHSS / LoRa CSS / RFID Backscatter",
        max_duty_cycle_pct=15.0,
        min_bw_khz=50.0,
        max_bw_khz=1000.0,
        allow_continuous_carrier=False,
        legal_notes="Frequency-hopping or low-duty-cycle packets expected. Continuous fixed-frequency carriers (>20% duty cycle) violate FHSS/SRD rules.",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=617.000,
        high_mhz=862.000,
        band_name="600-862 MHz Sub-GHz Cellular LTE / 5G NR Spectrum (Bands 71, 12, 13, 14, 28, 20, 5)",
        typical_devices="4G LTE / 5G NR Macro Cell Base Stations & Mobile Handset Uplinks (Region-Dependent)",
        expected_modulation="Wideband OFDM LTE / 5G NR (5-20 MHz) or SC-FDMA Uplink",
        max_duty_cycle_pct=100.0,
        min_bw_khz=150.0,
        max_bw_khz=25000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed Sub-GHz cellular spectrum (see Cell Tower Intelligence tab for exact regional Downlink vs. Uplink & Real vs. Fake Tower verification).",
    ),
    BandProfile(
        low_mhz=925.000,
        high_mhz=960.000,
        band_name="E-GSM 900 / LTE Band 8 Cellular Base Station Downlink (925-960 MHz)",
        typical_devices="Cellular Base Station Towers (24/7 Macro/Micro Cell Downlink BCCH / LTE Downlink)",
        expected_modulation="Continuous GSM BCCH Carrier (200 kHz) or Wideband LTE/UMTS Downlink",
        max_duty_cycle_pct=100.0,
        min_bw_khz=150.0,
        max_bw_khz=10000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed cellular base station downlink in Region 1/3 (UK/EU/AU); round-the-clock (24/7) high-occupancy carriers are normal here (NOT a US cellular band).",
    ),
    # --- 1000 MHz - 2000 MHz (L-BAND: AVIATION PULSES, GNSS, DECT, LTE 24/7 DOWNLINKS) ---
    BandProfile(
        low_mhz=1025.000,
        high_mhz=1095.000,
        band_name="1030 / 1090 MHz Aviation SSR / TCAS / ADS-B Transponder Band",
        typical_devices="Aircraft Mode-S / ADS-B Transponders (1090 MHz), Ground SSR Radar Interrogators (1030 MHz)",
        expected_modulation="PPM (Pulse Position Modulation) 1 MHz Wide Microsecond Pulses",
        max_duty_cycle_pct=15.0,
        min_bw_khz=50.0,
        max_bw_khz=3000.0,
        allow_continuous_carrier=False,
        legal_notes="PROTECTED AVIATION SAFETY BAND. Only pulsed aircraft/radar transponders permitted; continuous carriers are strictly ILLEGAL.",
    ),
    BandProfile(
        low_mhz=1164.000,
        high_mhz=1610.000,
        band_name="1.16-1.61 GHz GNSS (GPS L1/L2/L5, Galileo, GLONASS) & L-Band Satellite",
        typical_devices="Satellite Navigation Downlinks (1575.42 MHz GPS L1), Iridium/Inmarsat Satphones, Aviation DME",
        expected_modulation="CDMA Spread Spectrum (Below Thermal Noise) / Satellite TDMA",
        max_duty_cycle_pct=20.0,
        min_bw_khz=25.0,
        max_bw_khz=5000.0,
        allow_continuous_carrier=False,
        legal_notes="CRITICAL GNSS/SATELLITE SPECTRUM. Real GPS signals are below the HackRF noise floor; a strong round-the-clock carrier near 1575.42 MHz or 1227.60 MHz is a rogue GPS JAMMER/SPOOFER or local harmonic!",
    ),
    BandProfile(
        low_mhz=1710.000,
        high_mhz=1785.000,
        band_name="1710-1785 MHz LTE Band 3 / DCS-1800 Cellular Mobile Uplink",
        typical_devices="4G/5G Mobile Phones & Cellular Routers (Band 3 Uplink)",
        expected_modulation="SC-FDMA / OFDMA Uplink Bursts",
        max_duty_cycle_pct=35.0,
        min_bw_khz=50.0,
        max_bw_khz=20000.0,
        allow_continuous_carrier=False,
        legal_notes="Licensed mobile handset uplink; intermittent bursts indicate an active nearby phone/modem.",
    ),
    BandProfile(
        low_mhz=1805.000,
        high_mhz=1880.000,
        band_name="1805-1880 MHz LTE Band 3 / DCS-1800 Cellular Base Station Downlink",
        typical_devices="Cellular Macro/Small-Cell Base Stations (Round-the-Clock 24/7 Downlink)",
        expected_modulation="Continuous OFDM LTE / 5G NR Base Station Downlink",
        max_duty_cycle_pct=100.0,
        min_bw_khz=150.0,
        max_bw_khz=25000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed cellular base station downlink; continuous 24/7 transmission is normal here.",
    ),
    BandProfile(
        low_mhz=1880.000,
        high_mhz=1900.000,
        band_name="1880-1900 MHz DECT Cordless Phone / Wireless Intercom / Baby Monitor Band",
        typical_devices="DECT Cordless Phone Base Stations (24/7 Beacon Pulses), Wireless Intercoms, DECT Baby Monitors, Wireless Microphones",
        expected_modulation="GFSK 1.152 Mbps TDMA (10 ms Frame Pulses, ~1.728 MHz Channel Width)",
        max_duty_cycle_pct=100.0,
        min_bw_khz=50.0,
        max_bw_khz=3000.0,
        allow_continuous_carrier=True,
        legal_notes="License-free DECT band; base stations transmit a continuous 24/7 TDMA sync beacon even when no call is active.",
    ),
    BandProfile(
        low_mhz=1920.000,
        high_mhz=1980.000,
        band_name="1920-1980 MHz LTE Band 1 / UMTS 2100 Mobile Uplink",
        typical_devices="4G/5G Mobile Handsets & Cellular Modems (Band 1 Uplink)",
        expected_modulation="SC-FDMA / WCDMA Uplink",
        max_duty_cycle_pct=35.0,
        min_bw_khz=50.0,
        max_bw_khz=20000.0,
        allow_continuous_carrier=False,
        legal_notes="Licensed cellular mobile uplink; continuous fixed carrier is abnormal unless a cellular repeater/femtocell is malfunctioning.",
    ),
    # --- 2000 MHz - 3000 MHz (S-BAND: 2.4 GHz MESH/ISM, 24/7 VIDEO/CARRIERS, LTE, RADAR) ---
    BandProfile(
        low_mhz=2110.000,
        high_mhz=2170.000,
        band_name="2110-2170 MHz LTE Band 1 / UMTS 2100 Cellular Base Station Downlink",
        typical_devices="Cellular Base Station Towers / Indoor Small Cells (24/7 Downlink)",
        expected_modulation="Continuous OFDM LTE / WCDMA Downlink Carrier",
        max_duty_cycle_pct=100.0,
        min_bw_khz=150.0,
        max_bw_khz=25000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed cellular base station downlink; continuous 24/7 transmission is expected.",
    ),
    BandProfile(
        low_mhz=2300.000,
        high_mhz=2400.000,
        band_name="2300-2400 MHz LTE Band 40 TDD Cellular / 13cm Amateur / Wireless Video",
        typical_devices="LTE Band 40 TDD Small Cells, Commercial Telemetry, or 2.3 GHz Wireless Camera/Drone Links",
        expected_modulation="TDD OFDM / FM Video",
        max_duty_cycle_pct=100.0,
        min_bw_khz=50.0,
        max_bw_khz=25000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed LTE TDD Band 40 (and secondary Amateur allocation); check if narrowband continuous video carrier.",
    ),
    BandProfile(
        low_mhz=2400.000,
        high_mhz=2483.500,
        band_name="2.4 GHz Worldwide ISM & Mesh Band (Zigbee/Thread, Wi-Fi Mesh, BLE, Video Links)",
        typical_devices="Zigbee / Thread / Matter Mesh Nodes (Ch 11-26), Wi-Fi APs & 802.11s Mesh, BLE Mesh Beacons, OR Continuous Analog Camera/FPV/Baby Monitor",
        expected_modulation="O-QPSK (2 MHz Zigbee Mesh) / GFSK (1-2 MHz BLE) / OFDM (20 MHz Wi-Fi) / FM Video",
        max_duty_cycle_pct=65.0,
        min_bw_khz=50.0,
        max_bw_khz=25000.0,
        allow_continuous_carrier=False,
        legal_notes="Digital devices (Wi-Fi, Zigbee, Thread, BLE) use CSMA/CA or FHSS packet bursts. A 100% continuous non-packetized carrier in 2.4 GHz indicates an always-on analog wireless camera, baby monitor, microwave oven leakage, or jammer!",
        is_mesh_band=True,
    ),
    BandProfile(
        low_mhz=2500.000,
        high_mhz=2690.000,
        band_name="2500-2690 MHz LTE/5G Bands 7, 38 & 41 (High-Capacity Cellular)",
        typical_devices="4G LTE / 5G Base Stations (2570-2690 MHz 24/7 Downlink/TDD) & Mobile Uplinks (2500-2570 MHz)",
        expected_modulation="Wideband OFDM / SC-FDMA",
        max_duty_cycle_pct=100.0,
        min_bw_khz=100.0,
        max_bw_khz=40000.0,
        allow_continuous_carrier=True,
        legal_notes="Licensed high-capacity cellular spectrum; continuous 24/7 carriers in 2570-2690 MHz are normal cellular base stations.",
    ),
    BandProfile(
        low_mhz=2700.000,
        high_mhz=3000.000,
        band_name="2700-3000 MHz S-Band Airport ASR & Weather Surveillance Radar Band",
        typical_devices="Airport Surveillance Radar (ASR), Doppler Weather Radar (NEXRAD), Maritime S-Band Radar",
        expected_modulation="High-Power Pulsed Radar (Microsecond Pulses, Rotating Antenna Sweeps)",
        max_duty_cycle_pct=15.0,
        min_bw_khz=50.0,
        max_bw_khz=10000.0,
        allow_continuous_carrier=False,
        legal_notes="Restricted radiolocation/radar band; only pulsed radar sweeps are expected. Continuous fixed carriers here are anomalous/unlicensed.",
    ),
]


def match_band_profile(freq_mhz: float) -> BandProfile:
    for profile in DEVICE_PROFILES:
        if profile.low_mhz <= freq_mhz <= profile.high_mhz:
            return profile

    if 1.0 <= freq_mhz <= 30.0:
        return BandProfile(
            low_mhz=1.0,
            high_mhz=30.0,
            band_name="General HF Band (1-30 MHz Shortwave / Amateur / Utility)",
            typical_devices="HF Shortwave Broadcast, Amateur Radio, Maritime/Aviation HF, or Local Switching Power Supply (SMPS) Harmonics",
            expected_modulation="SSB / AM / CW / Digital HF",
            max_duty_cycle_pct=50.0,
            min_bw_khz=25.0,
            max_bw_khz=200.0,
            allow_continuous_carrier=False,
            legal_notes="Outside designated 6.78 / 13.56 / 27.12 MHz ISM bands; unmodulated 100% continuous carriers are typically local oscillator spurs or unlicensed transmitters.",
        )
    if 400.0 <= freq_mhz <= 450.0:
        return BandProfile(
            low_mhz=400.0,
            high_mhz=450.0,
            band_name="UHF Sub-Band (400-450 MHz Satellite / Amateur / Land Mobile)",
            typical_devices="UHF Commercial Radio, 70cm Amateur Radio (430-440 MHz), Satellite Downlinks (400-401 MHz)",
            expected_modulation="NFM / DMR / Digital Telemetry",
            max_duty_cycle_pct=40.0,
            min_bw_khz=25.0,
            max_bw_khz=250.0,
            allow_continuous_carrier=False,
            legal_notes="Requires license outside 433.05-434.79 MHz ISM and 446 MHz PMR.",
        )
    if 860.0 <= freq_mhz <= 930.0:
        return BandProfile(
            low_mhz=860.0,
            high_mhz=930.0,
            band_name="Sub-GHz UHF Band (860-930 MHz)",
            typical_devices="Sub-GHz Wireless Audio, Cellular Guard Band, or Custom UHF Transceiver",
            expected_modulation="FM / FSK / Digital",
            max_duty_cycle_pct=20.0,
            min_bw_khz=50.0,
            max_bw_khz=500.0,
            allow_continuous_carrier=False,
            legal_notes="Check regional allocation (870-880 MHz is typically restricted/SRD/Utilities).",
        )
    if 1000.0 <= freq_mhz <= 2000.0:
        return BandProfile(
            low_mhz=1000.0,
            high_mhz=2000.0,
            band_name="L-Band Spectrum (1000-2000 MHz Point-to-Point / Telemetry / Cellular)",
            typical_devices="L-Band Telemetry, Studio-Transmitter Links, Cellular Supplemental Downlinks, or 1.2 GHz FPV Video",
            expected_modulation="OFDM / FM Video / FSK",
            max_duty_cycle_pct=50.0,
            min_bw_khz=50.0,
            max_bw_khz=10000.0,
            allow_continuous_carrier=False,
            legal_notes="Licensed L-Band spectrum; note that 1.2 GHz analog video transmitters without an amateur/commercial license often interfere with aviation/GPS.",
        )
    return BandProfile(
        low_mhz=2000.0,
        high_mhz=3000.0,
        band_name="S-Band Spectrum (2000-3000 MHz Microwave / Telemetry / Wireless)",
        typical_devices="S-Band Point-to-Point Links, Wireless Camera Links, or Cellular Expansion Bands",
        expected_modulation="OFDM / QAM / FM",
        max_duty_cycle_pct=50.0,
        min_bw_khz=50.0,
        max_bw_khz=20000.0,
        allow_continuous_carrier=False,
        legal_notes="Licensed S-Band spectrum outside 2400-2483.5 MHz ISM.",
    )


# ==============================================================================
# SIGNAL CLUSTERING, PULSE TIMING, MESH & COMPLIANCE ENGINE
# ==============================================================================


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


def load_records(
    log_path: str,
) -> List[Tuple[str, Optional[datetime], str, float, float]]:
    records: List[Tuple[str, Optional[datetime], str, float, float]] = []
    if not os.path.exists(log_path):
        return records

    with open(log_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().startswith("#") or len(row) < 4:
                continue
            try:
                ts_str = row[0].strip()
                tier = row[1].strip()
                freq_mhz = float(row[2].strip())
                power_db = float(row[3].strip())
            except ValueError:
                continue
            records.append((ts_str, parse_timestamp(ts_str), tier, freq_mhz, power_db))
    return records


def evaluate_group_pulse_and_mesh(
    events: List[Tuple[float, float]],
    center_mhz: float,
    est_bw_khz: float,
    profile: BandProfile,
) -> Dict[str, Any]:
    """
    Compute burst intervals (PRI), multi-node power tiers, and relay echoes for a merged emission.
    """
    sorted_ev = sorted(events, key=lambda x: x[0])
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

    intervals: List[float] = []
    relay_echoes = 0
    for i in range(1, len(bursts)):
        dt = bursts[i][0] - bursts[i - 1][0]
        db_diff = abs(bursts[i][1] - bursts[i - 1][1])
        if 0.12 <= dt <= 1800.0:
            intervals.append(dt)
        if 0.05 <= dt <= 3.5 and db_diff >= 5.0:
            relay_echoes += 1

    # Cluster RSSI tiers (>= 5.5 dB separation)
    node_tiers: List[float] = []
    for _, b_db in sorted(bursts, key=lambda x: x[1], reverse=True):
        if not any(abs(b_db - c) < 5.5 for c in node_tiers):
            node_tiers.append(round(b_db, 1))

    mean_pri = 0.0
    median_pri = 0.0
    jitter_pri = 0.0
    cv_pri = 0.0
    if intervals:
        s_int = sorted(intervals)
        n_i = len(s_int)
        mean_pri = sum(s_int) / n_i
        median_pri = (
            s_int[n_i // 2]
            if n_i % 2 == 1
            else 0.5 * (s_int[n_i // 2 - 1] + s_int[n_i // 2])
        )
        jitter_pri = math.sqrt(sum((x - mean_pri) ** 2 for x in s_int) / n_i)
        cv_pri = jitter_pri / mean_pri if mean_pri > 0 else 0.0

    is_mesh_candidate = profile.is_mesh_band and (
        len(node_tiers) >= 2 or relay_echoes >= 1
    )

    return {
        "coalesced_bursts": len(bursts),
        "mean_pri_sec": round(mean_pri, 3),
        "median_pri_sec": round(median_pri, 3),
        "pri_jitter_sec": round(jitter_pri, 3),
        "cv_pri": round(cv_pri, 2),
        "estimated_mesh_nodes": len(node_tiers),
        "node_power_tiers_db": node_tiers,
        "relay_echoes": relay_echoes,
        "is_mesh_candidate": is_mesh_candidate,
    }


def group_contiguous_signals(
    records: List[Tuple[str, Optional[datetime], str, float, float]],
    bin_step_mhz: float = 0.050,
    merge_gap_mhz: float = 0.110,
) -> Dict[str, Any]:
    """
    1. Quantize hits into 50 kHz FFT bins.
    2. Merge adjacent active bins within `merge_gap_mhz` into a single coherent
       RF emission / device transmission.
    3. Normalize sweep occupancy per tier (excluding the 20 MHz internal clock spur)
       so duty cycle and 24/7 round-the-clock detection are accurate.
    """
    if not records:
        return {}

    all_timestamps = set()
    all_sweeps_by_tier: Dict[str, set] = {}
    external_sweeps_by_tier: Dict[str, set] = {}
    external_windows_by_tier: Dict[str, set] = {}
    valid_dts: List[datetime] = []
    bins: Dict[Tuple[str, float], Dict[str, Any]] = {}

    for ts_str, dt, tier, freq_mhz, power_db in records:
        all_timestamps.add(ts_str)
        all_sweeps_by_tier.setdefault(tier, set()).add(ts_str)
        epoch_s = dt.timestamp() if dt is not None else 0.0
        window_id = int(epoch_s // 60) if epoch_s > 0 else 0
        if dt is not None:
            valid_dts.append(dt)

        prof_check = match_band_profile(freq_mhz)
        if not prof_check.is_hardware_spur:
            external_sweeps_by_tier.setdefault(tier, set()).add(ts_str)
            if window_id > 0:
                external_windows_by_tier.setdefault(tier, set()).add(window_id)

        b_mhz = round(round(freq_mhz / bin_step_mhz) * bin_step_mhz, 4)
        key = (tier, b_mhz)
        if key not in bins:
            bins[key] = {
                "tier": tier,
                "bin_mhz": b_mhz,
                "hits": 0,
                "max_db": -999.0,
                "min_db": 999.0,
                "sum_db": 0.0,
                "sum_sq_db": 0.0,
                "timestamps": set(),
                "windows": set(),
                "events": [],
                "first_seen": ts_str,
                "last_seen": ts_str,
            }
        b = bins[key]
        b["hits"] += 1
        b["sum_db"] += power_db
        b["sum_sq_db"] += power_db * power_db
        if power_db > b["max_db"]:
            b["max_db"] = power_db
        if power_db < b["min_db"]:
            b["min_db"] = power_db
        b["timestamps"].add(ts_str)
        if window_id > 0:
            b["windows"].add(window_id)
        if epoch_s > 0:
            b["events"].append((epoch_s, power_db))
        b["last_seen"] = ts_str

    sorted_bins = sorted(bins.values(), key=lambda x: (x["tier"], x["bin_mhz"]))
    merged_groups: List[List[Dict[str, Any]]] = []

    for b in sorted_bins:
        if not merged_groups:
            merged_groups.append([b])
            continue
        prev_group = merged_groups[-1]
        prev_bin = prev_group[-1]
        if (
            b["tier"] == prev_bin["tier"]
            and (b["bin_mhz"] - prev_bin["bin_mhz"]) <= merge_gap_mhz
        ):
            prev_group.append(b)
        else:
            merged_groups.append([b])

    total_sweeps = max(len(all_timestamps), 1)
    duration_sec = (
        (max(valid_dts) - min(valid_dts)).total_seconds()
        if len(valid_dts) >= 2
        else 0.0
    )

    emissions: List[Dict[str, Any]] = []
    for group in merged_groups:
        tier = group[0]["tier"]
        low_bin = min(x["bin_mhz"] for x in group)
        high_bin = max(x["bin_mhz"] for x in group)
        est_bw_khz = round(((high_bin - low_bin) + bin_step_mhz) * 1000.0, 1)

        peak_bin_obj = max(group, key=lambda x: (x["max_db"], x["hits"]))
        center_mhz = peak_bin_obj["bin_mhz"]
        peak_db = peak_bin_obj["max_db"]
        min_db = min(x["min_db"] for x in group)

        total_group_hits = sum(x["hits"] for x in group)
        total_sum_db = sum(x["sum_db"] for x in group)
        total_sum_sq = sum(x["sum_sq_db"] for x in group)
        avg_db = total_sum_db / total_group_hits
        variance = max(0.0, (total_sum_sq / total_group_hits) - (avg_db * avg_db))
        std_db = math.sqrt(variance)

        union_timestamps = set()
        union_windows = set()
        all_events: List[Tuple[float, float]] = []
        for x in group:
            union_timestamps.update(x["timestamps"])
            union_windows.update(x["windows"])
            all_events.extend(x["events"])

        unique_bursts = len(union_timestamps)
        profile = match_band_profile(center_mhz)

        if profile.is_hardware_spur:
            duty_cycle_pct = min(100.0, (unique_bursts / total_sweeps) * 100.0)
            window_persistence_pct = 100.0
        else:
            tier_ext_sweeps = max(
                len(all_sweeps_by_tier.get(tier, set())),
                len(external_sweeps_by_tier.get(tier, set())),
                1,
            )
            tier_ext_windows = max(len(external_windows_by_tier.get(tier, set())), 1)
            duty_cycle_pct = min(100.0, (unique_bursts / tier_ext_sweeps) * 100.0)
            window_persistence_pct = min(
                100.0, (len(union_windows) / tier_ext_windows) * 100.0
            )

        first_seen = min(x["first_seen"] for x in group)
        last_seen = max(x["last_seen"] for x in group)

        pulse_mesh = evaluate_group_pulse_and_mesh(
            events=all_events,
            center_mhz=center_mhz,
            est_bw_khz=est_bw_khz,
            profile=profile,
        )

        verdict, confidence, audit_reasons = audit_emission(
            center_mhz=center_mhz,
            est_bw_khz=est_bw_khz,
            duty_cycle_pct=duty_cycle_pct,
            window_persistence_pct=window_persistence_pct,
            unique_bursts=unique_bursts,
            peak_db=peak_db,
            std_db=std_db,
            pulse_mesh=pulse_mesh,
            profile=profile,
        )

        emissions.append(
            {
                "tier": tier,
                "center_mhz": center_mhz,
                "span_mhz": f"{low_bin:.3f} - {high_bin:.3f} MHz",
                "est_bw_khz": est_bw_khz,
                "bin_count": len(group),
                "total_hits": total_group_hits,
                "unique_bursts": unique_bursts,
                "coalesced_pulses": pulse_mesh["coalesced_bursts"],
                "duty_cycle_pct": round(duty_cycle_pct, 2),
                "window_persistence_pct": round(window_persistence_pct, 2),
                "median_pri_sec": pulse_mesh["median_pri_sec"],
                "mean_pri_sec": pulse_mesh["mean_pri_sec"],
                "pri_jitter_sec": pulse_mesh["pri_jitter_sec"],
                "estimated_mesh_nodes": pulse_mesh["estimated_mesh_nodes"],
                "node_power_tiers_db": pulse_mesh["node_power_tiers_db"],
                "relay_echoes": pulse_mesh["relay_echoes"],
                "peak_db": round(peak_db, 2),
                "avg_db": round(avg_db, 2),
                "min_db": round(min_db, 2),
                "std_db": round(std_db, 2),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "band_name": profile.band_name,
                "typical_devices": profile.typical_devices,
                "expected_modulation": profile.expected_modulation,
                "legal_notes": profile.legal_notes,
                "verdict": verdict,
                "confidence": confidence,
                "audit_reasons": audit_reasons,
            }
        )

    emissions.sort(key=lambda e: (e["peak_db"], e["total_hits"]), reverse=True)
    return {
        "total_hits": len(records),
        "total_sweeps": total_sweeps,
        "duration_seconds": duration_sec,
        "emissions": emissions,
    }


def audit_emission(
    center_mhz: float,
    est_bw_khz: float,
    duty_cycle_pct: float,
    window_persistence_pct: float,
    unique_bursts: int,
    peak_db: float,
    std_db: float,
    pulse_mesh: Dict[str, Any],
    profile: BandProfile,
) -> Tuple[str, str, List[str]]:
    """
    Evaluate whether a captured emission matches:
      - An internal SDR clock spur
      - A multi-node Mesh Network
      - A 1-3 GHz or Sub-GHz Round-the-Clock (24/7) continuous transmitter
      - A periodic pulsed beacon / telemetry device
      - A compliant vs illegal/suspicious signal
    """
    reasons: List[str] = []

    # Case 1: Known HackRF internal hardware clock harmonic (e.g. 20.000 MHz)
    if profile.is_hardware_spur:
        reasons.append(
            f"Matches exact frequency ({center_mhz:.3f} MHz), narrow bandwidth (~{est_bw_khz:.0f} kHz), "
            f"and rock-steady amplitude (std dev {std_db:.2f} dB) of the HackRF One internal clock spur."
        )
        reasons.append(
            "Note: Live scanner now auto-notches 10/20 MHz spurs by default so future scans only log external signals."
        )
        return ("[HARDWARE SPUR / SDR CLOCK]", "HIGH (99%)", reasons)

    # Check Duty Cycle / Occupancy compliance (require >=3 bursts before flagging duty violation)
    duty_ok = (duty_cycle_pct <= profile.max_duty_cycle_pct) or (unique_bursts < 3)
    if duty_ok:
        reasons.append(
            f"Duty Cycle PASS: Measured {duty_cycle_pct:.2f}% tier occupancy ({unique_bursts} active sweeps) "
            f"is within the <= {profile.max_duty_cycle_pct:.1f}% limit for {profile.band_name}."
        )
    else:
        reasons.append(
            f"Duty Cycle VIOLATION: Measured {duty_cycle_pct:.2f}% tier occupancy exceeds the maximum expected/legal "
            f"limit of {profile.max_duty_cycle_pct:.1f}% for {profile.band_name}."
        )

    # Check Round-the-Clock (24/7) Continuous Carrier behavior
    is_continuous = (duty_cycle_pct >= 50.0 and unique_bursts >= 8) or (
        window_persistence_pct >= 75.0 and unique_bursts >= 15
    )
    if is_continuous:
        if profile.allow_continuous_carrier:
            reasons.append(
                f"Round-the-Clock (24/7) Carrier: Signal is transmitting continuously ({duty_cycle_pct:.1f}% sweep occupancy, "
                f"{window_persistence_pct:.1f}% window persistence), matching an always-on base station / beacon."
            )
        else:
            reasons.append(
                f"Round-the-Clock (24/7) Carrier VIOLATION: Signal is transmitting continuously ({duty_cycle_pct:.1f}% occupancy) "
                "in a band that mandates intermittent packet bursts (possible hidden continuous video transmitter, stuck carrier, or jammer)."
            )

    # Check Pulsed Cadence (PRI)
    med_pri = pulse_mesh.get("median_pri_sec", 0.0)
    cv_pri = pulse_mesh.get("cv_pri", 0.0)
    pulses = pulse_mesh.get("coalesced_bursts", 1)
    if pulses >= 2 and med_pri > 0:
        if cv_pri <= 0.30:
            reasons.append(
                f"Pulsed Timing Profile: Strict periodic pulse every {med_pri:.2f}s "
                f"(jitter ±{pulse_mesh['pri_jitter_sec']:.2f}s across {pulses} pulses) -> Automated beacon / sensor / TDMA sync."
            )
        else:
            reasons.append(
                f"Pulsed Timing Profile: Repeating burst cadence with median interval Δt={med_pri:.2f}s "
                f"(mean {pulse_mesh['mean_pri_sec']:.2f}s across {pulses} bursts)."
            )

    # Check Mesh Topology & Multi-Node Relay Evidence
    est_nodes = pulse_mesh.get("estimated_mesh_nodes", 1)
    echoes = pulse_mesh.get("relay_echoes", 0)
    tiers_db = pulse_mesh.get("node_power_tiers_db", [])
    if profile.is_mesh_band and (est_nodes >= 2 or echoes >= 1):
        tiers_str = ", ".join(f"{p:.1f} dB" for p in tiers_db[:4])
        reasons.append(
            f"Mesh Topology Detected: ~{est_nodes} distinct RSSI node power tier(s) [{tiers_str}] "
            f"with {echoes} store-and-forward relay echo(es) on this mesh channel."
        )

    # Check Bandwidth match
    bw_ok = profile.min_bw_khz <= est_bw_khz <= profile.max_bw_khz
    if bw_ok:
        reasons.append(
            f"Bandwidth PASS: Estimated ~{est_bw_khz:.0f} kHz occupied width matches expected "
            f"{profile.min_bw_khz:.0f}-{profile.max_bw_khz:.0f} kHz profile ({profile.expected_modulation})."
        )
    else:
        reasons.append(
            f"Bandwidth ANOMALY: Estimated ~{est_bw_khz:.0f} kHz width is outside typical "
            f"{profile.min_bw_khz:.0f}-{profile.max_bw_khz:.0f} kHz device channel width."
        )

    # Final Verdict Classification
    if is_continuous and not profile.allow_continuous_carrier:
        return ("[ILLEGAL / NON-COMPLIANT 24/7 TX]", "HIGH", reasons)
    if is_continuous and center_mhz >= 1000.0:
        return ("[1-3 GHz 24/7 CONTINUOUS CARRIER]", "HIGH", reasons)
    if profile.is_mesh_band and (est_nodes >= 2 and (echoes >= 1 or pulses >= 3)):
        return ("[CONFIRMED MESH NETWORK]", "HIGH", reasons)
    if not duty_ok:
        return ("[SUSPICIOUS / DUTY VIOLATION]", "MEDIUM-HIGH", reasons)
    if not bw_ok:
        return ("[SUSPICIOUS / BW ANOMALY]", "MEDIUM", reasons)

    return ("[COMPLIANT / TRUE DEVICE]", "HIGH", reasons)


def print_compliance_report(data: Dict[str, Any], log_path: str) -> None:
    sep = "=" * 100
    subsep = "-" * 100
    emissions = data.get("emissions", [])

    print(sep)
    print(
        " HACKRF RF DEVICE FINGERPRINTER, MESH AUDITOR & 1-3 GHz 24/7 VERIFIER (1 MHz - 3 GHz)"
    )
    print(sep)
    print(f" Source Log File      : {os.path.abspath(log_path)}")
    print(
        f" Scan Coverage        : {data['total_hits']} total bin hits across {data['total_sweeps']} sweeps "
        f"({data['duration_seconds']:.1f}s)"
    )
    print(
        f" Distinct Transmitters: {len(emissions)} grouped RF signal emission(s) identified"
    )
    print(subsep)

    verdict_counts: Dict[str, int] = {}
    for e in emissions:
        v = e["verdict"]
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    print(" EXECUTIVE COMPLIANCE & TOPOLOGY SUMMARY:")
    for v, count in verdict_counts.items():
        print(f"   * {v:<34} : {count} signal emission(s)")
    print(subsep)

    for idx, e in enumerate(emissions, start=1):
        print(
            f" SIGNAL #{idx}: {e['center_mhz']:.4f} MHz (Span: {e['span_mhz']} | Est. BW: ~{e['est_bw_khz']:.0f} kHz) "
            f"--> {e['verdict']}"
        )
        print(" " + "-" * 98)
        print(f"   Spectrum Tier      : {e['tier']}")
        pri_info = (
            f" | Median Pulse Δt: {e['median_pri_sec']:.2f}s"
            if e.get("median_pri_sec", 0.0) > 0
            else ""
        )
        mesh_info = (
            f" | Est. Nodes: ~{e['estimated_mesh_nodes']} (Echoes: {e['relay_echoes']})"
            if e.get("estimated_mesh_nodes", 1) >= 2
            else ""
        )
        print(
            f"   Signal Metrics     : Peak {e['peak_db']:.2f} dB | Avg {e['avg_db']:.2f} dB | "
            f"StdDev {e['std_db']:.2f} dB | Pulses: {e['coalesced_pulses']} ({e['duty_cycle_pct']:.2f}% tier occ){pri_info}{mesh_info}"
        )
        print(f"   Time Window        : {e['first_seen']}  to  {e['last_seen']}")
        print(f"   Band Allocation    : {e['band_name']}")
        print(f"   Likely Device(s)   : {e['typical_devices']}")
        print(f"   Expected Signal    : {e['expected_modulation']}")
        print("   Characteristic, Pulse, Mesh & Legality Audit:")
        for reason in e["audit_reasons"]:
            print(f"     - {reason}")
        print(f"   Regulatory Context : {e['legal_notes']}")
        print(subsep)

    print(sep)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit scanned HackRF frequencies (1 MHz - 3 GHz) to identify pulsed devices, mesh networks, and 24/7 carriers."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=DEFAULT_LOG_FILE,
        help=f"Path to scan log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--export-json",
        type=str,
        default=os.path.join(SCRIPT_DIR, "device_compliance_report.json"),
        help="Path to save JSON compliance audit report",
    )
    args = parser.parse_args()

    if not os.path.exists(args.file):
        sys.stderr.write(
            f"[!] Log file not found: {os.path.abspath(args.file)}\n"
            f"    Run a scan first so there is data to audit.\n"
        )
        return 1

    records = load_records(args.file)
    if not records:
        print(f"[i] No hits found in {args.file}.")
        return 0

    data = group_contiguous_signals(records)
    print_compliance_report(data, args.file)

    if args.export_json:
        with open(args.export_json, mode="w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(
            f"[+] Saved detailed compliance audit JSON to: {os.path.abspath(args.export_json)}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
