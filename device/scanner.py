"""
IoT SDR Scanner — Raspberry Pi Firmware
Runs on Pi Zero 2W with RTL-SDR dongle.
Detects active signals across configurable frequency bands
and publishes detections via MQTT.

Usage:
  python scanner.py              # real RTL-SDR mode
  python scanner.py --simulate   # simulation mode (no hardware needed)
"""

import argparse
import json
import logging
import math
import random
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False
    print("[warn] paho-mqtt not installed — running in print-only mode")

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

MQTT_BROKER   = "localhost"
MQTT_PORT     = 1883
MQTT_TOPIC    = "sdr/detections"
DEVICE_ID     = "sdr-node-01"
SCAN_INTERVAL = 1.0   # seconds between full scans

# Frequency bands to monitor (MHz)
BANDS = [
    {"name": "PMR446",   "start": 446.0,  "end": 446.2,  "step": 12.5},  # walkie-talkies
    {"name": "VHF",      "start": 136.0,  "end": 174.0,  "step": 25.0},  # aviation, marine
    {"name": "UHF-Low",  "start": 400.0,  "end": 430.0,  "step": 25.0},  # misc UHF
    {"name": "UHF-High", "start": 460.0,  "end": 470.0,  "step": 12.5},  # public safety
    {"name": "ISM-433",  "start": 433.0,  "end": 435.0,  "step": 10.0},  # IoT devices
    {"name": "FM-Radio", "start": 87.5,   "end": 108.0,  "step": 100.0}, # FM broadcast
    {"name": "Weather",  "start": 162.4,  "end": 162.55, "step": 25.0},  # NOAA weather
]

RSSI_THRESHOLD = -85  # dBm — signals below this are ignored (noise floor)

# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────

@dataclass
class Detection:
    device_id:   str
    timestamp:   str
    frequency:   float        # MHz
    rssi:        float        # dBm
    band:        str
    modulation:  str          # AM / FM / UNKNOWN
    active:      bool
    scan_id:     int

def guess_modulation(freq_mhz: float) -> str:
    """Rough modulation heuristic based on band."""
    if 87.5 <= freq_mhz <= 108.0:
        return "FM"
    if 118.0 <= freq_mhz <= 137.0:
        return "AM"   # aviation
    if 162.0 <= freq_mhz <= 163.0:
        return "FM"   # NOAA
    if 446.0 <= freq_mhz <= 446.2:
        return "FM"   # PMR446
    return "FM"       # most land-mobile is FM

def band_for_freq(freq_mhz: float) -> str:
    for b in BANDS:
        if b["start"] <= freq_mhz <= b["end"]:
            return b["name"]
    return "Unknown"

# ──────────────────────────────────────────────
# RTL-SDR scanner (real hardware)
# ──────────────────────────────────────────────

def scan_band_real(band: dict) -> list[Detection]:
    """
    Call rtl_power to sweep a band and parse results.
    Requires: rtl-sdr package installed (sudo apt install rtl-sdr)
    """
    detections = []
    start_hz = int(band["start"] * 1e6)
    end_hz   = int(band["end"]   * 1e6)
    step_hz  = int(band["step"]  * 1e3)

    cmd = [
        "rtl_power",
        "-f", f"{start_hz}:{end_hz}:{step_hz}",
        "-g", "40",          # gain dB
        "-i", "1",           # 1-second integration
        "-1",                # one shot
        "-"                  # output to stdout
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 6:
                continue
            try:
                # rtl_power CSV: date, time, hz_low, hz_high, hz_step, samples, dBm...
                hz_low  = float(parts[2])
                hz_step = float(parts[4])
                rssi_values = [float(x) for x in parts[6:] if x.strip()]
                for i, rssi in enumerate(rssi_values):
                    freq_hz  = hz_low + i * hz_step
                    freq_mhz = freq_hz / 1e6
                    if rssi > RSSI_THRESHOLD:
                        detections.append(Detection(
                            device_id  = DEVICE_ID,
                            timestamp  = datetime.utcnow().isoformat() + "Z",
                            frequency  = round(freq_mhz, 4),
                            rssi       = round(rssi, 1),
                            band       = band["name"],
                            modulation = guess_modulation(freq_mhz),
                            active     = True,
                            scan_id    = int(time.time()),
                        ))
            except (ValueError, IndexError):
                continue
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logging.warning(f"rtl_power error on {band['name']}: {e}")

    return detections

# ──────────────────────────────────────────────
# Simulation mode
# ──────────────────────────────────────────────

# Persistent "fake transmitters" so signals appear stable across scans
_SIM_TRANSMITTERS: list[dict] = []

def _init_sim_transmitters():
    global _SIM_TRANSMITTERS
    fixtures = [
        {"freq": 446.00625, "rssi_base": -62, "band": "PMR446",   "mod": "FM",  "drift": 0.3},
        {"freq": 446.01875, "rssi_base": -74, "band": "PMR446",   "mod": "FM",  "drift": 0.5},
        {"freq": 162.400,   "rssi_base": -55, "band": "Weather",  "mod": "FM",  "drift": 0.1},
        {"freq": 96.5,      "rssi_base": -45, "band": "FM-Radio", "mod": "FM",  "drift": 0.05},
        {"freq": 101.1,     "rssi_base": -48, "band": "FM-Radio", "mod": "FM",  "drift": 0.05},
        {"freq": 433.920,   "rssi_base": -71, "band": "ISM-433",  "mod": "FM",  "drift": 1.2},
        {"freq": 462.575,   "rssi_base": -78, "band": "UHF-High", "mod": "FM",  "drift": 0.8},
        {"freq": 155.340,   "rssi_base": -66, "band": "VHF",      "mod": "FM",  "drift": 0.4},
    ]
    _SIM_TRANSMITTERS = fixtures

def scan_band_simulated(band: dict, scan_id: int) -> list[Detection]:
    """Generate realistic fake detections for the given band."""
    detections = []
    t = time.time()

    for tx in _SIM_TRANSMITTERS:
        if tx["band"] != band["name"]:
            continue

        # Simulate fading / intermittent signals
        if random.random() < 0.08:   # 8% chance signal disappears this scan
            continue

        rssi = tx["rssi_base"] + random.gauss(0, tx["drift"])
        rssi = round(min(-30, max(-100, rssi)), 1)

        if rssi > RSSI_THRESHOLD:
            detections.append(Detection(
                device_id  = DEVICE_ID,
                timestamp  = datetime.utcnow().isoformat() + "Z",
                frequency  = round(tx["freq"] + random.gauss(0, 0.001), 5),
                rssi       = rssi,
                band       = band["name"],
                modulation = tx["mod"],
                active     = True,
                scan_id    = scan_id,
            ))

    # Occasionally add a random burst signal (walkie-talkie keying up)
    if band["name"] == "PMR446" and random.random() < 0.12:
        burst_ch = random.choice([
            446.03125, 446.04375, 446.05625, 446.06875,
            446.08125, 446.09375, 446.10625, 446.11875,
        ])
        detections.append(Detection(
            device_id  = DEVICE_ID,
            timestamp  = datetime.utcnow().isoformat() + "Z",
            frequency  = burst_ch,
            rssi       = round(random.uniform(-80, -60), 1),
            band       = "PMR446",
            modulation = "FM",
            active     = True,
            scan_id    = scan_id,
        ))

    return detections

# ──────────────────────────────────────────────
# MQTT publisher
# ──────────────────────────────────────────────

class MQTTPublisher:
    def __init__(self):
        if not MQTT_AVAILABLE:
            self.client = None
            return
        self.client = mqtt.Client(client_id=DEVICE_ID)
        self.client.on_connect    = self._on_connect
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"MQTT connected to {MQTT_BROKER}:{MQTT_PORT}")
        else:
            logging.error(f"MQTT connect failed: rc={rc}")

    def _on_disconnect(self, client, userdata, rc):
        logging.warning("MQTT disconnected")

    def connect(self):
        if not self.client:
            return
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            logging.warning(f"MQTT connect error: {e} — printing to stdout only")
            self.client = None

    def publish(self, detections: list[Detection]):
        payload = {
            "device_id":  DEVICE_ID,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "count":      len(detections),
            "detections": [asdict(d) for d in detections],
        }
        msg = json.dumps(payload)

        if self.client:
            self.client.publish(MQTT_TOPIC, msg, qos=1)
        else:
            print(msg)   # fallback: stdout

# ──────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true",
                        help="Run in simulation mode (no RTL-SDR hardware)")
    parser.add_argument("--broker", default=MQTT_BROKER)
    parser.add_argument("--port",   default=MQTT_PORT, type=int)
    parser.add_argument("--bands",  nargs="*",
                        help="Only scan specific bands (e.g. PMR446 VHF)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    if args.simulate:
        _init_sim_transmitters()
        logging.info("Running in SIMULATION mode")
        scan_fn = scan_band_simulated
    else:
        logging.info("Running in REAL mode — RTL-SDR hardware required")
        scan_fn = scan_band_real

    active_bands = BANDS
    if args.bands:
        active_bands = [b for b in BANDS if b["name"] in args.bands]
        if not active_bands:
            logging.error(f"No matching bands: {args.bands}")
            sys.exit(1)

    publisher = MQTTPublisher()
    publisher.connect()

    scan_id = 0
    logging.info(f"Scanning {len(active_bands)} bands: "
                 f"{[b['name'] for b in active_bands]}")

    try:
        while True:
            all_detections = []
            for band in active_bands:
                if args.simulate:
                    dets = scan_fn(band, scan_id)
                else:
                    dets = scan_fn(band)
                all_detections.extend(dets)

            publisher.publish(all_detections)

            active = [d for d in all_detections if d.active]
            logging.info(
                f"Scan #{scan_id:04d} — {len(active)} active signals "
                f"across {len(active_bands)} bands"
            )

            scan_id += 1
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        logging.info("Scanner stopped")

if __name__ == "__main__":
    main()