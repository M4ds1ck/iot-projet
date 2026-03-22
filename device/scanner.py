#!/usr/bin/env python3
"""
CHEMCHAM RTL-SDR scanner / simulator.

Produces a richer scan payload with:
  - signal classification and threat levels
  - adaptive scan timing with dwell prioritization
  - full per-band summaries and decision actions
  - HTTP delivery to the Flask backend
"""

from __future__ import annotations

import argparse
import logging
import math
import random
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import numpy as np
import requests

try:
    from rtlsdr import RtlSdr

    HAS_RTL = True
except ImportError:
    HAS_RTL = False

try:
    from scipy.signal import find_peaks, welch

    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("chemcham-scanner")

BAND_DB = [
    {"name": "PMR446", "f_min": 446.000, "f_max": 446.200, "ch_khz": 12.5, "mod": "NFM", "threat": "safe", "description": "European walkie-talkie"},
    {"name": "FRS", "f_min": 462.500, "f_max": 467.800, "ch_khz": 12.5, "mod": "NFM", "threat": "safe", "description": "US Family Radio Service"},
    {"name": "GMRS", "f_min": 462.500, "f_max": 467.800, "ch_khz": 20.0, "mod": "NFM", "threat": "safe", "description": "US General Mobile Radio Service"},
    {"name": "ISM_433", "f_min": 433.050, "f_max": 434.790, "ch_khz": 200.0, "mod": "OOK", "threat": "safe", "description": "433 MHz ISM IoT band"},
    {"name": "LoRa_868", "f_min": 868.000, "f_max": 868.600, "ch_khz": 500.0, "mod": "LoRa", "threat": "safe", "description": "LoRa EU ISM 868"},
    {"name": "LoRa_915", "f_min": 902.000, "f_max": 928.000, "ch_khz": 500.0, "mod": "LoRa", "threat": "safe", "description": "LoRa US ISM 915"},
    {"name": "Aviation", "f_min": 118.000, "f_max": 137.000, "ch_khz": 25.0, "mod": "AM", "threat": "monitor", "description": "Aviation VHF"},
    {"name": "Marine_VHF", "f_min": 156.000, "f_max": 174.000, "ch_khz": 25.0, "mod": "FM", "threat": "monitor", "description": "Marine VHF radio"},
    {"name": "CB_Radio", "f_min": 26.965, "f_max": 27.405, "ch_khz": 10.0, "mod": "AM", "threat": "monitor", "description": "Citizens Band radio"},
    {"name": "APRS", "f_min": 144.390, "f_max": 144.400, "ch_khz": 12.5, "mod": "AFSK", "threat": "monitor", "description": "Amateur packet radio"},
]

SCAN_PLAN = [
    {"name": "PMR446", "center_mhz": 446.100},
    {"name": "FRS", "center_mhz": 465.000},
    {"name": "ISM_433", "center_mhz": 433.920},
    {"name": "LoRa_868", "center_mhz": 868.300},
    {"name": "LoRa_915", "center_mhz": 915.000},
    {"name": "Aviation", "center_mhz": 127.500},
    {"name": "Marine_VHF", "center_mhz": 162.000},
    {"name": "CB_Radio", "center_mhz": 27.185},
]

PMR446_CHANNELS = {idx + 1: 446.00625 + idx * 0.0125 for idx in range(16)}
FRS_CHANNELS = {
    1: 462.5625,
    2: 462.5875,
    3: 462.6125,
    4: 462.6375,
    5: 462.6625,
    6: 462.6875,
    7: 462.7125,
    8: 467.5625,
    9: 467.5875,
    10: 467.6125,
    11: 467.6375,
    12: 467.6625,
    13: 467.6875,
    14: 467.7125,
    15: 462.5500,
    16: 462.5750,
    17: 462.6000,
    18: 462.6250,
    19: 462.6500,
    20: 462.6750,
    21: 462.7000,
    22: 462.7250,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def gaussian(mean: float, std: float) -> float:
    return float(np.random.normal(mean, std))


def freq_to_signal_key(freq_mhz: float) -> str:
    return f"{round(freq_mhz / 0.0125) * 0.0125:.4f}"


def quality_from_power(power_db: float, snr_db: float) -> int:
    return int(max(0, min(100, (power_db + 110.0) * 0.85 + snr_db * 1.5)))


def classify_signal(freq_mhz: float, power_db: float, bandwidth_khz: float | None = None) -> dict[str, Any]:
    for band in BAND_DB:
        if band["f_min"] <= freq_mhz <= band["f_max"]:
            width_mhz = band["ch_khz"] / 1000.0 if band["ch_khz"] else 0.0
            channel = int((freq_mhz - band["f_min"]) / width_mhz) + 1 if width_mhz else None
            confidence = 0.75
            if bandwidth_khz is not None and band["ch_khz"]:
                delta = abs(float(bandwidth_khz) - float(band["ch_khz"]))
                confidence = 0.95 if delta <= band["ch_khz"] * 0.3 else 0.7
            threat_level = band["threat"]
            if power_db > -40:
                threat_level = "alert"
            elif bandwidth_khz and band["ch_khz"] and abs(bandwidth_khz - band["ch_khz"]) > band["ch_khz"] * 0.8:
                threat_level = "monitor"
            return {
                "band": band["name"],
                "channel": channel,
                "classification": band["name"],
                "confidence": round(confidence, 3),
                "modulation": band["mod"],
                "description": band["description"],
                "isKnown": True,
                "threat_level": threat_level,
                "is_walkie_talkie": band["name"] in ("PMR446", "FRS", "GMRS"),
            }
    return {
        "band": "UNKNOWN",
        "channel": None,
        "classification": "UNKNOWN",
        "confidence": 0.0,
        "modulation": "UNKNOWN",
        "description": "Unidentified signal",
        "isKnown": False,
        "threat_level": "alert",
        "is_walkie_talkie": False,
    }


class AdaptiveScanEngine:
    def __init__(self, base_interval: float = 2.0):
        self.base_interval = base_interval
        self.current_interval = base_interval
        self.min_interval = 0.5
        self.max_interval = 30.0
        self.threat_frequencies: set[float] = set()
        self.dwell_scans_remaining = 0
        self.stable_scans = 0

    def update_interval(self, new_results: list[dict[str, Any]], prev_results: list[dict[str, Any]]) -> None:
        new_threats = [r for r in new_results if r.get("threat_level") == "alert"]
        new_devices = len(
            [r for r in new_results if r["freq_mhz"] not in {p["freq_mhz"] for p in prev_results}]
        )
        stable = (
            len(new_results) == len(prev_results)
            and {r["freq_mhz"] for r in new_results} == {p["freq_mhz"] for p in prev_results}
        )

        if new_threats:
            self.current_interval = self.min_interval
            self.threat_frequencies.update(round(r["freq_mhz"], 4) for r in new_threats)
            self.dwell_scans_remaining = 5
            self.stable_scans = 0
        elif new_devices > 0:
            self.current_interval = max(self.min_interval, self.current_interval * 0.7)
            self.stable_scans = 0
        elif stable:
            self.stable_scans += 1
            if self.stable_scans >= 3:
                self.current_interval = min(self.max_interval, self.current_interval * 1.25)
        elif not new_results:
            self.current_interval = min(self.max_interval, self.current_interval * 1.2)
            self.stable_scans = 0
        else:
            self.current_interval = self.base_interval
            self.stable_scans = 0

        if self.dwell_scans_remaining > 0:
            self.dwell_scans_remaining -= 1
        elif self.threat_frequencies:
            self.threat_frequencies.clear()

    def get_priority_frequencies(self, scan_results: list[dict[str, Any]]) -> list[float]:
        threats = [round(r["freq_mhz"], 4) for r in scan_results if r.get("threat_level") in ("alert", "monitor")]
        prioritized = list(dict.fromkeys(threats + list(self.threat_frequencies)))
        return prioritized


class SignalTracker:
    def __init__(self) -> None:
        self.memory: dict[str, dict[str, Any]] = {}

    def update(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = time.time()
        seen_keys: set[str] = set()
        enriched: list[dict[str, Any]] = []

        for sig in signals:
            key = freq_to_signal_key(float(sig["freq_mhz"]))
            state = self.memory.get(key)
            if state:
                state["last_seen"] = now
                state["seen_count"] += 1
                state["max_power"] = max(state["max_power"], sig["power_db"])
                sig["confirmed"] = state["seen_count"] >= 2
                sig["duration_ms"] = round((now - state["first_seen"]) * 1000.0, 1)
                sig["first_seen"] = False
                sig["first_seen_ts"] = state["first_seen_iso"]
                sig["was_known"] = True
            else:
                state = {
                    "first_seen": now,
                    "first_seen_iso": utc_now(),
                    "last_seen": now,
                    "seen_count": 1,
                    "max_power": sig["power_db"],
                    "misses": 0,
                }
                self.memory[key] = state
                sig["confirmed"] = False
                sig["duration_ms"] = 0.0
                sig["first_seen"] = True
                sig["first_seen_ts"] = state["first_seen_iso"]
                sig["was_known"] = False

            state["misses"] = 0
            sig["signal_key"] = key
            seen_keys.add(key)
            enriched.append(sig)

        for key, state in list(self.memory.items()):
            if key in seen_keys:
                continue
            state["misses"] += 1
            if state["misses"] > 3:
                del self.memory[key]

        return enriched


class DecisionEngine:
    def __init__(self) -> None:
        self.last_fired: dict[str, float] = {}
        self.rules = [
            {
                "id": "rule_unknown_signal",
                "name": "Unknown Signal Detected",
                "priority": "high",
                "cooldown": 30.0,
                "action": "alert",
                "condition": lambda s: s["classification"] == "UNKNOWN" and s["power_db"] > -95,
            },
            {
                "id": "rule_strong_walkie",
                "name": "Walkie-Talkie in Range",
                "priority": "medium",
                "cooldown": 10.0,
                "action": "notify",
                "condition": lambda s: s["band"] in ("PMR446", "FRS", "GMRS") and s["quality"] > 60,
            },
            {
                "id": "rule_signal_spike",
                "name": "Abnormal Signal Strength",
                "priority": "high",
                "cooldown": 15.0,
                "action": "alert",
                "condition": lambda s: s["power_db"] > -40,
            },
            {
                "id": "rule_new_device",
                "name": "New Device Appeared",
                "priority": "low",
                "cooldown": 5.0,
                "action": "notify",
                "condition": lambda s: bool(s.get("first_seen")),
            },
        ]

    def evaluate(self, device_id: str, scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = time.time()
        actions: list[dict[str, Any]] = []
        for sig in scan_results:
            for rule in self.rules:
                cache_key = f"{rule['id']}::{sig['signal_key']}"
                last = self.last_fired.get(cache_key, 0.0)
                if now - last < float(rule["cooldown"]):
                    continue
                if rule["condition"](sig):
                    self.last_fired[cache_key] = now
                    actions.append(
                        {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "action": rule["action"],
                            "priority": rule["priority"],
                            "signal_freq": sig["freq_mhz"],
                            "signal_band": sig["band"],
                            "signal_power": sig["power_db"],
                            "ts": utc_now(),
                            "ccId": device_id,
                        }
                    )
        return actions


class DataTransmitter:
    def __init__(self, server_url: str):
        self.endpoint = self._normalize_endpoint(server_url)
        self.session = requests.Session()

    @staticmethod
    def _normalize_endpoint(server_url: str) -> str:
        parsed = urlparse(server_url)
        if parsed.scheme in ("ws", "wss"):
            scheme = "https" if parsed.scheme == "wss" else "http"
            netloc = parsed.netloc
            return f"{scheme}://{netloc}/api/scan"
        if server_url.rstrip("/").endswith("/api/scan"):
            return server_url.rstrip("/")
        return server_url.rstrip("/") + "/api/scan"

    def send(self, payload: dict[str, Any]) -> None:
        try:
            resp = self.session.post(self.endpoint, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception as exc:
            log.warning("scan delivery failed: %s", exc)


class ScanEngine:
    SAMPLE_RATE = 2.4e6
    N_SAMPLES = 256 * 1024
    GAIN = "auto"
    DWELL_SEC = 0.12
    SIGNAL_THRESHOLD_DB = 6.0

    def __init__(self, simulate: bool = False):
        self.simulate = simulate or not HAS_RTL
        self.sdr = None
        self.scan_id = 0
        self.noise_memory: dict[str, float] = {}
        self.tracker = SignalTracker()
        self.decider = DecisionEngine()
        self.adaptive = AdaptiveScanEngine()
        self.previous_results: list[dict[str, Any]] = []
        self.device_id = socket.gethostname()
        if self.simulate:
            log.warning("RTL-SDR unavailable - running in simulation mode")

    def open(self) -> None:
        if self.simulate:
            return
        self.sdr = RtlSdr()
        self.sdr.sample_rate = self.SAMPLE_RATE
        self.sdr.gain = self.GAIN

    def close(self) -> None:
        if self.sdr is not None:
            self.sdr.close()
            self.sdr = None

    def ordered_scan_plan(self) -> list[dict[str, Any]]:
        priorities = self.adaptive.get_priority_frequencies(self.previous_results)
        if not priorities:
            return list(SCAN_PLAN)
        priority_names: list[str] = []
        for freq in priorities:
            for band in BAND_DB:
                if band["f_min"] <= freq <= band["f_max"] and band["name"] not in priority_names:
                    priority_names.append(band["name"])
        ranked = sorted(
            SCAN_PLAN,
            key=lambda item: (0 if item["name"] in priority_names else 1, item["name"]),
        )
        return ranked

    def read_samples(self, center_freq_hz: float) -> np.ndarray:
        if self.simulate:
            return self.simulate_samples(center_freq_hz)
        assert self.sdr is not None
        self.sdr.center_freq = center_freq_hz
        time.sleep(self.DWELL_SEC)
        return np.array(self.sdr.read_samples(self.N_SAMPLES))

    def simulate_samples(self, center_freq_hz: float) -> np.ndarray:
        n = self.N_SAMPLES
        t = np.arange(n) / self.SAMPLE_RATE
        iq = (np.random.randn(n) + 1j * np.random.randn(n)) * 0.01
        carriers: list[tuple[float, float, str]] = []

        if abs(center_freq_hz - 446.100e6) < 1.5e6 and random.random() < 0.45:
            ch, freq = random.choice(list(PMR446_CHANNELS.items()))
            carriers.append((freq * 1e6 - center_freq_hz, 10 ** (random.uniform(-65, -42) / 20.0), "voice"))
        if abs(center_freq_hz - 465.000e6) < 4e6 and random.random() < 0.35:
            ch, freq = random.choice(list(FRS_CHANNELS.items()))
            carriers.append((freq * 1e6 - center_freq_hz, 10 ** (random.uniform(-68, -44) / 20.0), "voice"))
        if abs(center_freq_hz - 433.920e6) < 1e6 and random.random() < 0.5:
            carriers.append((0.0, 10 ** (random.uniform(-62, -38) / 20.0), "burst"))
        if abs(center_freq_hz - 868.300e6) < 0.8e6 and random.random() < 0.35:
            carriers.append((gaussian(0.0, 120000.0), 10 ** (random.uniform(-70, -48) / 20.0), "lora"))
        if abs(center_freq_hz - 127.500e6) < 10e6 and random.random() < 0.12:
            carriers.append((gaussian(0.0, 250000.0), 10 ** (random.uniform(-72, -52) / 20.0), "am"))
        if random.random() < 0.08:
            carriers.append((gaussian(0.0, self.SAMPLE_RATE / 6.0), 10 ** (random.uniform(-50, -32) / 20.0), "unknown"))

        for offset_hz, amplitude, mode in carriers:
            if mode == "voice":
                audio = np.sin(2 * np.pi * 800 * t) + 0.35 * np.sin(2 * np.pi * 1400 * t)
                phase = 2 * np.pi * (offset_hz * t + 0.35 * np.cumsum(audio) / self.SAMPLE_RATE)
            elif mode == "burst":
                gate = (np.sin(2 * np.pi * 18 * t) > 0).astype(float)
                phase = 2 * np.pi * offset_hz * t
                iq += amplitude * gate * np.exp(1j * phase)
                continue
            else:
                phase = 2 * np.pi * offset_hz * t
            iq += amplitude * np.exp(1j * phase)

        time.sleep(self.DWELL_SEC * 0.25)
        return iq

    def compute_psd(self, samples: np.ndarray, center_freq_hz: float) -> tuple[np.ndarray, np.ndarray]:
        if HAS_SCIPY:
            freqs, power = welch(samples, fs=self.SAMPLE_RATE, nperseg=min(4096, len(samples)), return_onesided=False)
        else:
            freqs = np.fft.fftfreq(len(samples), d=1.0 / self.SAMPLE_RATE)
            power = np.abs(np.fft.fft(samples)) ** 2 / max(1, len(samples))
        power_db = 10 * np.log10(np.maximum(power, 1e-12))
        return center_freq_hz + np.fft.fftshift(freqs), np.fft.fftshift(power_db)

    def estimate_noise_floor(self, band_name: str, power_db: np.ndarray) -> float:
        median_db = float(np.median(power_db))
        prev = self.noise_memory.get(band_name, median_db)
        smoothed = prev * 0.92 + median_db * 0.08
        self.noise_memory[band_name] = smoothed
        return smoothed

    def detect_signals(self, freqs_hz: np.ndarray, power_db: np.ndarray, noise_floor: float) -> list[dict[str, Any]]:
        threshold = noise_floor + self.SIGNAL_THRESHOLD_DB
        if HAS_SCIPY:
            peaks, _ = find_peaks(power_db, height=threshold, distance=8, prominence=3)
        else:
            peaks = np.where(
                (power_db[1:-1] > power_db[:-2])
                & (power_db[1:-1] > power_db[2:])
                & (power_db[1:-1] > threshold)
            )[0] + 1

        bin_width_hz = self.SAMPLE_RATE / max(1, len(power_db))
        results: list[dict[str, Any]] = []
        for idx in peaks:
            left = idx
            right = idx
            while left > 0 and power_db[left - 1] > threshold:
                left -= 1
            while right < len(power_db) - 1 and power_db[right + 1] > threshold:
                right += 1
            bandwidth_khz = max(1.0, ((right - left + 1) * bin_width_hz) / 1000.0)
            freq_mhz = round(float(freqs_hz[idx]) / 1e6, 4)
            power = round(float(power_db[idx]), 2)
            snr = round(power - noise_floor, 2)
            classified = classify_signal(freq_mhz, power, bandwidth_khz)
            quality = quality_from_power(power, snr)
            results.append(
                {
                    "freq_mhz": freq_mhz,
                    "power_db": power,
                    "snr_db": snr,
                    "bandwidth_khz": round(float(bandwidth_khz), 2),
                    "quality": quality,
                    **classified,
                }
            )
        return results

    def build_band_summary(self, band_name: str, noise_floor: float, signals: list[dict[str, Any]]) -> dict[str, Any]:
        occupancy: dict[str, bool] = {}
        for sig in signals:
            if sig.get("channel") is not None:
                occupancy[str(sig["channel"])] = True
        return {
            "active": signals,
            "noise_floor": round(noise_floor, 2),
            "channel_occupancy": occupancy,
        }

    def scan_once(self) -> dict[str, Any]:
        started = time.perf_counter()
        raw_signals: list[dict[str, Any]] = []
        band_noise: dict[str, float] = {}
        grouped_raw: dict[str, list[dict[str, Any]]] = {}

        for plan in self.ordered_scan_plan():
            center_freq_hz = plan["center_mhz"] * 1e6
            samples = self.read_samples(center_freq_hz)
            freqs, power_db = self.compute_psd(samples, center_freq_hz)
            noise_floor = self.estimate_noise_floor(plan["name"], power_db)
            peaks = self.detect_signals(freqs, power_db, noise_floor)
            band_noise[plan["name"]] = round(noise_floor, 2)
            grouped_raw[plan["name"]] = peaks
            raw_signals.extend(peaks)

        tracked = self.tracker.update(raw_signals)
        grouped_final: dict[str, list[dict[str, Any]]] = {}
        for sig in tracked:
            grouped_final.setdefault(sig["band"], []).append(sig)

        decisions = self.decider.evaluate(self.device_id, tracked)
        self.adaptive.update_interval(tracked, self.previous_results)
        self.previous_results = [dict(item) for item in tracked]

        bands = {
            plan["name"]: self.build_band_summary(
                plan["name"],
                band_noise.get(plan["name"], -100.0),
                grouped_final.get(plan["name"], []),
            )
            for plan in SCAN_PLAN
        }

        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        wt_active = sum(1 for sig in tracked if sig.get("is_walkie_talkie"))
        threat_count = sum(1 for sig in tracked if sig.get("threat_level") == "alert")
        self.scan_id += 1
        return {
            "scan_id": self.scan_id,
            "timestamp": utc_now(),
            "mode": "simulate" if self.simulate else "hardware",
            "device_id": self.device_id,
            "scan_duration_ms": elapsed_ms,
            "total_signals": len(tracked),
            "wt_active": wt_active,
            "threat_count": threat_count,
            "adaptive_interval": round(self.adaptive.current_interval, 2),
            "noise_floors": band_noise,
            "all_signals": tracked,
            "bands": bands,
            "decision_actions": decisions,
        }


def run(args: argparse.Namespace) -> None:
    engine = ScanEngine(simulate=args.simulate)
    transmitter = DataTransmitter(args.server)
    engine.adaptive.base_interval = args.interval
    engine.adaptive.current_interval = args.interval
    engine.open()

    log.info("starting scanner | mode=%s | endpoint=%s", "simulate" if engine.simulate else "hardware", transmitter.endpoint)
    try:
        while True:
            cycle_started = time.perf_counter()
            result = engine.scan_once()
            transmitter.send(result)
            log.info(
                "scan=%s signals=%s walkies=%s threats=%s next=%.2fs",
                result["scan_id"],
                result["total_signals"],
                result["wt_active"],
                result["threat_count"],
                result["adaptive_interval"],
            )
            for sig in result["all_signals"][:8]:
                log.info(
                    "  %-10s %8.4f MHz %7.1f dB SNR %6.1f %s",
                    sig["classification"],
                    sig["freq_mhz"],
                    sig["power_db"],
                    sig["snr_db"],
                    sig["threat_level"],
                )
            sleep_for = max(0.0, float(result["adaptive_interval"]) - (time.perf_counter() - cycle_started))
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        log.info("stopped by user")
    finally:
        engine.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CHEMCHAM scanner")
    parser.add_argument("--server", default="http://localhost:5000", help="Server base URL or /api/scan endpoint")
    parser.add_argument("--interval", type=float, default=2.0, help="Base scan interval in seconds")
    parser.add_argument("--simulate", action="store_true", help="Force simulation mode")
    args = parser.parse_args()
    run(args)
