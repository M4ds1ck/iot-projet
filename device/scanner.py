#!/usr/bin/env python3
"""
IoT RF Signal Scanner - Enhanced Device Script
================================================
Scans the RF spectrum, detects signals, identifies walkie-talkie
channels (PMR446, FRS/GMRS, CB), and streams data to the server
via WebSocket in real time.

Hardware: RTL-SDR dongle (rtl2832u + R820T2 tuner)
Fallback:  Simulation mode when no hardware is present.

Dependencies:
    pip install pyrtlsdr numpy scipy websocket-client
"""

import time
import json
import math
import random
import threading
import argparse
import logging
from datetime import datetime
from typing import Optional

import numpy as np

# ── Optional hardware imports ────────────────────────────────────────────────
try:
    from rtlsdr import RtlSdr
    HAS_RTL = True
except ImportError:
    HAS_RTL = False

try:
    from scipy.signal import welch, find_peaks
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import websocket
    HAS_WS = True
except ImportError:
    HAS_WS = False

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("device")

# ═════════════════════════════════════════════════════════════════════════════
#  FREQUENCY BAND DEFINITIONS
# ═════════════════════════════════════════════════════════════════════════════

BANDS = {
    "PMR446": {
        "start":   446.006e6,
        "end":     446.194e6,
        "label":   "PMR446 (Walkie-Talkie EU)",
        "channels": 8,
        "channel_step": 25e3,
        "color":   "#00ff88",
        "priority": 1,
    },
    "FRS": {
        "start":   462.5625e6,
        "end":     467.7125e6,
        "label":   "FRS/GMRS (Walkie-Talkie US)",
        "channels": 22,
        "channel_step": 25e3,
        "color":   "#00d4ff",
        "priority": 1,
    },
    "CB": {
        "start":   26.965e6,
        "end":     27.405e6,
        "label":   "CB Radio (Citizens Band)",
        "channels": 40,
        "channel_step": 10e3,
        "color":   "#ffaa00",
        "priority": 2,
    },
    "AIRBAND": {
        "start":   118e6,
        "end":     137e6,
        "label":   "Aviation VHF",
        "channels": None,
        "channel_step": 25e3,
        "color":   "#ff6644",
        "priority": 3,
    },
    "MARINE_VHF": {
        "start":   156e6,
        "end":     174e6,
        "label":   "Marine VHF",
        "channels": 60,
        "channel_step": 25e3,
        "color":   "#4488ff",
        "priority": 3,
    },
    "ISM_433": {
        "start":   433.05e6,
        "end":     434.79e6,
        "label":   "ISM 433 MHz (IoT/Remote)",
        "channels": None,
        "channel_step": 200e3,
        "color":   "#dd44ff",
        "priority": 2,
    },
    "ISM_868": {
        "start":   868e6,
        "end":     868.6e6,
        "label":   "ISM 868 MHz (LoRa/Sigfox)",
        "channels": None,
        "channel_step": 200e3,
        "color":   "#ff44aa",
        "priority": 2,
    },
    "GSM_900": {
        "start":   935e6,
        "end":     960e6,
        "label":   "GSM 900 (Downlink)",
        "channels": None,
        "channel_step": 200e3,
        "color":   "#aaaaaa",
        "priority": 4,
    },
}

# PMR446 channel frequencies (8 channels)
PMR446_CHANNELS = {
    1: 446.006e6, 2: 446.019e6, 3: 446.031e6, 4: 446.044e6,
    5: 446.056e6, 6: 446.069e6, 7: 446.081e6, 8: 446.094e6,
}

# FRS/GMRS channel frequencies (22 channels)
FRS_CHANNELS = {i: 462.5625e6 + (i - 1) * 25e3 for i in range(1, 8)}
FRS_CHANNELS.update({8: 467.5625e6, 9: 467.5875e6})
for i in range(10, 15):
    FRS_CHANNELS[i] = 462.5500e6 + (i - 10) * 25e3
for i in range(15, 23):
    FRS_CHANNELS[i] = 467.5500e6 + (i - 15) * 25e3

# ═════════════════════════════════════════════════════════════════════════════
#  SIGNAL ANALYSER
# ═════════════════════════════════════════════════════════════════════════════

class SignalAnalyzer:
    """Processes raw IQ samples into meaningful signal metrics."""

    NOISE_FLOOR_ALPHA = 0.05        # adaptive noise floor update rate
    SIGNAL_THRESHOLD_DB = 6.0      # dB above noise floor to be "active"
    MIN_DURATION_MS = 50            # signal must persist this long

    def __init__(self):
        self.noise_floor_db: float = -100.0
        self.active_signals: dict = {}   # freq_hz -> {start, last_seen, peak_db}
        self.history: list = []

    # ── Core PSD ─────────────────────────────────────────────────────────────
    def compute_psd(self, samples: np.ndarray, sample_rate: float,
                    center_freq: float) -> tuple[np.ndarray, np.ndarray]:
        """Return (frequencies_hz, power_db) via Welch's method."""
        n = len(samples)
        if HAS_SCIPY:
            f, p = welch(samples, fs=sample_rate, nperseg=min(1024, n),
                         return_onesided=False)
        else:
            f = np.fft.fftfreq(n, d=1.0 / sample_rate)
            p = np.abs(np.fft.fft(samples)) ** 2 / n

        p_db = 10 * np.log10(np.maximum(p, 1e-12))
        freqs = center_freq + np.fft.fftshift(f)
        p_db  = np.fft.fftshift(p_db)
        return freqs, p_db

    # ── Noise floor ──────────────────────────────────────────────────────────
    def update_noise_floor(self, power_db: np.ndarray) -> float:
        median_db = float(np.median(power_db))
        self.noise_floor_db = (
            (1 - self.NOISE_FLOOR_ALPHA) * self.noise_floor_db
            + self.NOISE_FLOOR_ALPHA * median_db
        )
        return self.noise_floor_db

    # ── Peak detection ───────────────────────────────────────────────────────
    def detect_peaks(self, freqs: np.ndarray, power_db: np.ndarray,
                     noise_floor: float) -> list[dict]:
        threshold = noise_floor + self.SIGNAL_THRESHOLD_DB
        if HAS_SCIPY:
            peaks, props = find_peaks(power_db, height=threshold,
                                      distance=5, prominence=3)
        else:
            peaks = np.where(
                (power_db[1:-1] > power_db[:-2]) &
                (power_db[1:-1] > power_db[2:]) &
                (power_db[1:-1] > threshold)
            )[0] + 1

        results = []
        for idx in peaks:
            freq  = float(freqs[idx])
            power = float(power_db[idx])
            snr   = power - noise_floor
            bw    = self._estimate_bandwidth(power_db, idx, threshold)
            mod   = self._classify_modulation(snr, bw)
            band  = self._identify_band(freq)
            ch    = self._identify_channel(freq, band)
            results.append({
                "freq_hz":     freq,
                "freq_mhz":    round(freq / 1e6, 4),
                "power_db":    round(power, 2),
                "snr_db":      round(snr, 2),
                "bandwidth_hz": bw,
                "modulation":  mod,
                "band":        band,
                "channel":     ch,
                "is_walkie_talkie": band in ("PMR446", "FRS"),
            })
        return results

    def _estimate_bandwidth(self, power_db: np.ndarray, peak_idx: int,
                            threshold: float) -> float:
        lo = hi = peak_idx
        while lo > 0 and power_db[lo - 1] > threshold:
            lo -= 1
        while hi < len(power_db) - 1 and power_db[hi + 1] > threshold:
            hi += 1
        return int(hi - lo)   # in bins; caller can convert with bin width

    def _classify_modulation(self, snr_db: float, bw_bins: int) -> str:
        if bw_bins <= 2:
            return "CW/Narrowband"
        elif bw_bins <= 8:
            return "NFM" if snr_db > 15 else "AM"
        elif bw_bins <= 20:
            return "WFM"
        else:
            return "Digital/Spread"

    def _identify_band(self, freq_hz: float) -> Optional[str]:
        for name, b in BANDS.items():
            if b["start"] <= freq_hz <= b["end"]:
                return name
        return None

    def _identify_channel(self, freq_hz: float, band: Optional[str]) -> Optional[int]:
        if band == "PMR446":
            for ch, f in PMR446_CHANNELS.items():
                if abs(freq_hz - f) < 10e3:
                    return ch
        elif band == "FRS":
            for ch, f in FRS_CHANNELS.items():
                if abs(freq_hz - f) < 10e3:
                    return ch
        return None

    # ── Track signal persistence ──────────────────────────────────────────────
    def track_signals(self, peaks: list[dict]) -> list[dict]:
        now_ms = time.time() * 1000
        seen_freqs = set()
        enriched = []

        for pk in peaks:
            f = round(pk["freq_hz"] / 25e3) * 25e3    # quantize to 25 kHz
            seen_freqs.add(f)
            if f in self.active_signals:
                self.active_signals[f]["last_seen"] = now_ms
                self.active_signals[f]["peak_db"] = max(
                    self.active_signals[f]["peak_db"], pk["power_db"])
                self.active_signals[f]["count"] += 1
            else:
                self.active_signals[f] = {
                    "start": now_ms,
                    "last_seen": now_ms,
                    "peak_db": pk["power_db"],
                    "count": 1,
                }
            duration_ms = now_ms - self.active_signals[f]["start"]
            pk["duration_ms"] = round(duration_ms)
            pk["confirmed"] = duration_ms >= self.MIN_DURATION_MS
            enriched.append(pk)

        # expire stale signals
        stale = [f for f, v in self.active_signals.items()
                 if now_ms - v["last_seen"] > 500]
        for f in stale:
            del self.active_signals[f]

        return enriched


# ═════════════════════════════════════════════════════════════════════════════
#  SCAN ENGINE (Real hardware + Simulation fallback)
# ═════════════════════════════════════════════════════════════════════════════

class ScanEngine:
    """Iterates over frequency bands, collects IQ samples, and analyses them."""

    SAMPLE_RATE  = 2.4e6          # 2.4 MS/s
    GAIN         = "auto"
    N_SAMPLES    = 256 * 1024     # ~100 ms at 2.4 MS/s
    DWELL_SEC    = 0.15           # time per frequency stop
    LOOP_BANDS   = ["PMR446", "FRS", "CB", "AIRBAND",
                    "MARINE_VHF", "ISM_433", "ISM_868"]

    def __init__(self, simulate: bool = False):
        self.simulate = simulate or not HAS_RTL
        self.sdr: Optional["RtlSdr"] = None
        self.analyzer = SignalAnalyzer()
        self._running = False
        self._lock    = threading.Lock()
        self._scan_count = 0
        if self.simulate:
            log.warning("RTL-SDR not found — running in SIMULATION mode")
        else:
            log.info("RTL-SDR hardware detected")

    def open(self):
        if not self.simulate:
            self.sdr = RtlSdr()
            self.sdr.sample_rate = self.SAMPLE_RATE
            self.sdr.gain        = self.GAIN
            log.info(f"RTL-SDR opened | SR={self.SAMPLE_RATE/1e6:.1f} MS/s")

    def close(self):
        if self.sdr:
            self.sdr.close()

    # ── Read one chunk ────────────────────────────────────────────────────────
    def _read_samples(self, center_freq: float) -> np.ndarray:
        if self.simulate:
            return self._sim_samples(center_freq)
        self.sdr.center_freq = center_freq
        time.sleep(self.DWELL_SEC)
        raw = self.sdr.read_samples(self.N_SAMPLES)
        return np.array(raw)

    # ── Simulation: realistic-looking RF environment ──────────────────────────
    def _sim_samples(self, center_freq: float) -> np.ndarray:
        n = self.N_SAMPLES
        t = np.arange(n) / self.SAMPLE_RATE
        noise = (np.random.randn(n) + 1j * np.random.randn(n)) * 0.01

        # Always-present carriers in simulation
        carriers = [
            # (freq_offset, amplitude, phase_variation)
        ]

        # PMR446 — random channel activity
        if abs(center_freq - 446.05e6) < 1.5e6:
            if random.random() < 0.35:   # 35 % chance of active channel
                ch = random.randint(1, 8)
                offset = PMR446_CHANNELS[ch] - center_freq
                amp    = 10 ** (random.uniform(-60, -40) / 20)
                carriers.append((offset, amp, True))

        # FRS — random activity
        if abs(center_freq - 465e6) < 3e6:
            if random.random() < 0.20:
                ch     = random.randint(1, 14)
                offset = FRS_CHANNELS.get(ch, FRS_CHANNELS[1]) - center_freq
                amp    = 10 ** (random.uniform(-65, -45) / 20)
                carriers.append((offset, amp, False))

        # ISM 433 — bursty IoT
        if abs(center_freq - 433.92e6) < 1e6:
            if random.random() < 0.50:
                amp = 10 ** (random.uniform(-55, -35) / 20)
                carriers.append((0, amp, False))

        for offset, amp, voice in carriers:
            if voice:
                # FM voice: NFM + audio modulation
                audio = np.sin(2 * np.pi * 800 * t + 0.3 * np.random.randn(n))
                phase = 2 * np.pi * (offset * t + 0.5 * np.cumsum(audio) / self.SAMPLE_RATE)
            else:
                phase = 2 * np.pi * offset * t
            noise += amp * np.exp(1j * phase)

        time.sleep(self.DWELL_SEC * 0.3)  # simulate processing time
        return noise

    # ── Full scan loop ────────────────────────────────────────────────────────
    def scan_all_bands(self) -> dict:
        all_signals = []
        band_results = {}
        noise_floors = {}

        for band_name in self.LOOP_BANDS:
            band = BANDS[band_name]
            center = (band["start"] + band["end"]) / 2

            samples = self._read_samples(center)
            freqs, psd = self.analyzer.compute_psd(
                samples, self.SAMPLE_RATE, center)
            noise = self.analyzer.update_noise_floor(psd)
            peaks = self.analyzer.detect_peaks(freqs, psd, noise)
            peaks = self.analyzer.track_signals(peaks)

            noise_floors[band_name] = round(noise, 2)
            band_results[band_name] = {
                "label":       band["label"],
                "color":       band["color"],
                "noise_floor": round(noise, 2),
                "peak_count":  len(peaks),
                "active":      [p for p in peaks if p.get("confirmed")],
                "psd_sample":  self._downsample_psd(freqs, psd, 128),
            }
            all_signals.extend(peaks)

        self._scan_count += 1
        walkie_talkies = [s for s in all_signals if s.get("is_walkie_talkie")]
        return {
            "scan_id":        self._scan_count,
            "timestamp":      datetime.utcnow().isoformat() + "Z",
            "mode":           "simulation" if self.simulate else "hardware",
            "bands":          band_results,
            "all_signals":    all_signals,
            "walkie_talkies": walkie_talkies,
            "total_signals":  len(all_signals),
            "wt_active":      len(walkie_talkies),
            "noise_floors":   noise_floors,
        }

    def _downsample_psd(self, freqs, psd, n_points):
        """Return a compact spectrum snapshot for the dashboard."""
        idx = np.linspace(0, len(freqs) - 1, n_points, dtype=int)
        return {
            "freqs": [round(float(freqs[i]) / 1e6, 3) for i in idx],
            "power": [round(float(psd[i]), 1) for i in idx],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET TRANSMITTER
# ═════════════════════════════════════════════════════════════════════════════

class DataTransmitter:
    """Sends scan results to the server via WebSocket with auto-reconnect."""

    def __init__(self, server_url: str):
        self.url     = server_url
        self.ws: Optional["websocket.WebSocketApp"] = None
        self._connected = False
        self._queue: list = []
        self._lock  = threading.Lock()

    def connect_async(self):
        if not HAS_WS:
            log.warning("websocket-client not installed — printing to console")
            return

        def _on_open(ws):
            self._connected = True
            log.info(f"Connected to server: {self.url}")
            with self._lock:
                for msg in self._queue:
                    ws.send(msg)
                self._queue.clear()

        def _on_close(ws, code, msg):
            self._connected = False
            log.warning(f"Disconnected ({code}). Reconnecting in 5 s…")
            time.sleep(5)
            self.connect_async()

        def _on_error(ws, err):
            log.error(f"WS error: {err}")

        self.ws = websocket.WebSocketApp(
            self.url,
            on_open=_on_open,
            on_close=_on_close,
            on_error=_on_error,
        )
        t = threading.Thread(target=self.ws.run_forever, daemon=True)
        t.start()

    def send(self, data: dict):
        payload = json.dumps(data, default=str)
        if not HAS_WS:
            print(f"[SCAN #{data.get('scan_id')}] signals={data.get('total_signals')} "
                  f"walkie-talkies={data.get('wt_active')}")
            return
        if self._connected and self.ws:
            try:
                self.ws.send(payload)
            except Exception as e:
                log.error(f"Send failed: {e}")
                with self._lock:
                    self._queue.append(payload)
        else:
            with self._lock:
                self._queue = self._queue[-50:]    # cap buffer
                self._queue.append(payload)


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP
# ═════════════════════════════════════════════════════════════════════════════

def run(args):
    engine = ScanEngine(simulate=args.simulate)
    engine.open()

    tx = DataTransmitter(args.server)
    tx.connect_async()

    log.info(f"Starting scan loop | interval={args.interval}s | server={args.server}")

    try:
        while True:
            t0 = time.time()
            result = engine.scan_all_bands()

            # Console summary
            wt = result["wt_active"]
            total = result["total_signals"]
            mode  = result["mode"].upper()
            log.info(
                f"[{mode}] Scan #{result['scan_id']} | "
                f"{total} signal(s) | {wt} walkie-talkie(s)"
            )
            if wt:
                for s in result["walkie_talkies"]:
                    ch = f" ch{s['channel']}" if s.get("channel") else ""
                    log.info(
                        f"  WT  {s['freq_mhz']} MHz{ch} | "
                        f"{s['power_db']:.1f} dBm | SNR {s['snr_db']:.1f} dB | "
                        f"{s.get('modulation','?')} | {s.get('band','?')}"
                    )

            tx.send(result)

            elapsed = time.time() - t0
            sleep   = max(0.0, args.interval - elapsed)
            time.sleep(sleep)

    except KeyboardInterrupt:
        log.info("Stopped by user")
    finally:
        engine.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT RF Signal Scanner")
    parser.add_argument("--server",   default="ws://localhost:5000/ws",
                        help="WebSocket server URL")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Seconds between scans")
    parser.add_argument("--simulate", action="store_true",
                        help="Force simulation mode (no RTL-SDR needed)")
    args = parser.parse_args()
    run(args)