"""
IoT SDR Backend Server
Bridges MQTT → WebSocket → Dashboard
Also provides REST API for history and config.

Usage:
  python server.py              # connects to MQTT broker
  python server.py --simulate   # generates its own fake data (no Pi needed)

Endpoints:
  WS  ws://localhost:8765          — live signal stream
  GET http://localhost:8766/api/signals    — recent detections (JSON)
  GET http://localhost:8766/api/stats      — summary stats
  GET http://localhost:8766/api/config     — scanner config
  PUT http://localhost:8766/api/config     — update config (pushed to scanner)
"""

import argparse
import asyncio
import json
import logging
import math
import random
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import websockets

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

WS_HOST        = "0.0.0.0"
WS_PORT        = 8765
HTTP_HOST      = "0.0.0.0"
HTTP_PORT      = 8766
MQTT_BROKER    = "localhost"
MQTT_PORT      = 1883
MQTT_TOPIC     = "sdr/detections"
HISTORY_SIZE   = 500   # max detections kept in memory

# Mutable scanner config (can be updated via API)
SCANNER_CONFIG = {
    "bands":          ["PMR446", "VHF", "UHF-Low", "UHF-High", "ISM-433", "FM-Radio", "Weather"],
    "rssi_threshold": -85,
    "scan_interval":  1.0,
    "gain":           40,
    "simulate":       False,
}

# ──────────────────────────────────────────────
# Shared state
# ──────────────────────────────────────────────

_ws_clients:   set  = set()
_signal_history: deque = deque(maxlen=HISTORY_SIZE)
_band_stats: dict   = {}   # band → {count, last_rssi, last_seen}
_scan_count: int    = 0

def _update_band_stats(detections: list):
    global _scan_count
    _scan_count += 1
    for d in detections:
        band = d.get("band", "Unknown")
        if band not in _band_stats:
            _band_stats[band] = {"count": 0, "last_rssi": -999, "last_seen": None}
        _band_stats[band]["count"]     += 1
        _band_stats[band]["last_rssi"]  = d.get("rssi", -99)
        _band_stats[band]["last_seen"]  = d.get("timestamp")

# ──────────────────────────────────────────────
# WebSocket server
# ──────────────────────────────────────────────

async def ws_handler(websocket):
    _ws_clients.add(websocket)
    client_addr = websocket.remote_address
    logging.info(f"Dashboard connected: {client_addr} "
                 f"(total: {len(_ws_clients)})")

    # Send current history immediately on connect
    snapshot = {
        "type":    "snapshot",
        "history": list(_signal_history)[-100:],  # last 100
        "stats":   _band_stats,
        "config":  SCANNER_CONFIG,
        "scans":   _scan_count,
    }
    try:
        await websocket.send(json.dumps(snapshot))
    except Exception:
        pass

    try:
        async for raw in websocket:
            msg = json.loads(raw)
            if msg.get("type") == "config_update":
                SCANNER_CONFIG.update(msg.get("config", {}))
                logging.info(f"Config updated: {SCANNER_CONFIG}")
                # Broadcast config change to all clients
                await broadcast({"type": "config", "config": SCANNER_CONFIG})
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _ws_clients.discard(websocket)
        logging.info(f"Dashboard disconnected: {client_addr} "
                     f"(total: {len(_ws_clients)})")

async def broadcast(payload: dict):
    if not _ws_clients:
        return
    msg = json.dumps(payload)
    disconnected = set()
    for ws in list(_ws_clients):
        try:
            await ws.send(msg)
        except Exception:
            disconnected.add(ws)
    _ws_clients.difference_update(disconnected)

async def push_detections(detections: list):
    """Store detections and push to all dashboard clients."""
    _signal_history.extend(detections)
    _update_band_stats(detections)

    await broadcast({
        "type":       "detections",
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "detections": detections,
        "stats":      _band_stats,
        "scans":      _scan_count,
    })

# ──────────────────────────────────────────────
# MQTT bridge
# ──────────────────────────────────────────────

_loop: asyncio.AbstractEventLoop = None

def mqtt_on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload)
        dets    = payload.get("detections", [])
        if dets and _loop:
            asyncio.run_coroutine_threadsafe(push_detections(dets), _loop)
    except Exception as e:
        logging.error(f"MQTT parse error: {e}")

def start_mqtt():
    if not MQTT_AVAILABLE:
        logging.warning("paho-mqtt not available — MQTT disabled")
        return
    client = mqtt.Client()
    client.on_message = mqtt_on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT)
        client.subscribe(MQTT_TOPIC)
        client.loop_forever()
    except Exception as e:
        logging.warning(f"MQTT bridge failed: {e}")

# ──────────────────────────────────────────────
# Simulation mode (no Pi needed)
# ──────────────────────────────────────────────

SIM_TRANSMITTERS = [
    {"freq": 446.00625, "rssi": -62, "band": "PMR446",   "mod": "FM",  "drift": 0.4},
    {"freq": 446.01875, "rssi": -74, "band": "PMR446",   "mod": "FM",  "drift": 0.6},
    {"freq": 162.400,   "rssi": -55, "band": "Weather",  "mod": "FM",  "drift": 0.1},
    {"freq": 96.5,      "rssi": -45, "band": "FM-Radio", "mod": "FM",  "drift": 0.05},
    {"freq": 101.1,     "rssi": -48, "band": "FM-Radio", "mod": "FM",  "drift": 0.05},
    {"freq": 433.920,   "rssi": -71, "band": "ISM-433",  "mod": "FM",  "drift": 1.2},
    {"freq": 462.575,   "rssi": -78, "band": "UHF-High", "mod": "FM",  "drift": 0.8},
    {"freq": 155.340,   "rssi": -66, "band": "VHF",      "mod": "FM",  "drift": 0.4},
    {"freq": 107.9,     "rssi": -50, "band": "FM-Radio", "mod": "FM",  "drift": 0.05},
]

async def simulate_scanner():
    """Generates fake signal detections every second."""
    scan_id = 0
    logging.info("Simulation mode active — generating fake signals")
    while True:
        detections = []
        for tx in SIM_TRANSMITTERS:
            if tx["band"] not in SCANNER_CONFIG["bands"]:
                continue
            if random.random() < 0.07:
                continue  # signal fades
            rssi = tx["rssi"] + random.gauss(0, tx["drift"])
            rssi = round(min(-30, max(-100, rssi)), 1)
            if rssi > SCANNER_CONFIG["rssi_threshold"]:
                detections.append({
                    "device_id":  "sdr-node-01",
                    "timestamp":  datetime.utcnow().isoformat() + "Z",
                    "frequency":  round(tx["freq"] + random.gauss(0, 0.001), 5),
                    "rssi":       rssi,
                    "band":       tx["band"],
                    "modulation": tx["mod"],
                    "active":     True,
                    "scan_id":    scan_id,
                })

        # Occasional burst (walkie-talkie keying up)
        if "PMR446" in SCANNER_CONFIG["bands"] and random.random() < 0.10:
            ch = random.choice([446.03125, 446.04375, 446.05625, 446.06875])
            detections.append({
                "device_id":  "sdr-node-01",
                "timestamp":  datetime.utcnow().isoformat() + "Z",
                "frequency":  ch,
                "rssi":       round(random.uniform(-80, -60), 1),
                "band":       "PMR446",
                "modulation": "FM",
                "active":     True,
                "scan_id":    scan_id,
            })

        if detections:
            await push_detections(detections)

        scan_id += 1
        await asyncio.sleep(SCANNER_CONFIG["scan_interval"])

# ──────────────────────────────────────────────
# HTTP REST API (simple, no framework needed)
# ──────────────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default HTTP logs

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/signals":
            self._send_json({
                "count":    len(_signal_history),
                "signals":  list(_signal_history)[-200:],
            })
        elif self.path == "/api/stats":
            self._send_json({
                "band_stats": _band_stats,
                "scan_count": _scan_count,
                "connected_clients": len(_ws_clients),
                "uptime": time.strftime("%H:%M:%S", time.gmtime(
                    time.time() - _start_time
                )),
            })
        elif self.path == "/api/config":
            self._send_json(SCANNER_CONFIG)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_PUT(self):
        if self.path == "/api/config":
            length  = int(self.headers.get("Content-Length", 0))
            body    = self.rfile.read(length)
            try:
                updates = json.loads(body)
                SCANNER_CONFIG.update(updates)
                self._send_json({"ok": True, "config": SCANNER_CONFIG})
                logging.info(f"Config updated via HTTP: {updates}")
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, 400)
        else:
            self._send_json({"error": "not found"}, 404)

def start_http():
    server = HTTPServer((HTTP_HOST, HTTP_PORT), APIHandler)
    logging.info(f"REST API listening on http://{HTTP_HOST}:{HTTP_PORT}")
    server.serve_forever()

# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

_start_time = time.time()

async def main_async(simulate: bool):
    global _loop
    _loop = asyncio.get_running_loop()

    tasks = []

    # WebSocket server
    ws_server = await websockets.serve(ws_handler, WS_HOST, WS_PORT)
    logging.info(f"WebSocket server listening on ws://{WS_HOST}:{WS_PORT}")

    if simulate:
        tasks.append(asyncio.create_task(simulate_scanner()))
    else:
        # MQTT bridge runs in a thread (paho is not async)
        mqtt_thread = Thread(target=start_mqtt, daemon=True)
        mqtt_thread.start()

    await asyncio.gather(*tasks, return_exceptions=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true",
                        help="Generate fake signals (no Pi/MQTT needed)")
    parser.add_argument("--broker", default=MQTT_BROKER)
    parser.add_argument("--port",   default=MQTT_PORT, type=int)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    # HTTP API in background thread
    http_thread = Thread(target=start_http, daemon=True)
    http_thread.start()

    try:
        asyncio.run(main_async(simulate=args.simulate))
    except KeyboardInterrupt:
        logging.info("Server stopped")

if __name__ == "__main__":
    main()