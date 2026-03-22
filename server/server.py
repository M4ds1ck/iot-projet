#!/usr/bin/env python3
"""
IoT RF Signal Scanner - Enhanced Server
=========================================
Flask + Flask-SocketIO server that:
  • Receives scan results from device(s) over WebSocket
  • Persists signal history in SQLite
  • Serves the dashboard HTML
  • Provides a REST API for history queries
  • Runs an alert engine for threshold violations

Dependencies:
    pip install flask flask-socketio flask-cors eventlet
"""

import json
import sqlite3
import threading
import time
import os
from datetime import datetime, timedelta
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory, abort
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS

# ─── App setup ───────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, "signals.db")
DASH_DIR  = os.path.join(BASE_DIR, "..", "dashboard")

app = Flask(__name__, static_folder=DASH_DIR)
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)

# ─── In-memory state (last N scans) ──────────────────────────────────────────
MAX_LIVE_HISTORY = 300          # scans kept in RAM
live_history: list[dict] = []
live_lock = threading.Lock()

# ─── Alert thresholds ────────────────────────────────────────────────────────
ALERTS: list[dict] = []
ALERT_LOG: list[dict] = []
MAX_ALERT_LOG = 500

DEFAULT_ALERTS = [
    {"id": "a1", "name": "Strong PMR446 signal",  "band": "PMR446",
     "threshold_db": -50, "active": True},
    {"id": "a2", "name": "Any FRS/GMRS activity", "band": "FRS",
     "threshold_db": -70, "active": True},
    {"id": "a3", "name": "High noise floor",       "band": None,
     "metric": "noise_floor", "threshold_db": -80, "active": True},
]
ALERTS.extend(DEFAULT_ALERTS)


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            timestamp   TEXT,
            mode        TEXT,
            total_sigs  INTEGER,
            wt_active   INTEGER,
            payload     TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS signals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_db_id  INTEGER,
            timestamp   TEXT,
            freq_mhz    REAL,
            power_db    REAL,
            snr_db      REAL,
            band        TEXT,
            channel     INTEGER,
            modulation  TEXT,
            is_wt       INTEGER,
            confirmed   INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            alert_id    TEXT,
            alert_name  TEXT,
            freq_mhz    REAL,
            power_db    REAL,
            band        TEXT,
            channel     INTEGER
        )
    """)
    conn.commit()
    conn.close()


def db_insert_scan(data: dict) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (scan_id, timestamp, mode, total_sigs, wt_active, payload)
        VALUES (?,?,?,?,?,?)
    """, (
        data.get("scan_id"),
        data.get("timestamp"),
        data.get("mode"),
        data.get("total_signals", 0),
        data.get("wt_active", 0),
        json.dumps(data),
    ))
    scan_db_id = c.lastrowid

    for sig in data.get("all_signals", []):
        if not sig.get("confirmed"):
            continue
        c.execute("""
            INSERT INTO signals
            (scan_db_id, timestamp, freq_mhz, power_db, snr_db,
             band, channel, modulation, is_wt, confirmed)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_db_id,
            data.get("timestamp"),
            sig.get("freq_mhz"),
            sig.get("power_db"),
            sig.get("snr_db"),
            sig.get("band"),
            sig.get("channel"),
            sig.get("modulation"),
            1 if sig.get("is_walkie_talkie") else 0,
            1,
        ))
    conn.commit()
    conn.close()
    return scan_db_id


def db_insert_alert(alert_data: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO alert_log
        (timestamp, alert_id, alert_name, freq_mhz, power_db, band, channel)
        VALUES (?,?,?,?,?,?,?)
    """, (
        alert_data["timestamp"],
        alert_data["alert_id"],
        alert_data["alert_name"],
        alert_data.get("freq_mhz"),
        alert_data.get("power_db"),
        alert_data.get("band"),
        alert_data.get("channel"),
    ))
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# Cooldown: don't re-fire the same alert within 30 s
_alert_cooldown: dict[str, float] = {}
COOLDOWN_SEC = 30.0


def check_alerts(scan_data: dict):
    now = time.time()
    fired = []

    for rule in ALERTS:
        if not rule.get("active"):
            continue
        key = rule["id"]
        if now - _alert_cooldown.get(key, 0) < COOLDOWN_SEC:
            continue

        # Band-specific signal threshold
        if rule.get("band"):
            band_data = scan_data.get("bands", {}).get(rule["band"], {})
            for sig in band_data.get("active", []):
                if sig.get("power_db", -999) >= rule["threshold_db"]:
                    ev = {
                        "timestamp":  datetime.utcnow().isoformat() + "Z",
                        "alert_id":   key,
                        "alert_name": rule["name"],
                        "freq_mhz":   sig.get("freq_mhz"),
                        "power_db":   sig.get("power_db"),
                        "band":       rule["band"],
                        "channel":    sig.get("channel"),
                    }
                    _alert_cooldown[key] = now
                    fired.append(ev)
                    ALERT_LOG.append(ev)
                    db_insert_alert(ev)
                    if len(ALERT_LOG) > MAX_ALERT_LOG:
                        ALERT_LOG.pop(0)
                    break

        # Noise floor threshold
        elif rule.get("metric") == "noise_floor":
            for band_name, nf in scan_data.get("noise_floors", {}).items():
                if nf >= rule["threshold_db"]:
                    ev = {
                        "timestamp":  datetime.utcnow().isoformat() + "Z",
                        "alert_id":   key,
                        "alert_name": rule["name"] + f" ({band_name})",
                        "power_db":   nf,
                        "band":       band_name,
                    }
                    _alert_cooldown[key] = now
                    fired.append(ev)
                    ALERT_LOG.append(ev)
                    db_insert_alert(ev)
                    break

    if fired:
        socketio.emit("alerts", fired, room="dashboard")

    return fired


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET EVENTS  (device → server)
# ═══════════════════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    print(f"[WS] Client connected: {request.sid}")


@socketio.on("disconnect")
def on_disconnect():
    print(f"[WS] Client disconnected: {request.sid}")


@socketio.on("join")
def on_join(data):
    room = data.get("room", "dashboard")
    join_room(room)
    print(f"[WS] {request.sid} joined room '{room}'")


@socketio.on("scan_result")
def on_scan_result(data: dict):
    """Receive a scan payload from the device."""
    try:
        # Persist
        db_insert_scan(data)

        # Update live history
        with live_lock:
            live_history.append(data)
            if len(live_history) > MAX_LIVE_HISTORY:
                live_history.pop(0)

        # Check alerts
        alerts = check_alerts(data)

        # Broadcast to all dashboard clients
        socketio.emit("scan_update", data, room="dashboard")

    except Exception as e:
        print(f"[ERROR] on_scan_result: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  REST API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/status")
def api_status():
    with live_lock:
        last = live_history[-1] if live_history else None
    return jsonify({
        "status": "ok",
        "scans_in_memory": len(live_history),
        "last_scan_ts": last["timestamp"] if last else None,
        "wt_active": last["wt_active"] if last else 0,
    })


@app.route("/api/latest")
def api_latest():
    with live_lock:
        if not live_history:
            return jsonify({}), 204
        return jsonify(live_history[-1])


@app.route("/api/history")
def api_history():
    """Return last N scans (default 60) with summary only."""
    n = min(int(request.args.get("n", 60)), 300)
    with live_lock:
        subset = live_history[-n:]
    summaries = [
        {
            "scan_id":       s.get("scan_id"),
            "timestamp":     s.get("timestamp"),
            "total_signals": s.get("total_signals"),
            "wt_active":     s.get("wt_active"),
            "noise_floors":  s.get("noise_floors"),
        }
        for s in subset
    ]
    return jsonify(summaries)


@app.route("/api/signals")
def api_signals():
    """Query persisted signals from DB."""
    band   = request.args.get("band")
    hours  = int(request.args.get("hours", 1))
    limit  = int(request.args.get("limit", 500))
    wt_only = request.args.get("wt_only", "false").lower() == "true"

    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    q = "SELECT * FROM signals WHERE timestamp >= ? "
    params = [since]
    if band:
        q += "AND band = ? "
        params.append(band)
    if wt_only:
        q += "AND is_wt = 1 "
    q += "ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(q, params)]
    conn.close()
    return jsonify(rows)


@app.route("/api/stats")
def api_stats():
    """Aggregate statistics from DB."""
    conn = sqlite3.connect(DB_PATH)
    stats = {}
    stats["total_scans"] = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    stats["total_signals"] = conn.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
    stats["wt_detections"] = conn.execute(
        "SELECT COUNT(*) FROM signals WHERE is_wt=1").fetchone()[0]
    stats["band_breakdown"] = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT band, COUNT(*) FROM signals WHERE band IS NOT NULL "
            "GROUP BY band ORDER BY COUNT(*) DESC"
        )
    }
    stats["top_channels"] = [
        {"freq_mhz": row[0], "count": row[1], "band": row[2]}
        for row in conn.execute(
            "SELECT freq_mhz, COUNT(*) as cnt, band FROM signals "
            "GROUP BY freq_mhz ORDER BY cnt DESC LIMIT 10"
        )
    ]
    conn.close()
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(ALERT_LOG[-100:])


@app.route("/api/alerts/rules")
def api_alert_rules():
    return jsonify(ALERTS)


@app.route("/api/alerts/rules/<rule_id>", methods=["PATCH"])
def api_toggle_alert(rule_id):
    data = request.get_json(force=True)
    for rule in ALERTS:
        if rule["id"] == rule_id:
            if "active" in data:
                rule["active"] = bool(data["active"])
            if "threshold_db" in data:
                rule["threshold_db"] = float(data["threshold_db"])
            return jsonify(rule)
    abort(404)


@app.route("/api/export/csv")
def api_export_csv():
    """Export signal history as CSV."""
    from io import StringIO
    import csv
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, freq_mhz, power_db, snr_db, band, channel, "
        "modulation, is_wt FROM signals ORDER BY timestamp DESC LIMIT 5000"
    ).fetchall()
    conn.close()

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "freq_mhz", "power_db", "snr_db",
                "band", "channel", "modulation", "is_walkie_talkie"])
    for r in rows:
        w.writerow(list(r))

    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=signals.csv"},
    )


# ─── Serve dashboard ─────────────────────────────────────────────────────────
@app.route("/")
def serve_dashboard():
    dash = os.path.join(BASE_DIR, "..", "dashboard", "index.html")
    if os.path.exists(dash):
        return send_from_directory(os.path.dirname(dash), "index.html")
    return "<h2>Dashboard not found. Place index.html in /dashboard/</h2>", 404


@app.route("/health")
def health():
    return "OK", 200


# ═══════════════════════════════════════════════════════════════════════════════
#  STARTUP
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IoT RF Signal Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    init_db()
    print(f"""
╔══════════════════════════════════════════════╗
║       IoT RF Signal Scanner — Server         ║
║  http://{args.host}:{args.port}              ║
║  Dashboard → http://localhost:{args.port}/   ║
╚══════════════════════════════════════════════╝
    """)
    socketio.run(app, host=args.host, port=args.port, debug=args.debug)