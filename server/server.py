#!/usr/bin/env python3
"""
CHEMCHAM IoT RF field server.

Flask + Flask-SocketIO backend that:
  - stores scan payloads and signal history in SQLite
  - tracks dashboard peer presence and walkie ownership
  - persists topology for late-joining clients
  - forwards WebRTC signaling messages between peers
  - logs decision actions, calls, alerts, and signaling events
"""

from __future__ import annotations

import csv
import json
import os
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import requests
from flask import Flask, Response, abort, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "signals.db"
ALERTS_FILE = BASE_DIR / "alerts.log"
DASH_DIR = BASE_DIR.parent / "dashboard"

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip()
MAX_LIVE_HISTORY = int(os.getenv("MAX_LIVE_HISTORY", "500"))
ALERT_COOLDOWN_SEC = float(os.getenv("ALERT_COOLDOWN_SEC", "30"))

HEARTBEAT_INTERVAL_SEC = 10
HEARTBEAT_TIMEOUT_SEC = HEARTBEAT_INTERVAL_SEC * 3
DISCONNECT_GRACE_SEC = 5

app = Flask(__name__, static_folder=str(DASH_DIR))
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)

live_history: list[dict[str, Any]] = []
live_lock = threading.RLock()

clients: dict[str, dict[str, Any]] = {}
clients_lock = threading.RLock()

call_sessions: dict[str, dict[str, Any]] = {}
call_lock = threading.RLock()

topology_state: dict[str, Any] = {
    "devices": {},
    "links": {},
    "nextId": 1,
    "updated_at": None,
    "updated_by": None,
}
topology_lock = threading.RLock()

ALERT_LOG: list[dict[str, Any]] = []
MAX_ALERT_LOG = 500

DEFAULT_ALERTS = [
    {
        "id": "a1",
        "name": "Strong PMR446 signal",
        "band": "PMR446",
        "threshold_db": -50,
        "active": True,
    },
    {
        "id": "a2",
        "name": "Any FRS/GMRS activity",
        "band": "FRS",
        "threshold_db": -70,
        "active": True,
    },
    {
        "id": "a3",
        "name": "High noise floor",
        "band": None,
        "metric": "noise_floor",
        "threshold_db": -80,
        "active": True,
    },
]
ALERTS: list[dict[str, Any]] = list(DEFAULT_ALERTS)
_alert_cooldown: dict[str, float] = {}
_background_tasks_started = False


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def current_ts() -> float:
    return time.time()


def default_topology() -> dict[str, Any]:
    return {"devices": {}, "links": {}, "nextId": 1, "updated_at": None, "updated_by": None}


def safe_json_load(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def normalize_topology(payload: Any) -> dict[str, Any]:
    topo = payload if isinstance(payload, dict) else {}
    return {
        "devices": topo.get("devices", {}) if isinstance(topo.get("devices", {}), dict) else {},
        "links": topo.get("links", {}) if isinstance(topo.get("links", {}), dict) else {},
        "nextId": int(topo.get("nextId", 1) or 1),
        "updated_at": topo.get("updated_at"),
        "updated_by": topo.get("updated_by"),
    }


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def init_db() -> None:
    conn = db_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id           INTEGER,
            timestamp         TEXT,
            mode              TEXT,
            device_id         TEXT,
            scan_duration_ms  REAL,
            total_sigs        INTEGER,
            wt_active         INTEGER,
            threat_count      INTEGER DEFAULT 0,
            adaptive_interval REAL,
            payload           TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS signals (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_db_id     INTEGER,
            timestamp      TEXT,
            freq_mhz       REAL,
            power_db       REAL,
            snr_db         REAL,
            bandwidth_khz  REAL,
            band           TEXT,
            channel        INTEGER,
            modulation     TEXT,
            classification TEXT,
            threat_level   TEXT,
            confidence     REAL,
            description    TEXT,
            is_wt          INTEGER,
            confirmed      INTEGER,
            duration_ms    REAL
        )
        """
    )
    conn.execute(
        """
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
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            chemcham_id   TEXT,
            rule_id       TEXT,
            rule_name     TEXT,
            action        TEXT,
            priority      TEXT,
            signal_freq   REAL,
            signal_band   TEXT,
            signal_power  REAL,
            auto_resolved INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS signaling_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            from_client TEXT,
            to_client   TEXT,
            signal_type TEXT,
            freq        REAL,
            band        TEXT,
            channel     INTEGER,
            payload     TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS call_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at    TEXT,
            ended_at      TEXT,
            from_client   TEXT,
            to_client     TEXT,
            freq          REAL,
            band          TEXT,
            channel       INTEGER,
            duration_ms   REAL,
            quality       REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS topology_state (
            id         INTEGER PRIMARY KEY CHECK(id = 1),
            updated_at TEXT,
            updated_by TEXT,
            payload    TEXT
        )
        """
    )

    ensure_columns(
        conn,
        "scans",
        {
            "device_id": "TEXT",
            "scan_duration_ms": "REAL",
            "threat_count": "INTEGER DEFAULT 0",
            "adaptive_interval": "REAL",
        },
    )
    ensure_columns(
        conn,
        "signals",
        {
            "bandwidth_khz": "REAL",
            "classification": "TEXT",
            "threat_level": "TEXT",
            "confidence": "REAL",
            "description": "TEXT",
            "duration_ms": "REAL",
        },
    )

    conn.execute(
        """
        INSERT OR IGNORE INTO topology_state (id, updated_at, updated_by, payload)
        VALUES (1, ?, ?, ?)
        """,
        (utc_now(), "system", json.dumps(default_topology())),
    )
    conn.commit()
    conn.close()


def load_topology() -> dict[str, Any]:
    conn = db_conn()
    row = conn.execute("SELECT payload FROM topology_state WHERE id = 1").fetchone()
    conn.close()
    return normalize_topology(safe_json_load(row["payload"] if row else None, default_topology()))


def save_topology(payload: Any, updated_by: str = "system") -> dict[str, Any]:
    topo = normalize_topology(payload)
    topo["updated_at"] = utc_now()
    topo["updated_by"] = updated_by
    with topology_lock:
        topology_state.clear()
        topology_state.update(topo)
    conn = db_conn()
    conn.execute(
        """
        INSERT INTO topology_state (id, updated_at, updated_by, payload)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by,
            payload = excluded.payload
        """,
        (topo["updated_at"], topo["updated_by"], json.dumps(topo)),
    )
    conn.commit()
    conn.close()
    return topo


def get_latest_scan() -> dict[str, Any] | None:
    with live_lock:
        if live_history:
            return live_history[-1]
    conn = db_conn()
    row = conn.execute("SELECT payload FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return safe_json_load(row["payload"] if row else None, None)


def get_remote_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "127.0.0.1"


def reverse_lookup_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def get_sid_for_client(client_id: str) -> str | None:
    with clients_lock:
        return clients.get(client_id, {}).get("sid")


def compute_peer_status(info: dict[str, Any]) -> str:
    now = current_ts()
    disconnect_requested_at = info.get("disconnect_requested_at")
    last_seen = float(info.get("last_seen", 0) or 0)
    if disconnect_requested_at and now - disconnect_requested_at < DISCONNECT_GRACE_SEC:
        return "grace"
    if info.get("sid") and now - last_seen < HEARTBEAT_TIMEOUT_SEC:
        return "online"
    return "offline"


def serialize_client(client_id: str, info: dict[str, Any]) -> dict[str, Any]:
    return {
        "clientId": client_id,
        "sid": info.get("sid"),
        "hostname": info.get("hostname"),
        "ip": info.get("ip"),
        "walkie_id": info.get("walkie_id"),
        "band": info.get("band"),
        "channel": info.get("channel"),
        "freq": info.get("freq"),
        "joined_at": info.get("joined_at"),
        "last_seen": info.get("last_seen_iso"),
        "status": compute_peer_status(info),
        "user_agent": info.get("user_agent"),
    }


def all_peers() -> list[dict[str, Any]]:
    with clients_lock:
        return [serialize_client(client_id, info) for client_id, info in sorted(clients.items())]


def append_alert_log(item: dict[str, Any]) -> None:
    ALERT_LOG.append(item)
    if len(ALERT_LOG) > MAX_ALERT_LOG:
        ALERT_LOG.pop(0)


def db_insert_alert(alert_data: dict[str, Any]) -> None:
    conn = db_conn()
    conn.execute(
        """
        INSERT INTO alert_log
        (timestamp, alert_id, alert_name, freq_mhz, power_db, band, channel)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            alert_data.get("timestamp"),
            alert_data.get("alert_id"),
            alert_data.get("alert_name"),
            alert_data.get("freq_mhz"),
            alert_data.get("power_db"),
            alert_data.get("band"),
            alert_data.get("channel"),
        ),
    )
    conn.commit()
    conn.close()


def db_insert_signaling(event_type: str, data: dict[str, Any]) -> None:
    conn = db_conn()
    conn.execute(
        """
        INSERT INTO signaling_log
        (timestamp, from_client, to_client, signal_type, freq, band, channel, payload)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            utc_now(),
            data.get("from"),
            data.get("to"),
            event_type,
            data.get("freq"),
            data.get("band"),
            data.get("channel"),
            json.dumps(data),
        ),
    )
    conn.commit()
    conn.close()


def db_insert_decision_actions(payload: dict[str, Any]) -> None:
    actions = payload.get("decision_actions", []) or []
    if not actions:
        return
    conn = db_conn()
    for action in actions:
        conn.execute(
            """
            INSERT INTO decision_log
            (timestamp, chemcham_id, rule_id, rule_name, action, priority,
             signal_freq, signal_band, signal_power, auto_resolved)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                action.get("ts") or payload.get("timestamp") or utc_now(),
                payload.get("device_id") or payload.get("chemcham_id"),
                action.get("rule_id") or action.get("rule", {}).get("id"),
                action.get("rule_name") or action.get("rule", {}).get("name"),
                action.get("action") or action.get("rule", {}).get("action"),
                action.get("priority") or action.get("rule", {}).get("priority"),
                action.get("signal_freq") or action.get("signal", {}).get("freq_mhz"),
                action.get("signal_band") or action.get("signal", {}).get("band"),
                action.get("signal_power") or action.get("signal", {}).get("power_db") or action.get("signal", {}).get("rxDbm"),
                1 if action.get("auto_resolved") else 0,
            ),
        )
    conn.commit()
    conn.close()


def db_insert_call_rows(session: dict[str, Any], ended_at: str, duration_ms: float, quality: float | None) -> None:
    targets = session.get("targets") or [None]
    conn = db_conn()
    for target in targets:
        conn.execute(
            """
            INSERT INTO call_log
            (started_at, ended_at, from_client, to_client, freq, band, channel, duration_ms, quality)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                session.get("started_at"),
                ended_at,
                session.get("from_client"),
                target,
                session.get("freq"),
                session.get("band"),
                session.get("channel"),
                duration_ms,
                quality,
            ),
        )
    conn.commit()
    conn.close()


def db_insert_scan(data: dict[str, Any]) -> int:
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans
        (scan_id, timestamp, mode, device_id, scan_duration_ms, total_sigs,
         wt_active, threat_count, adaptive_interval, payload)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            data.get("scan_id"),
            data.get("timestamp"),
            data.get("mode"),
            data.get("device_id"),
            data.get("scan_duration_ms"),
            data.get("total_signals", 0),
            data.get("wt_active", 0),
            data.get("threat_count", 0),
            data.get("adaptive_interval"),
            json.dumps(data),
        ),
    )
    scan_db_id = int(cur.lastrowid)

    for sig in data.get("all_signals", []):
        bandwidth_khz = sig.get("bandwidth_khz")
        if bandwidth_khz is None and sig.get("bandwidth_hz") is not None:
            bandwidth_khz = round(float(sig["bandwidth_hz"]) / 1000.0, 3)
        conn.execute(
            """
            INSERT INTO signals
            (scan_db_id, timestamp, freq_mhz, power_db, snr_db, bandwidth_khz,
             band, channel, modulation, classification, threat_level, confidence,
             description, is_wt, confirmed, duration_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                scan_db_id,
                data.get("timestamp"),
                sig.get("freq_mhz"),
                sig.get("power_db"),
                sig.get("snr_db"),
                bandwidth_khz,
                sig.get("band"),
                sig.get("channel"),
                sig.get("modulation"),
                sig.get("classification"),
                sig.get("threat_level"),
                sig.get("confidence"),
                sig.get("description"),
                1 if sig.get("is_walkie_talkie") else 0,
                1 if sig.get("confirmed") else 0,
                sig.get("duration_ms"),
            ),
        )

    conn.commit()
    conn.close()
    return scan_db_id


def fire_webhook(url: str, payload: dict[str, Any]) -> None:
    """Non-blocking webhook delivery with retry."""

    if not url:
        return

    def _send() -> None:
        for attempt in range(3):
            try:
                requests.post(url, json=payload, timeout=5)
                return
            except Exception:
                time.sleep(2**attempt)

    threading.Thread(target=_send, daemon=True).start()


def write_alert_file(payload: dict[str, Any]) -> None:
    try:
        with ALERTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except Exception:
        pass


def enrich_scan_payload(data: dict[str, Any]) -> dict[str, Any]:
    payload = dict(data or {})
    payload["timestamp"] = payload.get("timestamp") or utc_now()
    payload["mode"] = payload.get("mode") or "simulate"
    payload["device_id"] = payload.get("device_id") or payload.get("scanner_id") or "scanner"
    payload["scan_duration_ms"] = float(payload.get("scan_duration_ms") or 0.0)
    payload["all_signals"] = payload.get("all_signals", []) or []
    payload["bands"] = payload.get("bands", {}) or {}
    payload["noise_floors"] = payload.get("noise_floors", {}) or {}
    payload["decision_actions"] = payload.get("decision_actions", []) or []
    payload["adaptive_interval"] = payload.get("adaptive_interval")

    for sig in payload["all_signals"]:
        sig.setdefault("classification", sig.get("band") or "UNKNOWN")
        sig.setdefault("threat_level", "safe")
        sig.setdefault("confidence", 0.0)
        sig.setdefault("confirmed", False)
        sig.setdefault("duration_ms", 0.0)

    if not payload.get("total_signals"):
        payload["total_signals"] = len(payload["all_signals"])
    if not payload.get("wt_active"):
        payload["wt_active"] = sum(1 for sig in payload["all_signals"] if sig.get("is_walkie_talkie"))
    payload["threat_count"] = sum(1 for sig in payload["all_signals"] if sig.get("threat_level") == "alert")
    return payload


def check_alerts(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    now = current_ts()
    fired: list[dict[str, Any]] = []

    for rule in ALERTS:
        if not rule.get("active"):
            continue
        key = str(rule["id"])
        if now - _alert_cooldown.get(key, 0.0) < ALERT_COOLDOWN_SEC:
            continue

        if rule.get("band"):
            band_data = scan_data.get("bands", {}).get(rule["band"], {})
            for sig in band_data.get("active", []):
                if float(sig.get("power_db", -999.0)) >= float(rule["threshold_db"]):
                    event = {
                        "timestamp": utc_now(),
                        "alert_id": key,
                        "alert_name": rule["name"],
                        "freq_mhz": sig.get("freq_mhz"),
                        "power_db": sig.get("power_db"),
                        "band": sig.get("band"),
                        "channel": sig.get("channel"),
                    }
                    _alert_cooldown[key] = now
                    fired.append(event)
                    append_alert_log(event)
                    db_insert_alert(event)
                    break
        elif rule.get("metric") == "noise_floor":
            for band_name, noise_floor in scan_data.get("noise_floors", {}).items():
                if float(noise_floor) >= float(rule["threshold_db"]):
                    event = {
                        "timestamp": utc_now(),
                        "alert_id": key,
                        "alert_name": f"{rule['name']} ({band_name})",
                        "freq_mhz": None,
                        "power_db": noise_floor,
                        "band": band_name,
                        "channel": None,
                    }
                    _alert_cooldown[key] = now
                    fired.append(event)
                    append_alert_log(event)
                    db_insert_alert(event)
                    break

    return fired


def process_scan_payload(raw: dict[str, Any]) -> dict[str, Any]:
    payload = enrich_scan_payload(raw)
    db_insert_scan(payload)
    db_insert_decision_actions(payload)

    with live_lock:
        live_history.append(payload)
        if len(live_history) > MAX_LIVE_HISTORY:
            live_history.pop(0)

    alerts = check_alerts(payload)

    if payload["threat_count"] > 0:
        alert_signals = [sig for sig in payload["all_signals"] if sig.get("threat_level") == "alert"]
        lead = alert_signals[0] if alert_signals else {}
        summary = {
            "timestamp": payload["timestamp"],
            "alert_id": "scan_threat",
            "alert_name": f"High-priority signal(s) detected: {payload['threat_count']}",
            "freq_mhz": lead.get("freq_mhz"),
            "power_db": lead.get("power_db"),
            "band": lead.get("band"),
            "channel": lead.get("channel"),
            "signals": alert_signals[:10],
            "device_id": payload.get("device_id"),
        }
        append_alert_log(summary)
        db_insert_alert(summary)
        write_alert_file(summary)
        socketio.emit("high_priority_alert", summary, room="field")

        webhook_url = payload.get("alert_webhook_url") or WEBHOOK_URL
        if webhook_url:
            fire_webhook(
                webhook_url,
                {
                    "event": "high_priority_alert",
                    "source": "chemcham",
                    "scan": {
                        "device_id": payload.get("device_id"),
                        "scan_id": payload.get("scan_id"),
                        "timestamp": payload.get("timestamp"),
                    },
                    "signals": alert_signals[:10],
                },
            )

    for action in payload.get("decision_actions", []):
        priority = action.get("priority") or action.get("rule", {}).get("priority")
        if priority == "high":
            webhook_url = payload.get("alert_webhook_url") or WEBHOOK_URL
            if webhook_url:
                fire_webhook(
                    webhook_url,
                    {
                        "event": "decision_action",
                        "priority": priority,
                        "device_id": payload.get("device_id"),
                        "action": action,
                    },
                )

    socketio.emit("scan_update", payload, room="dashboard")
    socketio.emit("scan_update", payload, room="field")
    if alerts:
        socketio.emit("alerts", alerts, room="dashboard")
        socketio.emit("alerts", alerts, room="field")

    return payload


def emit_field_state(sid: str | None = None) -> None:
    with topology_lock:
        topo = dict(topology_state)
    payload = {
        "topology": topo,
        "peers": all_peers(),
        "latestScan": get_latest_scan(),
        "ts": utc_now(),
    }
    if sid:
        emit("field_state", payload, room=sid)
    else:
        socketio.emit("field_state", payload, room="field")


def stale_client_monitor() -> None:
    while True:
        time.sleep(1)
        offline_updates: list[dict[str, Any]] = []
        with clients_lock:
            for client_id, info in clients.items():
                status = compute_peer_status(info)
                if status == "offline" and not info.get("offline_announced"):
                    info["offline_announced"] = True
                    offline_updates.append(serialize_client(client_id, info))
        for peer in offline_updates:
            socketio.emit("client_offline", peer, room="field")
            socketio.emit("peer_snapshot", all_peers(), room="field")
            if WEBHOOK_URL:
                fire_webhook(WEBHOOK_URL, {"event": "peer_offline", "peer": peer})


def ensure_background_tasks() -> None:
    global _background_tasks_started
    if _background_tasks_started:
        return
    _background_tasks_started = True
    socketio.start_background_task(stale_client_monitor)


@socketio.on("connect")
def on_connect() -> None:
    ensure_background_tasks()
    join_room("dashboard")
    emit("server_ready", {"sid": request.sid, "ts": utc_now()})


@socketio.on("disconnect")
def on_disconnect() -> None:
    left: dict[str, Any] | None = None
    with clients_lock:
        for client_id, info in clients.items():
            if info.get("sid") == request.sid:
                info["sid"] = None
                info["disconnect_requested_at"] = current_ts()
                info["offline_announced"] = False
                left = {
                    "clientId": client_id,
                    "graceMs": int(DISCONNECT_GRACE_SEC * 1000),
                    "peer": serialize_client(client_id, info),
                }
                break

    if left:
        socketio.emit("client_left", left, room="field")
        if WEBHOOK_URL:
            fire_webhook(WEBHOOK_URL, {"event": "peer_disconnected", "peer": left["peer"]})


@socketio.on("join")
def on_join(data: dict[str, Any]) -> None:
    room = (data or {}).get("room", "dashboard")
    join_room(room)
    emit("joined", {"room": room, "ts": utc_now()})


@socketio.on("client_register")
def on_client_register(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if not client_id:
        emit("client_register_error", {"error": "clientId is required"})
        return

    ip = get_remote_ip()
    hostname = payload.get("hostname") or reverse_lookup_hostname(ip)
    join_room("field")
    join_room(f"walkie:{client_id}")
    join_room("dashboard")

    with clients_lock:
        prev = clients.get(client_id, {})
        clients[client_id] = {
            **prev,
            "sid": request.sid,
            "hostname": hostname,
            "ip": ip,
            "walkie_id": payload.get("walkie_id"),
            "band": payload.get("band"),
            "channel": payload.get("channel"),
            "freq": payload.get("freq"),
            "joined_at": prev.get("joined_at") or utc_now(),
            "last_seen": current_ts(),
            "last_seen_iso": utc_now(),
            "disconnect_requested_at": None,
            "offline_announced": False,
            "user_agent": request.headers.get("User-Agent"),
        }
        peer = serialize_client(client_id, clients[client_id])

    emit(
        "client_registered",
        {
            "clientId": client_id,
            "peer": peer,
            "topology": topology_state,
            "peers": all_peers(),
            "latestScan": get_latest_scan(),
            "whoami": {"ip": ip, "hostname": hostname},
        },
        room=request.sid,
    )
    emit("client_joined", peer, room="field", include_self=False)
    socketio.emit("peer_snapshot", all_peers(), room="field")

    if WEBHOOK_URL:
        fire_webhook(WEBHOOK_URL, {"event": "peer_connected", "peer": peer})


@socketio.on("client_heartbeat")
def on_client_heartbeat(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if not client_id:
        return
    with clients_lock:
        info = clients.get(client_id)
        if not info:
            return
        info["last_seen"] = current_ts()
        info["last_seen_iso"] = utc_now()
        info["disconnect_requested_at"] = None
        info["offline_announced"] = False
        info["sid"] = request.sid
        for key in ("walkie_id", "band", "channel", "freq"):
            if key in payload:
                info[key] = payload[key]


@socketio.on("client_leave")
def on_client_leave(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if not client_id:
        return
    with clients_lock:
        info = clients.get(client_id)
        if not info:
            return
        info["sid"] = None
        info["disconnect_requested_at"] = current_ts()
        info["offline_announced"] = False
        peer = serialize_client(client_id, info)
    socketio.emit(
        "client_left",
        {"clientId": client_id, "graceMs": int(DISCONNECT_GRACE_SEC * 1000), "peer": peer},
        room="field",
    )


@socketio.on("walkie_state")
def on_walkie_state(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if client_id:
        with clients_lock:
            info = clients.get(client_id)
            if info:
                for key in ("band", "channel", "freq", "walkie_id"):
                    if key in payload:
                        info[key] = payload[key]
                info["last_seen"] = current_ts()
                info["last_seen_iso"] = utc_now()
    emit("walkie_state", payload, room="field", include_self=False)


@socketio.on("field_state_request")
def on_field_state_request(_: dict[str, Any] | None = None) -> None:
    emit_field_state(request.sid)


@socketio.on("topology_update")
def on_topology_update(data: dict[str, Any]) -> None:
    payload = data or {}
    topo = payload.get("topology", payload)
    saved = save_topology(topo, updated_by=payload.get("clientId") or get_remote_ip())
    emit("topology_updated", {"topology": saved, "ts": utc_now()}, room="field", include_self=False)


@socketio.on("decision_action")
def on_decision_action(data: dict[str, Any]) -> None:
    payload = data or {}
    db_insert_decision_actions({"device_id": payload.get("ccId"), "decision_actions": [payload]})
    emit("decision_action", payload, room="field", include_self=False)
    if (payload.get("priority") or payload.get("rule", {}).get("priority")) == "high":
        webhook_url = payload.get("webhookUrl") or WEBHOOK_URL
        if webhook_url:
            fire_webhook(webhook_url, {"event": "decision_action", "action": payload})


@socketio.on("scan_result")
def on_scan_result(data: dict[str, Any]) -> None:
    process_scan_payload(data or {})


@socketio.on("webrtc_offer")
def on_webrtc_offer(data: dict[str, Any]) -> None:
    payload = data or {}
    db_insert_signaling("offer", payload)
    target_sid = get_sid_for_client(payload.get("to", ""))
    if target_sid:
        emit("webrtc_offer", payload, room=target_sid)


@socketio.on("webrtc_answer")
def on_webrtc_answer(data: dict[str, Any]) -> None:
    payload = data or {}
    db_insert_signaling("answer", payload)
    target_sid = get_sid_for_client(payload.get("to", ""))
    if target_sid:
        emit("webrtc_answer", payload, room=target_sid)


@socketio.on("webrtc_ice")
def on_webrtc_ice(data: dict[str, Any]) -> None:
    payload = data or {}
    db_insert_signaling("ice", payload)
    target_sid = get_sid_for_client(payload.get("to", ""))
    if target_sid:
        emit("webrtc_ice", payload, room=target_sid)


@socketio.on("ptt_start")
def on_ptt_start(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if client_id:
        with call_lock:
            call_sessions[client_id] = {
                "started_at": utc_now(),
                "started_at_ts": current_ts(),
                "from_client": client_id,
                "targets": payload.get("targets", []),
                "freq": payload.get("freq"),
                "band": payload.get("band"),
                "channel": payload.get("channel"),
            }
    emit("peer_tx_start", payload, room="field", include_self=False)


@socketio.on("ptt_stop")
def on_ptt_stop(data: dict[str, Any]) -> None:
    payload = data or {}
    client_id = payload.get("clientId")
    if client_id:
        with call_lock:
            session = call_sessions.pop(client_id, None)
        if session:
            ended_at = utc_now()
            duration_ms = max(0.0, (current_ts() - float(session["started_at_ts"])) * 1000.0)
            db_insert_call_rows(session, ended_at, duration_ms, payload.get("quality"))
    emit("peer_tx_stop", payload, room="field", include_self=False)


@app.route("/api/status")
def api_status() -> Response:
    latest = get_latest_scan()
    return jsonify(
        {
            "status": "ok",
            "scans_in_memory": len(live_history),
            "last_scan_ts": latest.get("timestamp") if latest else None,
            "wt_active": latest.get("wt_active") if latest else 0,
            "peers_online": sum(1 for peer in all_peers() if peer["status"] == "online"),
        }
    )


@app.route("/api/whoami")
def api_whoami() -> Response:
    ip = get_remote_ip()
    return jsonify(
        {
            "ip": ip,
            "hostname": reverse_lookup_hostname(ip),
            "userAgent": request.headers.get("User-Agent"),
            "ts": utc_now(),
        }
    )


@app.route("/api/latest")
def api_latest() -> Response:
    latest = get_latest_scan()
    if not latest:
        return jsonify({}), 204
    return jsonify(latest)


@app.route("/api/history")
def api_history() -> Response:
    n = min(int(request.args.get("n", 60)), MAX_LIVE_HISTORY)
    with live_lock:
        subset = live_history[-n:]
    if not subset:
        conn = db_conn()
        rows = conn.execute("SELECT payload FROM scans ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        conn.close()
        subset = [safe_json_load(row["payload"], {}) for row in reversed(rows)]
    summaries = [
        {
            "scan_id": item.get("scan_id"),
            "timestamp": item.get("timestamp"),
            "total_signals": item.get("total_signals"),
            "wt_active": item.get("wt_active"),
            "threat_count": item.get("threat_count"),
            "adaptive_interval": item.get("adaptive_interval"),
            "noise_floors": item.get("noise_floors"),
        }
        for item in subset
    ]
    return jsonify(summaries)


@app.route("/api/signals")
def api_signals() -> Response:
    band = request.args.get("band")
    hours = int(request.args.get("hours", 1))
    limit = int(request.args.get("limit", 500))
    wt_only = request.args.get("wt_only", "false").lower() == "true"

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    conn = db_conn()
    query = "SELECT * FROM signals WHERE timestamp >= ? "
    params: list[Any] = [since]
    if band:
        query += "AND band = ? "
        params.append(band)
    if wt_only:
        query += "AND is_wt = 1 "
    query += "ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/stats")
def api_stats() -> Response:
    conn = db_conn()
    stats = {
        "total_scans": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
        "total_signals": conn.execute("SELECT COUNT(*) FROM signals").fetchone()[0],
        "wt_detections": conn.execute("SELECT COUNT(*) FROM signals WHERE is_wt = 1").fetchone()[0],
        "band_breakdown": {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT band, COUNT(*) FROM signals WHERE band IS NOT NULL GROUP BY band ORDER BY COUNT(*) DESC"
            )
        },
        "top_channels": [
            {"freq_mhz": row[0], "count": row[1], "band": row[2]}
            for row in conn.execute(
                "SELECT freq_mhz, COUNT(*) AS cnt, band FROM signals GROUP BY freq_mhz, band "
                "ORDER BY cnt DESC LIMIT 10"
            )
        ],
    }
    conn.close()
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts() -> Response:
    conn = db_conn()
    rows = [dict(row) for row in conn.execute("SELECT * FROM alert_log ORDER BY id DESC LIMIT 100").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/alerts/rules")
def api_alert_rules() -> Response:
    return jsonify(ALERTS)


@app.route("/api/alerts/rules/<rule_id>", methods=["PATCH"])
def api_toggle_alert(rule_id: str) -> Response:
    payload = request.get_json(force=True)
    for rule in ALERTS:
        if rule["id"] == rule_id:
            if "active" in payload:
                rule["active"] = bool(payload["active"])
            if "threshold_db" in payload:
                rule["threshold_db"] = float(payload["threshold_db"])
            return jsonify(rule)
    abort(404)


@app.route("/api/decisions")
def api_decisions() -> Response:
    hours = int(request.args.get("hours", 24))
    priority = request.args.get("priority")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    conn = db_conn()
    query = "SELECT * FROM decision_log WHERE timestamp >= ? "
    params: list[Any] = [since]
    if priority:
        query += "AND priority = ? "
        params.append(priority)
    query += "ORDER BY id DESC"
    rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/calls")
def api_calls() -> Response:
    limit = int(request.args.get("limit", 100))
    conn = db_conn()
    rows = [dict(row) for row in conn.execute("SELECT * FROM call_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/peers")
def api_peers() -> Response:
    return jsonify(all_peers())


@app.route("/api/peers/<client_id>")
def api_peer(client_id: str) -> Response:
    with clients_lock:
        info = clients.get(client_id)
        if not info:
            abort(404)
        return jsonify(serialize_client(client_id, info))


@app.route("/api/topology", methods=["GET", "POST"])
def api_topology() -> Response:
    if request.method == "POST":
        payload = request.get_json(force=True) or {}
        topo = payload.get("topology", payload)
        saved = save_topology(topo, updated_by=payload.get("clientId") or get_remote_ip())
        socketio.emit(
            "field_state",
            {"topology": saved, "peers": all_peers(), "latestScan": get_latest_scan()},
            room="field",
        )
        return jsonify({"ok": True, "topology": saved})

    with topology_lock:
        topo = dict(topology_state)
    return jsonify({"topology": topo, "peers": all_peers(), "latestScan": get_latest_scan()})


@app.route("/api/scan", methods=["POST"])
def api_scan() -> Response:
    payload = request.get_json(force=True) or {}
    processed = process_scan_payload(payload)
    return jsonify({"ok": True, "scan_id": processed.get("scan_id"), "threat_count": processed.get("threat_count")})


@app.route("/api/export/csv")
def api_export_csv() -> Response:
    conn = db_conn()
    rows = conn.execute(
        "SELECT timestamp, freq_mhz, power_db, snr_db, bandwidth_khz, band, channel, "
        "modulation, classification, threat_level, confidence, is_wt, confirmed "
        "FROM signals ORDER BY timestamp DESC LIMIT 5000"
    ).fetchall()
    conn.close()

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(
        [
            "timestamp",
            "freq_mhz",
            "power_db",
            "snr_db",
            "bandwidth_khz",
            "band",
            "channel",
            "modulation",
            "classification",
            "threat_level",
            "confidence",
            "is_walkie_talkie",
            "confirmed",
        ]
    )
    for row in rows:
        writer.writerow(list(row))

    return Response(
        sio.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=signals.csv"},
    )


@app.route("/")
def serve_dashboard() -> Response:
    dash = DASH_DIR / "index.html"
    if dash.exists():
        return send_from_directory(str(dash.parent), dash.name)
    return Response("<h2>Dashboard not found. Place index.html in /dashboard/</h2>", status=404)


@app.route("/health")
def health() -> tuple[str, int]:
    return "OK", 200


init_db()
with topology_lock:
    topology_state.update(load_topology())


if __name__ == "__main__":
    ensure_background_tasks()
    print(
        f"""
CHEMCHAM IoT RF Server
  Dashboard: http://localhost:{PORT}/
  Listen:    http://{HOST}:{PORT}
  DB:        {DB_PATH}
        """.strip()
    )
    socketio.run(app, host=HOST, port=PORT, debug=DEBUG)
