# CHEMCHAM IoT RF Field Manager

Single-file dashboard plus Flask backend and RTL-SDR/simulation scanner.

Current workspace layout:

```text
iot-sdr/
├── dashboard/index.html
├── server/server.py
├── device/scanner.py
├── requirements.txt
└── .env.example
```

## Features

- Multi-client dashboard presence with auto-registered walkie-talkies
- Peer registry, topology sync, alerts, decisions, signaling, and call history on the server
- WebRTC signaling path for live push-to-talk audio between browser peers
- Adaptive scanner payloads with signal classification, threat tagging, and decision actions
- RF field simulation with richer path loss, SNR, and walkie detection metadata

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run The Server

```bash
python server/server.py
```

The dashboard is served at [http://localhost:5000/](http://localhost:5000/).

## Run The Scanner

Simulation mode:

```bash
python device/scanner.py --simulate --server http://localhost:5000
```

Hardware mode:

```bash
python device/scanner.py --server http://localhost:5000
```

The scanner posts full scan payloads to `/api/scan`. The server stores them in SQLite and rebroadcasts them to dashboards over Socket.IO.

## Notes

- Microphone permission is only requested on first PTT.
- Each browser tab gets a separate `clientId` via `sessionStorage`.
- The existing topology is still saved locally in `localStorage`, and is also synced to the server when connected.
