# Wireless Network Security Monitor

A lightweight wireless network monitoring and intrusion detection system built with ESP32 microcontrollers, Python, and a real-time web dashboard. Designed for small institutional networks (labs, offices, small campuses) where enterprise-grade tools are too expensive or complex.

The system captures 802.11 management frames on both 2.4 GHz and 5 GHz bands simultaneously, detects common wireless attacks, builds per-device behavioral baselines, and assigns risk scores — all viewable on a live dashboard.

---

## Features

| Feature | Description |
|---|---|
| **Dual-Band Monitoring** | Simultaneous 2.4 GHz + 5 GHz capture via ESP32-C6 and ESP32-C5 |
| **8 Detection Rules** | Deauth flood, rogue AP, evil twin, beacon flood, disassoc flood, probe harvesting, RSSI anomaly, unknown device |
| **Behavior Profiling** | 6-dimension fingerprinting (packet rate, frame distribution, active hours, destination diversity, new destinations, channel spread) |
| **Risk Scoring** | Per-device 0–100 score with plain-English reasons and a "Why?" breakdown |
| **Real-time Dashboard** | Live WebSocket updates, frame/channel charts, device table, alert feed |
| **Dark/Light Mode** | Toggle with localStorage persistence |
| **MAC Vendor Lookup** | Built-in OUI database (200+ vendors) |
| **Column Sorting** | Sortable device table headers |
| **Baseline Comparison** | Click any risk score → popup showing normal vs. current behavior |
| **HTML Reports** | Downloadable security summary report |
| **DB Auto-Cleanup** | Automatic deletion of data older than 72 hours |
| **Trusted AP Whitelist** | Mark known access points to suppress false positives |
| **Interactive About Page** | Animated architecture diagram with clickable components |
| **Built-in Simulator** | Test all detection rules without hardware |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      WiFi Environment                        │
│   📶 Routers (2.4G/5G)          💀 Attackers                │
└───────────────┬──────────────────────┬───────────────────────┘
                │  802.11 mgmt frames  │
        ┌───────▼──────┐       ┌───────▼──────┐
        │  ESP32-C6    │       │  ESP32-C5    │    ┌──────────┐
        │  2.4 GHz     │       │  5 GHz       │    │ ESP32-C3 │
        │  Channel 1   │       │  Ch 36→165   │    │ Attacker │
        └──────┬───────┘       └──────┬───────┘    │ (Test)   │
               │ UART                 │ UART       └──────────┘
        ┌──────▼──────────────────────▼───────┐
        │       UART Orchestrator             │
        │       (Python - host PC)            │
        └──────────────┬──────────────────────┘
                       │ HTTP POST /api/ingest
        ┌──────────────▼──────────────────────┐
        │       FastAPI Backend               │
        │  ┌─────────┐ ┌──────────────────┐   │
        │  │ Rule     │ │ Behavior         │   │◄──► SQLite DB
        │  │ Engine   │ │ Profiler         │   │
        │  └─────────┘ └──────────────────┘   │
        └──────────────┬──────────────────────┘
                       │ WebSocket
        ┌──────────────▼──────────────────────┐
        │       Dashboard (Browser)           │
        │  Charts │ Devices │ Alerts │ APs    │
        └─────────────────────────────────────┘
```

---

## Project Structure

```
IBM/
├── backend/                    # FastAPI server
│   ├── main.py                 # App entry point, routes, WebSocket, background tasks
│   ├── rule_engine.py          # 8 detection rules
│   ├── behavior_profiler.py    # 6-dimension behavioral fingerprinting
│   ├── database.py             # SQLAlchemy async engine & session
│   ├── models.py               # ORM models (WifiEvent, Alert, TrustedAP)
│   ├── requirements.txt        # Python dependencies
│   └── static/                 # Frontend assets
│       ├── index.html          # Dashboard page
│       ├── about.html          # Interactive architecture page
│       ├── app.js              # Dashboard logic (WebSocket, charts, tables)
│       └── style.css           # Styles with dark/light mode CSS variables
├── firmware/                   # Arduino sketches
│   ├── esp32_c6_sniffer/       # 2.4 GHz promiscuous mode sniffer
│   ├── esp32_c5_scanner/       # 5 GHz channel-hopping sniffer
│   └── esp32_c3_attacker/      # Deauth attack node (testing only)
├── host_scripts/
│   └── uart_orchestrator.py    # Serial reader → HTTP poster
├── simulator/
│   └── fake_esp32.py           # Software simulator (no hardware needed)
├── start.bat                   # One-click launcher (Windows)
└── README.md
```

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **pip**
- (Optional) ESP32-C6, ESP32-C5, ESP32-C3 boards + USB cables

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Backend

```bash
cd backend
python main.py
```

The server starts at **http://localhost:8000**.

### 3. Open the Dashboard

Open [http://localhost:8000](http://localhost:8000) in your browser.

### 4. Feed Data

**Option A — With hardware:**
```bash
cd host_scripts
python uart_orchestrator.py
```

**Option B — Without hardware (simulator):**
```bash
cd simulator
python fake_esp32.py
```

**Option C — Built-in simulator:**
Use the simulator panel at the bottom of the dashboard. Click buttons to generate normal traffic, deauth attacks, rogue APs, or beacon floods.

### Windows One-Click

Double-click `start.bat` to launch both the backend and UART orchestrator in separate windows.

---

## Detection Rules

| Rule | Trigger | Score | Severity |
|---|---|---|---|
| Deauth Flood | >10 deauth frames from same MAC in 30s | +50 | CRITICAL |
| Rogue AP | Unknown BSSID advertising a trusted SSID | +80 | CRITICAL |
| Evil Twin | Trusted SSID seen on wrong channel or BSSID | +80 | CRITICAL |
| Beacon Flood | >50 beacon frames from same MAC in 60s | +60 | HIGH |
| Disassoc Flood | >5 disassociation frames in 30s | +40 | HIGH |
| Probe Harvesting | >20 probe requests from same MAC in 60s | +30 | WARNING |
| RSSI Anomaly | Signal strength swing >30 dBm | +25 | WARNING |
| Unknown Device | New MAC not seen before | +20 | WARNING |

---

## Behavior Profiling

Each device builds a baseline over time. The profiler compares current behavior against the baseline across 6 dimensions:

| Dimension | What it measures | Max Score |
|---|---|---|
| Packet Rate | Frames/min vs historical avg ± std | 25 |
| Frame Distribution | Ratio of frame types vs normal | 20 |
| Active Hours | Activity outside usual hours | 15 |
| Destination Diversity | Number of unique destinations contacted | 15 |
| New Destinations | Previously unseen destinations | 15 |
| Channel Spread | Number of channels used vs normal | 10 |

Total behavioral anomaly score: **0–100**

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/ingest` | Submit a captured WiFi frame |
| `GET` | `/api/devices` | List all discovered devices |
| `GET` | `/api/device-risks` | Risk scores with reasons for all devices |
| `GET` | `/api/device-baseline/{mac}` | Baseline vs current stats for a device |
| `GET` | `/api/alerts` | All alerts |
| `POST` | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| `GET` | `/api/stats` | System statistics |
| `GET` | `/api/trusted-aps` | List trusted access points |
| `POST` | `/api/trusted-aps` | Add a trusted AP |
| `DELETE` | `/api/trusted-aps/{id}` | Remove a trusted AP |
| `GET` | `/api/report` | Download HTML security report |
| `GET` | `/about` | Interactive architecture page |
| `WebSocket` | `/ws` | Real-time event stream |

---

## Hardware Setup

### Components

| Board | Role | Band | Approx. Cost |
|---|---|---|---|
| ESP32-C6 | 2.4 GHz sniffer | 2.4 GHz | ~$5 |
| ESP32-C5 | 5 GHz sniffer | 5 GHz | ~$7 |
| ESP32-C3 | Attack simulator (testing) | 2.4 GHz | ~$3 |

### Wiring

All boards connect to the host PC via USB (UART). No additional wiring needed.

### Firmware

Flash each board using Arduino IDE:
1. Open the sketch from `firmware/esp32_cX_*/`
2. Select the correct board in Arduino IDE
3. Flash via USB

---

## Comparison with Existing Tools

| Feature | Wireshark | Nagios/PRTG | Our System |
|---|---|---|---|
| Multi-channel capture | ❌ (1 adapter = 1 channel) | ❌ | ✅ (2.4G + 5G simultaneous) |
| Behavioral profiling | ❌ | ❌ | ✅ (6-dimension baselines) |
| Automatic risk scoring | ❌ | ⚠️ (manual thresholds) | ✅ (rule + behavior scores) |
| Admin-friendly UI | ❌ (expert tool) | ⚠️ (complex setup) | ✅ (open browser, done) |
| Cost | Free (software only) | $$$ (licenses) | ~$15 (3 ESP32 boards) |
| Deployment complexity | Medium | High | Low (pip install + run) |

---

## Tech Stack

- **Hardware:** ESP32-C6, ESP32-C5, ESP32-C3 (Arduino/ESP-IDF)
- **Backend:** Python 3.12, FastAPI, Uvicorn
- **Database:** SQLite with SQLAlchemy (async via aiosqlite)
- **Frontend:** Vanilla HTML/JS/CSS, Chart.js
- **Transport:** UART Serial (115200 baud) + REST API + WebSocket

---

## License

Educational project — for academic and research use.
