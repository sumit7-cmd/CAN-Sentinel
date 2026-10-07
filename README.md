# CAN-Sentinel

[![Tests](https://github.com/sumit7-cmd/CAN-Sentinel-V2/actions/workflows/tests.yml/badge.svg)](https://github.com/sumit7-cmd/CAN-Sentinel-V2/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**SOC-style Automotive ECU Intrusion Detection Platform for an isolated Linux virtual CAN lab.**

A defensive automotive cybersecurity laboratory project built around a **Linux virtual CAN (`vcan0`)** network.

V2 adds:

- SOC-style PyQt6 dashboard
- Live frame-rate and anomaly-score charts
- SQLite event/incident storage
- ECU behavioral fingerprinting
- Rule-based attack classification
- Isolation Forest anomaly detection
- Severity scoring
- Alert/incident history
- Traffic explorer
- ECU profile table
- C raw SocketCAN sniffer
- Synthetic vehicle traffic + safe simulated attack modes
- Automated demo workflow

> **Safety:** the supplied traffic generator, monitor, and sniffer deliberately refuse non-`vcan*` interfaces. Use an isolated virtual CAN lab only.

---

## Architecture

```text
                  ┌─────────────────────────┐
                  │ Synthetic Vehicle ECU   │
                  │ Traffic Generator       │
                  └────────────┬────────────┘
                               │
                               ▼
                         Linux vcan0
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        C SocketCAN      Python Monitor     candump
        Raw Sniffer            │
                               ▼
                    ┌────────────────────┐
                    │ Feature Extraction │
                    │ + ECU Fingerprint  │
                    └─────────┬──────────┘
                              │
                  ┌───────────┴──────────┐
                  ▼                      ▼
           Isolation Forest        Detection Rules
                  │                      │
                  └───────────┬──────────┘
                              ▼
                     Incident Classifier
                              │
                   ┌──────────┴──────────┐
                   ▼                     ▼
             SQLite Database       PyQt6 SOC UI
                                     │
                         ┌───────────┼───────────┐
                         ▼           ▼           ▼
                      Overview     Traffic      ECUs
                                     │
                                     ▼
                                  Incidents
```

---

## Presentation Implementation Details

The following sections document the implementation represented in **Project Presentation slides 4, 5, 6, 7, and 9**.

### Slide 4 — System Architecture

CAN-Sentinel follows an end-to-end defensive automotive SOC pipeline:

\`\`\`text
Synthetic ECU Traffic
        |
        v
     Linux vcan0
        |
        +--------------> C SocketCAN Raw Sniffer
        |
        v
   Python CAN Monitor
        |
        v
 Feature Extraction
 + ECU Fingerprinting
        |
        +--------------> Isolation Forest
        |
        +--------------> Detection Rules
                               |
                               v
                    Incident Classification
                               |
                     +---------+---------+
                     |                   |
                     v                   v
               SQLite Evidence      PyQt6 SOC UI
\`\`\`

Implementation mapping:

| Layer | Repository implementation |
|---|---|
| Synthetic vehicle traffic | \`scripts/mock_vehicle.py\` |
| Virtual CAN lab | Linux SocketCAN \`vcan0\` |
| Python monitoring | \`src/monitor.py\` |
| Feature extraction | \`src/detection.py\` |
| ECU behavioral profiles | \`src/ecu.py\` |
| ML detection | Isolation Forest in \`src/detection.py\` |
| Rule-based detection | \`classify()\` in \`src/detection.py\` |
| Evidence storage | \`src/database.py\` / SQLite |
| SOC dashboard | \`src/app.py\` |
| Raw CAN capture | \`src/can_sniffer.c\` |

The monitor explicitly enforces the virtual-lab boundary by refusing interfaces that do not start with \`vcan\`.

### Slide 5 — Baseline ECU Traffic

Calibration uses a synthetic vehicle communication profile:

| CAN ID | Signal | Approx. Rate |
|---|---|---:|
| \`0x100\` | RPM | 20 Hz |
| \`0x110\` | Speed | 10 Hz |
| \`0x120\` | Temperature | 4 Hz |
| \`0x200\` | Brake Status | 2 Hz |

During calibration, the monitor learns:

- Known CAN identifier set
- Dominant DLC for each identifier
- Aggregate baseline traffic rate
- ECU behavioral profiles
- Window-level feature vectors used to train the Isolation Forest model

The dashboard progresses through **CALIBRATING** windows and then changes to **MONITORING** once a usable baseline has been established.

### Slide 6 — Detection Features

Each monitoring window is represented by an eight-dimensional feature vector:

| # | Feature | Purpose |
|---:|---|---|
| 1 | Frames/sec (FPS) | Measures aggregate CAN traffic volume |
| 2 | Unique IDs | Tracks identifier diversity |
| 3 | Maximum ID rate | Detects unusually fast individual senders |
| 4 | Mean IAT | Measures average inter-arrival timing |
| 5 | IAT standard deviation | Captures timing variability |
| 6 | Unknown IDs | Counts identifiers absent from calibration |
| 7 | DLC deviations | Detects data-length changes from baseline |
| 8 | Replay ratio | Measures repeated-payload behavior |

The same feature representation is used for both calibration and live monitoring.

The implementation is in \`src/detection.py\` through \`build_features()\`.

### Slide 7 — Detection & Classification

CAN-Sentinel combines **explainable rule-based evidence** with **Isolation Forest anomaly scoring**.

Supported classifications:

| Classification | Detection signal | Typical severity |
|---|---|---|
| **CAN Flood / DoS** | Very high per-ID transmission rate | CRITICAL / HIGH |
| **Unknown-ID Injection** | Previously unseen ID transmitting at a sustained rate | CRITICAL / HIGH |
| **Replay-like Burst** | High repeated-payload ratio | HIGH / MEDIUM |
| **Payload/DLC Anomaly** | DLC differs from calibration | HIGH / MEDIUM |
| **Behavioral Anomaly** | Isolation Forest anomaly score or aggregate traffic-rate jump | MEDIUM / LOW |

The classifier records:

- CAN ID associated with the alert
- Isolation Forest anomaly score
- Confidence
- Detection reason
- Evidence string containing window metrics

The implementation is centered on \`classify()\` and \`severity_for()\` in \`src/detection.py\`.

### Slide 9 — SOC Dashboard

The operator-facing PyQt6 dashboard is implemented in \`src/app.py\`.

#### Overview

Provides:

- Frames/sec
- Unique CAN IDs
- Isolation Forest anomaly score
- Incident count
- Top CAN ID
- Current system state
- Live CAN traffic chart
- Live anomaly-score chart

#### Traffic

Displays recent CAN telemetry:

- Timestamp
- CAN ID
- DLC
- Payload

#### ECU Fingerprints

Displays learned and observed ECU behavior:

- CAN ID
- Observed message count
- Rate
- Period
- DLC
- Fingerprint score
- Status

#### Incidents

Displays investigation-oriented alert information:

- Timestamp
- Severity
- Classification
- CAN ID
- ML anomaly score
- Confidence
- Detection reason
- Evidence

The dashboard receives telemetry from \`CANMonitor\` through Qt signals and persists frames, incidents, and ECU profiles through the SQLite database layer.

---

## Requirements

Recommended:

- Ubuntu 22.04/24.04 or WSL2 with SocketCAN support
- Python 3.10+
- GCC
- `can-utils`
- Graphical Linux session for the PyQt6 UI

Install system packages:

```bash
sudo apt update
sudo apt install -y build-essential can-utils python3-venv python3-pip
```

Create the Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Virtual CAN setup

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan 2>/dev/null || true
sudo ip link set up vcan0
ip -details link show vcan0
```

Optional:

```bash
candump vcan0
```

## Start the SOC dashboard

```bash
source .venv/bin/activate
python src/app.py
```

The UI starts in **CALIBRATING** mode and learns a normal baseline. After calibration it switches to **MONITORING**.

## Generate normal traffic

In another terminal:

```bash
source .venv/bin/activate
python scripts/mock_vehicle.py --mode normal
```

Simulated ECUs:

| CAN ID | Signal | Approx. Rate |
|---|---|---:|
| `0x100` | RPM | 20 Hz |
| `0x110` | Speed | 10 Hz |
| `0x120` | Temperature | 4 Hz |
| `0x200` | Brake Status | 2 Hz |

## Defensive test scenarios

After calibration, stop normal traffic and run one of these **only on `vcan0`**.

CAN Flood / DoS:

```bash
python scripts/mock_vehicle.py --mode flood --attack-id 0x321
```

Unknown-ID Injection:

```bash
python scripts/mock_vehicle.py --mode injection --attack-id 0x321
```

Replay-like burst:

```bash
python scripts/mock_vehicle.py --mode replay --attack-id 0x321
```

The dashboard records the detected ID, classification, severity, anomaly score, confidence, reason, and evidence.

## Detection pipeline

Each monitoring window calculates:

- total frames
- frames/second
- unique CAN IDs
- maximum per-ID rate
- mean inter-arrival time
- inter-arrival standard deviation
- unknown IDs
- DLC deviations
- payload repeat ratio

The Isolation Forest model is trained on calibration windows and combined with explainable detection rules.

Classifications include:

- **CAN Flood / DoS**
- **Unknown-ID Injection**
- **Replay-like Burst**
- **Payload/DLC Anomaly**
- **Behavioral Anomaly**

## ECU behavioral fingerprinting

For each baseline CAN ID, the project stores:

- expected rate
- expected period
- DLC mode
- message count
- observation timestamps
- rate tolerance

This is a behavioral profile, not cryptographic ECU identity.

## SQLite evidence store

The dashboard automatically creates:

```text
data/can_sentinel.db
```

Tables:

- `incidents`
- `frames`
- `ecu_profiles`

Inspect with:

```bash
sqlite3 data/can_sentinel.db
```

## C raw CAN sniffer

Build:

```bash
mkdir -p build
gcc -O2 -Wall -Wextra -o build/can_sniffer src/can_sniffer.c
```

Run:

```bash
sudo ./build/can_sniffer vcan0
```

CSV capture:

```bash
sudo ./build/can_sniffer vcan0 data/can_capture.csv
```

## Tests

```bash
pip install pytest
pytest -q
```

The test suite covers feature extraction, attack classification, and ECU fingerprint calculations.

## Project report

See [`report/PROJECT_REPORT.md`](report/PROJECT_REPORT.md) for a ready-to-use college project report skeleton.

## Safety / responsible use

This repository is intentionally limited to a virtual CAN environment. Do not connect the simulator, monitor, or sniffer to a real vehicle or safety-critical automotive bus. Real automotive security research requires explicit authorization, isolation, and professional safety engineering.
