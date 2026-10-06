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
