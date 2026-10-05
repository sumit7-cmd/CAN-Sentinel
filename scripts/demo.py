#!/usr/bin/env python3
"""Print the recommended presentation flow for CAN-Sentinel V2."""

print(r"""
╔══════════════════════════════════════════════════════════════╗
║ CAN-SENTINEL V2 — PRESENTATION DEMO                         ║
╚══════════════════════════════════════════════════════════════╝

Terminal 1 — virtual CAN:
  sudo modprobe vcan
  sudo ip link add dev vcan0 type vcan 2>/dev/null || true
  sudo ip link set up vcan0

Terminal 2 — dashboard:
  source .venv/bin/activate
  python src/app.py

Terminal 3 — baseline:
  source .venv/bin/activate
  python scripts/mock_vehicle.py --mode normal

Wait for the dashboard to change from CALIBRATING to MONITORING.

Then stop the normal generator with Ctrl+C and choose ONE test:

Flood / DoS:
  python scripts/mock_vehicle.py --mode flood --attack-id 0x321

Unknown-ID injection:
  python scripts/mock_vehicle.py --mode injection --attack-id 0x321

Replay-like burst:
  python scripts/mock_vehicle.py --mode replay --attack-id 0x321

The dashboard will show:
  • anomaly score
  • suspicious CAN ID
  • classification
  • severity
  • confidence
  • evidence
  • ECU fingerprint status

Optional C sniffer:
  mkdir -p build
  gcc -O2 -Wall -Wextra -o build/can_sniffer src/can_sniffer.c
  sudo ./build/can_sniffer vcan0 data/can_capture.csv
""")
