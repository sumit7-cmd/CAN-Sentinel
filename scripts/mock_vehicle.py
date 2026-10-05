#!/usr/bin/env python3
"""Safe virtual-CAN traffic simulator for CAN-Sentinel V2.

Modes:
  normal    realistic periodic synthetic ECU traffic
  flood     high-rate repeated unknown ID
  injection sparse repeated unknown-ID injection
  replay    high ratio of identical payloads

Safety: only vcan* interfaces are accepted.
"""

from __future__ import annotations

import argparse
import random
import time
import can


NORMAL_IDS = {
    0x100: ("RPM", 0.050),
    0x110: ("SPEED", 0.100),
    0x120: ("TEMPERATURE", 0.250),
    0x200: ("BRAKE_STATUS", 0.500),
}


def payload_for(name: str) -> bytes:
    if name == "RPM":
        rpm = random.randint(800, 3500)
        return rpm.to_bytes(2, "big") + bytes(6)
    if name == "SPEED":
        speed = random.randint(0, 140)
        return speed.to_bytes(2, "big") + bytes(6)
    if name == "TEMPERATURE":
        temp = random.randint(60, 110)
        return temp.to_bytes(2, "big") + bytes(6)
    state = random.choice([0, 0, 0, 1])
    return bytes([state]) + bytes(7)


def send(bus, can_id: int, payload: bytes):
    bus.send(
        can.Message(
            arbitration_id=can_id,
            data=payload,
            is_extended_id=False,
        )
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--interface", default="vcan0")
    p.add_argument("--mode", choices=["normal", "flood", "injection", "replay"], default="normal")
    p.add_argument("--attack-id", type=lambda x: int(x, 0), default=0x321)
    p.add_argument("--seconds", type=float, default=0.0)
    args = p.parse_args()

    if not args.interface.startswith("vcan"):
        raise SystemExit("Safety stop: the simulator only permits vcan* interfaces.")

    bus = can.Bus(interface="socketcan", channel=args.interface)
    started = time.monotonic()
    next_due = {cid: started for cid in NORMAL_IDS}

    replay_payload = bytes.fromhex("52 45 50 4C 41 59 00 00")
    injection_payload = bytes.fromhex("49 4E 4A 45 43 54 00 00")
    flood_payload = bytes.fromhex("46 4C 4F 4F 44 00 00 00")

    print(f"CAN-Sentinel V2 simulator: {args.mode} on {args.interface}")
    try:
        while not args.seconds or (time.monotonic() - started) < args.seconds:
            now = time.monotonic()

            for cid, (name, period) in NORMAL_IDS.items():
                if now >= next_due[cid]:
                    send(bus, cid, payload_for(name))
                    next_due[cid] = now + period

            if args.mode == "flood":
                for _ in range(12):
                    send(bus, args.attack_id, flood_payload)
                time.sleep(0.0008)

            elif args.mode == "injection":
                send(bus, args.attack_id, injection_payload)
                time.sleep(0.015)

            elif args.mode == "replay":
                for _ in range(5):
                    send(bus, args.attack_id, replay_payload)
                time.sleep(0.015)

            else:
                time.sleep(0.002)
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()
        print("Simulator stopped.")


if __name__ == "__main__":
    main()
