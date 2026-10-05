from __future__ import annotations

from collections import defaultdict
import statistics
import time
from datetime import datetime, timezone

import can
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from .config import CALIBRATION_WINDOWS, WINDOW_SECONDS
from .database import Database
from .detection import build_features, classify, train_model
from .ecu import make_profiles, live_match


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CANMonitor(QObject):
    metrics = pyqtSignal(dict)
    frame_signal = pyqtSignal(dict)
    incident_signal = pyqtSignal(dict)
    ecu_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)

    def __init__(self, db: Database, interface="vcan0"):
        super().__init__()
        if not interface.startswith("vcan"):
            raise ValueError("Safety stop: CANMonitor only permits vcan* interfaces.")
        self.db = db
        self.interface = interface
        self.running = False
        self.bus = None
        self.model = None
        self.baseline_ids = set()
        self.baseline_dlc = {}
        self.baseline_rate = 0.0
        self.profiles = {}

    def _collect_window(self):
        deadline = time.monotonic() + WINDOW_SECONDS
        messages = []
        while time.monotonic() < deadline and self.running:
            remaining = max(0.0, deadline - time.monotonic())
            msg = self.bus.recv(timeout=remaining)
            if msg is None:
                continue
            ts = time.monotonic()
            payload = bytes(msg.data)
            messages.append((ts, msg.arbitration_id, msg.dlc, payload))
            self.frame_signal.emit({
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "can_id": msg.arbitration_id,
                "dlc": msg.dlc,
                "data": payload.hex(" ").upper(),
            })
        return messages

    @pyqtSlot()
    def run(self):
        self.running = True
        self.status_signal.emit("CONNECTING")
        try:
            self.bus = can.Bus(interface="socketcan", channel=self.interface)
        except Exception as exc:
            self.status_signal.emit(f"ERROR: {exc}")
            return

        self.status_signal.emit("CALIBRATING")
        calibration = []

        for i in range(CALIBRATION_WINDOWS):
            messages = self._collect_window()
            calibration.extend(messages)
            window = build_features(messages, WINDOW_SECONDS)
            self.metrics.emit({
                "state": f"CALIBRATING {i+1}/{CALIBRATION_WINDOWS}",
                "frames": window.frames,
                "fps": window.fps,
                "unique_ids": window.unique_ids,
                "anomaly": 0.0,
                "severity": "INFO",
            })

        if not calibration:
            self.status_signal.emit("ERROR: no CAN traffic during calibration")
            self.running = False
            self.bus.shutdown()
            return

        self.baseline_ids = {x[1] for x in calibration}
        dlc_groups = defaultdict(list)
        for _, cid, dlc, _ in calibration:
            dlc_groups[cid].append(dlc)
        self.baseline_dlc = {
            cid: max(set(values), key=values.count)
            for cid, values in dlc_groups.items()
        }

        self.baseline_rate = len(calibration) / max(1.0, CALIBRATION_WINDOWS * WINDOW_SECONDS)

        vectors = []
        start = calibration[0][0]
        chunk = []
        for row in calibration:
            if row[0] - start < WINDOW_SECONDS:
                chunk.append(row)
            else:
                vectors.append(
                    build_features(
                        chunk, WINDOW_SECONDS, self.baseline_ids, self.baseline_dlc
                    ).feature_vector
                )
                start = row[0]
                chunk = [row]
        if chunk:
            vectors.append(
                build_features(
                    chunk, WINDOW_SECONDS, self.baseline_ids, self.baseline_dlc
                ).feature_vector
            )

        # Isolation Forest needs enough samples to be useful. Duplicate the
        # small calibration set rather than failing in a short lab demo.
        while len(vectors) < 3:
            vectors.append(vectors[-1].copy())
        self.model = train_model(vectors)

        self.profiles = make_profiles(
            calibration,
            first_seen=utc_iso(),
            last_seen=utc_iso(),
        )
        for profile in self.profiles.values():
            self.db.upsert_ecu_profile(profile.__dict__)
            self.ecu_signal.emit({
                "can_id": profile.can_id,
                "count": profile.message_count,
                "rate": profile.expected_rate,
                "period": profile.expected_period,
                "dlc": profile.dlc_mode,
                "score": 1.0,
                "status": "BASELINE",
            })

        self.status_signal.emit("MONITORING")

        while self.running:
            messages = self._collect_window()
            if not messages:
                continue

            window = build_features(
                messages, WINDOW_SECONDS, self.baseline_ids, self.baseline_dlc
            )
            ml_score = float(self.model.decision_function([window.feature_vector])[0])

            per_id = defaultdict(list)
            for ts, cid, dlc, payload in messages:
                per_id[cid].append((ts, dlc, payload))
            rates = {cid: len(items) / WINDOW_SECONDS for cid, items in per_id.items()}

            result = classify(
                window, ml_score, self.baseline_rate, rates, self.baseline_dlc
            )

            top_score = 0.0
            if window.top_id is not None and window.top_id in self.profiles:
                items = per_id[window.top_id]
                observed_dlc = statistics.mode([x[1] for x in items])
                top_score = live_match(
                    self.profiles[window.top_id],
                    rates[window.top_id],
                    observed_dlc,
                )

            self.metrics.emit({
                "state": "MONITORING",
                "frames": window.frames,
                "fps": window.fps,
                "unique_ids": window.unique_ids,
                "anomaly": ml_score,
                "severity": result.severity,
                "top_id": window.top_id,
                "classification": result.classification,
            })

            if window.top_id is not None:
                top_items = per_id[window.top_id]
                dlcs = [x[1] for x in top_items]
                self.ecu_signal.emit({
                    "can_id": window.top_id,
                    "count": window.frames,
                    "rate": rates.get(window.top_id, 0.0),
                    "period": 1.0 / max(rates.get(window.top_id, 0.1), 0.1),
                    "dlc": max(set(dlcs), key=dlcs.count),
                    "score": top_score,
                    "status": "SUSPECT" if result.is_alert else "NORMAL",
                })

            frame_rows = [
                (
                    datetime.now().isoformat(timespec="milliseconds"),
                    cid, dlc, payload.hex(" ")
                )
                for _, cid, dlc, payload in messages
            ]
            self.db.insert_frames(frame_rows)

            if result.is_alert:
                event = {
                    "timestamp": utc_iso(),
                    "severity": result.severity,
                    "classification": result.classification,
                    "can_id": result.can_id,
                    "anomaly_score": result.anomaly_score,
                    "confidence": result.confidence,
                    "reason": result.reason,
                    "evidence": result.evidence,
                }
                self.db.insert_incident(**event)
                self.incident_signal.emit(event)

        if self.bus:
            self.bus.shutdown()
            self.bus = None
        self.status_signal.emit("STOPPED")

    def stop(self):
        self.running = False
