from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    classification TEXT NOT NULL,
    can_id INTEGER,
    anomaly_score REAL,
    confidence REAL,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    can_id INTEGER NOT NULL,
    dlc INTEGER NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ecu_profiles (
    can_id INTEGER PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    message_count INTEGER NOT NULL,
    expected_rate REAL NOT NULL,
    expected_period REAL NOT NULL,
    dlc_mode INTEGER NOT NULL,
    rate_tolerance REAL NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_frames(self, rows: Iterable[tuple[str, int, int, str]]) -> None:
        self.conn.executemany(
            "INSERT INTO frames(timestamp, can_id, dlc, payload) VALUES(?,?,?,?)",
            rows
        )
        self.conn.commit()

    def insert_incident(
        self,
        timestamp: str,
        severity: str,
        classification: str,
        can_id: int | None,
        anomaly_score: float,
        confidence: float,
        reason: str,
        evidence: str,
    ) -> None:
        self.conn.execute(
            """INSERT INTO incidents
               (timestamp, severity, classification, can_id, anomaly_score,
                confidence, reason, evidence)
               VALUES(?,?,?,?,?,?,?,?)""",
            (timestamp, severity, classification, can_id, anomaly_score,
             confidence, reason, evidence)
        )
        self.conn.commit()

    def recent_incidents(self, limit: int = 100):
        return self.conn.execute(
            """SELECT timestamp, severity, classification, can_id,
                      anomaly_score, confidence, reason
               FROM incidents ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()

    def upsert_ecu_profile(self, profile: dict) -> None:
        self.conn.execute(
            """INSERT INTO ecu_profiles
               (can_id, first_seen, last_seen, message_count,
                expected_rate, expected_period, dlc_mode, rate_tolerance)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(can_id) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 message_count=excluded.message_count,
                 expected_rate=excluded.expected_rate,
                 expected_period=excluded.expected_period,
                 dlc_mode=excluded.dlc_mode,
                 rate_tolerance=excluded.rate_tolerance
            """,
            (
                profile["can_id"], profile["first_seen"], profile["last_seen"],
                profile["message_count"], profile["expected_rate"],
                profile["expected_period"], profile["dlc_mode"],
                profile["rate_tolerance"]
            )
        )
        self.conn.commit()

    def ecu_profiles(self):
        return self.conn.execute(
            """SELECT can_id, first_seen, last_seen, message_count,
                      expected_rate, expected_period, dlc_mode, rate_tolerance
               FROM ecu_profiles ORDER BY can_id"""
        ).fetchall()
