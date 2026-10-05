from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from .config import (
    DLC_DEVIATION_THRESHOLD,
    FLOOD_MIN_RATE,
    REPLAY_RATIO_THRESHOLD,
)


@dataclass
class WindowResult:
    frames: int
    fps: float
    unique_ids: int
    max_id_rate: float
    mean_iat_ms: float
    iat_std_ms: float
    unknown_ids: int
    dlc_deviations: int
    replay_ratio: float
    top_id: int | None
    feature_vector: np.ndarray


@dataclass
class DetectionResult:
    is_alert: bool
    classification: str
    severity: str
    can_id: int | None
    anomaly_score: float
    confidence: float
    reason: str
    evidence: str


def build_features(messages: list[tuple[float, int, int, bytes]], duration: float,
                   baseline_ids: set[int] | None = None,
                   baseline_dlc: dict[int, int] | None = None) -> WindowResult:
    duration = max(duration, 1e-6)
    if not messages:
        vec = np.zeros(8, dtype=float)
        return WindowResult(0, 0.0, 0, 0.0, 0.0, 0.0, 0, 0, 0.0, None, vec)

    by_id: dict[int, list[tuple[float, int, bytes]]] = defaultdict(list)
    for ts, cid, dlc, payload in messages:
        by_id[cid].append((ts, dlc, payload))

    all_iat = []
    rates = {}
    replay_counts = 0

    for cid, items in by_id.items():
        rates[cid] = len(items) / duration
        ts_values = [x[0] for x in items]
        all_iat.extend(np.diff(ts_values).tolist())
        payloads = [x[2] for x in items]
        if len(payloads) >= 3:
            counts = Counter(payloads)
            replay_counts += counts.most_common(1)[0][1]

    fps = len(messages) / duration
    unique_ids = len(by_id)
    max_id_rate = max(rates.values(), default=0.0)

    mean_iat_ms = float(np.mean(all_iat) * 1000) if all_iat else 0.0
    iat_std_ms = float(np.std(all_iat) * 1000) if all_iat else 0.0

    unknown_ids = (
        sum(1 for cid in by_id if baseline_ids is not None and cid not in baseline_ids)
        if baseline_ids is not None else 0
    )

    dlc_deviations = 0
    if baseline_dlc is not None:
        for cid, items in by_id.items():
            expected = baseline_dlc.get(cid)
            if expected is None:
                continue
            if any(abs(dlc - expected) >= DLC_DEVIATION_THRESHOLD for _, dlc, _ in items):
                dlc_deviations += 1

    replay_ratio = replay_counts / len(messages) if messages else 0.0
    top_id = max(rates, key=rates.get) if rates else None

    vec = np.array([
        fps,
        unique_ids,
        max_id_rate,
        mean_iat_ms,
        iat_std_ms,
        unknown_ids,
        dlc_deviations,
        replay_ratio,
    ], dtype=float)

    return WindowResult(
        len(messages), fps, unique_ids, max_id_rate, mean_iat_ms, iat_std_ms,
        unknown_ids, dlc_deviations, replay_ratio, top_id, vec
    )


def severity_for(kind: str, score: float, top_rate: float) -> str:
    if kind in {"CAN Flood / DoS", "Unknown-ID Injection"}:
        return "CRITICAL" if top_rate > 200 or score < -0.45 else "HIGH"
    if kind in {"Replay-like Burst", "Payload/DLC Anomaly"}:
        return "HIGH" if score < -0.35 else "MEDIUM"
    return "MEDIUM" if score < -0.2 else "LOW"


def classify(window: WindowResult, ml_score: float,
             baseline_rate: float, per_id_rates: dict[int, float],
             baseline_dlc: dict[int, int]) -> DetectionResult:
    top_id = window.top_id
    top_rate = per_id_rates.get(top_id, 0.0) if top_id is not None else 0.0

    candidates: list[tuple[str, int | None, float, str]] = []

    unknown_candidates = [
        (cid, rate) for cid, rate in per_id_rates.items()
        if cid not in baseline_dlc and rate >= 5.0
    ]
    if unknown_candidates:
        unknown_id, unknown_rate = max(unknown_candidates, key=lambda x: x[1])
        candidates.append((
            "Unknown-ID Injection", unknown_id,
            min(0.99, 0.60 + unknown_rate / 500.0),
            f"CAN ID 0x{unknown_id:03X} was absent from calibration and is transmitting at {unknown_rate:.1f} fps."
        ))

    if top_id is not None and top_rate >= FLOOD_MIN_RATE:
        candidates.append((
            "CAN Flood / DoS", top_id, min(0.99, 0.70 + top_rate / 600.0),
            f"CAN ID 0x{top_id:03X} reached {top_rate:.1f} fps, exceeding the lab flood threshold."
        ))

    if window.replay_ratio >= REPLAY_RATIO_THRESHOLD and window.frames >= 10:
        candidates.append((
            "Replay-like Burst", top_id, min(0.98, 0.70 + window.replay_ratio / 4.0),
            f"{window.replay_ratio * 100:.0f}% of frames repeat the same payload pattern within the window."
        ))

    if window.dlc_deviations:
        candidates.append((
            "Payload/DLC Anomaly", top_id, 0.78,
            f"{window.dlc_deviations} CAN ID(s) showed a data-length-code deviation from calibration."
        ))

    ml_alert = ml_score < 0
    rate_jump = baseline_rate > 0 and window.fps > baseline_rate * 1.8
    if ml_alert or rate_jump:
        candidates.append((
            "Behavioral Anomaly", top_id,
            min(0.95, 0.55 + abs(ml_score)),
            f"Isolation Forest score={ml_score:+.4f}; aggregate rate={window.fps:.1f} fps vs baseline {baseline_rate:.1f} fps."
        ))

    if not candidates:
        return DetectionResult(
            False, "Normal", "INFO", None, ml_score, 0.0,
            "Traffic is consistent with the learned baseline.",
            ""
        )

    priority = {
        "CAN Flood / DoS": 5,
        "Unknown-ID Injection": 4,
        "Replay-like Burst": 3,
        "Payload/DLC Anomaly": 2,
        "Behavioral Anomaly": 1,
    }
    candidates.sort(key=lambda x: (priority.get(x[0], 0), x[2]), reverse=True)
    kind, cid, confidence, reason = candidates[0]
    severity = severity_for(kind, ml_score, top_rate)

    evidence = (
        f"frames={window.frames}; fps={window.fps:.1f}; unique_ids={window.unique_ids}; "
        f"max_id_rate={window.max_id_rate:.1f}; mean_iat_ms={window.mean_iat_ms:.2f}; "
        f"unknown_ids={window.unknown_ids}; dlc_deviations={window.dlc_deviations}; "
        f"replay_ratio={window.replay_ratio:.2f}"
    )

    return DetectionResult(
        True, kind, severity, cid, ml_score, confidence, reason, evidence
    )


def train_model(vectors: list[np.ndarray]) -> IsolationForest:
    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
    )
    model.fit(np.vstack(vectors))
    return model
