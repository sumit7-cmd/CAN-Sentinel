import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.detection import build_features, classify


def normal_messages():
    rows = []
    t = 0.0
    for i in range(20):
        rows.append((t, 0x100, 8, bytes([i % 5, 0, 0, 0, 0, 0, 0, 0])))
        t += 0.05
    for i in range(10):
        rows.append((i * 0.1, 0x110, 8, b"\x01" * 8))
    rows.sort()
    return rows


def test_feature_shape():
    w = build_features(normal_messages(), 1.0, {0x100, 0x110}, {0x100: 8, 0x110: 8})
    assert w.feature_vector.shape == (8,)
    assert w.frames == 30
    assert w.unique_ids == 2


def test_unknown_id_is_classified():
    rows = normal_messages() + [
        (0.90 + i * 0.001, 0x321, 8, b"INJECT!!") for i in range(10)
    ]
    w = build_features(rows, 1.0, {0x100, 0x110}, {0x100: 8, 0x110: 8})
    per_id = {0x321: 10.0, 0x100: 20.0, 0x110: 10.0}
    result = classify(w, -0.3, 30.0, per_id, {0x100: 8, 0x110: 8})
    assert result.is_alert
    assert result.classification in {"Unknown-ID Injection", "Behavioral Anomaly"}
    assert result.can_id == 0x321


def test_normal_is_not_alert():
    rows = normal_messages()
    w = build_features(rows, 1.0, {0x100, 0x110}, {0x100: 8, 0x110: 8})
    per_id = {0x100: 20.0, 0x110: 10.0}
    result = classify(w, 0.2, 30.0, per_id, {0x100: 8, 0x110: 8})
    assert not result.is_alert
