import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.detection import build_features, classify


def test_empty_window_returns_zeroed_features():
    window = build_features([], 1.0)

    assert window.frames == 0
    assert window.fps == 0.0
    assert window.unique_ids == 0
    assert window.top_id is None
    assert window.feature_vector.shape == (8,)


def test_non_positive_duration_is_clamped():
    messages = [(1.0, 0x100, 8, b"12345678")]

    window = build_features(messages, 0.0)

    assert window.frames == 1
    assert window.fps > 0
    assert window.feature_vector.shape == (8,)


def test_dlc_deviation_is_counted_against_baseline():
    messages = [
        (0.0, 0x100, 8, b"12345678"),
        (0.1, 0x100, 6, b"123456"),
    ]

    window = build_features(messages, 1.0, {0x100}, {0x100: 8})

    assert window.dlc_deviations == 1
    assert window.feature_vector[6] == 1


def test_flood_rate_produces_flood_alert():
    messages = [(i * 0.001, 0x100, 8, b"12345678") for i in range(80)]
    window = build_features(messages, 1.0, {0x100}, {0x100: 8})

    result = classify(window, 0.1, 20.0, {0x100: 80.0}, {0x100: 8})

    assert result.is_alert
    assert result.classification == "CAN Flood / DoS"
    assert result.can_id == 0x100
    assert result.severity in {"HIGH", "CRITICAL"}
    assert "80.0 fps" in result.reason


def test_repeated_payload_burst_is_classified():
    messages = [(i * 0.1, 0x100, 8, b"REPEAT!!") for i in range(10)]
    window = build_features(messages, 1.0, {0x100}, {0x100: 8})

    result = classify(window, 0.2, 10.0, {0x100: 10.0}, {0x100: 8})

    assert window.replay_ratio >= 0.70
    assert result.is_alert
    assert result.classification == "Replay-like Burst"


def test_unique_payloads_do_not_trigger_replay_threshold():
    messages = [
        (i * 0.1, 0x100, 8, bytes([i, 0, 0, 0, 0, 0, 0, 0]))
        for i in range(10)
    ]

    window = build_features(messages, 1.0, {0x100}, {0x100: 8})

    assert window.replay_ratio < 0.70
