import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.ecu import make_profiles, live_match


def test_ecu_profile_rate_and_dlc():
    msgs = [(i * 0.1, 0x110, 8, b"\x01" * 8) for i in range(10)]
    profiles = make_profiles(msgs)
    profile = profiles[0x110]
    assert profile.can_id == 0x110
    assert profile.dlc_mode == 8
    assert profile.expected_rate > 0


def test_live_match_prefers_expected_behavior():
    msgs = [(i * 0.1, 0x110, 8, b"\x01" * 8) for i in range(10)]
    profile = make_profiles(msgs)[0x110]
    expected = live_match(profile, profile.expected_rate, 8)
    wrong = live_match(profile, profile.expected_rate * 3, 4)
    assert expected >= wrong
