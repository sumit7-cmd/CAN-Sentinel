from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import statistics


@dataclass
class ECUProfile:
    can_id: int
    first_seen: str
    last_seen: str
    message_count: int
    expected_rate: float
    expected_period: float
    dlc_mode: int
    rate_tolerance: float

    def match_score(self, observed_rate: float, observed_dlc: int) -> float:
        rate_error = abs(observed_rate - self.expected_rate) / max(self.expected_rate, 0.1)
        dlc_penalty = 0.35 if observed_dlc != self.dlc_mode else 0.0
        score = max(0.0, 1.0 - min(1.0, rate_error * 0.6 + dlc_penalty))
        return score


def make_profiles(messages: list[tuple[float, int, int, bytes]],
                  first_seen: str = "calibration",
                  last_seen: str = "calibration") -> dict[int, ECUProfile]:
    per_id = defaultdict(list)
    for ts, cid, dlc, payload in messages:
        per_id[cid].append((ts, dlc))

    profiles = {}
    for cid, items in per_id.items():
        times = [x[0] for x in items]
        rates = len(items) / max(times[-1] - times[0], 1.0)
        intervals = []
        if len(times) > 1:
            intervals = [b - a for a, b in zip(times, times[1:])]
        period = statistics.mean(intervals) if intervals else 0.0
        dlc_values = [x[1] for x in items]
        dlc_mode = max(set(dlc_values), key=dlc_values.count)
        tolerance = max(0.2 * rates, 1.0)

        profiles[cid] = ECUProfile(
            cid, first_seen, last_seen, len(items),
            rates, period, dlc_mode, tolerance
        )
    return profiles


def live_match(profile: ECUProfile, observed_rate: float, observed_dlc: int) -> float:
    return profile.match_score(observed_rate, observed_dlc)
