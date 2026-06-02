from __future__ import annotations

from .cause_band import BAND_RANK


def recovered_to_safe(ranks: list[int]) -> bool:
    seen_non_safe = False
    for rank in ranks:
        if rank > BAND_RANK["safe_range"]:
            seen_non_safe = True
        elif seen_non_safe and rank == BAND_RANK["safe_range"]:
            return True
    return False


def is_oscillating(ranks: list[int]) -> bool:
    seen_non_safe = False
    seen_recovery = False
    for rank in ranks:
        if rank > BAND_RANK["safe_range"]:
            if seen_recovery:
                return True
            seen_non_safe = True
        elif seen_non_safe and rank == BAND_RANK["safe_range"]:
            seen_recovery = True
    return False


def trajectory_direction(ranks: list[int]) -> str:
    if len(ranks) < 2:
        return "stable"
    if is_oscillating(ranks):
        return "oscillating"

    deltas = [right - left for left, right in zip(ranks, ranks[1:])]
    has_up = any(delta > 0 for delta in deltas)
    has_down = any(delta < 0 for delta in deltas)

    if has_up and not has_down:
        return "degrading"
    if has_down and not has_up:
        return "recovering"
    if has_up and has_down:
        if ranks[-1] == BAND_RANK["safe_range"]:
            return "recovering"
        return "mixed"
    return "stable"
