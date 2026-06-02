from __future__ import annotations

SAFE_RANK = 0


def recovered_to_safe(ranks: list[int]) -> bool:
    seen_non_safe = False
    for rank in ranks:
        if rank > SAFE_RANK:
            seen_non_safe = True
        elif seen_non_safe and rank == SAFE_RANK:
            return True
    return False


def is_oscillating(ranks: list[int]) -> bool:
    seen_non_safe = False
    seen_recovery = False
    for rank in ranks:
        if rank > SAFE_RANK:
            if seen_recovery:
                return True
            seen_non_safe = True
        elif seen_non_safe and rank == SAFE_RANK:
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
        if ranks[-1] == SAFE_RANK:
            return "recovering"
        return "mixed"
    return "stable"
