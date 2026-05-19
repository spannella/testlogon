from __future__ import annotations

import secrets
from typing import Any, Callable, Mapping, Sequence


class LotterySelectionError(ValueError):
    pass


def _validate_outcomes(outcomes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    total = 0
    for idx, raw in enumerate(outcomes):
        outcome_id = str(raw.get("outcome_id") or "").strip()
        weight_bps = int(raw.get("weight_bps") or 0)
        if not outcome_id:
            raise LotterySelectionError(f"outcomes[{idx}].outcome_id is required")
        if weight_bps <= 0:
            raise LotterySelectionError(f"outcomes[{idx}].weight_bps must be > 0")
        normalized.append({"outcome_id": outcome_id, "weight_bps": weight_bps, **dict(raw)})
        total += weight_bps
    if total != 10_000:
        raise LotterySelectionError("outcome weights must sum to 10,000 basis points")
    return normalized


def _secure_roll_1_to_10000() -> int:
    # Domain is [1, 10_000] inclusive.
    return secrets.randbelow(10_000) + 1


def choose_weighted_outcome(
    outcomes: Sequence[Mapping[str, Any]],
    *,
    roll: int | None = None,
    roll_fn: Callable[[], int] | None = None,
) -> tuple[dict[str, Any], int]:
    """Return selected outcome and roll using cumulative integer basis-point ranges."""
    normalized = _validate_outcomes(outcomes)

    if roll is not None and roll_fn is not None:
        raise LotterySelectionError("provide either roll or roll_fn, not both")

    rng_roll = int(roll if roll is not None else (roll_fn() if roll_fn else _secure_roll_1_to_10000()))
    if rng_roll < 1 or rng_roll > 10_000:
        raise LotterySelectionError("roll must be in [1, 10_000]")

    cumulative = 0
    for outcome in normalized:
        cumulative += int(outcome["weight_bps"])
        if rng_roll <= cumulative:
            return outcome, rng_roll

    # Should be unreachable when total is 10_000; keep deterministic guard.
    raise LotterySelectionError("failed to select outcome from weighted ranges")
