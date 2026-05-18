from __future__ import annotations

import pytest

from app.services.messaging_lottery_rng import LotterySelectionError, choose_weighted_outcome


OUTCOMES = [
    {"outcome_id": "o1", "weight_bps": 2500},
    {"outcome_id": "o2", "weight_bps": 2500},
    {"outcome_id": "o3", "weight_bps": 5000},
]


def test_choose_weighted_outcome_domain_edges() -> None:
    first, roll_first = choose_weighted_outcome(OUTCOMES, roll=1)
    assert roll_first == 1
    assert first["outcome_id"] == "o1"

    edge1, _ = choose_weighted_outcome(OUTCOMES, roll=2500)
    assert edge1["outcome_id"] == "o1"

    edge2, _ = choose_weighted_outcome(OUTCOMES, roll=2501)
    assert edge2["outcome_id"] == "o2"

    edge3, _ = choose_weighted_outcome(OUTCOMES, roll=5000)
    assert edge3["outcome_id"] == "o2"

    last, roll_last = choose_weighted_outcome(OUTCOMES, roll=10_000)
    assert roll_last == 10_000
    assert last["outcome_id"] == "o3"


def test_choose_weighted_outcome_rejects_invalid_roll_domain() -> None:
    with pytest.raises(LotterySelectionError):
        choose_weighted_outcome(OUTCOMES, roll=0)
    with pytest.raises(LotterySelectionError):
        choose_weighted_outcome(OUTCOMES, roll=10_001)


def test_choose_weighted_outcome_rejects_invalid_weights() -> None:
    with pytest.raises(LotterySelectionError):
        choose_weighted_outcome([
            {"outcome_id": "o1", "weight_bps": 9999},
            {"outcome_id": "o2", "weight_bps": 0},
        ], roll=1)

    with pytest.raises(LotterySelectionError):
        choose_weighted_outcome([
            {"outcome_id": "o1", "weight_bps": 9999},
            {"outcome_id": "o2", "weight_bps": 2},
        ], roll=1)


def test_choose_weighted_outcome_boundary_intervals_first_and_last_bps() -> None:
    outcomes = [
        {"outcome_id": "first", "weight_bps": 1},
        {"outcome_id": "middle", "weight_bps": 9998},
        {"outcome_id": "last", "weight_bps": 1},
    ]

    first_start, _ = choose_weighted_outcome(outcomes, roll=1)
    assert first_start["outcome_id"] == "first"

    middle_start, _ = choose_weighted_outcome(outcomes, roll=2)
    assert middle_start["outcome_id"] == "middle"

    middle_end, _ = choose_weighted_outcome(outcomes, roll=9_999)
    assert middle_end["outcome_id"] == "middle"

    last_end, _ = choose_weighted_outcome(outcomes, roll=10_000)
    assert last_end["outcome_id"] == "last"
