"""
GAP-0067 regression: creative_weights written by apply_recommendation must be
consumed by _weighted_random_creative in ad_serving.py.

Offline (in-memory, no real AWS). Run with:
    .venv/bin/pytest tests/test_gap_0067_creative_weights.py -v
"""
import random


def test_weighted_random_creative_uses_campaign_weights():
    """When campaign_weights is supplied, it must override rotation_weight."""
    from app.services.ad_serving import _weighted_random_creative

    creatives = [
        {"creative_id": "cr_a", "rotation_weight": 50},
        {"creative_id": "cr_b", "rotation_weight": 50},
    ]
    campaign_weights = {"cr_a": 95, "cr_b": 5}

    # Run 1000 samples; with 95:5 split cr_a should win ~95 % of the time.
    # Before fix: campaign_weights is ignored (signature lacks the parameter),
    # so both creatives get weight=50 -> ~50 % each -> test fails (or TypeError).
    counts = {"cr_a": 0, "cr_b": 0}
    random.seed(42)
    for _ in range(1000):
        result = _weighted_random_creative(creatives, campaign_weights=campaign_weights)
        counts[result["creative_id"]] += 1

    assert counts["cr_a"] > 850, (
        f"cr_a won {counts['cr_a']}/1000 - creative_weights are not being honoured. "
        "This is the GAP-0067 regression."
    )


def test_weighted_random_creative_fallback_without_campaign_weights():
    """When no campaign_weights is provided, behaviour must be unchanged."""
    from app.services.ad_serving import _weighted_random_creative

    creatives = [
        {"creative_id": "cr_a", "rotation_weight": 80},
        {"creative_id": "cr_b", "rotation_weight": 20},
    ]
    counts = {"cr_a": 0, "cr_b": 0}
    random.seed(99)
    for _ in range(1000):
        result = _weighted_random_creative(creatives)
        counts[result["creative_id"]] += 1

    # 80:20 -> cr_a should win >65 % of samples.
    assert counts["cr_a"] > 650


def test_weighted_random_creative_partial_campaign_weights():
    """Creatives absent from campaign_weights fall back to rotation_weight."""
    from app.services.ad_serving import _weighted_random_creative

    creatives = [
        {"creative_id": "cr_a", "rotation_weight": 50},
        {"creative_id": "cr_b", "rotation_weight": 50},
        {"creative_id": "cr_c", "rotation_weight": 50},  # not in campaign_weights
    ]
    campaign_weights = {"cr_a": 80, "cr_b": 20}  # cr_c absent

    random.seed(7)
    results = {
        _weighted_random_creative(creatives, campaign_weights=campaign_weights)["creative_id"]
        for _ in range(200)
    }
    # All three creatives should be reachable (cr_c falls back to rotation_weight).
    assert "cr_c" in results, "cr_c (absent from campaign_weights) never selected"
