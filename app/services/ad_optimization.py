"""Ad performance optimization service (ADS-017).

Provides automated optimization for ad campaigns by building on the existing
analytics rollups (``app/services/ad_analytics.py``) and the campaign/creative
records (``ad_campaigns.py`` / ``ad_creatives.py``):

- Creative auto-rotation weighting (weight by CTR, 5% floor, sum = 1.0)
- Underperformer detection (auto-pause candidates)
- Deterministic recommendation generation persisted to DynamoDB
- Apply / dismiss a recommendation (mutating the underlying campaign/creative)
- Recommendation history
- Suggested bid + budget recommendation
- A/B test statistical significance (two-proportion Z-test, pure-Python)
- Performance alerts (CTR / ROAS / budget pacing)

Recommendation generation is a pure, deterministic function of the analytics
inputs, exposed via an explicit generate-now entry point so E2E tests do not
depend on a background timer. Analytics / rollup data is seeded directly in
tests.
"""

from __future__ import annotations

import hashlib
import logging
import math
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_analytics
from app.services.ad_creatives import (
    get_creative_by_id,
    list_creatives,
)

logger = logging.getLogger(__name__)

# ─── Configuration defaults ──────────────────────────────────────────

DEFAULT_AUTO_PAUSE_CTR_THRESHOLD = 0.005  # 0.5%
DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS = 1000
DEFAULT_CTR_ALERT_THRESHOLD = 0.01  # 1%
DEFAULT_ROAS_ALERT_THRESHOLD = 1.0  # break-even
DEFAULT_BUDGET_PACE_ALERT_RATIO = 1.2  # 120% of daily target
MIN_WEIGHT = 0.05  # 5% rotation floor


# ─── Helpers: deterministic float storage ────────────────────────────


def _dec(x: float) -> Decimal:
    return Decimal(str(x))


def _floats_to_decimal(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_floats_to_decimal(v) for v in obj]
    return obj


def _to_num(v: Any) -> float:
    if isinstance(v, Decimal):
        return float(v)
    return float(v or 0)


# ─── Creative performance (reuse ad_analytics) ───────────────────────


def get_creative_stats(
    account_id: str, campaign_id: str, days: int = 7
) -> List[Dict[str, Any]]:
    """Pull per-creative performance from the analytics breakdown.

    Reuses ``ad_analytics.get_breakdown`` (the by_creative rollup aggregation),
    then maps it into ``{creative_id, impressions, clicks, ctr}`` entries.
    Creatives with no analytics rows still appear with zeroed stats so the
    rotation weights cover every active creative.
    """
    breakdown = ad_analytics.get_breakdown(
        account_id, campaign_id, dimension="creative", days=days
    )
    stats: Dict[str, Dict[str, Any]] = {}
    for row in breakdown:
        cid = row.get("dimension_key")
        if not cid:
            continue
        impressions = int(row.get("impressions", 0))
        clicks = int(row.get("clicks", 0))
        stats[cid] = {
            "creative_id": cid,
            "impressions": impressions,
            "clicks": clicks,
            "ctr": (clicks / impressions) if impressions > 0 else 0.0,
        }

    # Ensure every existing creative is represented (zeroed if no analytics).
    for cr in list_creatives(campaign_id):
        cid = cr.get("creative_id")
        if cid and cid not in stats:
            stats[cid] = {
                "creative_id": cid,
                "impressions": 0,
                "clicks": 0,
                "ctr": 0.0,
            }

    # Deterministic ordering (by creative_id) for reproducible output.
    return [stats[k] for k in sorted(stats.keys())]


# ─── Creative rotation weights ───────────────────────────────────────


def calculate_creative_weights(
    creative_stats: List[Dict[str, Any]]
) -> Dict[str, float]:
    """Rotation weights proportional to CTR with a MIN_WEIGHT floor, sum=1.0."""
    if not creative_stats:
        return {}

    ctrs: Dict[str, float] = {}
    for stat in creative_stats:
        cid = stat["creative_id"]
        impressions = int(stat.get("impressions", 0) or 0)
        clicks = int(stat.get("clicks", 0) or 0)
        ctrs[cid] = (clicks / impressions) if impressions > 0 else 0.0

    total_ctr = sum(ctrs.values())
    if total_ctr == 0:
        n = len(creative_stats)
        return {s["creative_id"]: round(1.0 / n, 6) for s in creative_stats}

    weights = {cid: max(MIN_WEIGHT, ctr / total_ctr) for cid, ctr in ctrs.items()}
    total = sum(weights.values())
    return {cid: round(w / total, 6) for cid, w in weights.items()}


def identify_underperformers(
    creative_stats: List[Dict[str, Any]],
    ctr_threshold: float = DEFAULT_AUTO_PAUSE_CTR_THRESHOLD,
    min_impressions: int = DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS,
) -> List[Dict[str, Any]]:
    """Creatives with >= min_impressions and CTR below threshold."""
    underperformers: List[Dict[str, Any]] = []
    for stat in creative_stats:
        impressions = int(stat.get("impressions", 0) or 0)
        clicks = int(stat.get("clicks", 0) or 0)
        ctr = (clicks / impressions) if impressions > 0 else 0.0
        if impressions >= min_impressions and ctr < ctr_threshold:
            underperformers.append(
                {
                    "creative_id": stat["creative_id"],
                    "impressions": impressions,
                    "clicks": clicks,
                    "ctr": round(ctr, 6),
                    "threshold": ctr_threshold,
                    "reason": f"CTR {ctr:.4f} below threshold {ctr_threshold:.4f}",
                }
            )
    return underperformers


# ─── Suggested bid / budget ──────────────────────────────────────────


def _calculate_targeting_specificity(targeting: Dict[str, Any]) -> float:
    score = 0.0
    age_range = targeting.get("age_range")
    if age_range and len(age_range) == 2:
        span = age_range[1] - age_range[0]
        score += max(0, (47 - span) / 47) * 0.3
    interests = targeting.get("interests")
    if interests:
        score += min(len(interests) * 0.1, 0.3)
    geo = targeting.get("geo")
    if geo:
        if len(geo) == 1:
            score += 0.2
        elif len(geo) <= 3:
            score += 0.1
    return min(score, 1.0)


def calculate_suggested_bid(
    *,
    targeting: Optional[Dict[str, Any]] = None,
    content_category: str = "general",
) -> Dict[str, Any]:
    """Deterministic bid range based on targeting specificity."""
    if not targeting:
        return {
            "min_bid_cpm_cents": 200,
            "suggested_bid_cpm_cents": 500,
            "max_bid_cpm_cents": 1000,
            "estimated_fill_rate": 0.85,
            "competition_level": "medium",
        }

    specificity = _calculate_targeting_specificity(targeting)
    base = 500
    suggested = int(base * (1 + specificity))
    min_bid = int(suggested * 0.4)
    max_bid = int(suggested * 2.0)
    fill_rate = max(0.3, 1.0 - specificity * 0.7)
    competition = (
        "low" if specificity < 0.33 else "medium" if specificity < 0.66 else "high"
    )
    return {
        "min_bid_cpm_cents": min_bid,
        "suggested_bid_cpm_cents": suggested,
        "max_bid_cpm_cents": max_bid,
        "estimated_fill_rate": round(fill_rate, 2),
        "competition_level": competition,
    }


def recommend_daily_budget(
    *,
    targeting: Optional[Dict[str, Any]] = None,
    desired_daily_reach: int = 1000,
) -> Dict[str, Any]:
    """Daily budget recommendation that scales with desired reach."""
    bid_info = calculate_suggested_bid(targeting=targeting)
    estimated_cpm = bid_info["suggested_bid_cpm_cents"]
    budget_cents = int((desired_daily_reach / 1000) * estimated_cpm)
    budget_cents = max(500, budget_cents)
    return {
        "estimated_daily_reach": desired_daily_reach,
        "recommended_daily_budget_cents": budget_cents,
        "estimated_cpm_cents": estimated_cpm,
        "reach_per_dollar": round(1000 / estimated_cpm * 100, 1)
        if estimated_cpm > 0
        else 0,
    }


# ─── A/B test significance ───────────────────────────────────────────


def _normal_cdf(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def ab_test_significance(
    *,
    variant_a: Dict[str, int],
    variant_b: Dict[str, int],
    confidence_level: float = 0.95,
) -> Dict[str, Any]:
    """Two-proportion Z-test between two creatives."""
    n_a = int(variant_a.get("impressions", 0) or 0)
    x_a = int(variant_a.get("clicks", 0) or 0)
    n_b = int(variant_b.get("impressions", 0) or 0)
    x_b = int(variant_b.get("clicks", 0) or 0)

    min_sample = 100
    if n_a < min_sample or n_b < min_sample:
        p_a = x_a / n_a if n_a > 0 else 0.0
        p_b = x_b / n_b if n_b > 0 else 0.0
        return {
            "variant_a_ctr": round(p_a, 6),
            "variant_b_ctr": round(p_b, 6),
            "lift_percent": 0.0,
            "z_score": 0.0,
            "p_value": 1.0,
            "significant": False,
            "confidence_level": confidence_level,
            "winner": None,
            "sample_size_sufficient": False,
        }

    p_a = x_a / n_a
    p_b = x_b / n_b
    p_pool = (x_a + x_b) / (n_a + n_b)
    se = math.sqrt(p_pool * (1 - p_pool) * (1 / n_a + 1 / n_b))

    if se == 0:
        z_score = 0.0
        p_value = 1.0
    else:
        z_score = (p_a - p_b) / se
        p_value = 2 * (1 - _normal_cdf(abs(z_score)))

    alpha = 1 - confidence_level
    significant = p_value < alpha
    winner = ("a" if p_a > p_b else "b") if significant else None
    lift = ((p_a - p_b) / p_b * 100) if p_b > 0 else 0.0

    return {
        "variant_a_ctr": round(p_a, 6),
        "variant_b_ctr": round(p_b, 6),
        "lift_percent": round(lift, 2),
        "z_score": round(z_score, 4),
        "p_value": round(p_value, 6),
        "significant": significant,
        "confidence_level": confidence_level,
        "winner": winner,
        "sample_size_sufficient": True,
    }


# ─── Performance alerts ──────────────────────────────────────────────


def check_performance_alerts(
    *,
    campaign_id: str,
    campaign_metrics: Dict[str, Any],
    alert_config: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    config = alert_config or {}
    ctr_threshold = config.get("ctr_threshold", DEFAULT_CTR_ALERT_THRESHOLD)
    roas_threshold = config.get("roas_threshold", DEFAULT_ROAS_ALERT_THRESHOLD)
    pace_ratio = config.get("budget_pace_ratio", DEFAULT_BUDGET_PACE_ALERT_RATIO)

    alerts: List[Dict[str, Any]] = []
    m = campaign_metrics

    ctr = m.get("ctr", 0)
    if ctr < ctr_threshold and m.get("impressions", 0) > 500:
        alerts.append(
            {
                "alert_type": "ctr_below_threshold",
                "severity": "warning",
                "message": f"Campaign CTR ({ctr:.2%}) is below threshold ({ctr_threshold:.2%})",
                "current_value": round(ctr, 6),
                "threshold": ctr_threshold,
            }
        )

    roas = m.get("roas", 0)
    if roas < roas_threshold and m.get("spend_cents", 0) > 1000:
        alerts.append(
            {
                "alert_type": "roas_below_threshold",
                "severity": "warning",
                "message": f"Campaign ROAS ({roas:.2f}x) is below break-even ({roas_threshold:.2f}x)",
                "current_value": round(roas, 4),
                "threshold": roas_threshold,
            }
        )

    daily_budget = m.get("daily_budget_cents", 0)
    spent_today = m.get("spent_today_cents", 0)
    if daily_budget > 0:
        pacing = spent_today / daily_budget
        if pacing > pace_ratio:
            alerts.append(
                {
                    "alert_type": "budget_overpacing",
                    "severity": "warning",
                    "message": f"Campaign is pacing at {pacing:.0%} of daily budget",
                    "current_value": round(pacing, 4),
                    "threshold": pace_ratio,
                }
            )

    return alerts


# ─── Recommendation persistence ──────────────────────────────────────


def _rec_id(campaign_id: str, action: str, creative_id: Optional[str], salt: str) -> str:
    """Deterministic recommendation id for a (campaign, action, creative) tuple.

    Salting with ``salt`` (the generation timestamp) lets repeated generate
    runs produce fresh, distinct records while a single run stays deterministic.
    """
    raw = f"{campaign_id}|{action}|{creative_id or ''}|{salt}"
    return "rec_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def _store_recommendation(rec: Dict[str, Any]) -> None:
    item = {
        "pk": f"CAMP#{rec['campaign_id']}",
        "sk": f"REC#{rec['recommendation_id']}",
        **rec,
    }
    T.ad_optimization_recommendations.put_item(Item=_floats_to_decimal(item))


def _rec_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "recommendation_id": item.get("recommendation_id", ""),
        "campaign_id": item.get("campaign_id", ""),
        "account_id": item.get("account_id", ""),
        "action": item.get("action", ""),
        "creative_id": item.get("creative_id"),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "impact": item.get("impact", ""),
        "severity": item.get("severity", "info"),
        "details": {
            k: (_to_num(v) if isinstance(v, Decimal) else v)
            for k, v in (item.get("details") or {}).items()
        },
        "status": item.get("status", "open"),
        "created_at": int(item.get("created_at", 0) or 0),
        "updated_at": int(item.get("updated_at", 0) or 0),
        "applied_at": int(item["applied_at"]) if item.get("applied_at") else None,
        "dismissed_at": int(item["dismissed_at"]) if item.get("dismissed_at") else None,
    }


def get_recommendation(campaign_id: str, recommendation_id: str) -> Optional[Dict[str, Any]]:
    resp = T.ad_optimization_recommendations.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"REC#{recommendation_id}"}
    )
    item = resp.get("Item")
    return _rec_out(item) if item else None


def list_recommendations(
    campaign_id: str, status: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Recommendation history for a campaign (newest first)."""
    resp = T.ad_optimization_recommendations.query(
        IndexName="ByCampaignCreatedAt",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
        ScanIndexForward=False,
    )
    out = [_rec_out(i) for i in resp.get("Items", [])]
    if status:
        out = [r for r in out if r["status"] == status]
    return out


# ─── Deterministic recommendation generation ─────────────────────────


def generate_recommendations(
    *,
    account_id: str,
    campaign: Dict[str, Any],
    days: int = 7,
) -> Dict[str, Any]:
    """Deterministically analyze performance and persist recommendations.

    Pure function of the analytics inputs + campaign config. Produces:
    - creative rotation weights
    - underperformer (auto-pause candidate) recommendations
    - budget reallocation recommendation (shift toward best creative)
    - bid adjustment recommendation when campaign CTR is weak
    """
    campaign_id = campaign["campaign_id"]
    config = campaign.get("optimization_config") or {}
    ctr_threshold = _to_num(config.get("ctr_threshold", DEFAULT_AUTO_PAUSE_CTR_THRESHOLD)) or DEFAULT_AUTO_PAUSE_CTR_THRESHOLD
    min_impr = int(
        _to_num(config.get("auto_pause_min_impressions", DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS))
        or DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS
    )

    stats = get_creative_stats(account_id, campaign_id, days=days)
    weights = calculate_creative_weights(stats)
    underperformers = identify_underperformers(
        stats, ctr_threshold=ctr_threshold, min_impressions=min_impr
    )

    total_impr = sum(s["impressions"] for s in stats)
    total_clicks = sum(s["clicks"] for s in stats)
    campaign_ctr = (total_clicks / total_impr) if total_impr > 0 else 0.0

    ts = now_ts()
    salt = str(ts)
    recs: List[Dict[str, Any]] = []

    # 1) Pause underperforming creatives.
    underperformer_ids = {u["creative_id"] for u in underperformers}
    for u in underperformers:
        cid = u["creative_id"]
        recs.append(
            {
                "recommendation_id": _rec_id(campaign_id, "pause_creative", cid, salt),
                "campaign_id": campaign_id,
                "account_id": account_id,
                "action": "pause_creative",
                "creative_id": cid,
                "title": "Pause underperforming creative",
                "description": (
                    f"Creative {cid} has a CTR of {u['ctr'] * 100:.2f}% over "
                    f"{u['impressions']} impressions, below the "
                    f"{ctr_threshold * 100:.2f}% threshold."
                ),
                "impact": "Stops spending on a low-CTR creative",
                "severity": "warning",
                "details": {
                    "impressions": u["impressions"],
                    "clicks": u["clicks"],
                    "ctr": u["ctr"],
                    "threshold": ctr_threshold,
                },
                "status": "open",
                "created_at": ts,
                "updated_at": ts,
            }
        )

    # 2) Reallocate budget toward the best creative via rotation weights.
    scored = [s for s in stats if s["impressions"] > 0 and s["creative_id"] not in underperformer_ids]
    if len(scored) >= 2 and weights:
        best = max(scored, key=lambda s: (s["ctr"], s["creative_id"]))
        recs.append(
            {
                "recommendation_id": _rec_id(campaign_id, "reallocate_budget", best["creative_id"], salt),
                "campaign_id": campaign_id,
                "account_id": account_id,
                "action": "reallocate_budget",
                "creative_id": best["creative_id"],
                "title": "Reallocate budget to top creative",
                "description": (
                    f"Creative {best['creative_id']} has the highest CTR "
                    f"({best['ctr'] * 100:.2f}%). Shift rotation weight toward it."
                ),
                "impact": "Improves campaign ROI via performance-weighted rotation",
                "severity": "info",
                "details": {"creative_weights": weights},
                "status": "open",
                "created_at": ts,
                "updated_at": ts,
            }
        )

    # 3) Adjust bid when overall campaign CTR is weak.
    if total_impr >= 500 and campaign_ctr < DEFAULT_CTR_ALERT_THRESHOLD:
        bid_info = calculate_suggested_bid(
            targeting=campaign.get("targeting") if isinstance(campaign.get("targeting"), dict) else None
        )
        recs.append(
            {
                "recommendation_id": _rec_id(campaign_id, "adjust_bid", None, salt),
                "campaign_id": campaign_id,
                "account_id": account_id,
                "action": "adjust_bid",
                "creative_id": None,
                "title": "Adjust campaign bid",
                "description": (
                    f"Campaign CTR ({campaign_ctr * 100:.2f}%) is weak. Consider "
                    f"adjusting bid toward the suggested "
                    f"{bid_info['suggested_bid_cpm_cents']}c CPM."
                ),
                "impact": "Targets a more efficient bid for current performance",
                "severity": "info",
                "details": {
                    "campaign_ctr": round(campaign_ctr, 6),
                    "suggested_bid_cpm_cents": bid_info["suggested_bid_cpm_cents"],
                    "min_bid_cpm_cents": bid_info["min_bid_cpm_cents"],
                    "max_bid_cpm_cents": bid_info["max_bid_cpm_cents"],
                },
                "status": "open",
                "created_at": ts,
                "updated_at": ts,
            }
        )

    for rec in recs:
        _store_recommendation(rec)

    alerts = check_performance_alerts(
        campaign_id=campaign_id,
        campaign_metrics={
            "ctr": campaign_ctr,
            "impressions": total_impr,
            "daily_budget_cents": int(_to_num(campaign.get("daily_budget_cents", 0))),
            "spent_today_cents": int(_to_num(campaign.get("spent_today_cents", 0))),
        },
        alert_config=config,
    )

    return {
        "campaign_id": campaign_id,
        "creative_weights": weights,
        "creative_stats": [
            {
                "creative_id": s["creative_id"],
                "impressions": s["impressions"],
                "clicks": s["clicks"],
                "ctr": round(s["ctr"], 6),
                "weight": weights.get(s["creative_id"], 0.0),
            }
            for s in stats
        ],
        "underperformers": underperformers,
        "alerts": alerts,
        "recommendations": [_rec_out({**r}) for r in recs],
        "generated_at": ts,
    }


# ─── Apply / dismiss a recommendation ────────────────────────────────


def _update_status(
    campaign_id: str, recommendation_id: str, status: str, ts_field: str
) -> None:
    ts = now_ts()
    T.ad_optimization_recommendations.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"REC#{recommendation_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u, " + ts_field + " = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status, ":u": ts, ":t": ts},
    )


def apply_recommendation(
    *, account_id: str, campaign: Dict[str, Any], recommendation_id: str
) -> Dict[str, Any]:
    """Apply a recommendation, mutating the underlying campaign/creative.

    - pause_creative   → set creative status = "auto_paused"
    - reallocate_budget → write creative_weights onto the campaign record
    - adjust_bid        → write suggested_bid_cpm_cents onto the campaign record
    """
    campaign_id = campaign["campaign_id"]
    rec = get_recommendation(campaign_id, recommendation_id)
    if not rec:
        raise ValueError("Recommendation not found")
    if rec["status"] != "open":
        raise ValueError(f"Recommendation is already {rec['status']}")

    action = rec["action"]
    applied: Dict[str, Any] = {"action": action}

    if action == "pause_creative":
        cid = rec.get("creative_id")
        cr = get_creative_by_id(cid) if cid else None
        if not cr:
            raise ValueError("Creative not found")
        # Safety: never pause the last remaining active creative.
        active = [
            c
            for c in list_creatives(campaign_id)
            if c.get("status") not in ("auto_paused", "archived", "rejected")
        ]
        if len(active) <= 1 and any(c.get("creative_id") == cid for c in active):
            raise ValueError("Cannot pause the last active creative in a campaign")
        # Set status directly (CreativeUpdateIn does not expose `status`),
        # recording the auto-pause reason + timestamp for audit.
        T.ad_creatives.update_item(
            Key={"pk": cr["pk"], "sk": cr["sk"]},
            UpdateExpression=(
                "SET #s = :s, paused_reason = :r, paused_at = :t, updated_at = :t"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "auto_paused",
                ":r": rec.get("description", "CTR below threshold"),
                ":t": now_ts(),
            },
        )
        applied["creative_id"] = cid
        applied["new_creative_status"] = "auto_paused"

    elif action == "reallocate_budget":
        weights = rec.get("details", {}).get("creative_weights") or {}
        _set_campaign_field(account_id, campaign, "creative_weights", weights)
        applied["creative_weights"] = weights

    elif action == "adjust_bid":
        new_bid = int(rec.get("details", {}).get("suggested_bid_cpm_cents", 0) or 0)
        _set_campaign_field(account_id, campaign, "suggested_bid_cpm_cents", new_bid)
        applied["suggested_bid_cpm_cents"] = new_bid

    else:
        raise ValueError(f"Unknown recommendation action: {action}")

    _update_status(campaign_id, recommendation_id, "applied", "applied_at")
    logger.info(
        "ad_optimization_applied campaign_id=%s rec_id=%s action=%s",
        campaign_id,
        recommendation_id,
        action,
    )
    return {"ok": True, "status": "applied", **applied}


def dismiss_recommendation(
    *, campaign_id: str, recommendation_id: str
) -> Dict[str, Any]:
    rec = get_recommendation(campaign_id, recommendation_id)
    if not rec:
        raise ValueError("Recommendation not found")
    if rec["status"] != "open":
        raise ValueError(f"Recommendation is already {rec['status']}")
    _update_status(campaign_id, recommendation_id, "dismissed", "dismissed_at")
    logger.info(
        "ad_optimization_dismissed campaign_id=%s rec_id=%s",
        campaign_id,
        recommendation_id,
    )
    return {"ok": True, "status": "dismissed"}


def _set_campaign_field(
    account_id: str, campaign: Dict[str, Any], field: str, value: Any
) -> None:
    T.ad_campaigns.update_item(
        Key={"pk": campaign["pk"], "sk": campaign["sk"]},
        UpdateExpression="SET #f = :v, updated_at = :u",
        ExpressionAttributeNames={"#f": field},
        ExpressionAttributeValues={":v": _floats_to_decimal(value), ":u": now_ts()},
    )


# ─── Optimization config ─────────────────────────────────────────────


def update_optimization_config(
    campaign: Dict[str, Any], updates: Dict[str, Any]
) -> Dict[str, Any]:
    """Persist optimization config (and auto_optimize_enabled) on the campaign."""
    existing = dict(campaign.get("optimization_config") or {})
    auto_enabled = campaign.get("auto_optimize_enabled", False)

    if "auto_optimize_enabled" in updates and updates["auto_optimize_enabled"] is not None:
        auto_enabled = bool(updates["auto_optimize_enabled"])

    for key in (
        "ctr_threshold",
        "auto_pause_min_impressions",
        "roas_threshold",
        "budget_pace_alert_ratio",
    ):
        if updates.get(key) is not None:
            existing[key] = updates[key]

    T.ad_campaigns.update_item(
        Key={"pk": campaign["pk"], "sk": campaign["sk"]},
        UpdateExpression="SET optimization_config = :c, auto_optimize_enabled = :a, updated_at = :u",
        ExpressionAttributeValues={
            ":c": _floats_to_decimal(existing),
            ":a": auto_enabled,
            ":u": now_ts(),
        },
    )
    return {
        "ok": True,
        "auto_optimize_enabled": auto_enabled,
        "optimization_config": {
            k: (_to_num(v) if isinstance(v, Decimal) else v) for k, v in existing.items()
        },
    }
