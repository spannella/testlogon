# ADS-017: Ad Performance Optimization

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: ADS-001 (campaign manager), ADS-002 (ad creative management), ADS-004 (ad serving), ADS-007 (ad billing), ADS-008 (ad analytics) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets not yet in the codebase. -->

---

## 1. Overview & Motivation

### The Gap

The advertising platform (ADS-001 through ADS-010) provides campaign management, creative hosting, serving, and analytics — but no automated optimization. Advertisers must manually monitor campaign performance, identify underperforming creatives, adjust bids, and reallocate budgets. This is labor-intensive and reactive: by the time an advertiser notices a creative has a 0.1% CTR (vs. the 2% average), they have already wasted days of budget.

The ad serving engine (ADS-004) treats all creatives within a campaign equally, showing each with roughly the same frequency. In reality, some creatives perform dramatically better than others. A simple performance-weighted rotation would automatically shift impressions toward higher-performing creatives, improving campaign ROI without advertiser intervention.

### Why This Is Needed

1. **Creative optimization**: In a campaign with 5 creatives, one typically outperforms the others by 3-5x. Equal rotation wastes 60-80% of impressions on underperformers. Auto-rotation by CTR shifts budget to the best creative automatically.

2. **Budget efficiency**: Auto-pause stops spending on creatives or ad groups that fall below a performance threshold (e.g., CTR < 0.5%), saving budget for better-performing assets.

3. **Bid guidance**: New advertisers often set bids too high (overpaying) or too low (no impressions). Suggested bids based on historical fill rates and competition help advertisers find the sweet spot.

4. **A/B testing rigor**: Advertisers run A/B tests between creatives but have no statistical significance calculation. They make premature decisions based on small sample sizes or miss significant differences in large datasets.

5. **Proactive alerts**: Rather than checking dashboards daily, advertisers should receive notifications when CTR drops below a threshold, ROAS deteriorates, or spend is on pace to exceed budget.

6. **Budget recommendations**: Advertisers frequently ask "how much should I spend?" Estimating daily reach based on historical fill rates and targeting specificity answers this question programmatically.

### Architecture After This Change

```
┌──────────────────────────────────────────────────┐
│  Ad Optimization Engine                           │
│  app/services/ad_optimization.py                  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ Auto-Rotate Creatives                       │  │
│  │                                             │  │
│  │ For each campaign:                          │  │
│  │ 1. Calculate CTR for each creative          │  │
│  │ 2. Weight distribution by CTR               │  │
│  │ 3. Creative with 3x CTR gets 3x impressions│  │
│  │ 4. Store weights on campaign record         │  │
│  │                                             │  │
│  │ Serving engine reads weights when selecting │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ Auto-Pause Underperformers                  │  │
│  │                                             │  │
│  │ Threshold: configurable per campaign        │  │
│  │ Default: CTR < 0.5% after 1000 impressions  │  │
│  │                                             │  │
│  │ Action: set creative status = "auto_paused" │  │
│  │ Notification: alert advertiser              │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ Suggested Bid                               │  │
│  │                                             │  │
│  │ Based on: competition level + fill rate     │  │
│  │ Output: min_bid, suggested_bid, max_bid     │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ Budget Recommendation                       │  │
│  │                                             │  │
│  │ Input: targeting + desired reach            │  │
│  │ Output: estimated daily budget              │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ A/B Test Significance                       │  │
│  │                                             │  │
│  │ Method: Z-test for proportions              │  │
│  │ Output: p-value, confidence level,          │  │
│  │         winner, lift percentage             │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │ Performance Alerts                          │  │
│  │                                             │  │
│  │ Triggers:                                   │  │
│  │ - CTR drops below threshold                 │  │
│  │ - ROAS drops below threshold                │  │
│  │ - Budget pace exceeds 120% of daily target  │  │
│  │ - Creative fatigue (CTR declining 3+ days)  │  │
│  │                                             │  │
│  │ Delivery: in-app alert + optional webhook   │  │
│  └─────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Data Flow — Auto-Optimize Run

```
Background Check / Manual Trigger
        │
        ▼
┌───────────────────────────────────────┐
│  Optimization Engine                   │
│                                       │
│  1. Fetch all active campaigns        │
│  2. For each campaign:                │
│     a. Fetch creative performance     │
│        (impressions, clicks by       │
│         creative_id, last 7 days)    │
│     b. Calculate CTR per creative     │
│     c. Generate rotation weights      │
│     d. Identify underperformers       │
│     e. Check alert thresholds         │
│                                       │
│  3. Write results:                    │
│     - creative_weights on campaign    │
│     - auto_pause flagged creatives    │
│     - alert notifications             │
│     - optimization_log entry          │
└───────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────┐
│  DynamoDB                             │
│                                       │
│  Campaign record updated:             │
│  creative_weights: {                  │
│    "cr_1": 0.50,  ← 50% (best CTR)  │
│    "cr_2": 0.30,  ← 30%             │
│    "cr_3": 0.15,  ← 15%             │
│    "cr_4": 0.05,  ← 5% (worst CTR)  │
│  }                                    │
│                                       │
│  Auto-paused creative:                │
│  cr_5: { status: "auto_paused",      │
│           paused_reason: "CTR<0.5%"  │
│           paused_at: 1748534400 }    │
└───────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Ad Serving (ADS-004)

The ad serving engine selects creatives from a campaign's creative list. Currently, selection is uniform (round-robin or random) — all creatives get roughly equal impressions regardless of performance. The serving engine needs to accept `creative_weights` from the campaign record and use weighted random selection.

### 2.2 Ad Analytics (ADS-008)

The analytics system provides per-creative metrics: impressions, clicks, completions. These metrics are the input for optimization calculations. The analytics data is stored in the `AdImpressions` table with PK `AD_IMP#{date}` and filterable by `creative_id`.

### 2.3 Ad Billing (ADS-007)

Campaign spend tracking exists. The optimization engine needs spend data for ROAS calculations and budget pacing alerts.

### 2.4 Alerts (`app/services/alerts.py`)

The alert system supports in-app notifications via `create_alert()`. Performance alerts can use this existing infrastructure.

### 2.5 Gaps

1. No creative performance weighting in ad serving
2. No auto-pause logic for underperforming creatives
3. No bid suggestion based on competition/historical data
4. No budget recommendation based on reach estimation
5. No A/B test statistical significance calculation
6. No performance alert triggers
7. No optimization run history/audit trail
8. No `creative_weights` field on campaign records

---

## 3. Technical Design

### 3.1 Optimization Service: `app/services/ad_optimization.py`

```python
"""Ad performance optimization service (ADS-017).

Provides automated optimization for ad campaigns:
- Creative auto-rotation (weight by CTR)
- Auto-pause underperformers
- Suggested bids
- Budget recommendations
- A/B test significance
- Performance alerts
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from scipy import stats  # For A/B test significance (or pure-Python fallback)

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────

DEFAULT_AUTO_PAUSE_CTR_THRESHOLD = 0.005  # 0.5%
DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS = 1000
DEFAULT_CTR_ALERT_THRESHOLD = 0.01  # 1%
DEFAULT_ROAS_ALERT_THRESHOLD = 1.0  # Break-even
DEFAULT_BUDGET_PACE_ALERT_RATIO = 1.2  # 120% of daily target
MIN_WEIGHT = 0.05  # Minimum rotation weight (5% floor)


# ─── Creative Rotation ──────────────────────────────────────────

def calculate_creative_weights(
    creative_stats: List[Dict[str, Any]]
) -> Dict[str, float]:
    """Calculate rotation weights proportional to CTR.

    Each creative gets weight = CTR / sum(all CTRs), with a minimum
    floor of MIN_WEIGHT (5%) to prevent complete rotation-out.

    Args:
        creative_stats: List of {creative_id, impressions, clicks}

    Returns:
        Dict mapping creative_id to weight (0.0-1.0), sum = 1.0
    """
    if not creative_stats:
        return {}

    # Calculate CTR for each creative
    ctrs = {}
    for stat in creative_stats:
        cid = stat["creative_id"]
        impressions = stat.get("impressions", 0)
        clicks = stat.get("clicks", 0)
        if impressions > 0:
            ctrs[cid] = clicks / impressions
        else:
            ctrs[cid] = 0.0

    total_ctr = sum(ctrs.values())
    if total_ctr == 0:
        # No clicks at all — equal weights
        n = len(creative_stats)
        return {s["creative_id"]: 1.0 / n for s in creative_stats}

    # Proportional weights with minimum floor
    weights = {}
    for cid, ctr in ctrs.items():
        weights[cid] = max(MIN_WEIGHT, ctr / total_ctr)

    # Normalize to sum=1.0
    total = sum(weights.values())
    return {cid: w / total for cid, w in weights.items()}


def identify_underperformers(
    creative_stats: List[Dict[str, Any]],
    ctr_threshold: float = DEFAULT_AUTO_PAUSE_CTR_THRESHOLD,
    min_impressions: int = DEFAULT_AUTO_PAUSE_MIN_IMPRESSIONS,
) -> List[Dict[str, Any]]:
    """Identify creatives that should be auto-paused.

    A creative is flagged if:
    - It has >= min_impressions impressions
    - Its CTR is below ctr_threshold
    """
    underperformers = []
    for stat in creative_stats:
        impressions = stat.get("impressions", 0)
        clicks = stat.get("clicks", 0)
        ctr = clicks / impressions if impressions > 0 else 0

        if impressions >= min_impressions and ctr < ctr_threshold:
            underperformers.append({
                "creative_id": stat["creative_id"],
                "impressions": impressions,
                "clicks": clicks,
                "ctr": ctr,
                "threshold": ctr_threshold,
                "reason": f"CTR {ctr:.4f} below threshold {ctr_threshold:.4f}",
            })

    return underperformers


# ─── Suggested Bid ───────────────────────────────────────────────

def calculate_suggested_bid(
    *, targeting: Optional[Dict[str, Any]] = None,
    content_category: str = "general",
) -> Dict[str, Any]:
    """Recommend bid based on competition level and historical fill rates.

    In dev mode, returns deterministic values based on targeting breadth.

    Returns:
    {
        "min_bid_cpm_cents": int,    # Floor price
        "suggested_bid_cpm_cents": int,  # Recommended bid
        "max_bid_cpm_cents": int,    # Ceiling (above this = overpaying)
        "estimated_fill_rate": float,  # Expected fill rate at suggested bid
        "competition_level": str,    # "low", "medium", "high"
    }
    """
    # Dev mode: deterministic based on targeting specificity
    if not targeting:
        return {
            "min_bid_cpm_cents": 200,
            "suggested_bid_cpm_cents": 500,
            "max_bid_cpm_cents": 1000,
            "estimated_fill_rate": 0.85,
            "competition_level": "medium",
        }

    # Narrower targeting = higher competition = higher suggested bid
    specificity = _calculate_targeting_specificity(targeting)

    base = 500  # base CPM in cents
    suggested = int(base * (1 + specificity))
    min_bid = int(suggested * 0.4)
    max_bid = int(suggested * 2.0)
    fill_rate = max(0.3, 1.0 - specificity * 0.7)

    competition = "low" if specificity < 0.33 else "medium" if specificity < 0.66 else "high"

    return {
        "min_bid_cpm_cents": min_bid,
        "suggested_bid_cpm_cents": suggested,
        "max_bid_cpm_cents": max_bid,
        "estimated_fill_rate": round(fill_rate, 2),
        "competition_level": competition,
    }


def _calculate_targeting_specificity(targeting: Dict[str, Any]) -> float:
    """Calculate targeting specificity score (0.0=broad, 1.0=narrow)."""
    score = 0.0
    if targeting.get("age_range"):
        age_range = targeting["age_range"]
        if len(age_range) == 2:
            span = age_range[1] - age_range[0]
            score += max(0, (47 - span) / 47) * 0.3  # Full range = 18-65 = 47

    if targeting.get("interests"):
        score += min(len(targeting["interests"]) * 0.1, 0.3)

    if targeting.get("geo"):
        geo = targeting["geo"]
        if len(geo) == 1:
            score += 0.2
        elif len(geo) <= 3:
            score += 0.1

    return min(score, 1.0)


# ─── Budget Recommendation ──────────────────────────────────────

def recommend_daily_budget(
    *, targeting: Optional[Dict[str, Any]] = None,
    desired_daily_reach: int = 1000,
) -> Dict[str, Any]:
    """Recommend daily budget based on targeting and desired reach.

    Formula: budget = (reach / 1000) * estimated_cpm

    Returns:
    {
        "estimated_daily_reach": int,
        "recommended_daily_budget_cents": int,
        "estimated_cpm_cents": int,
        "reach_per_dollar": float,
    }
    """
    bid_info = calculate_suggested_bid(targeting=targeting)
    estimated_cpm = bid_info["suggested_bid_cpm_cents"]

    budget_cents = int((desired_daily_reach / 1000) * estimated_cpm)
    budget_cents = max(500, budget_cents)  # Minimum $5/day

    return {
        "estimated_daily_reach": desired_daily_reach,
        "recommended_daily_budget_cents": budget_cents,
        "estimated_cpm_cents": estimated_cpm,
        "reach_per_dollar": round(1000 / estimated_cpm * 100, 1) if estimated_cpm > 0 else 0,
    }


# ─── A/B Test Significance ──────────────────────────────────────

def ab_test_significance(
    *,
    variant_a: Dict[str, int],  # {"impressions": N, "clicks": M}
    variant_b: Dict[str, int],
    confidence_level: float = 0.95,
) -> Dict[str, Any]:
    """Calculate statistical significance for A/B test between two creatives.

    Uses two-proportion Z-test.

    Returns:
    {
        "variant_a_ctr": float,
        "variant_b_ctr": float,
        "lift_percent": float,
        "z_score": float,
        "p_value": float,
        "significant": bool,
        "confidence_level": float,
        "winner": str | None,  # "a", "b", or None
        "sample_size_sufficient": bool,
    }
    """
    n_a = variant_a.get("impressions", 0)
    x_a = variant_a.get("clicks", 0)
    n_b = variant_b.get("impressions", 0)
    x_b = variant_b.get("clicks", 0)

    min_sample = 100
    if n_a < min_sample or n_b < min_sample:
        p_a = x_a / n_a if n_a > 0 else 0
        p_b = x_b / n_b if n_b > 0 else 0
        return {
            "variant_a_ctr": round(p_a, 6),
            "variant_b_ctr": round(p_b, 6),
            "lift_percent": 0,
            "z_score": 0,
            "p_value": 1.0,
            "significant": False,
            "confidence_level": confidence_level,
            "winner": None,
            "sample_size_sufficient": False,
            "min_sample_size": min_sample,
        }

    p_a = x_a / n_a
    p_b = x_b / n_b

    # Pooled proportion
    p_pool = (x_a + x_b) / (n_a + n_b)
    se = math.sqrt(p_pool * (1 - p_pool) * (1/n_a + 1/n_b))

    if se == 0:
        z_score = 0.0
        p_value = 1.0
    else:
        z_score = (p_a - p_b) / se
        # Two-tailed p-value using normal distribution approximation
        p_value = 2 * (1 - _normal_cdf(abs(z_score)))

    alpha = 1 - confidence_level
    significant = p_value < alpha
    winner = None
    if significant:
        winner = "a" if p_a > p_b else "b"

    lift = ((p_a - p_b) / p_b * 100) if p_b > 0 else 0

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


def _normal_cdf(x: float) -> float:
    """Approximate normal CDF using error function (no scipy needed)."""
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


# ─── Performance Alerts ──────────────────────────────────────────

def check_performance_alerts(
    *, campaign_id: str, campaign_metrics: Dict[str, Any],
    alert_config: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Check if campaign metrics trigger any performance alerts.

    Returns list of triggered alerts.
    """
    config = alert_config or {}
    ctr_threshold = config.get("ctr_threshold", DEFAULT_CTR_ALERT_THRESHOLD)
    roas_threshold = config.get("roas_threshold", DEFAULT_ROAS_ALERT_THRESHOLD)
    pace_ratio = config.get("budget_pace_ratio", DEFAULT_BUDGET_PACE_ALERT_RATIO)

    alerts = []
    metrics = campaign_metrics

    # CTR alert
    ctr = metrics.get("ctr", 0)
    if ctr < ctr_threshold and metrics.get("impressions", 0) > 500:
        alerts.append({
            "alert_type": "ctr_below_threshold",
            "severity": "warning",
            "message": f"Campaign CTR ({ctr:.2%}) is below threshold ({ctr_threshold:.2%})",
            "current_value": ctr,
            "threshold": ctr_threshold,
        })

    # ROAS alert
    roas = metrics.get("roas", 0)
    if roas < roas_threshold and metrics.get("spend_cents", 0) > 1000:
        alerts.append({
            "alert_type": "roas_below_threshold",
            "severity": "warning",
            "message": f"Campaign ROAS ({roas:.2f}x) is below break-even ({roas_threshold:.2f}x)",
            "current_value": roas,
            "threshold": roas_threshold,
        })

    # Budget pacing alert
    daily_budget = metrics.get("daily_budget_cents", 0)
    spent_today = metrics.get("spent_today_cents", 0)
    if daily_budget > 0:
        pacing = spent_today / daily_budget
        if pacing > pace_ratio:
            alerts.append({
                "alert_type": "budget_overpacing",
                "severity": "warning",
                "message": f"Campaign is pacing at {pacing:.0%} of daily budget",
                "current_value": pacing,
                "threshold": pace_ratio,
            })

    return alerts


# ─── Full Optimization Run ───────────────────────────────────────

def run_campaign_optimization(
    *, campaign_id: str, dry_run: bool = False
) -> Dict[str, Any]:
    """Run full optimization for a campaign.

    Steps:
    1. Fetch creative performance stats (last 7 days)
    2. Calculate rotation weights
    3. Identify underperformers for auto-pause
    4. Check performance alert thresholds
    5. Generate recommendations

    If dry_run=False, applies changes (weights, pauses, alerts).
    If dry_run=True, returns what would be changed without applying.
    """
    ...

def apply_auto_optimize(
    *, campaign_id: str, actions: List[str] = None
) -> Dict[str, Any]:
    """Apply optimization recommendations.

    actions: list of optimization actions to apply
    - "rotate": Apply calculated creative weights
    - "pause": Auto-pause underperforming creatives
    - "alerts": Send performance alert notifications
    - "all": Apply all optimizations
    """
    ...
```

### 3.2 Campaign Schema Extension

Add to campaign record:

```python
# Optimization fields on campaign record
creative_weights: Optional[Dict[str, float]] = None  # creative_id → weight
auto_optimize_enabled: bool = False
optimization_config: Optional[Dict[str, Any]] = None  # Thresholds
last_optimized_at: Optional[int] = None
optimization_log: Optional[List[Dict]] = None  # Recent optimization runs
```

### 3.3 Router Endpoints

**File**: `app/routers/ad_optimization.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/ads/campaigns/{id}/recommendations` | `require_ui_session` | Get optimization recommendations (dry run) |
| POST | `/ui/ads/campaigns/{id}/auto-optimize` | `require_ui_session` | Apply optimization actions |
| GET | `/ui/ads/campaigns/{id}/ab-test` | `require_ui_session` | A/B test results between creatives |
| GET | `/ui/ads/campaigns/{id}/suggested-bid` | `require_ui_session` | Get suggested bid |
| GET | `/ui/ads/campaigns/{id}/budget-recommendation` | `require_ui_session` | Get budget recommendation |
| PATCH | `/ui/ads/campaigns/{id}/optimization-config` | `require_ui_session` | Update optimization settings |

### 3.4 Pydantic Models

**File**: `app/models.py`

```python
class OptimizationRecommendation(BaseModel):
    campaign_id: str
    creative_weights: Dict[str, float]
    underperformers: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    suggested_actions: List[str]
    last_run_at: int

class AutoOptimizeRequest(BaseModel):
    actions: List[str] = Field(
        default=["all"],
        description='Actions to apply: "rotate", "pause", "alerts", "all"'
    )

class ABTestRequest(BaseModel):
    creative_a_id: str
    creative_b_id: str
    confidence_level: float = Field(default=0.95, ge=0.80, le=0.99)

class ABTestResult(BaseModel):
    variant_a_ctr: float
    variant_b_ctr: float
    lift_percent: float
    z_score: float
    p_value: float
    significant: bool
    confidence_level: float
    winner: Optional[str] = None
    sample_size_sufficient: bool

class SuggestedBidOut(BaseModel):
    min_bid_cpm_cents: int
    suggested_bid_cpm_cents: int
    max_bid_cpm_cents: int
    estimated_fill_rate: float
    competition_level: str

class BudgetRecommendationOut(BaseModel):
    estimated_daily_reach: int
    recommended_daily_budget_cents: int
    estimated_cpm_cents: int
    reach_per_dollar: float

class OptimizationConfigUpdate(BaseModel):
    auto_optimize_enabled: Optional[bool] = None
    ctr_threshold: Optional[float] = Field(default=None, ge=0.001, le=0.5)
    auto_pause_min_impressions: Optional[int] = Field(default=None, ge=100)
    roas_threshold: Optional[float] = Field(default=None, ge=0.1)
    budget_pace_alert_ratio: Optional[float] = Field(default=None, ge=1.0, le=3.0)
```

### 3.5 Frontend Components

#### OptimizationPanel (`frontend/src/pages/ads/OptimizationPanel.tsx`)

Panel within the campaign detail page. Contains:

- **Auto-optimize toggle**: Enable/disable automatic optimization
- **Threshold configuration**: CTR threshold, min impressions, ROAS threshold sliders
- **Current weights visualization**: Bar chart showing creative rotation weights
- **Recommendations list**: Cards for each recommendation with "Apply" buttons
- **Run now button**: Manually trigger optimization run

#### RecommendationCards (`frontend/src/components/ads/RecommendationCards.tsx`)

```typescript
interface RecommendationCardProps {
  type: "rotate" | "pause" | "alert" | "bid" | "budget";
  title: string;
  description: string;
  impact: string;  // e.g., "Estimated +15% CTR"
  onApply: () => void;
}
```

#### ABTestResults (`frontend/src/components/ads/ABTestResults.tsx`)

```typescript
interface ABTestResultsProps {
  campaignId: string;
  creativeAId: string;
  creativeBId: string;
}
```

Displays:
- Side-by-side creative preview
- CTR comparison bars
- Statistical significance indicator (green check / red X)
- P-value and confidence level
- Lift percentage
- Winner declaration with confidence badge
- "Needs more data" warning if sample size insufficient

### 3.6 Frontend API

**File**: `frontend/src/api/endpoints/adOptimization.ts`

```typescript
export const getRecommendations = (campaignId: string) =>
  client.get(`/ui/ads/campaigns/${campaignId}/recommendations`);
export const autoOptimize = (campaignId: string, data: { actions: string[] }) =>
  client.post(`/ui/ads/campaigns/${campaignId}/auto-optimize`, data);
export const getABTestResults = (campaignId: string, params: ABTestRequest) =>
  client.get(`/ui/ads/campaigns/${campaignId}/ab-test`, { params });
export const getSuggestedBid = (campaignId: string) =>
  client.get(`/ui/ads/campaigns/${campaignId}/suggested-bid`);
export const getBudgetRecommendation = (campaignId: string, params: { desired_daily_reach: number }) =>
  client.get(`/ui/ads/campaigns/${campaignId}/budget-recommendation`, { params });
export const updateOptimizationConfig = (campaignId: string, data: OptimizationConfigUpdate) =>
  client.patch(`/ui/ads/campaigns/${campaignId}/optimization-config`, data);
```

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface OptimizationRecommendation {
  campaign_id: string;
  creative_weights: Record<string, number>;
  underperformers: Array<{
    creative_id: string;
    impressions: number;
    clicks: number;
    ctr: number;
    reason: string;
  }>;
  alerts: Array<{
    alert_type: string;
    severity: string;
    message: string;
  }>;
  suggested_actions: string[];
  last_run_at: number;
}

export interface ABTestResult {
  variant_a_ctr: number;
  variant_b_ctr: number;
  lift_percent: number;
  z_score: number;
  p_value: number;
  significant: boolean;
  confidence_level: number;
  winner: string | null;
  sample_size_sufficient: boolean;
}

export interface SuggestedBid {
  min_bid_cpm_cents: number;
  suggested_bid_cpm_cents: number;
  max_bid_cpm_cents: number;
  estimated_fill_rate: number;
  competition_level: string;
}

export interface BudgetRecommendation {
  estimated_daily_reach: number;
  recommended_daily_budget_cents: number;
  estimated_cpm_cents: number;
  reach_per_dollar: number;
}
```

---

## 4. Implementation Plan

### 4.1 Backend — Phase 1: Core Optimization (Days 1-3)

1. **`app/services/ad_optimization.py`**: New file. All optimization functions: creative weights, underperformer identification, suggested bid, budget recommendation, A/B test significance, performance alerts.
2. **`app/models.py`**: Add Pydantic models for optimization requests and responses.
3. **Campaign schema update**: Add `creative_weights`, `auto_optimize_enabled`, `optimization_config`, `last_optimized_at` fields.

### 4.2 Backend — Phase 2: Router & Integration (Days 4-5)

4. **`app/routers/ad_optimization.py`**: New router. Six endpoints. Register in `app/main.py`.
5. **`app/main.py`**: Register router.
6. **Ad serving integration**: Modify serving engine to use `creative_weights` for weighted creative selection.

### 4.3 Frontend (Days 5-7)

7. **`frontend/src/api/types.ts`**: Add optimization TypeScript types.
8. **`frontend/src/api/endpoints/adOptimization.ts`**: New file. API wrappers.
9. **`frontend/src/pages/ads/OptimizationPanel.tsx`**: New component. Optimization dashboard within campaign detail.
10. **`frontend/src/components/ads/RecommendationCards.tsx`**: New component. Action cards for recommendations.
11. **`frontend/src/components/ads/ABTestResults.tsx`**: New component. A/B test result display.

### 4.4 E2E Tests (Days 8-9)

12. **`frontend/e2e/ad-optimization.spec.ts`**: New file. 12 tests across 3 sections.

---

## 5. Security Considerations

### 5.1 Optimization Access

- Only the campaign owner can view recommendations and apply optimizations.
- Non-owners receive 403.

### 5.2 Auto-Pause Safety

- Auto-paused creatives can be manually resumed by the advertiser.
- Auto-pause never affects the last remaining active creative in a campaign (at least one must remain).
- Auto-pause is logged with reason and timestamp for audit.

### 5.3 Statistical Integrity

- A/B test results clearly indicate when sample sizes are insufficient (< 100 impressions per variant).
- P-values are calculated server-side (not client-side) to prevent manipulation.
- No "winner" is declared unless the test reaches statistical significance at the configured confidence level.

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_ad_optimization.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Creative weights proportional to CTR | 3x CTR → ~3x weight (after normalization) |
| 2 | Minimum weight floor enforced | Worst performer gets at least 5% |
| 3 | Weights sum to 1.0 | Total of all weights = 1.0 |
| 4 | Underperformer with <0.5% CTR flagged | 1000+ impressions + low CTR → flagged |
| 5 | Underperformer below min impressions not flagged | 500 impressions → not flagged |
| 6 | A/B test significance with clear winner | p-value < 0.05 → significant, winner declared |
| 7 | A/B test insufficient sample size | < 100 impressions → not significant |
| 8 | Suggested bid varies with targeting specificity | Narrow targeting → higher bid |
| 9 | Budget recommendation scales with reach | 2x reach → ~2x budget |

### 6.2 E2E Tests (`frontend/e2e/ad-optimization.spec.ts`)

**Test File**: `frontend/e2e/ad-optimization.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser)
- Create a campaign as Alice with 3 creatives
- Seed mock impression data for the creatives (varying CTRs)

**Section 411: Creative Optimization API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Get optimization recommendations` | GET /campaigns/{id}/recommendations → 200, has creative_weights, underperformers, alerts |
| 2 | `Creative weights proportional to performance` | Best-performing creative has highest weight |
| 3 | `Apply auto-optimize updates campaign weights` | POST /campaigns/{id}/auto-optimize → 200; GET campaign → creative_weights updated |
| 4 | `Underperformer identified` | Creative with very low CTR appears in underperformers list |

**Section 412: A/B Test & Bid Suggestion API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `A/B test returns significance result` | GET /campaigns/{id}/ab-test?creative_a_id=...&creative_b_id=... → 200, has p_value, significant, winner |
| 6 | `A/B test with insufficient data marks not significant` | Query with low-impression creatives → significant=false, sample_size_sufficient=false |
| 7 | `Suggested bid returns bid range` | GET /campaigns/{id}/suggested-bid → 200, has min/suggested/max bid + competition level |
| 8 | `Budget recommendation scales with reach` | GET /campaigns/{id}/budget-recommendation?desired_daily_reach=5000 → budget > 0 |

**Section 413: Optimization Config API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Update optimization config` | PATCH /campaigns/{id}/optimization-config → 200, config updated |
| 10 | `Enable auto-optimize` | PATCH with auto_optimize_enabled=true → 200 |
| 11 | `Invalid threshold rejected` | PATCH with ctr_threshold=5.0 (>0.5) → 422 |
| 12 | `Non-owner cannot access optimization` | GET recommendations as Bob → 403 |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_optimization.py` | All optimization algorithms |
| `app/routers/ad_optimization.py` | Optimization API endpoints |
| `frontend/src/api/endpoints/adOptimization.ts` | API wrappers |
| `frontend/src/pages/ads/OptimizationPanel.tsx` | Optimization dashboard |
| `frontend/src/components/ads/RecommendationCards.tsx` | Recommendation action cards |
| `frontend/src/components/ads/ABTestResults.tsx` | A/B test result display |
| `frontend/e2e/ad-optimization.spec.ts` | E2E tests (12 tests, sections 411-413) |
| `tests/test_ad_optimization.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add optimization Pydantic models |
| `app/main.py` | Register optimization router |
| `frontend/src/api/types.ts` | Add optimization TypeScript types |

## 9. Acceptance Criteria

1. Optimization recommendations include creative rotation weights, underperformer identification, and performance alerts
2. Creative weights are proportional to CTR with a 5% minimum floor, and sum to 1.0
3. Auto-pause correctly identifies creatives with CTR below threshold after minimum impressions
4. A/B test significance calculation uses Z-test with configurable confidence level (default 95%)
5. Insufficient sample sizes (< 100 impressions) are clearly flagged without declaring a winner
6. Suggested bid varies based on targeting specificity (narrow targeting = higher bid)
7. Budget recommendation scales linearly with desired daily reach
8. Performance alerts trigger on CTR drop, ROAS drop, and budget overpacing
9. Auto-optimize can be applied as a one-click action or selectively (rotate only, pause only)
10. All 12 E2E tests pass in `frontend/e2e/ad-optimization.spec.ts`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 25, 222, 279 | Existing: `DEV_AD_CREATIVES` (line 25), `record_ad_impression` (line 222), `_credit_ad_revenue` (line 279) |
| `app/core/tables.py` | 93 | Existing `ad_impressions` table handle |
| `app/services/ad_optimization.py` | — | Does not exist yet — new implementation required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_ad_optimization.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_ad_optimization` | Creates record with correct fields and generated ID |
| `test_create_ad_optimization_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_ad_optimization_found` | Returns correct record by ID |
| `test_get_ad_optimization_not_found` | Returns None for non-existent ID |
| `test_list_ad_optimization` | Returns all records for the given scope/owner |
| `test_update_ad_optimization` | Updates mutable fields and sets updated_at |
| `test_delete_ad_optimization` | Removes record; subsequent get returns None |
| `test_ad_optimization_owner_check` | Rejects operations from non-owner users |
| `test_ad_optimization_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_ad_optimization_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-optimization.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: `AD_OPTIMIZATION_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-001 | Campaign manager | Pending | No |
| ADS-002 | Creative management | Pending | No |
| ADS-004 | Ad serving engine | Pending | No |
| ADS-007 | Billing (spend data) | Pending | No |
| ADS-008 | Analytics for optimization | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Sequential (after ADS-008)**


- Must merge after: ADS-001, ADS-002, ADS-004, ADS-007, ADS-008
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/ads.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
