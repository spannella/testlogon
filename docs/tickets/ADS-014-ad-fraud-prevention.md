# ADS-014: Ad Fraud Prevention

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: ADS-001 (advertiser accounts), ADS-004 (ad serving engine), ADS-007 (ad billing) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets. Existing: ad_placement.py (record_ad_impression), affiliate_links.py (bot detection patterns), billing_shared.py. -->

---

## 1. Overview & Motivation

### The Gap

The current ad impression tracking system (`app/services/ad_placement.py`) records impressions and credits creators with revenue based on CPM, but performs zero fraud validation. Every reported impression is treated as legitimate — the `record_ad_impression()` function at line 222 unconditionally writes the event and, on "complete" events, calls `_credit_ad_revenue()` which credits the creator's billing ledger. There is no check for:

- Rapid-fire clicks from the same user (click fraud)
- Bulk impressions from a single IP (bot traffic)
- Suspiciously short view times (invalid traffic)
- Abnormal click-through ratios (click farm patterns)
- Geographic mismatches with campaign targeting
- Known bot user-agents

Without fraud detection, the platform is vulnerable to:
1. **Inflated creator earnings**: Creators (or bots acting on their behalf) generate fake impressions to earn undeserved ad revenue
2. **Wasted advertiser budgets**: Advertisers pay for impressions that no real human saw
3. **Platform liability**: Advertisers who discover fraud lose trust and leave the platform
4. **Metric pollution**: Analytics dashboards show inflated numbers, making data-driven decisions impossible

### Why This Is Needed

1. **Financial integrity**: Ad fraud costs the global digital advertising industry $100B+ annually. Even a basic rule-based detection system prevents the most common fraud patterns.

2. **Advertiser confidence**: Advertisers will not invest significant budgets without fraud protection. "We have fraud detection" is table-stakes for any ad platform.

3. **Fair creator compensation**: Legitimate creators are harmed when fraudulent creators earn disproportionate ad revenue from fake traffic.

4. **Regulatory compliance**: Some jurisdictions require ad platforms to have fraud prevention measures and transparent reporting on invalid traffic.

### Architecture After This Change

```
Ad Event (impression/click/completion)
        │
        ▼
┌─────────────────────────────────────────────┐
│  Fraud Detection Pipeline                    │
│  app/services/ad_fraud_detection.py          │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │ Rule Engine (synchronous, per-event)    │ │
│  │                                         │ │
│  │ 1. Click Velocity Check                 │ │
│  │    >5 clicks / same user / same ad / 1m │ │
│  │                                         │ │
│  │ 2. IP Clustering Check                  │ │
│  │    >50 impressions / same IP / 5m       │ │
│  │                                         │ │
│  │ 3. Bot Detection                        │ │
│  │    User-agent classification             │ │
│  │                                         │ │
│  │ 4. Invalid Traffic (IVT) Check          │ │
│  │    View time < 1 second                 │ │
│  │                                         │ │
│  │ 5. CTR Anomaly Check                    │ │
│  │    Campaign CTR > 30%                   │ │
│  │                                         │ │
│  │ 6. Geo Mismatch Check                   │ │
│  │    Click country not in targeting       │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  Score: 0-100 (threshold: 70 = flagged)      │
│                                              │
│  ┌──────────────┐  ┌──────────────────────┐  │
│  │ score < 70   │  │ score >= 70          │  │
│  │ LEGITIMATE   │  │ FLAGGED              │  │
│  │              │  │                      │  │
│  │ → Bill       │  │ → Exclude from       │  │
│  │   advertiser │  │   billing            │  │
│  │ → Credit     │  │ → Record in fraud    │  │
│  │   creator    │  │   events table       │  │
│  │              │  │ → Update account     │  │
│  │              │  │   risk score         │  │
│  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────┘
        │
        ▼ (if fraud_rate > 20%)
┌────────────────────────────┐
│ Auto-Suspend Account       │
│ Notify admin for review    │
└────────────────────────────┘
```

### Data Flow — Fraud Check on Impression

```
Browser                          Backend                              DynamoDB
  │                                 │                                    │
  │── POST /ui/ads/impression ─────>│                                    │
  │   { video_id, slot_type,        │                                    │
  │     creative_id, view_time_ms,  │                                    │
  │     event_type: "complete" }    │                                    │
  │                                 │                                    │
  │                                 │── fraud_check(event) ─────────────│
  │                                 │                                    │
  │                                 │   Rule 1: Click velocity           │
  │                                 │   ← query recent events for user   │
  │                                 │   → score += 0-25                  │
  │                                 │                                    │
  │                                 │   Rule 2: IP clustering            │
  │                                 │   ← query recent events for IP     │
  │                                 │   → score += 0-25                  │
  │                                 │                                    │
  │                                 │   Rule 3: Bot UA check             │
  │                                 │   → score += 0-20                  │
  │                                 │                                    │
  │                                 │   Rule 4: IVT (view time < 1s)     │
  │                                 │   → score += 0-15                  │
  │                                 │                                    │
  │                                 │   Rule 5: CTR anomaly              │
  │                                 │   ← query campaign CTR             │
  │                                 │   → score += 0-10                  │
  │                                 │                                    │
  │                                 │   Rule 6: Geo mismatch             │
  │                                 │   → score += 0-5                   │
  │                                 │                                    │
  │                                 │   Total score: 0-100               │
  │                                 │                                    │
  │                                 │── if score >= 70: ─────────────────│
  │                                 │   write to ad_fraud_events         │
  │                                 │   DO NOT bill advertiser           │
  │                                 │   DO NOT credit creator            │
  │                                 │                                    │
  │                                 │── if score < 70: ──────────────────│
  │                                 │   write to ad_impressions          │
  │                                 │   bill advertiser, credit creator  │
  │                                 │                                    │
  │<── 200 { ok: true,             │                                    │
  │     fraud_score: 15 }           │                                    │
```

---

## 2. Current State Analysis

### 2.1 Ad Impression Recording (`app/services/ad_placement.py`, line 222)

The `record_ad_impression()` function:
- Accepts `video_id`, `user_id`, `slot_type`, `slot_index`, `creative_id`, `event_type`
- Writes to `T.ad_impressions` unconditionally (line 243)
- Increments `ad_impression_count` on video metadata (line 264)
- On "complete" events, calls `_credit_ad_revenue()` (line 274) which credits the creator's billing ledger

**No validation is performed on:**
- Request frequency (same user, same ad)
- Client IP address
- User-agent string
- View duration
- Geographic origin

### 2.2 Affiliate Link Bot Detection (`app/services/affiliate_links.py`)

The affiliate links service already has basic user-agent classification for bot detection. This can be reused:

```python
# Existing bot detection patterns (approximate location in affiliate_links.py)
BOT_UA_PATTERNS = [
    r"bot", r"crawler", r"spider", r"scraper",
    r"headless", r"phantom", r"selenium", r"puppeteer",
]
```

This pattern list can be imported and extended for ad fraud detection.

### 2.3 Billing Ledger (`app/services/billing_shared.py`)

The `new_ledger_entry()` function creates ledger entries in the billing table. Fraudulent impressions should NOT generate ledger entries. The fraud detection must run BEFORE the billing step.

### 2.4 AdImpressions Table

PK: `AD_IMP#{date}`, SK: `VIDEO#{video_id}#{user_id}#{ts}`. No IP address, user-agent, or view-time fields are currently stored. These must be added to enable fraud detection.

### 2.5 Gaps

1. No fraud scoring on ad events
2. No velocity checks (clicks/impressions per time window)
3. No IP-based clustering detection
4. No bot user-agent detection on ad events
5. No view-time validation
6. No CTR anomaly detection
7. No fraud event storage or audit trail
8. No admin fraud review dashboard
9. No automatic account suspension for high fraud rates
10. AdImpressions records missing IP, user-agent, view-time fields

---

## 3. Technical Design

### 3.1 Fraud Detection Service: `app/services/ad_fraud_detection.py`

```python
"""Ad fraud detection service (ADS-014).

Rule-based fraud detection for ad impressions and clicks.
Each rule contributes a score (0-100). Events scoring >= 70
are flagged as fraudulent and excluded from billing.

All rules are deterministic and synchronous for dev/MVP.
"""

import re
import logging
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

FRAUD_THRESHOLD = 70
AUTO_SUSPEND_FRAUD_RATE = 0.20  # 20%

# ─── Rule weights ────────────────────────────────────────────────

WEIGHT_CLICK_VELOCITY = 25
WEIGHT_IP_CLUSTERING = 25
WEIGHT_BOT_UA = 20
WEIGHT_IVT = 15
WEIGHT_CTR_ANOMALY = 10
WEIGHT_GEO_MISMATCH = 5

# ─── Bot UA patterns (extended from affiliate_links.py) ──────────

BOT_UA_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"bot", r"crawler", r"spider", r"scraper",
        r"headless", r"phantom", r"selenium", r"puppeteer",
        r"wget", r"curl/", r"python-requests", r"go-http-client",
        r"httpclient", r"java/", r"apache-httpclient",
    ]
]


class FraudCheckResult:
    def __init__(
        self, *, score: int, flagged: bool,
        rule_scores: Dict[str, int],
        details: Dict[str, Any],
    ):
        self.score = score
        self.flagged = flagged
        self.rule_scores = rule_scores
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fraud_score": self.score,
            "flagged": self.flagged,
            "rule_scores": self.rule_scores,
            "details": self.details,
        }


def check_fraud(
    *,
    user_id: str,
    ip_address: str,
    user_agent: str,
    creative_id: str,
    campaign_id: str,
    view_time_ms: int,
    event_type: str,
    geo_country: str = "",
    targeting_countries: List[str] = None,
) -> FraudCheckResult:
    """Run all fraud detection rules against an ad event.

    Returns FraudCheckResult with total score and per-rule breakdown.
    Events with score >= FRAUD_THRESHOLD are flagged.
    """
    rule_scores: Dict[str, int] = {}
    details: Dict[str, Any] = {}
    total = 0

    # Rule 1: Click/impression velocity
    vel_score, vel_detail = _check_click_velocity(
        user_id=user_id, creative_id=creative_id
    )
    rule_scores["click_velocity"] = vel_score
    details["click_velocity"] = vel_detail
    total += vel_score

    # Rule 2: IP clustering
    ip_score, ip_detail = _check_ip_clustering(ip_address=ip_address)
    rule_scores["ip_clustering"] = ip_score
    details["ip_clustering"] = ip_detail
    total += ip_score

    # Rule 3: Bot user-agent
    bot_score, bot_detail = _check_bot_ua(user_agent=user_agent)
    rule_scores["bot_ua"] = bot_score
    details["bot_ua"] = bot_detail
    total += bot_score

    # Rule 4: Invalid traffic (view time)
    ivt_score, ivt_detail = _check_ivt(
        view_time_ms=view_time_ms, event_type=event_type
    )
    rule_scores["ivt"] = ivt_score
    details["ivt"] = ivt_detail
    total += ivt_score

    # Rule 5: CTR anomaly
    ctr_score, ctr_detail = _check_ctr_anomaly(campaign_id=campaign_id)
    rule_scores["ctr_anomaly"] = ctr_score
    details["ctr_anomaly"] = ctr_detail
    total += ctr_score

    # Rule 6: Geo mismatch
    geo_score, geo_detail = _check_geo_mismatch(
        geo_country=geo_country,
        targeting_countries=targeting_countries or [],
    )
    rule_scores["geo_mismatch"] = geo_score
    details["geo_mismatch"] = geo_detail
    total += geo_score

    total = min(total, 100)
    flagged = total >= FRAUD_THRESHOLD

    return FraudCheckResult(
        score=total, flagged=flagged,
        rule_scores=rule_scores, details=details,
    )


def _check_click_velocity(
    *, user_id: str, creative_id: str
) -> tuple[int, Dict[str, Any]]:
    """Check if user has >5 events on the same creative in the last 60 seconds.

    Queries ad_fraud_velocity table (PK=USER#{user_id}, SK=CREATIVE#{creative_id}#{minute_bucket}).
    """
    ts = now_ts()
    minute_bucket = ts // 60
    pk = f"VEL#{user_id}"
    sk = f"CR#{creative_id}#{minute_bucket}"

    try:
        resp = T.ad_fraud_events.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET #cnt = if_not_exists(#cnt, :z) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#cnt": "event_count", "#ttl": "ttl"},
            ExpressionAttributeValues={":z": 0, ":one": 1, ":ttl": ts + 120},
            ReturnValues="UPDATED_NEW",
        )
        count = int(resp["Attributes"]["event_count"])
    except Exception:
        return 0, {"error": "velocity_check_failed"}

    if count > 5:
        return WEIGHT_CLICK_VELOCITY, {"events_in_window": count, "threshold": 5}
    return 0, {"events_in_window": count, "threshold": 5}


def _check_ip_clustering(*, ip_address: str) -> tuple[int, Dict[str, Any]]:
    """Check if >50 impressions from the same IP in the last 5 minutes."""
    ts = now_ts()
    five_min_bucket = ts // 300
    pk = f"IP#{ip_address}"
    sk = f"BUCKET#{five_min_bucket}"

    try:
        resp = T.ad_fraud_events.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET #cnt = if_not_exists(#cnt, :z) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#cnt": "event_count", "#ttl": "ttl"},
            ExpressionAttributeValues={":z": 0, ":one": 1, ":ttl": ts + 600},
            ReturnValues="UPDATED_NEW",
        )
        count = int(resp["Attributes"]["event_count"])
    except Exception:
        return 0, {"error": "ip_check_failed"}

    if count > 50:
        return WEIGHT_IP_CLUSTERING, {"events_in_window": count, "threshold": 50}
    return 0, {"events_in_window": count, "threshold": 50}


def _check_bot_ua(*, user_agent: str) -> tuple[int, Dict[str, Any]]:
    """Check user-agent against known bot patterns."""
    for pattern in BOT_UA_PATTERNS:
        if pattern.search(user_agent):
            return WEIGHT_BOT_UA, {"matched_pattern": pattern.pattern, "user_agent": user_agent[:100]}
    return 0, {"bot_detected": False}


def _check_ivt(*, view_time_ms: int, event_type: str) -> tuple[int, Dict[str, Any]]:
    """Flag impressions with view time < 1 second (1000ms) as invalid traffic.

    Only applies to 'complete' events — impressions and skips may naturally
    have short view times.
    """
    if event_type != "complete":
        return 0, {"skipped": True, "reason": "not_complete_event"}
    if view_time_ms < 1000:
        return WEIGHT_IVT, {"view_time_ms": view_time_ms, "threshold_ms": 1000}
    return 0, {"view_time_ms": view_time_ms, "threshold_ms": 1000}


def _check_ctr_anomaly(*, campaign_id: str) -> tuple[int, Dict[str, Any]]:
    """Flag campaigns with CTR > 30% (industry average ~2%).

    Reads cached campaign metrics. In dev mode, returns 0 (no historical data).
    """
    # In production: query campaign metrics for CTR
    # In dev mode: always pass (no historical data to compare)
    return 0, {"ctr_check": "skipped_dev_mode"}


def _check_geo_mismatch(
    *, geo_country: str, targeting_countries: List[str]
) -> tuple[int, Dict[str, Any]]:
    """Flag clicks from countries not in campaign targeting."""
    if not targeting_countries or not geo_country:
        return 0, {"geo_check": "no_targeting_or_geo"}
    if geo_country.upper() not in [c.upper() for c in targeting_countries]:
        return WEIGHT_GEO_MISMATCH, {
            "user_country": geo_country,
            "targeting_countries": targeting_countries,
        }
    return 0, {"geo_match": True}
```

### 3.2 Fraud Event Recording

```python
def record_fraud_event(
    *,
    event_id: str,
    user_id: str,
    ip_address: str,
    campaign_id: str,
    creative_id: str,
    event_type: str,
    fraud_result: FraudCheckResult,
) -> None:
    """Record a flagged fraud event for admin review."""
    ts = now_ts()
    date_str = _date_str(ts)

    T.ad_fraud_events.put_item(
        Item={
            "pk": f"FRAUD#{date_str}",
            "sk": f"EVENT#{ts}#{event_id}",
            "event_id": event_id,
            "user_id": user_id,
            "ip_address": ip_address,
            "campaign_id": campaign_id,
            "creative_id": creative_id,
            "event_type": event_type,
            "fraud_score": fraud_result.score,
            "rule_scores": fraud_result.rule_scores,
            "details": fraud_result.details,
            "created_at": ts,
            "GSI1PK": f"ACCOUNT#{campaign_id}",
            "GSI1SK": ts,
            "GSI2PK": f"CAMPAIGN#{campaign_id}",
            "GSI2SK": ts,
        }
    )
```

### 3.3 Account Risk Score & Auto-Suspension

```python
def update_account_risk(*, account_id: str) -> Dict[str, Any]:
    """Recalculate account fraud rate and auto-suspend if > 20%.

    fraud_rate = flagged_events / total_events (last 7 days)
    """
    # Query total events and flagged events for account in last 7 days
    # Calculate fraud_rate
    # If fraud_rate > AUTO_SUSPEND_FRAUD_RATE:
    #   Update account status to "suspended"
    #   Send admin notification
    ...

def get_account_risk_scores() -> List[Dict[str, Any]]:
    """Return risk scores for all accounts with recent ad activity.

    Used by admin fraud dashboard.
    """
    ...
```

### 3.4 DynamoDB Table: `ad_fraud_events`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="ad_fraud_events",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),  # By account
        GsiDef("GSI2", "GSI2PK", "GSI2SK"),  # By campaign
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
)
```

**PK patterns:**

| PK Pattern | SK Pattern | Purpose |
|------------|------------|---------|
| `FRAUD#{date}` | `EVENT#{ts}#{event_id}` | Flagged fraud events by date |
| `VEL#{user_id}` | `CR#{creative_id}#{minute_bucket}` | Click velocity counters (TTL) |
| `IP#{ip_address}` | `BUCKET#{five_min_bucket}` | IP clustering counters (TTL) |
| `RISK#{account_id}` | `META` | Account risk score summary |

**Settings** in `app/core/settings.py`:
```python
ad_fraud_events_table_name: str = os.environ.get("DDB_AD_FRAUD_EVENTS", "ad_fraud_events")
```

**Table handle** in `app/core/tables.py`:
```python
ad_fraud_events=ddb.Table(S.ad_fraud_events_table_name),
```

### 3.5 Integration with `record_ad_impression()`

**File**: `app/services/ad_placement.py` — Modify `record_ad_impression()`:

```python
def record_ad_impression(
    *,
    video_id: str,
    user_id: str,
    slot_type: str,
    slot_index: int,
    creative_id: str = "",
    event_type: str = "impression",
    ip_address: str = "",
    user_agent: str = "",
    view_time_ms: int = 0,
    campaign_id: str = "",
    geo_country: str = "",
) -> Dict[str, Any]:
    """Record an ad impression with fraud detection.

    Runs fraud check before recording. Flagged events are excluded
    from billing and recorded in the fraud events table.
    """
    from app.services.ad_fraud_detection import check_fraud, record_fraud_event

    # Run fraud detection
    fraud_result = check_fraud(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        creative_id=creative_id,
        campaign_id=campaign_id,
        view_time_ms=view_time_ms,
        event_type=event_type,
        geo_country=geo_country,
    )

    event_id = f"adimp_{uuid.uuid4().hex}"

    if fraud_result.flagged:
        # Record fraud event, do NOT bill
        record_fraud_event(
            event_id=event_id,
            user_id=user_id,
            ip_address=ip_address,
            campaign_id=campaign_id,
            creative_id=creative_id,
            event_type=event_type,
            fraud_result=fraud_result,
        )
        return {
            "ok": True,
            "event_id": event_id,
            "fraud_score": fraud_result.score,
            "flagged": True,
        }

    # Legitimate event — proceed with existing logic
    # (write to ad_impressions, increment counters, credit creator)
    ...
```

### 3.6 Admin Fraud Dashboard Endpoints

**File**: `app/routers/ads_admin.py` (extend existing admin router)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/ads/fraud/events` | `require_admin_or_root` | List flagged fraud events (paginated, by date) |
| GET | `/v1/admin/ads/fraud/events/{event_id}` | `require_admin_or_root` | Get fraud event details |
| GET | `/v1/admin/ads/fraud/accounts` | `require_admin_or_root` | List accounts with risk scores |
| GET | `/v1/admin/ads/fraud/accounts/{id}` | `require_admin_or_root` | Get account fraud details |
| POST | `/v1/admin/ads/fraud/accounts/{id}/suspend` | `require_admin_or_root` | Manually suspend account |
| POST | `/v1/admin/ads/fraud/accounts/{id}/unsuspend` | `require_admin_or_root` | Unsuspend account |
| GET | `/v1/admin/ads/fraud/summary` | `require_admin_or_root` | Fraud summary stats |

### 3.7 Pydantic Models

**File**: `app/models.py`

```python
class FraudEventOut(BaseModel):
    event_id: str
    user_id: str
    ip_address: str
    campaign_id: str
    creative_id: str
    event_type: str
    fraud_score: int
    rule_scores: Dict[str, int]
    details: Dict[str, Any]
    created_at: int

class AccountRiskOut(BaseModel):
    account_id: str
    fraud_rate: float
    total_events_7d: int
    flagged_events_7d: int
    status: str  # "active", "suspended"
    last_fraud_event_at: Optional[int] = None

class FraudSummaryOut(BaseModel):
    total_events_today: int
    flagged_events_today: int
    fraud_rate_today: float
    suspended_accounts: int
    top_fraud_rules: Dict[str, int]  # rule_name → count
```

### 3.8 Frontend: Admin Fraud Dashboard

**File**: `frontend/src/pages/admin/ads/FraudDashboard.tsx`

Components:
- **FraudSummaryCards**: Total events, flagged events, fraud rate, suspended accounts
- **FraudEventsTable**: Paginated table of flagged events with columns: timestamp, user, campaign, score, top rule, actions
- **AccountRiskList**: List of accounts sorted by fraud rate, with suspend/unsuspend buttons
- **FraudEventDetail**: Expandable row showing rule-by-rule score breakdown

**Route** in `frontend/src/App.tsx`:
```tsx
<Route path="/admin/ads/fraud" element={<FraudDashboard />} />
```

### 3.9 Frontend API

**File**: `frontend/src/api/endpoints/adFraud.ts`

```typescript
export const getFraudEvents = (params: { date?: string; limit?: number; cursor?: string }) =>
  client.get("/v1/admin/ads/fraud/events", { params });
export const getFraudAccounts = () =>
  client.get("/v1/admin/ads/fraud/accounts");
export const suspendAccount = (accountId: string) =>
  client.post(`/v1/admin/ads/fraud/accounts/${accountId}/suspend`);
export const unsuspendAccount = (accountId: string) =>
  client.post(`/v1/admin/ads/fraud/accounts/${accountId}/unsuspend`);
export const getFraudSummary = () =>
  client.get("/v1/admin/ads/fraud/summary");
```

---

## 4. Implementation Plan

### 4.1 Backend — Phase 1: Fraud Detection Core (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `ad_fraud_events` table definition with 2 GSIs.
2. **`app/core/settings.py`**: Add `ad_fraud_events_table_name`.
3. **`app/core/tables.py`**: Add `ad_fraud_events` table handle.
4. **`app/services/ad_fraud_detection.py`**: New file. All six fraud rules, scoring engine, fraud event recording, account risk calculation.

### 4.2 Backend — Phase 2: Integration & Admin (Days 4-6)

5. **`app/services/ad_placement.py`**: Modify `record_ad_impression()` to call `check_fraud()` before billing. Add `ip_address`, `user_agent`, `view_time_ms` parameters.
6. **`app/routers/ads_admin.py`**: Add fraud admin endpoints (7 endpoints).
7. **`app/models.py`**: Add Pydantic models for fraud events, account risk, and summary.
8. **`app/main.py`**: Register admin fraud router if not already combined with existing admin router.

### 4.3 Frontend (Days 7-8)

9. **`frontend/src/api/types.ts`**: Add TypeScript types for fraud events and risk scores.
10. **`frontend/src/api/endpoints/adFraud.ts`**: New file. API wrappers.
11. **`frontend/src/pages/admin/ads/FraudDashboard.tsx`**: New page. Summary cards, events table, account risk list.
12. **`frontend/src/App.tsx`**: Add `/admin/ads/fraud` route.

### 4.4 E2E Tests (Days 8-10)

13. **`frontend/e2e/ad-fraud.spec.ts`**: New file. 15 tests across 4 sections.

---

## 5. Security Considerations

### 5.1 Fraud Score Transparency

- Fraud scores are NOT returned to end users in production (only to admins).
- The `record_ad_impression()` response includes `fraud_score` only in dev mode.
- Exposing fraud scores to end users would allow adversaries to calibrate their attacks.

### 5.2 Rate Counter Security

- Velocity and IP counters use DDB atomic counters with TTL cleanup.
- Counters are best-effort — DDB errors fail open (allow the event).
- This prevents fraud detection from becoming a DoS vector.

### 5.3 Admin Access

- All fraud endpoints require `require_admin_or_root` (role >= ADMIN).
- Account suspension is logged with actor and timestamp.
- Unsuspension requires explicit admin action (no auto-unsuspend).

### 5.4 IP Address Handling

- IP addresses are stored for fraud detection only.
- IP data should be subject to data retention policies (TTL or periodic purge).
- Consider hashing IPs for privacy in non-admin contexts.

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_ad_fraud.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Normal event scores 0 | Legitimate event with normal params → score = 0 |
| 2 | Bot UA detected | user_agent="Googlebot" → bot_ua score = 20 |
| 3 | Click velocity triggers at 6 events | 6 events in 1 minute → velocity score = 25 |
| 4 | IP clustering triggers at 51 events | 51 events from same IP in 5 min → score = 25 |
| 5 | IVT triggers for short view time | view_time_ms=500 → ivt score = 15 |
| 6 | Combined rules exceed threshold | Bot + velocity → total >= 70, flagged = True |
| 7 | Flagged event excluded from billing | No ledger entry created for flagged event |
| 8 | Account auto-suspended at 20% fraud rate | After many flagged events, account status = "suspended" |

### 6.2 E2E Tests (`frontend/e2e/ad-fraud.spec.ts`)

**Test File**: `frontend/e2e/ad-fraud.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (creator), Bob (viewer), Root (admin)
- Create a video as Alice with access_mode="ad_supported"
- Configure ad slots on the video

**Section 401: Fraud Detection Rules API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Normal impression passes fraud check` | POST /ads/impression with normal params → 200, fraud_score < 70 |
| 2 | `Bot user-agent flagged` | POST with user_agent="Selenium/4.0" → 200, fraud_score >= 20 |
| 3 | `Short view time flagged as IVT` | POST with view_time_ms=100, event_type="complete" → 200, IVT rule triggered |
| 4 | `Rapid-fire clicks trigger velocity check` | POST 6 impressions in quick succession → last one has velocity score > 0 |

**Section 402: Fraud Event Recording API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Flagged event not billed` | POST combined bot+velocity event (score >= 70) → no new billing ledger entry |
| 6 | `Flagged event recorded in fraud events` | GET /admin/ads/fraud/events → includes the flagged event with score and rule breakdown |
| 7 | `Legitimate event IS billed` | POST normal impression → billing ledger entry created |
| 8 | `Fraud event details include rule scores` | GET /admin/ads/fraud/events/{id} → rule_scores has click_velocity, bot_ua, etc. |

**Section 403: Admin Fraud Dashboard API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Admin can list fraud events` | GET /admin/ads/fraud/events as Root → 200, array of events |
| 10 | `Admin can view fraud summary` | GET /admin/ads/fraud/summary → 200, has total_events, flagged_events, fraud_rate fields |
| 11 | `Admin can view account risk scores` | GET /admin/ads/fraud/accounts → 200, array with fraud_rate field |
| 12 | `Non-admin cannot access fraud endpoints` | GET /admin/ads/fraud/events as Alice → 403 |

**Section 404: Account Suspension API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Admin can suspend account` | POST /admin/ads/fraud/accounts/{id}/suspend → 200, status="suspended" |
| 14 | `Admin can unsuspend account` | POST /admin/ads/fraud/accounts/{id}/unsuspend → 200, status="active" |
| 15 | `Suspended account ads not served` | After suspension, ad serving for account returns no ads |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_fraud_detection.py` | Fraud detection rules, scoring, event recording |
| `frontend/src/api/endpoints/adFraud.ts` | Admin fraud API wrappers |
| `frontend/src/pages/admin/ads/FraudDashboard.tsx` | Admin fraud review dashboard |
| `frontend/e2e/ad-fraud.spec.ts` | E2E tests (15 tests, sections 401-404) |
| `tests/test_ad_fraud.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/services/ad_placement.py` | Integrate fraud check into `record_ad_impression()` |
| `app/models.py` | Add fraud Pydantic models |
| `app/routers/ads_admin.py` | Add fraud admin endpoints (or new router) |
| `app/main.py` | Register fraud admin router |
| `app/core/settings.py` | Add `ad_fraud_events_table_name` |
| `app/core/tables.py` | Add `ad_fraud_events` table handle |
| `scripts/local-ddb-init.py` | Add `ad_fraud_events` table with 2 GSIs |
| `frontend/src/api/types.ts` | Add fraud TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/ads/fraud` route |

## 9. Acceptance Criteria

1. Every ad impression/click/completion event passes through a 6-rule fraud detection pipeline before billing
2. Events scoring >= 70 are flagged as fraudulent and excluded from billing (no advertiser charge, no creator credit)
3. Flagged events are recorded in the ad_fraud_events table with per-rule score breakdown
4. Click velocity detection flags >5 events from the same user on the same ad within 1 minute
5. IP clustering detection flags >50 impressions from the same IP within 5 minutes
6. Bot user-agent detection flags known bot patterns
7. Invalid traffic detection flags "complete" events with <1 second view time
8. Admin fraud dashboard shows flagged events, account risk scores, and summary statistics
9. Admin can manually suspend/unsuspend accounts
10. Accounts with >20% fraud rate are auto-suspended
11. All 15 E2E tests pass in `frontend/e2e/ad-fraud.spec.ts`

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 222 | Existing `record_ad_impression` — currently no fraud validation |
| `app/services/affiliate_links.py` | — | Existing bot detection patterns (reference for fraud detection heuristics) |
| `app/services/billing_shared.py` | — | Existing billing ledger — for credit reversal on fraud detection |
| `app/auth/policy.py` | 67 | `require_admin_or_root` — for admin fraud review endpoints |
| `app/services/ad_fraud_detection.py` | — | Does not exist yet — new implementation required |
| `ad_fraud_events` DDB table | — | Does not exist yet — new implementation required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_ad_fraud_detection.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_ad_fraud_detection` | Creates record with correct fields and generated ID |
| `test_create_ad_fraud_detection_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_ad_fraud_detection_found` | Returns correct record by ID |
| `test_get_ad_fraud_detection_not_found` | Returns None for non-existent ID |
| `test_list_ad_fraud_detection` | Returns all records for the given scope/owner |
| `test_update_ad_fraud_detection` | Updates mutable fields and sets updated_at |
| `test_delete_ad_fraud_detection` | Removes record; subsequent get returns None |
| `test_ad_fraud_detection_owner_check` | Rejects operations from non-owner users |
| `test_ad_fraud_detection_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_ad_fraud_detection_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-fraud.spec.ts`


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


**DDB seed data**:


| Table | PK/SK Pattern | Notes |
|-------|--------------|-------|
| `AdFraudEvents` | See DDB schema in technical design section | Created by `scripts/local-ddb-init.py` |

### CI/Pipeline


- **Feature flags**: `AD_FRAUD_DETECTION_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-001 | Advertiser accounts | Pending | No |
| ADS-004 | Ad serving (impression/click events) | Pending | No |
| ADS-007 | Billing (charge reversal) | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| ADS-018 | Fraud metrics for admin dashboard |

### Merge Strategy


**Sequential (after ADS-004, ADS-007)**


- Must merge after: ADS-001, ADS-004, ADS-007
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB table(s) added to `scripts/local-ddb-init.py`: `AdFraudEvents`
- [ ] Settings added to `app/core/settings.py` + `app/core/tables.py`: `ad_fraud_events_table_name`
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/ads.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
