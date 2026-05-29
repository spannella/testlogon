# SOCIAL-005: Tip Leaderboards / Top Supporters

**Ticket**: SOCIAL-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform has a robust tip ledger system (`app/services/tip_ledger.py`, 149 lines) that writes paired debit/credit entries for every tip transaction across four tipping surfaces: message-attached tips, post-send message tips, post tips, and comment tips. Each ledger entry includes `tipper_user_id`, `recipient_user_id`, `amount_cents`, `content_type`, and `content_id`. These entries are written to the billing DynamoDB table but are never aggregated or queried for ranking purposes.

<!-- NOTE: This ticket's "current state" description is OUTDATED. Tip leaderboards have been FULLY IMPLEMENTED:
  - Backend service: app/services/tip_leaderboard.py — get_leaderboard, refresh_creator_leaderboard, refresh_all_leaderboards
  - Backend router: app/routers/tip_leaderboard.py — GET /ui/creators/{creator_id}/top-supporters (line 30), POST /internal/tip-leaderboards/refresh (line 54)
  - Registered in main.py at lines 107-108 and 430-431
  - Pydantic models: TopSupportersOut, TopSupporterItem in app/models.py
  All "Files to Create" listed in section 7.9 already exist (tip_leaderboard.py service + router).
-->

There is no "top supporters" endpoint, no leaderboard aggregation logic, no ranking query, and no frontend widget. Creators cannot see who their top tippers are, and supporters have no recognition mechanism for their contributions. This is a significant gap in the social engagement layer -- leaderboards are a proven driver of competitive tipping behavior on platforms like Twitch, YouTube Super Chat, and Patreon.

This ticket implements a tip aggregation service, a `GET /ui/creators/{creator_id}/top-supporters` API endpoint, a configurable leaderboard widget for creator profiles, and integration into the analytics dashboard. The system reads existing billing ledger credit entries, aggregates by tipper over configurable time periods, and returns ranked lists. A background pre-computation job runs periodically to keep leaderboard data fresh without real-time DynamoDB scans. The pre-computed data is stored in the billing table using a `BOARD#` prefix key pattern, with DynamoDB TTL for automatic cleanup of stale rankings.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: View Top Supporters as Creator**

As a creator, I want to see my top 10 supporters ranked by total tip amount so that I know who my biggest fans are.

Acceptance criteria:
- Leaderboard shows ranked list of up to 10 supporters.
- Each entry displays: rank number, display name, avatar (or placeholder), total tip amount (formatted as USD), and number of individual tips.
- Top 3 supporters have special medal styling (gold/silver/bronze).
- Empty state message when no tips exist: "No tips received yet."
- Data is fresh within 1 hour (pre-computed hourly).

**US-2: Filter by Time Period**

As a creator, I want to filter top supporters by time period (week/month/all-time) so that I can see recent versus lifetime loyalty.

Acceptance criteria:
- Period selector with three options: "7 Days", "30 Days", "All Time".
- Changing the period triggers a new API call with the `period` query parameter.
- Each period shows different data (e.g., weekly top tipper may differ from all-time).
- Default period is "30d" (monthly view).

**US-3: See Top Supporters in Analytics Dashboard**

As a creator, I want to see my top supporters in my analytics dashboard so that I have all monetization data in one place.

Acceptance criteria:
- "Top Supporters" card appears on the AnalyticsPage below the existing "Top Content" section.
- Card includes period toggle and ranked supporter list.
- Uses the same `useTopSupporters(period)` query hook as the profile widget.

**US-4: Public Leaderboard on Creator Profile**

As a viewer, I want to see who the top supporters are on a creator's storefront so that I understand the community's engagement level.

Acceptance criteria:
- Top Supporters widget appears on the creator's public profile page (SOC-006 dependency).
- Widget is visible to all authenticated users.
- Creator can toggle leaderboard visibility via a profile setting (future, out of scope for v1).

**US-5: See My Own Rank**

As a supporter, I want to see my position on a creator's leaderboard so that I know where I stand.

Acceptance criteria:
- If the authenticated user appears in the top 50, their entry is highlighted.
- The API response includes the viewer's rank if they are in the supporters list.

### 2.2 Pain Points

1. **No supporter recognition**: Top tippers invest significant money but receive no public acknowledgment, reducing motivation for continued tipping. Competitive recognition drives 15-30% more tipping revenue on comparable platforms.
2. **No aggregated tip data**: Creators must manually scan individual billing entries to understand who supports them most -- there is no summary view anywhere in the application.
3. **No gamification incentive**: Leaderboards drive competitive tipping behavior. The absence of this feature means tips are purely transactional with no social layer.
4. **Underutilized billing data**: The `write_tip_ledger` function writes comprehensive data (content_type, content_id, amounts, tipper/recipient IDs) that is never queried for analytics or social features. This data is being generated and stored at cost with zero return.

---

## 3. Current State Analysis

### 3.1 Tip Ledger Service (`app/services/tip_ledger.py:1-149`)

The `TipLedgerEntry` class (line 20) defines the data contract for all tip transactions:

```python
# app/services/tip_ledger.py:35-60
class TipLedgerEntry:
    def __init__(
        self,
        *,
        tipper_user_id: str,
        recipient_user_id: str,
        amount_cents: int,
        currency: str = "USD",
        content_type: str,        # "message", "post", "comment"
        content_id: str,
        payment_method_id: Optional[str] = None,
        tip_payment_id: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ):
```

The `write_tip_ledger` function (line 87-149) writes two items to `T.billing` for every tip:

```python
# app/services/tip_ledger.py:108-120 (DEBIT entry)
T.billing.put_item(Item={
    "pk": f"USER#{entry.tipper_user_id}",
    "sk": f"LEDGER#{ts}#{debit_id}",
    "entry_id": debit_id,
    "ts": ts,
    "type": "debit",
    "amount_cents": entry.amount_cents,
    "currency": entry.currency,
    "state": "settled",
    "reason": reason,
    "meta": meta,
})

# app/services/tip_ledger.py:130-140 (CREDIT entry)
T.billing.put_item(Item={
    "pk": f"USER#{entry.recipient_user_id}",
    "sk": f"LEDGER#{ts}#{credit_id}",
    # ... same structure, type="credit" ...
})
```

1. **DEBIT entry**: `pk=USER#{tipper_user_id}`, `sk=LEDGER#{ts}#{debit_id}` -- charges the tipper.
2. **CREDIT entry**: `pk=USER#{recipient_user_id}`, `sk=LEDGER#{ts}#{credit_id}` -- income for the creator.

Meta object includes: `content_type` ("message"|"post"|"comment"), `content_id`, `tipper_user_id`, `recipient_user_id`, `tip_payment_id`, optional `payment_method_id`.

**Citation**: `app/services/tip_ledger.py:87-149` -- `write_tip_ledger` function verified.

### 3.2 Tip Entry Reason Strings (`app/services/tip_ledger.py:63-69`)

```python
# app/services/tip_ledger.py:63-69
def _reason_for_content_type(content_type: str) -> str:
    return {
        "message": "Tip: message",
        "post": "Tip: post",
        "comment": "Tip: comment",
    }.get(content_type, f"Tip: {content_type}")
```

Reason strings are standardized with a `"Tip: "` prefix. This prefix is used by the earnings service to categorize entries.

**Citation**: `app/services/tip_ledger.py:63-69` -- reason mapping verified.

### 3.3 Meta Object Structure (`app/services/tip_ledger.py:72-84`)

```python
# app/services/tip_ledger.py:72-84
def _build_meta(entry: TipLedgerEntry) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "content_type": entry.content_type,
        "content_id": entry.content_id,
        "tipper_user_id": entry.tipper_user_id,
        "recipient_user_id": entry.recipient_user_id,
        "tip_payment_id": entry.tip_payment_id,
    }
    if entry.payment_method_id:
        meta["payment_method_id"] = entry.payment_method_id
    meta.update(entry.extra_meta)
    return meta
```

The `tipper_user_id` in the meta is the key field for leaderboard aggregation. Each credit entry on the creator's partition contains the tipper's identity in `meta.tipper_user_id`.

**Citation**: `app/services/tip_ledger.py:72-84` -- meta includes `tipper_user_id`.

### 3.4 Billing Table Structure

The billing table uses single-table design:
- **PK**: `pk` (S) = `USER#{user_id}`
- **SK**: `sk` (S) = `LEDGER#{timestamp}#{entry_id}`

Credit entries for a recipient can be queried with:
- `KeyConditionExpression`: `pk = USER#{recipient_user_id} AND sk begins_with LEDGER#`
- `FilterExpression`: `type = "credit" AND reason begins_with "Tip"`

**Important DDB gotcha**: `FilterExpression` is applied AFTER page fetch (1MB per page). A creator with 10,000 total billing entries but only 50 tip credits will read all 10,000 items across multiple pages. The filter only reduces the *result set*, not the *data read*. Must loop via `LastEvaluatedKey`.

**Citation**: `app/services/tip_ledger.py:109-119` -- debit entry structure.
**Citation**: `app/services/tip_ledger.py:130-140` -- credit entry structure.
**Citation**: `CLAUDE.md` gotchas section -- FilterExpression behavior.

### 3.5 Earnings Service Already Queries Credits (`app/services/creator_earnings.py:22-33`)

```python
# app/services/creator_earnings.py:22-33
def _reason_to_category(reason: str) -> str:
    reason_lower = reason.lower() if reason else ""
    if "subscription" in reason_lower:
        return "subscriptions"
    if reason_lower.startswith("tip"):
        return "tips"
    if "unlock" in reason_lower:
        return "unlocks"
    if "vod" in reason_lower:
        return "vod_purchases"
    return "other"
```

The `get_earnings_summary` function (line 47) already queries all credit entries for a user from the billing table and categorizes tip entries via the `"tip"` prefix. This same query pattern can be reused for leaderboard aggregation, with the addition of grouping by `meta.tipper_user_id`.

**Citation**: `app/services/creator_earnings.py:22-33` -- `_reason_to_category` mapping.
**Citation**: `app/services/creator_earnings.py:47-114` -- full credit scan with pagination loop.

### 3.6 Analytics Page (`frontend/src/pages/analytics/AnalyticsPage.tsx`)

The analytics page exists and has a "Top Content" section (ending around line 419). The Top Supporters card would be added after this section, using the same card layout pattern.

**Citation**: `frontend/src/pages/analytics/AnalyticsPage.tsx:374-419` -- Top Content table structure.

### 3.7 What Does NOT Exist

- No `GET /ui/creators/{id}/top-supporters` endpoint in any router (grep returns 0 matches).
- No aggregation function in `tip_ledger.py` (write-only service, no read/query functions).
- No leaderboard component in any frontend page.
- No pre-computed leaderboard data in DynamoDB (no `BOARD#` prefix items).
- Zero search results for "leaderboard", "top.*supporter", "top.*tipper" across the entire codebase.
- No profile page widget system (SOC-006 not yet implemented).

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+---------------------+       +----------------------+       +---------------------+
| Creator Profile     |       | Backend API          |       | DynamoDB            |
| / Analytics Page    |       | (tip_leaderboard.py) |       |                     |
|                     |       |                      |       | billing table       |
| TopSupporters       |<----->| GET /creators/{id}/  |<----->| pk=USER#{creator}   |
|   Widget            |       |   top-supporters     |       | sk=LEDGER#...       |
|                     |       |                      |       | (credit entries)    |
+---------------------+       +----------------------+       |                     |
                                      ^                      | Pre-computed:       |
                                      |                      | pk=BOARD#{creator}  |
+---------------------+       +----------------------+       | sk=PERIOD#{period}  |
| Background Job      |       | Aggregation Engine   |       | supporters: [...]   |
| (every 1 hour)      |------>| (tip_leaderboard.py) |<----->|                     |
| refresh_leaderboard |       | aggregate_tips()     |       +---------------------+
+---------------------+       +----------------------+
```

### 4.2 Aggregation Approach

Since DynamoDB does not support GROUP BY or SUM aggregations, the system uses a **pre-computation model**:

1. **Hourly background job** scans credit entries for each creator with tip-related reasons.
2. Aggregates by `tipper_user_id` from the `meta` field on each credit entry.
3. Writes pre-computed ranked lists to the billing DynamoDB table with a `BOARD#` prefix.
4. API endpoint reads pre-computed results (single `get_item`, ~10ms latency).
5. Falls back to on-demand computation if pre-computed data is missing or expired.

### 4.3 Data Flow

1. Tip occurs (any surface: message, post, comment).
2. `write_tip_ledger()` writes debit + credit entries to billing table (existing, no changes).
3. Background job queries credit entries for a creator: `pk=USER#{creator_id}`, `sk begins_with LEDGER#`, `FilterExpression: reason begins_with "Tip" AND type = "credit"`.
4. Groups entries by `meta.tipper_user_id`, sums `amount_cents` per tipper.
5. Ranks by total amount descending, caps at top 50.
6. Writes ranked list to: `pk=BOARD#{creator_id}`, `sk=PERIOD#{period}` (where period = "7d", "30d", "all").
7. API endpoint reads `pk=BOARD#{creator_id}`, `sk=PERIOD#{period}` and enriches with display names from profile service.

### 4.4 Creator Discovery for Background Job

The background job needs to know which creators to process. Two approaches:

**Option A (scan-based)**: Scan the billing table for distinct `pk` values with `BOARD#` prefix items or recent tip credits. Expensive for large tables.

**Option B (event-driven, recommended)**: Maintain a lightweight set of "active creators" in DDB. Each time `write_tip_ledger` writes a credit, also upsert a `BOARD_QUEUE#{creator_id}` item with `last_tip_at`. The background job queries this queue for creators with recent tips.

For v1, use **Option A** with a bounded scan (process at most 100 creators per cycle) since the user base is small in dev mode. Document Option B as a scaling optimization.

---

## 5. Data Model

### 5.1 Pre-computed Leaderboard Item (billing table, single-table pattern)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `BOARD#{creator_id}` | `"BOARD#alice@test.local"` |
| `sk` | S | `PERIOD#{period}` | `"PERIOD#30d"` |
| `supporters` | L | Ordered list of supporter objects | `[{user_id, total_cents, tip_count, last_tip_at}]` |
| `total_tip_cents` | N | Sum of all tips in this period | `7500` |
| `total_supporters` | N | Count of unique tippers | `2` |
| `computed_at` | N | Unix timestamp of last computation | `1748380800` |
| `ttl_epoch` | N | `computed_at + 86400` (expire after 24h) | `1748467200` |

### 5.2 Supporter Object (within `supporters` list)

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | S | Tipper's user ID (email-format) |
| `total_cents` | N | Sum of all tip amounts from this tipper in the period |
| `tip_count` | N | Number of individual tips from this tipper |
| `last_tip_at` | N | Unix timestamp of the most recent tip from this tipper |

### 5.3 Supported Periods

| Period Key | Query Range | Description | SK Value |
|-----------|-------------|-------------|----------|
| `7d` | Last 7 days (604800 seconds) | Weekly leaderboard | `PERIOD#7d` |
| `30d` | Last 30 days (2592000 seconds) | Monthly leaderboard | `PERIOD#30d` |
| `all` | All time (no time filter) | Lifetime leaderboard | `PERIOD#all` |

### 5.4 Example DynamoDB Items

**Pre-computed leaderboard (30-day)**:
```json
{
  "pk": "BOARD#alice@test.local",
  "sk": "PERIOD#30d",
  "supporters": [
    {
      "user_id": "bob@test.local",
      "total_cents": 5000,
      "tip_count": 12,
      "last_tip_at": 1748380800
    },
    {
      "user_id": "charlie@test.local",
      "total_cents": 2500,
      "tip_count": 5,
      "last_tip_at": 1748294400
    }
  ],
  "total_tip_cents": 7500,
  "total_supporters": 2,
  "computed_at": 1748380800,
  "ttl_epoch": 1748467200
}
```

**Active creator queue item** (for background job discovery):
```json
{
  "pk": "BOARD_QUEUE#alice@test.local",
  "sk": "META",
  "creator_id": "alice@test.local",
  "last_tip_at": 1748380800,
  "tip_count_total": 47
}
```

---

## 6. API Contract

### 6.1 GET `/ui/creators/{creator_id}/top-supporters`

**Auth**: `require_ui_session` (creator sees own leaderboard, or any authenticated user views public leaderboard)

**Path parameters**:
- `creator_id` (string): The creator's user ID.

**Query parameters**:
- `period` (string, default "30d"): One of "7d", "30d", or "all". Validated via regex `^(7d|30d|all)$`.
- `limit` (int, default 10, ge=1, le=50): Maximum number of supporters to return.

**Response (200)**:

```json
{
  "creator_id": "alice@test.local",
  "period": "30d",
  "supporters": [
    {
      "rank": 1,
      "user_id": "bob@test.local",
      "display_name": "Bob",
      "avatar_url": "/mock/s3/avatars/bob.jpg",
      "total_cents": 5000,
      "tip_count": 12,
      "last_tip_at": 1748380800
    },
    {
      "rank": 2,
      "user_id": "charlie@test.local",
      "display_name": "Charlie",
      "avatar_url": null,
      "total_cents": 2500,
      "tip_count": 5,
      "last_tip_at": 1748294400
    }
  ],
  "total_tip_cents": 7500,
  "total_supporters": 2,
  "computed_at": 1748380800
}
```

**Example curl**:
```bash
curl -b "ui_session=...; ui_access_token=..." \
  "http://localhost:8000/ui/creators/alice@test.local/top-supporters?period=30d&limit=10"
```

**Error responses**:

| Status | Body | Condition |
|--------|------|-----------|
| 200 | Success (may have empty `supporters` list) | Normal response |
| 401 | `{"detail": "Not authenticated"}` | Missing/invalid session |
| 422 | `{"detail": "Invalid period"}` | `period` not in (7d, 30d, all) |

Note: 404 is NOT returned for unknown `creator_id` -- the endpoint returns an empty supporters list instead. This prevents user enumeration.

### 6.2 POST `/internal/tip-leaderboards/refresh`

**Auth**: Internal API only (no user session required, protected by internal middleware)

**Request body** (optional):
```json
{
  "creator_id": "alice@test.local"
}
```

Omitting `creator_id` refreshes all creators with recent tips (bounded to 100 per cycle).

**Response (200)**:
```json
{
  "ok": true,
  "creators_processed": 1,
  "periods_updated": 3,
  "duration_seconds": 1.2
}
```

**Example curl**:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"creator_id": "alice@test.local"}' \
  http://localhost:8000/internal/tip-leaderboards/refresh
```

**Error responses**:

| Status | Body | Condition |
|--------|------|-----------|
| 200 | Success | Normal |
| 500 | `{"detail": "Refresh failed: ..."}` | DDB error during scan/write |

---

## 7. Implementation Plan

### 7.1 Backend -- Service Layer

**New file**: `app/services/tip_leaderboard.py` (~200 lines)

```python
"""Tip leaderboard aggregation and pre-computation service (SOCIAL-005)."""

from __future__ import annotations
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional
from boto3.dynamodb.conditions import Attr, Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

SUPPORTED_PERIODS = {"7d": 7 * 86400, "30d": 30 * 86400, "all": 0}
BOARD_TTL_SECONDS = 86400  # 24-hour TTL on pre-computed data
MAX_SUPPORTERS = 50        # Store top 50 per period


def aggregate_tips_for_creator(creator_id: str, period: str) -> List[Dict[str, Any]]:
    """Query billing credits for a creator, aggregate by tipper.
    
    Scans USER#{creator_id} LEDGER entries with reason starting with "Tip"
    and type = "credit". Groups by meta.tipper_user_id, sums amount_cents.
    
    Returns sorted list of {user_id, total_cents, tip_count, last_tip_at}.
    """
    pk = f"USER#{creator_id}"
    now = now_ts()
    period_seconds = SUPPORTED_PERIODS.get(period, 0)
    
    # Build key condition with time range
    if period_seconds > 0:
        cutoff_ts = now - period_seconds
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{cutoff_ts}", "LEDGER#9999999999z"
        )
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    
    filter_expr = Attr("type").eq("credit") & Attr("reason").begins_with("Tip")
    
    # Aggregate by tipper
    tipper_totals: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"total_cents": 0, "tip_count": 0, "last_tip_at": 0}
    )
    
    query_kwargs = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
    }
    
    while True:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
            meta = item.get("meta", {})
            tipper_id = meta.get("tipper_user_id", "")
            if not tipper_id:
                continue
            amount = int(item.get("amount_cents", 0))
            ts = int(item.get("ts", 0))
            entry = tipper_totals[tipper_id]
            entry["total_cents"] += amount
            entry["tip_count"] += 1
            entry["last_tip_at"] = max(entry["last_tip_at"], ts)
        
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    
    # Sort by total_cents descending, cap at MAX_SUPPORTERS
    ranked = sorted(
        [{"user_id": uid, **data} for uid, data in tipper_totals.items()],
        key=lambda x: x["total_cents"],
        reverse=True,
    )[:MAX_SUPPORTERS]
    
    return ranked


def write_leaderboard(creator_id: str, period: str, supporters: List[Dict[str, Any]]) -> None:
    """Write pre-computed leaderboard to billing table."""
    now = now_ts()
    total_cents = sum(s["total_cents"] for s in supporters)
    T.billing.put_item(Item={
        "pk": f"BOARD#{creator_id}",
        "sk": f"PERIOD#{period}",
        "supporters": supporters,
        "total_tip_cents": total_cents,
        "total_supporters": len(supporters),
        "computed_at": now,
        "ttl_epoch": now + BOARD_TTL_SECONDS,
    })


def get_leaderboard(creator_id: str, period: str, limit: int = 10) -> Dict[str, Any]:
    """Read pre-computed leaderboard. Falls back to on-demand computation."""
    resp = T.billing.get_item(Key={
        "pk": f"BOARD#{creator_id}",
        "sk": f"PERIOD#{period}",
    })
    item = resp.get("Item")
    
    if not item or (now_ts() - int(item.get("computed_at", 0)) > BOARD_TTL_SECONDS):
        # Fallback: compute on demand
        supporters = aggregate_tips_for_creator(creator_id, period)
        write_leaderboard(creator_id, period, supporters)
        item = {
            "supporters": supporters,
            "total_tip_cents": sum(s["total_cents"] for s in supporters),
            "total_supporters": len(supporters),
            "computed_at": now_ts(),
        }
    
    supporters = item.get("supporters", [])[:limit]
    
    # Enrich with display names and avatars
    enriched = []
    for i, s in enumerate(supporters):
        profile = get_profile(s["user_id"]) or {}
        enriched.append({
            "rank": i + 1,
            "user_id": s["user_id"],
            "display_name": profile.get("display_name", s["user_id"]),
            "avatar_url": profile.get("avatar_url"),
            "total_cents": int(s.get("total_cents", 0)),
            "tip_count": int(s.get("tip_count", 0)),
            "last_tip_at": int(s.get("last_tip_at", 0)),
        })
    
    return {
        "creator_id": creator_id,
        "period": period,
        "supporters": enriched,
        "total_tip_cents": int(item.get("total_tip_cents", 0)),
        "total_supporters": int(item.get("total_supporters", 0)),
        "computed_at": int(item.get("computed_at", 0)),
    }


def refresh_all_leaderboards() -> Dict[str, Any]:
    """Background job: find creators with recent tips, recompute all periods.
    
    Scans for BOARD_QUEUE# items to find active creators.
    Bounded to 100 creators per cycle.
    """
    # ... implementation scans BOARD_QUEUE# items or billing table ...
```

### 7.2 Backend -- Router

**New file**: `app/routers/tip_leaderboard.py` (~50 lines)

```python
"""Tip leaderboard router (SOCIAL-005)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from app.services.sessions import require_ui_session
from app.models import TopSupportersOut, TopSupporterItem
from app.services.tip_leaderboard import get_leaderboard, refresh_all_leaderboards

router = APIRouter(prefix="/ui/creators", tags=["tip-leaderboard"])
internal_router = APIRouter(prefix="/internal/tip-leaderboards", tags=["internal"])


@router.get("/{creator_id}/top-supporters", response_model=TopSupportersOut)
def get_top_supporters(
    creator_id: str,
    period: str = Query(default="30d", pattern="^(7d|30d|all)$"),
    limit: int = Query(default=10, ge=1, le=50),
    session=Depends(require_ui_session),
):
    """Get top supporters leaderboard for a creator."""
    result = get_leaderboard(creator_id, period, limit)
    return TopSupportersOut(
        creator_id=result["creator_id"],
        period=result["period"],
        supporters=[TopSupporterItem(**s) for s in result["supporters"]],
        total_tip_cents=result["total_tip_cents"],
        total_supporters=result["total_supporters"],
        computed_at=result["computed_at"],
    )


@internal_router.post("/refresh")
def refresh_leaderboards(body: dict = {}):
    """Internal: refresh leaderboard pre-computations."""
    creator_id = body.get("creator_id")
    if creator_id:
        from app.services.tip_leaderboard import aggregate_tips_for_creator, write_leaderboard
        for period in ("7d", "30d", "all"):
            supporters = aggregate_tips_for_creator(creator_id, period)
            write_leaderboard(creator_id, period, supporters)
        return {"ok": True, "creators_processed": 1, "periods_updated": 3}
    
    result = refresh_all_leaderboards()
    return result
```

### 7.3 Backend -- Registration (`app/main.py`)

Add imports and register both routers:
```python
from app.routers.tip_leaderboard import router as tip_leaderboard_router
from app.routers.tip_leaderboard import internal_router as tip_leaderboard_internal_router

app.include_router(tip_leaderboard_router)
app.include_router(tip_leaderboard_internal_router)
```

Register background refresh job as a startup task:
```python
async def _leaderboard_refresh_loop():
    import asyncio
    while True:
        try:
            refresh_all_leaderboards()
        except Exception:
            logger.exception("Leaderboard refresh failed")
        await asyncio.sleep(3600)  # Every hour

app.add_event_handler("startup", lambda: asyncio.ensure_future(_leaderboard_refresh_loop()))
```

### 7.4 Backend -- Pydantic Models (`app/models.py`)

Add after the PayoutActionOut model:

```python
# -- Tip Leaderboards (SOCIAL-005) --

class TopSupporterItem(BaseModel):
    rank: int
    user_id: str
    display_name: str = ""
    avatar_url: Optional[str] = None
    total_cents: int = 0
    tip_count: int = 0
    last_tip_at: int = 0

class TopSupportersOut(BaseModel):
    creator_id: str
    period: str
    supporters: List[TopSupporterItem] = Field(default_factory=list)
    total_tip_cents: int = 0
    total_supporters: int = 0
    computed_at: int = 0
```

### 7.5 Frontend -- TypeScript Types (`frontend/src/api/types.ts`)

```typescript
// -- Tip Leaderboards (SOCIAL-005) --

export interface TopSupporter {
  rank: number;
  user_id: string;
  display_name: string;
  avatar_url: string | null;
  total_cents: number;
  tip_count: number;
  last_tip_at: number;
}

export interface TopSupportersResp {
  creator_id: string;
  period: string;
  supporters: TopSupporter[];
  total_tip_cents: number;
  total_supporters: number;
  computed_at: number;
}
```

### 7.6 Frontend -- API Client

Add to `frontend/src/api/endpoints/social.ts` (or create new file):

```typescript
export const getTopSupporters = (
  creatorId: string,
  params?: { period?: string; limit?: number },
) =>
  api.get<TopSupportersResp>(
    `/ui/creators/${creatorId}/top-supporters`,
    { params },
  ).then((r) => r.data);
```

### 7.7 Frontend -- TopSupportersWidget Component

**New file**: `frontend/src/pages/profile/TopSupportersWidget.tsx` (~150 lines)

```
TopSupportersWidget (props: { creatorId: string })
├── Card
│   ├── CardHeader
│   │   ├── Trophy icon
│   │   └── "Top Supporters" title
│   ├── PeriodToggleGroup
│   │   ├── Button: "7d" (7 Days)
│   │   ├── Button: "30d" (30 Days) -- default selected
│   │   └── Button: "All" (All Time)
│   ├── SupportersList
│   │   └── For each supporter:
│   │       ├── RankBadge (1=gold medal, 2=silver medal, 3=bronze medal, 4+=number)
│   │       ├── Avatar (or fallback initials)
│   │       ├── DisplayName text
│   │       ├── TipCount text ("12 tips")
│   │       └── TotalAmount text ("$50.00")
│   ├── SummaryFooter
│   │   └── "X supporters tipped $Y.YY total"
│   └── EmptyState (when supporters list is empty)
│       └── "No tips received in this period"
└── LoadingState (Skeleton)
```

**React Query hook**:
```typescript
const { data, isLoading } = useQuery({
  queryKey: ["top-supporters", creatorId, period],
  queryFn: () => getTopSupporters(creatorId, { period, limit: 10 }),
  staleTime: 300_000, // 5 minutes (data is pre-computed hourly)
  enabled: !!creatorId,
});
```

### 7.8 Frontend -- Integration Points

1. **Analytics Page** (`frontend/src/pages/analytics/AnalyticsPage.tsx`): Add `<TopSupportersWidget creatorId={userId} />` after the existing Top Content section (after line 419).

2. **Creator Profile Page** (when SOC-006 is implemented): Render `<TopSupportersWidget creatorId={profileUserId} />` in the sidebar or below profile tabs.

### 7.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/tip_leaderboard.py` | Aggregation engine, pre-computation, read logic | ~200 |
| `app/routers/tip_leaderboard.py` | API endpoints (public + internal) | ~50 |
| `frontend/src/pages/profile/TopSupportersWidget.tsx` | Leaderboard card component | ~150 |
| `tests/test_tip_leaderboard.py` | Unit tests for aggregation | ~150 |
| `frontend/e2e/tip-leaderboard.spec.ts` | E2E tests | ~200 |

### 7.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `tip_leaderboard_router` and `tip_leaderboard_internal_router`; register background refresh loop |
| `app/models.py` | Add `TopSupporterItem`, `TopSupportersOut` Pydantic models |
| `frontend/src/api/types.ts` | Add `TopSupporter`, `TopSupportersResp` interfaces |
| `frontend/src/api/endpoints/social.ts` | Add `getTopSupporters` API wrapper |
| `frontend/src/pages/analytics/AnalyticsPage.tsx` | Add `TopSupportersWidget` card after Top Content section |

---

## 8. Performance Considerations

### 8.1 Aggregation Cost

**Per-creator, per-period computation**:
- Query `USER#{creator_id}` with `sk begins_with LEDGER#`, filter `reason begins_with "Tip" AND type = "credit"`.
- DDB `FilterExpression` applies AFTER page fetch (1MB pages). Must loop via `LastEvaluatedKey`.
- For a creator with 10,000 ledger entries, ~50 might be tip credits. The scan reads all 10,000 items but only processes 50.
- Estimated RCU: 10-100 RCU per creator per period computation.
- Estimated time: 1-5 seconds per creator depending on ledger size.

### 8.2 Pre-computation Cadence

- Hourly refresh is acceptable. Leaderboards are not real-time critical.
- TTL of 24 hours ensures stale data is cleaned up even if the job fails.
- On-demand fallback: if pre-computed data is expired, compute synchronously (slower but correct).
- Background job processes at most 100 creators per cycle (bounded to prevent runaway costs).

### 8.3 API Response Latency

| Mode | Latency | When |
|------|---------|------|
| Pre-computed (cache hit) | ~10ms DDB `get_item` + ~30ms profile batch lookups | Normal case |
| On-demand fallback | 1-5 seconds (full scan + aggregation) | First request or expired data |
| Profile enrichment | ~3ms per supporter (batched) | Always |

### 8.4 DDB Write Capacity

Pre-computed writes: 3 items per creator (one per period) * 100 creators = 300 writes per hour. At ~5 WCU per item, this is ~25 WCU burst every hour. Well within default DDB capacity.

### 8.5 Caching Strategy

- Frontend: `staleTime: 300_000` (5 minutes). Leaderboards change slowly; no need for frequent re-fetches.
- Backend: Single `get_item` for pre-computed data (no scan on the hot path).
- Cache invalidation: Not needed. Pre-computed data refreshes on its own schedule.

---

## 9. Testing Plan

### 9.1 Unit Tests (pytest)

**File**: `tests/test_tip_leaderboard.py`

| # | Test Function | Assertion |
|---|--------------|-----------|
| 1 | `test_aggregate_tips_groups_by_tipper` | 3 tips from Bob, 2 from Charlie -> Bob first with higher total |
| 2 | `test_aggregate_tips_respects_7d_period` | Only tips within last 7 days counted; older tips excluded |
| 3 | `test_aggregate_tips_all_period` | All historical tips counted regardless of age |
| 4 | `test_ranking_by_total_cents_descending` | Highest tipper is rank 1, second highest is rank 2 |
| 5 | `test_tip_count_is_correct` | 3 separate tips from Bob -> tip_count=3 |
| 6 | `test_last_tip_at_is_most_recent` | Most recent timestamp from Bob's tips is returned |
| 7 | `test_precomputed_write_read_roundtrip` | Write leaderboard then read returns same supporters data |
| 8 | `test_limit_parameter_caps_results` | 50 supporters in data, limit=10 returns only 10 |
| 9 | `test_non_tip_credits_excluded` | Subscription and unlock credits not counted in tip totals |
| 10 | `test_empty_leaderboard_returns_empty_list` | Creator with no tips returns empty supporters list |
| 11 | `test_debit_entries_excluded` | Only credit entries counted, debit entries ignored |
| 12 | `test_expired_precomputed_triggers_recomputation` | After TTL expires, on-demand fallback computes fresh data |
| 13 | `test_profile_enrichment_adds_display_name` | Supporter entries include display_name from profile service |
| 14 | `test_refresh_all_processes_active_creators` | Background job finds and refreshes creators with recent tips |

### 9.2 E2E Tests

**File**: `frontend/e2e/tip-leaderboard.spec.ts`

**Section 1: Top Supporters API (5 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 1.1 | Endpoint returns 200 for valid creator | GET `top-supporters`; 200 response; `supporters` array present |
| 1.2 | Period filter changes results | `?period=7d` may return different supporter list than `?period=all` |
| 1.3 | Limit parameter respected | `?limit=5` returns at most 5 entries in `supporters` array |
| 1.4 | Supporters ordered by total_cents desc | First supporter `total_cents` >= second supporter `total_cents` |
| 1.5 | Endpoint returns 401 without auth | No session cookies; 401 response |

**Section 2: Analytics Integration (3 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 2.1 | Top Supporters card visible on analytics page | Navigate to /analytics; heading "Top Supporters" visible |
| 2.2 | Period toggle changes data | Click "7d" button; supporter list re-renders with new data |
| 2.3 | Empty state shown when no tips | Creator with zero tips sees "No tips received" message |

**Section 3: Profile Widget (3 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 3.1 | Top Supporters widget renders on profile | Navigate to creator profile; "Top Supporters" card visible |
| 3.2 | Medal icons on top 3 supporters | Rank 1/2/3 entries have gold/silver/bronze medal styling |
| 3.3 | Widget hidden when no tips | Creator with no tips: widget renders empty state or is hidden |

### 9.3 Edge Cases

- Creator with exactly 1 tipper (single entry, rank 1).
- Creator with 100+ tippers (top 50 stored, limit parameter caps display).
- Tipper with very small tips (1 cent each, many transactions).
- Tipper with one very large tip (single $500 tip).
- Multiple tippers with identical total amounts (stable sort by user_id).
- Tip from a deleted/deactivated user account (display_name fallback to user_id).
- Clock skew: `computed_at` timestamp vs TTL comparison.

---

## 10. Migration & Rollout

### 10.1 Feature Flag

`TIP_LEADERBOARD_ENABLED` (env var, default `true`). When `false`:
- Background refresh loop is a no-op.
- API endpoint returns empty supporters list (200 with empty array).
- Frontend widget renders empty state.

Add to `app/core/settings.py`:
```python
tip_leaderboard_enabled: bool = os.environ.get("TIP_LEADERBOARD_ENABLED", "1") not in ("0", "false", "False")
```

### 10.2 DynamoDB Changes

No new tables needed. Pre-computed leaderboard items use the existing billing table with `BOARD#` prefix keys. This is backward compatible -- existing items are unaffected.

TTL is already enabled on the billing table (used by other features). The `ttl_epoch` attribute on leaderboard items integrates with the existing TTL mechanism.

### 10.3 Rollout Steps

1. Deploy `app/services/tip_leaderboard.py` and `app/routers/tip_leaderboard.py`.
2. Register routers in `app/main.py`.
3. Add Pydantic models to `app/models.py`.
4. Deploy frontend TypeScript types, API wrapper, and `TopSupportersWidget`.
5. Integrate widget into `AnalyticsPage.tsx`.
6. Run E2E tests.
7. Trigger initial pre-computation via `POST /internal/tip-leaderboards/refresh`.

### 10.4 Rollback

Set `TIP_LEADERBOARD_ENABLED=false`. Background loop stops. API returns empty data. Pre-computed items expire via DDB TTL within 24 hours.

---

## 11. Security Considerations

### 11.1 Auth Requirements

| Endpoint | Auth | Notes |
|----------|------|-------|
| `GET /ui/creators/{id}/top-supporters` | `require_ui_session` | Any authenticated user can view any creator's leaderboard |
| `POST /internal/tip-leaderboards/refresh` | Internal middleware | No user session; protected by internal API access controls |

### 11.2 Privacy

- Supporter `user_id` and `display_name` are exposed on the leaderboard. This is intentional (the purpose of a leaderboard is public recognition).
- Future enhancement: add a "Hide me from leaderboards" user preference that filters out opted-out users.
- The `meta` object from billing entries is NOT exposed in the API response (only aggregated totals).

### 11.3 Rate Limiting

- The public endpoint inherits the global rate limiter.
- The on-demand fallback computation is bounded (single creator, capped at MAX_SUPPORTERS=50 results).
- The background job is bounded (100 creators per cycle).

### 11.4 Input Validation

- `period` parameter: regex validated `^(7d|30d|all)$`.
- `limit` parameter: `ge=1, le=50`.
- `creator_id` path parameter: validated as non-empty string (no SQL injection risk with DDB).

---

## 12. Acceptance Criteria

1. `GET /ui/creators/{creator_id}/top-supporters` returns a ranked list of supporters with display names, avatars, total amounts, and tip counts.
2. Period filter supports "7d", "30d", and "all" time ranges.
3. Supporters are ranked by total tip amount in descending order.
4. Each supporter entry includes `rank`, `display_name`, `avatar_url`, `total_cents`, `tip_count`, and `last_tip_at`.
5. Background job pre-computes leaderboards hourly for creators with recent tips.
6. Pre-computed leaderboard data expires via DDB TTL after 24 hours.
7. Top Supporters card is displayed on the AnalyticsPage with a period toggle.
8. Empty states are shown gracefully when no tips exist for a period.
9. The internal refresh endpoint can trigger on-demand recomputation for a specific creator.
10. All 11 E2E tests pass.
11. All 14 unit tests pass.

---

## 13. Dependencies

- **MON-002 (Tip Ledger Integration)**: Provides the paired debit/credit entries that this feature aggregates. `app/services/tip_ledger.py`. Must be deployed.
- **MON-003 (Creator Earnings Dashboard)**: Uses the same billing table and credit entry format. `app/services/creator_earnings.py`. Provides the category mapping pattern.
- **SOC-006 (Creator Storefront / Public Profile)**: The leaderboard widget integrates into the creator profile page. Can be built independently and integrated later when SOC-006 ships.
- **ANALYTICS-001 (Creator Analytics Dashboard)**: The Top Supporters card integrates into AnalyticsPage (already exists).
- **Profile Service**: `app/services/profile.py::get_profile()` used for display name enrichment.

---

## 14. Open Questions

1. **Leaderboard opt-out**: Should supporters be able to hide themselves from leaderboards? Defer to v2.
2. **Creator visibility toggle**: Should creators be able to disable their public leaderboard? Defer to SOC-006 profile settings.
3. **Real-time updates**: Should tips immediately update the leaderboard? Current design: hourly pre-computation. Real-time would require atomic counter updates on each tip (significantly more complex).
4. **Subscriber badge**: Should subscribers who are also top tippers have a special badge? Defer to v2.
5. **Cross-creator leaderboards**: Should there be a global "top supporters across all creators" leaderboard? Out of scope for this ticket.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `write_tip_ledger` writes paired debit/credit | `app/services/tip_ledger.py` | 87-149 | VERIFIED |
| TipLedgerEntry includes tipper_user_id, recipient_user_id | `app/services/tip_ledger.py` | 35-60 | VERIFIED |
| Meta includes content_type, content_id, tipper/recipient IDs | `app/services/tip_ledger.py` | 72-84 | VERIFIED |
| Reason strings: "Tip: message", "Tip: post", "Tip: comment" | `app/services/tip_ledger.py` | 63-69 | VERIFIED |
| Credit entry: pk=USER#{recipient}, sk=LEDGER#{ts}#{id} | `app/services/tip_ledger.py` | 130-140 | VERIFIED |
| Debit entry: pk=USER#{tipper}, sk=LEDGER#{ts}#{id} | `app/services/tip_ledger.py` | 108-120 | VERIFIED |
| Earnings categorizes tips via reason prefix "tip" | `app/services/creator_earnings.py` | 22-33 | VERIFIED |
| Earnings summary queries billing table credits with pagination | `app/services/creator_earnings.py` | 47-114 | VERIFIED |
| get_earnings_transactions with FilterExpression loop | `app/services/creator_earnings.py` | 117-207 | VERIFIED |
| No aggregation/leaderboard endpoint in any router | `app/routers/tip_leaderboard.py` | 30, 54 | **OUTDATED** — GET /top-supporters and POST /refresh exist |
| No "leaderboard" or "top.*supporter" in codebase | `app/services/tip_leaderboard.py`, `app/routers/tip_leaderboard.py` | — | **OUTDATED** — service + router fully implemented |
| Tip leaderboard router registered | `app/main.py` | 107-108, 430-431 | **ALREADY IMPLEMENTED** |
| TopSupportersOut / TopSupporterItem models | `app/models.py` | — | **ALREADY IMPLEMENTED** |
| AnalyticsPage top content table area | `frontend/src/pages/analytics/AnalyticsPage.tsx` | 374-419 | VERIFIED |
| FilterExpression applied AFTER DDB page fetch | `CLAUDE.md` | gotchas | VERIFIED |
| get_profile returns display_name, avatar_url | `app/services/profile.py` | various | VERIFIED |
