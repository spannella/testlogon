# VOD-018: Ad-Supported Video Tier — Monetization via Ad Placements

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Dependencies**: MON-001 (VOD pay-per-view), MON-005 (subscription-gated VOD), VOD-017 (video gallery hub)

---

## 1. Overview & Motivation

### The Gap

The VOD system currently supports four access modes defined in `app/models_video.py` (line 94): `free`, `ppv`, `subscriber_only`, and `subscriber_free`. These modes gate access via payment or subscription, but there is **no ad-supported tier** — a monetization model where videos are free to watch but include advertisements.

The entitlement cascade in `check_vod_access()` (`app/services/vod_purchase.py`, line 77) handles the four existing modes but has no concept of "entitled with conditions" — every entitled result means unrestricted playback. An ad-supported tier requires a new pattern: the viewer IS entitled (no paywall), but the playback experience includes ad insertions.

Creators currently have two monetization levers: individual sales (PPV) and subscriptions. Adding ad-supported content creates a third revenue stream — especially valuable for creators who want broad audience reach (free access) while still earning revenue. This is the YouTube model: viewers watch for free, creators earn from ad impressions.

In dev/MVP mode, ads are simulated with static placeholder content. The ad tracking infrastructure (impressions, completions, skips) is built as the foundation for future ad network integration.

### Why This Is Needed

1. **Monetization gap**: Free videos generate zero revenue. Ad support fills the gap between free content and paid content, giving creators a middle-ground option.

2. **Viewer acquisition**: Paywalled content limits audience size. Ad-supported content lets new viewers discover creators without financial commitment, driving funnel conversion to subscriptions.

3. **Platform revenue share**: Ad revenue creates a platform-level monetization path (future: platform takes a percentage of ad revenue). Currently the platform only earns from payment processing fees.

4. **Subscriber value**: "Watch ad-free" is a compelling subscription benefit. Subscribers who skip ads get tangible value from their subscription even on ad-supported content.

### Architecture After This Change

```
                   Video Access Mode Decision Tree (updated)
                   ─────────────────────────────────────────

Viewer requests video
        │
        ▼
  ┌─────────────┐
  │ Is Owner?   │──── Yes ──→ PLAY (no ads, owner always ad-free)
  └──────┬──────┘
         │ No
         ▼
  ┌─────────────┐
  │ Is Free?    │──── Yes ──→ PLAY (no ads, truly free content)
  └──────┬──────┘
         │ No
         ▼
  ┌─────────────────┐
  │ access_mode?    │
  │                 │
  │ ad_supported ───│──→ ENTITLED (with ads)
  │                 │    ├── Is subscriber + ads_free_for_subscribers?
  │                 │    │   ├── Yes → PLAY (no ads, subscriber benefit)
  │                 │    │   └── No  → PLAY (with ads: pre-roll, mid-roll, overlay)
  │                 │    │
  │                 │    └── Record ad impressions → Creator ad revenue
  │                 │
  │ ppv ────────────│──→ (existing: check purchase)
  │ subscriber_only │──→ (existing: check subscription)
  │ subscriber_free │──→ (existing: check purchase or subscription)
  └─────────────────┘
```

### Detailed Data Flow — Ad-Supported Playback

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── GET /ui/videos/{id} ───────────>│                                    │
  │                                   │── get_video(id) ─────────────────>│
  │                                   │<── video (access_mode=ad_supported)│
  │                                   │                                    │
  │                                   │── check_vod_access() ─────────────│
  │                                   │   → access_mode == "ad_supported"  │
  │                                   │   → entitled=True, reason="ad"     │
  │                                   │                                    │
  │                                   │── [check subscriber ad-free]       │
  │                                   │   has_active_subscription() ──────>│
  │                                   │<── True/False ────────────────────│
  │                                   │                                    │
  │<── 200 { entitled: true,          │                                    │
  │     access_reason: "ad",          │                                    │
  │     ads_enabled: true/false,      │                                    │
  │     playback_url, ... }           │                                    │
  │                                   │                                    │
  │── GET /ui/ads/placement/{id} ────>│                                    │
  │                                   │── get_video ad_config ────────────>│
  │                                   │<── ad_config ─────────────────────│
  │                                   │                                    │
  │                                   │── resolve ad creatives ────────────│
  │                                   │   (static placeholders in dev)     │
  │                                   │                                    │
  │<── 200 { slots: [                 │                                    │
  │     {type: "pre_roll", ts: 0,     │                                    │
  │      duration: 15, url: "..."},   │                                    │
  │     {type: "mid_roll", ts: 300,   │                                    │
  │      duration: 30, url: "..."},   │                                    │
  │   ] }                             │                                    │
  │                                   │                                    │
  │── POST /ui/ads/impression ───────>│                                    │
  │   {video_id, slot_type,           │── write AdImpressions ───────────>│
  │    slot_index, ad_creative_id}    │── update creator ad revenue ──────>│
  │                                   │<── ok ────────────────────────────│
  │<── 200 { ok }                     │                                    │
```

---

## 2. Current State Analysis

### 2.1 Access Mode Field (`app/models_video.py`, line 94)

```python
access_mode: Optional[str] = None  # "free", "ppv", "subscriber_only", "subscriber_free"
```

The regex pattern validation in `VodPricingIn` (`app/routers/video_listing.py`, line 484):
```python
access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free)$")
```

Both must be updated to accept `"ad_supported"` as a valid value.

### 2.2 Entitlement Cascade (`app/services/vod_purchase.py`, lines 77-153)

The `check_vod_access()` function handles modes in this order:
1. Owner → entitled (line 97)
2. Free (price=0 or mode=free) → entitled (line 101)
3. Purchase check → entitled (line 105)
4. Subscription check for subscriber_only/subscriber_free → entitled (line 109)
5. Fallback → not entitled (lines 121-153)

`ad_supported` is not handled. Without changes, an `ad_supported` video with `price_cents > 0` would fall through to step 5 and be treated as not entitled. With `price_cents = 0`, it would be caught by step 2 as "free" — close but missing the ad insertion signal.

### 2.3 Video Player (`frontend/src/pages/broadcast/LivePlayer.tsx`)

The existing player handles HLS playback via `hls.js`. It has no ad insertion hooks, no pre-roll mechanism, and no overlay system. Adding ad support requires:
- A pre-play ad phase (blocking playback until ad completes or is skipped)
- Mid-roll insertion (pausing content at configured timestamps)
- Overlay rendering (semi-transparent banner during playback)

### 2.4 Billing/Ledger Infrastructure

The billing ledger (`T.billing`) supports debit/credit entries with structured metadata. Ad revenue entries follow the same pattern as VOD purchase credits — a `LEDGER` entry with `reason="Ad revenue"` and meta containing ad impression details.

The existing `new_ledger_entry()` helper (`app/services/billing_shared.py`) can be reused for ad revenue credits.

### 2.5 Static Assets in Dev Mode

The project already serves static files from `app/static/` (referenced in `app/main.py`). The `app/static/uploads/watermarks/` directory exists. Dev-mode ad creatives can be served from `app/static/ads/`.

---

## 3. Technical Design

### 3.1 Access Mode Extension

Add `"ad_supported"` to the valid access modes:

**File**: `app/models_video.py` — Update comment on line 94:
```python
access_mode: Optional[str] = None  # "free", "ppv", "subscriber_only", "subscriber_free", "ad_supported"
```

**File**: `app/routers/video_listing.py` — Update `VodPricingIn` regex (line 484):
```python
access_mode: Optional[str] = Field(
    default=None,
    pattern=r"^(free|ppv|subscriber_only|subscriber_free|ad_supported)$"
)
```

### 3.2 Ad Configuration Model

Add ad config fields to `VideoMetadataModel`:

```python
class VideoMetadataModel(BaseModel):
    # ... existing fields ...

    # Ad support (VOD-018)
    ad_config: Optional[dict] = None         # Ad placement configuration
    ads_free_for_subscribers: bool = False    # Subscribers skip ads
    ad_revenue_cents: int = 0                # Total ad revenue earned
    ad_impression_count: int = 0             # Total ad impressions served
```

Ad config schema (stored as DDB map):
```python
{
    "pre_roll": True,                        # Show ad before video starts
    "mid_roll_intervals_seconds": [300, 600], # Mid-roll break timestamps
    "overlay_enabled": False,                 # Banner overlay during playback
    "skip_after_seconds": 5,                  # Allow skip after N seconds (0 = no skip)
}
```

### 3.3 Entitlement Cascade Update

**File**: `app/services/vod_purchase.py`

Insert `ad_supported` handling between step 2 (free check) and step 3 (purchase check):

```python
def check_vod_access(
    *,
    user_id: str,
    video_id: str,
    video: "VideoMetadataModel",
) -> VodAccessResult:
    creator_id = video.owner_user_id
    access_mode = video.access_mode or "free"
    price = video.price_cents or 0

    # 1. Owner check
    if user_id == creator_id:
        return VodAccessResult(entitled=True, reason="owner")

    # 2. Free video check
    # IMPORTANT BEHAVIORAL CHANGE (VOD-018): The existing code at line 101
    # uses `or` logic: `if price == 0 or access_mode == "free":`.
    # This is intentionally changed to `and` + explicit mode list to prevent
    # ad_supported videos with price_cents=0 from being caught as "free"
    # (which would bypass ad insertion). Without this change, ad_supported
    # videos with price_cents=0 would never reach the ad_supported branch.
    # Side effect: videos with price_cents=0 but a non-free/non-None
    # access_mode (e.g., "ppv" with price_cents=0) will no longer be
    # treated as free — they will fall through to the purchase/subscription
    # checks. Verify no existing videos rely on the old `or` behavior
    # before deploying this change.
    if price == 0 and access_mode in ("free", None):
        return VodAccessResult(entitled=True, reason="free")

    # 2.5 Ad-supported check (VOD-018)
    if access_mode == "ad_supported":
        # Always entitled — ads are the gate, not a paywall
        ads_enabled = True
        # Check if subscriber gets ad-free access
        if getattr(video, "ads_free_for_subscribers", False):
            has_sub = has_active_subscription(
                subscriber_id=user_id, creator_id=creator_id
            )
            if has_sub:
                ads_enabled = False
        return VodAccessResult(
            entitled=True,
            reason="ad",
            ads_enabled=ads_enabled,
        )

    # 3. Explicit purchase check
    # ... (unchanged) ...
```

Update `VodAccessResult` to include `ads_enabled`:

```python
class VodAccessResult:
    def __init__(
        self,
        *,
        entitled: bool,
        reason: str,
        subscription_available: bool = False,
        purchase_available: bool = False,
        price_cents: Optional[int] = None,
        subscription_upsell: bool = False,
        ads_enabled: bool = False,          # VOD-018: True when ads should be shown
    ):
        # ... existing fields ...
        self.ads_enabled = ads_enabled

    def to_dict(self) -> Dict[str, Any]:
        d = {
            # ... existing fields ...
            "ads_enabled": self.ads_enabled,
        }
        return d
```

### 3.4 Ad Placement Service: `app/services/ad_placement.py`

```python
"""Ad placement service (VOD-018).

Handles ad configuration, placement resolution, impression tracking,
and revenue calculation. In dev mode, ads are static placeholders.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.video_metadata_store import get_video
from app.services.billing_shared import new_ledger_entry, user_pk

logger = logging.getLogger(__name__)

# Default CPM rate in cents ($5 CPM = 500 cents per 1000 impressions)
DEFAULT_CPM_CENTS = 500

# Dev-mode placeholder ad creatives
DEV_AD_CREATIVES = [
    {
        "creative_id": "dev_ad_preroll_15s",
        "type": "video",
        "duration_seconds": 15,
        "url": "/static/ads/placeholder_preroll.mp4",
        "title": "Placeholder Pre-Roll Ad",
    },
    {
        "creative_id": "dev_ad_midroll_30s",
        "type": "video",
        "duration_seconds": 30,
        "url": "/static/ads/placeholder_midroll.mp4",
        "title": "Placeholder Mid-Roll Ad",
    },
    {
        "creative_id": "dev_ad_overlay",
        "type": "image",
        "duration_seconds": 10,
        "url": "/static/ads/placeholder_overlay.png",
        "title": "Placeholder Overlay Ad",
    },
]


def get_default_ad_config(duration_seconds: float) -> Dict[str, Any]:
    """Generate default ad configuration based on video duration.

    Rules:
    - Videos < 10 min: pre_roll only
    - Videos >= 10 min: pre_roll + one mid_roll at the midpoint
    - Maximum 1 mid_roll per 5 minutes of content
    - Skip allowed after 5 seconds by default
    """
    config: Dict[str, Any] = {
        "pre_roll": True,
        "mid_roll_intervals_seconds": [],
        "overlay_enabled": False,
        "skip_after_seconds": 5,
    }

    if duration_seconds >= 600:  # >= 10 minutes
        # Add mid-rolls every 5 minutes (max 1 per 5 min)
        interval = 300  # 5 minutes
        t = interval
        while t < duration_seconds - 60:  # Stop 60s before end
            config["mid_roll_intervals_seconds"].append(t)
            t += interval

    return config


def validate_ad_config(config: Dict[str, Any], duration_seconds: float) -> Dict[str, Any]:
    """Validate and sanitize creator-provided ad configuration.

    Enforces:
    - pre_roll: boolean
    - mid_roll_intervals_seconds: list of ints, max 1 per 5 min of content
    - Each mid_roll timestamp < duration - 30s
    - overlay_enabled: boolean
    - skip_after_seconds: int, 0-30

    Returns sanitized config or raises ValueError.
    """
    sanitized: Dict[str, Any] = {}

    sanitized["pre_roll"] = bool(config.get("pre_roll", True))
    sanitized["overlay_enabled"] = bool(config.get("overlay_enabled", False))

    skip = int(config.get("skip_after_seconds", 5))
    sanitized["skip_after_seconds"] = max(0, min(30, skip))

    # Validate mid-roll intervals
    mid_rolls = config.get("mid_roll_intervals_seconds", [])
    if not isinstance(mid_rolls, list):
        mid_rolls = []

    max_mid_rolls = max(1, int(duration_seconds / 300))  # 1 per 5 min
    validated_mid_rolls = []
    for ts in mid_rolls[:max_mid_rolls]:
        ts_int = int(ts)
        if 30 <= ts_int < duration_seconds - 30:
            validated_mid_rolls.append(ts_int)

    validated_mid_rolls.sort()
    sanitized["mid_roll_intervals_seconds"] = validated_mid_rolls

    return sanitized


def get_ad_placements(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Resolve ad placements for a video.

    Returns the ad slot list with creative URLs for the player to render.
    In dev mode, returns static placeholder creatives.

    Args:
        video_id: The video being played.
        user_id: The viewer (used for future ad targeting).

    Returns:
        {
            "slots": [
                {
                    "type": "pre_roll" | "mid_roll" | "overlay",
                    "timestamp_seconds": int,
                    "duration_seconds": int,
                    "creative_id": str,
                    "creative_url": str,
                    "creative_type": "video" | "image",
                    "skip_after_seconds": int,
                    "slot_index": int,
                },
                ...
            ],
            "ad_free": false,
        }
    """
    video = get_video(video_id)

    if video.access_mode != "ad_supported":
        return {"slots": [], "ad_free": True}

    # Check subscriber ad-free setting
    if getattr(video, "ads_free_for_subscribers", False):
        from app.services.subscription_access import has_active_subscription
        if has_active_subscription(subscriber_id=user_id, creator_id=video.owner_user_id):
            return {"slots": [], "ad_free": True}

    # Get ad config (creator-configured or default)
    ad_config = video.ad_config
    if not ad_config:
        duration = video.duration_seconds or 60
        ad_config = get_default_ad_config(duration)

    slots: List[Dict[str, Any]] = []
    slot_index = 0

    # Pre-roll
    if ad_config.get("pre_roll"):
        creative = DEV_AD_CREATIVES[0]  # Pre-roll placeholder
        slots.append({
            "type": "pre_roll",
            "timestamp_seconds": 0,
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
            "slot_index": slot_index,
        })
        slot_index += 1

    # Mid-rolls
    for ts in ad_config.get("mid_roll_intervals_seconds", []):
        creative = DEV_AD_CREATIVES[1]  # Mid-roll placeholder
        slots.append({
            "type": "mid_roll",
            "timestamp_seconds": ts,
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": ad_config.get("skip_after_seconds", 5),
            "slot_index": slot_index,
        })
        slot_index += 1

    # Overlay
    if ad_config.get("overlay_enabled"):
        creative = DEV_AD_CREATIVES[2]  # Overlay placeholder
        slots.append({
            "type": "overlay",
            "timestamp_seconds": 30,  # Show 30s into playback
            "duration_seconds": creative["duration_seconds"],
            "creative_id": creative["creative_id"],
            "creative_url": creative["url"],
            "creative_type": creative["type"],
            "skip_after_seconds": 0,  # Overlays don't have skip
            "slot_index": slot_index,
        })
        slot_index += 1

    return {"slots": slots, "ad_free": False}


def record_ad_impression(
    *,
    video_id: str,
    user_id: str,
    slot_type: str,
    slot_index: int,
    creative_id: str,
    event_type: str = "impression",   # "impression" | "complete" | "skip"
) -> Dict[str, Any]:
    """Record an ad impression/completion/skip event.

    Writes to AdImpressions table for tracking. On "complete" events,
    credits the creator with ad revenue based on CPM rate.

    Args:
        video_id: The video the ad was shown on.
        user_id: The viewer who saw the ad.
        slot_type: "pre_roll" | "mid_roll" | "overlay".
        slot_index: Index of the ad slot in the placement list.
        creative_id: The creative that was shown.
        event_type: "impression" (ad started), "complete" (watched fully),
                    "skip" (skipped by viewer).

    Returns:
        {"ok": True, "event_id": str}
    """
    ts = now_ts()
    event_id = f"adimp_{uuid.uuid4().hex}"

    # Write impression record
    try:
        T.ad_impressions.put_item(
            Item={
                "pk": f"AD_IMP#{_date_str(ts)}",
                "sk": f"VIDEO#{video_id}#{user_id}#{ts}",
                "event_id": event_id,
                "video_id": video_id,
                "user_id": user_id,
                "slot_type": slot_type,
                "slot_index": slot_index,
                "creative_id": creative_id,
                "event_type": event_type,
                "created_at": ts,
            }
        )
    except Exception:
        logger.warning("ad_impression_write_failed", extra={
            "video_id": video_id, "user_id": user_id, "event_type": event_type,
        })

    # On complete: credit creator with ad revenue
    if event_type == "complete":
        _credit_ad_revenue(video_id=video_id, event_id=event_id, ts=ts)

    # Increment impression count on video metadata
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET ad_impression_count = if_not_exists(ad_impression_count, :z) + :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:
        logger.warning("ad_impression_counter_failed", extra={"video_id": video_id})

    return {"ok": True, "event_id": event_id}


def _credit_ad_revenue(*, video_id: str, event_id: str, ts: int) -> None:
    """Credit creator with ad revenue for a completed ad impression.

    Uses configurable CPM rate (default $5 CPM = 0.5 cents per impression).
    Revenue = CPM_CENTS / 1000 per completed impression.
    """
    video = get_video(video_id)
    cpm = getattr(S, "ad_cpm_cents", DEFAULT_CPM_CENTS)
    # Revenue per impression: CPM / 1000 (e.g., 500/1000 = 0.5 cents)
    # Since we deal in integer cents, we accumulate fractional cents
    # and credit whole cents. For simplicity in MVP: credit 1 cent per
    # 2 completed impressions (round up to nearest cent).
    revenue_microcents = cpm * 1000 // 1000  # microcents per impression
    # For MVP: just credit the fractional amount (will be sub-cent for most impressions)
    # Accumulate on video metadata; periodic job settles to ledger.

    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET ad_revenue_cents = if_not_exists(ad_revenue_cents, :z) + :rev",
            ExpressionAttributeValues={":z": 0, ":rev": max(1, cpm // 1000)},
        )
    except Exception:
        logger.warning("ad_revenue_credit_failed", extra={"video_id": video_id})

    # Write ledger credit for creator (best-effort)
    try:
        revenue_cents = max(1, cpm // 1000)
        _sk, credit_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(video.owner_user_id),
            entry_type="ad_revenue_credit",
            amount_cents=revenue_cents,
            state="settled",
            reason="Ad revenue",
            meta={
                "video_id": video_id,
                "event_id": event_id,
                "creative_type": "completed_view",
            },
        )
        T.billing.put_item(Item=credit_item)
    except Exception:
        logger.warning("ad_revenue_ledger_failed", extra={
            "video_id": video_id, "creator_id": video.owner_user_id,
        })


def _date_str(ts: int) -> str:
    """Convert Unix timestamp to YYYY-MM-DD string."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
```

### 3.5 Ad Impressions DDB Table

```python
TableDef(
    "ad_impressions",
    "pk",    # AD_IMP#{YYYY-MM-DD}
    "sk",    # VIDEO#{video_id}#{user_id}#{ts}
    gsi=[
        {
            "index_name": "ByVideo",
            "partition_key": "video_id",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByCreative",
            "partition_key": "creative_id",
            "sort_key": "created_at",
        },
    ],
    attr_types={"created_at": "N"},
),
```

**PK pattern**: `AD_IMP#{date}` partitions impressions by day. This provides natural time-series partitioning and allows efficient daily analytics queries.

**Hot partition risk**: A viral video could generate thousands of impressions per day on the same PK partition. DDB on-demand billing handles this. For production scale, consider sharding: `AD_IMP#{date}#{shard}` where shard = `hash(video_id) % N`.

Settings (`app/core/settings.py`):
```python
ad_impressions_table_name: str = os.environ.get("AD_IMPRESSIONS_TABLE_NAME", "ad_impressions")
ad_cpm_cents: int = int(os.environ.get("AD_CPM_CENTS", "500"))  # $5 CPM default
```

Table handle (`app/core/tables.py`):
```python
ad_impressions: Any
# In T = Tables(...):
ad_impressions=ddb.Table(S.ad_impressions_table_name),
```

### 3.6 API Endpoints

#### 3.6.1 Configure Ad Placement (Creator)

```
PATCH /ui/videos/{video_id}/ad-config
```

Request:
```python
class AdConfigIn(BaseModel):
    pre_roll: bool = True
    mid_roll_intervals_seconds: List[int] = Field(default_factory=list)
    overlay_enabled: bool = False
    skip_after_seconds: int = Field(default=5, ge=0, le=30)
    ads_free_for_subscribers: bool = False
```

Only the video owner can configure ads. Validates ownership via `video.owner_user_id == user_sub`.

Handler:
```python
@router.patch("/{video_id}/ad-config")
def set_ad_config(video_id: str, body: AdConfigIn, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)
    if video.owner_user_id != user_sub:
        raise HTTPException(403, "not your video")

    duration = video.duration_seconds or 60
    validated = validate_ad_config(body.model_dump(), duration)

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET ad_config = :ac, ads_free_for_subscribers = :afs, updated_at = :ua",
        ExpressionAttributeValues={
            ":ac": validated,
            ":afs": body.ads_free_for_subscribers,
            ":ua": now_ts(),
        },
    )
    return {"ok": True, "ad_config": validated, "ads_free_for_subscribers": body.ads_free_for_subscribers}
```

#### 3.6.2 Get Ad Placements (Viewer)

```
GET /ui/ads/placement/{video_id}
```

Response:
```python
class AdSlot(BaseModel):
    type: str              # "pre_roll" | "mid_roll" | "overlay"
    timestamp_seconds: int
    duration_seconds: int
    creative_id: str
    creative_url: str
    creative_type: str     # "video" | "image"
    skip_after_seconds: int
    slot_index: int

class AdPlacementOut(BaseModel):
    slots: List[AdSlot]
    ad_free: bool          # True if subscriber with ads_free_for_subscribers
```

#### 3.6.3 Record Ad Impression

```
POST /ui/ads/impression
```

Request:
```python
class AdImpressionIn(BaseModel):
    video_id: str
    slot_type: str = Field(pattern=r"^(pre_roll|mid_roll|overlay)$")
    slot_index: int = Field(ge=0)
    creative_id: str
    event_type: str = Field(default="impression", pattern=r"^(impression|complete|skip)$")
```

Response:
```python
class AdImpressionOut(BaseModel):
    ok: bool
    event_id: str
```

#### 3.6.4 Ad Revenue Summary (Creator)

```
GET /ui/ads/revenue/{video_id}
```

Response:
```python
class AdRevenueOut(BaseModel):
    video_id: str
    ad_revenue_cents: int
    ad_impression_count: int
    estimated_cpm_cents: int
```

### 3.7 Frontend Player Integration

The video player needs three new behaviors:

**Pre-roll ad phase**:
```typescript
function AdPreRoll({ slot, onComplete, onSkip }: AdPreRollProps) {
  const [elapsed, setElapsed] = useState(0);
  const canSkip = elapsed >= slot.skip_after_seconds;

  useEffect(() => {
    // Record impression event when ad starts
    recordAdImpression({ videoId, slotType: "pre_roll", ... eventType: "impression" });
  }, []);

  const handleComplete = () => {
    recordAdImpression({ videoId, slotType: "pre_roll", ... eventType: "complete" });
    onComplete();
  };

  const handleSkip = () => {
    recordAdImpression({ videoId, slotType: "pre_roll", ... eventType: "skip" });
    onSkip();
  };

  return (
    <div className="relative">
      <video src={slot.creative_url} autoPlay onEnded={handleComplete} />
      {canSkip && (
        <Button className="absolute bottom-4 right-4" onClick={handleSkip}>
          Skip Ad
        </Button>
      )}
      {!canSkip && (
        <span className="absolute bottom-4 right-4 text-white">
          Skip in {slot.skip_after_seconds - elapsed}s
        </span>
      )}
      <Badge className="absolute top-4 left-4">Ad</Badge>
    </div>
  );
}
```

**Mid-roll interruption**: Player monitors `currentTime` and pauses at mid-roll timestamps, showing an ad before resuming.

**Overlay**: Semi-transparent banner at bottom of player. Dismissible after `duration_seconds`.

**Subscriber upsell**: When ads are shown, display "Watch ad-free with a subscription" CTA below the player.

### 3.8 Frontend Types

```typescript
export interface AdSlot {
  type: "pre_roll" | "mid_roll" | "overlay";
  timestamp_seconds: number;
  duration_seconds: number;
  creative_id: string;
  creative_url: string;
  creative_type: "video" | "image";
  skip_after_seconds: number;
  slot_index: number;
}

export interface AdPlacementResponse {
  slots: AdSlot[];
  ad_free: boolean;
}

export interface AdImpressionRequest {
  video_id: string;
  slot_type: string;
  slot_index: number;
  creative_id: string;
  event_type: "impression" | "complete" | "skip";
}

export interface AdConfigRequest {
  pre_roll: boolean;
  mid_roll_intervals_seconds: number[];
  overlay_enabled: boolean;
  skip_after_seconds: number;
  ads_free_for_subscribers: boolean;
}

export interface AdRevenueResponse {
  video_id: string;
  ad_revenue_cents: number;
  ad_impression_count: number;
  estimated_cpm_cents: number;
}
```

### 3.9 VideoDetailOut Update

Add `ads_enabled` field to `VideoDetailOut` (`app/routers/video_listing.py`, line 67):

```python
class VideoDetailOut(BaseModel):
    # ... existing fields ...
    # Ad support (VOD-018)
    ads_enabled: bool = False              # True when viewer should see ads
    ads_free_for_subscribers: bool = False  # Creator's ad-free subscriber setting
    ad_config: Optional[dict] = None       # Ad placement config (creator only)
```

---

## 4. Implementation Plan

### Step 1: Extend Access Mode

**File**: `app/models_video.py` — Add `ad_config`, `ads_free_for_subscribers`, `ad_revenue_cents`, `ad_impression_count` fields  
**File**: `app/routers/video_listing.py` — Update `VodPricingIn` regex to include `ad_supported`

### Step 2: Update Entitlement Cascade

**File**: `app/services/vod_purchase.py` — Add `ad_supported` handling in `check_vod_access()`, add `ads_enabled` to `VodAccessResult`

### Step 3: Create Ad Impressions Table

**File**: `scripts/local-ddb-init.py` — Add `ad_impressions` table definition  
**File**: `app/core/settings.py` — Add `ad_impressions_table_name`, `ad_cpm_cents`  
**File**: `app/core/tables.py` — Add `ad_impressions` table handle

### Step 4: Create Ad Placement Service

**File**: `app/services/ad_placement.py` (new, ~300 lines)

### Step 5: Add API Endpoints

**File**: `app/routers/video_listing.py` — Add ad-config, placement, impression, revenue endpoints

### Step 6: Create Dev Ad Placeholder Assets

**File**: `app/static/ads/placeholder_preroll.mp4` — 15s placeholder video  
**File**: `app/static/ads/placeholder_midroll.mp4` — 30s placeholder video  
**File**: `app/static/ads/placeholder_overlay.png` — Banner image

(In dev mode, these can be simple solid-color videos generated with ffmpeg.)

### Step 7: Frontend Types and API

**File**: `frontend/src/api/types.ts` — Add ad types  
**File**: `frontend/src/api/endpoints/ads.ts` (new) — API wrappers

### Step 8: Frontend Player Ad Integration

**File**: `frontend/src/pages/vod/VideoPlayerPage.tsx` — Add `AdPreRoll`, mid-roll hooks, overlay component

### Step 9: Update VideoDetailOut

**File**: `app/routers/video_listing.py` — Add `ads_enabled`, `ads_free_for_subscribers` to detail response

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/models_video.py` | Add ad fields | ~8 |
| `app/services/vod_purchase.py` | Ad-supported cascade + VodAccessResult | ~25 |
| `app/services/ad_placement.py` | New service | ~300 |
| `app/routers/video_listing.py` | Ad endpoints + response updates | ~150 |
| `app/core/settings.py` | Add settings | ~5 |
| `app/core/tables.py` | Add table handle | ~3 |
| `scripts/local-ddb-init.py` | Add table | ~15 |
| `frontend/src/api/types.ts` | Add TypeScript types | ~40 |
| `frontend/src/api/endpoints/ads.ts` | New API wrappers | ~40 |
| `frontend/src/pages/vod/VideoPlayerPage.tsx` | Ad player integration | ~200 |
| **Total** | | **~786** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_ad_placement.py`)

New file, ~400 lines.

```python
def test_default_ad_config_short_video():
    """Videos < 10 min get pre_roll only, no mid_rolls."""
    config = get_default_ad_config(300)  # 5 min
    assert config["pre_roll"] is True
    assert config["mid_roll_intervals_seconds"] == []

def test_default_ad_config_long_video():
    """Videos >= 10 min get pre_roll + mid_rolls every 5 min."""
    config = get_default_ad_config(900)  # 15 min
    assert config["pre_roll"] is True
    assert len(config["mid_roll_intervals_seconds"]) >= 1
    assert 300 in config["mid_roll_intervals_seconds"]

def test_validate_ad_config_max_midrolls():
    """Mid-rolls capped at 1 per 5 min of content."""
    config = validate_ad_config(
        {"mid_roll_intervals_seconds": [60, 120, 180, 240, 300, 360]},
        duration_seconds=600,
    )
    assert len(config["mid_roll_intervals_seconds"]) <= 2

def test_validate_ad_config_skip_range():
    """skip_after_seconds clamped to 0-30."""
    config = validate_ad_config({"skip_after_seconds": 100}, duration_seconds=600)
    assert config["skip_after_seconds"] == 30
    config2 = validate_ad_config({"skip_after_seconds": -5}, duration_seconds=600)
    assert config2["skip_after_seconds"] == 0

def test_ad_placement_non_ad_video():
    """Non ad_supported video returns empty slots and ad_free=True."""
    # Seed video with access_mode="ppv"
    result = get_ad_placements(video_id=vid_ppv, user_id="bob")
    assert result["slots"] == []
    assert result["ad_free"] is True

def test_ad_placement_ad_supported_video():
    """Ad-supported video returns pre_roll slot."""
    result = get_ad_placements(video_id=vid_ad, user_id="bob")
    assert len(result["slots"]) >= 1
    assert result["slots"][0]["type"] == "pre_roll"
    assert result["ad_free"] is False

def test_ad_placement_subscriber_ad_free():
    """Subscriber with ads_free_for_subscribers=True gets no ads."""
    # Seed active subscription for bob -> alice (creator)
    result = get_ad_placements(video_id=vid_ad_sub_free, user_id="bob")
    assert result["slots"] == []
    assert result["ad_free"] is True

def test_record_impression_writes_to_ddb():
    """Impression event writes to ad_impressions table."""
    result = record_ad_impression(
        video_id=vid_ad, user_id="bob",
        slot_type="pre_roll", slot_index=0,
        creative_id="dev_ad_preroll_15s",
        event_type="impression",
    )
    assert result["ok"] is True
    assert result["event_id"].startswith("adimp_")

def test_complete_event_credits_creator():
    """Completed ad view credits creator with ad revenue."""
    record_ad_impression(
        video_id=vid_ad, user_id="bob",
        slot_type="pre_roll", slot_index=0,
        creative_id="dev_ad_preroll_15s",
        event_type="complete",
    )
    # Verify revenue incremented on video
    video = get_video(vid_ad)
    assert video.ad_revenue_cents > 0

def test_skip_event_no_revenue():
    """Skipped ad does NOT credit creator."""
    initial_revenue = get_video(vid_ad).ad_revenue_cents
    record_ad_impression(
        video_id=vid_ad, user_id="bob",
        slot_type="pre_roll", slot_index=0,
        creative_id="dev_ad_preroll_15s",
        event_type="skip",
    )
    assert get_video(vid_ad).ad_revenue_cents == initial_revenue

def test_entitlement_cascade_ad_supported():
    """ad_supported videos are always entitled with reason='ad'."""
    video = make_video(access_mode="ad_supported", price_cents=0, owner="alice")
    result = check_vod_access(user_id="bob", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "ad"
    assert result.ads_enabled is True
```

### 5.2 E2E Tests (`frontend/e2e/ad-supported-video.spec.ts`)

New file, ~400 lines.

**Section 134: Ad Configuration API (4 tests)**

1. `Creator sets ad config on video` — PATCH /ad-config with pre_roll + mid_roll, verify 200
2. `Creator enables ads_free_for_subscribers` — PATCH with flag, verify stored
3. `Non-owner cannot set ad config` — PATCH as Bob, verify 403
4. `Invalid mid_roll timestamps rejected` — PATCH with timestamp > duration, verify sanitized

**Section 135: Ad Impression Tracking + Revenue (4 tests)**

1. `Ad placement returns pre_roll slot for ad_supported video` — GET /ads/placement/{id}, verify slot
2. `Impression event recorded` — POST /ads/impression with event_type=impression, verify 200
3. `Complete event credits creator revenue` — POST with event_type=complete, query billing ledger
4. `Skip event does not credit revenue` — POST with event_type=skip, verify no new ledger entry

**Test setup (beforeAll):**
- Seed sessions for Alice (creator) and Bob (viewer)
- Create and publish a video as Alice with `access_mode=ad_supported`
- Configure ad slots on the video

---

## 6. Security Considerations

### 6.1 Authentication

- All ad endpoints require `require_ui_session`. No anonymous ad tracking.
- Ad config (`PATCH`) validates video ownership. Non-owners get 403.
- Impression recording validates authenticated user_id — clients cannot forge impressions for other users.

### 6.2 Ad Fraud Prevention

- **Client-side impression reporting**: The backend trusts the client to report impression/complete/skip events. In production, server-side verification (playback token validation, session duration checks) should be added.
- **Impression deduplication**: The current design does NOT deduplicate impressions (same user can trigger multiple impressions per video per day). Future: add dedup key `VIDEO#{video_id}#{user_id}#{slot_index}#{date}`.
- **CPM manipulation**: CPM rate is server-configured (`S.ad_cpm_cents`), not client-provided. Creators cannot inflate their own CPM.

### 6.3 Rate Limiting

- Impression endpoint: 120 per minute per user (generous for mid-roll-heavy videos).
- Placement endpoint: 60 per minute per user.
- Ad config: 10 per minute per user.

### 6.4 Ad Creative Validation

All ad creative assets (uploaded or fetched from future ad networks) must pass validation before being served:

**File type restrictions:**
- Video: `video/mp4` only. No `video/webm` (codec attack surface), no `application/octet-stream`.
- Image: `image/png`, `image/jpeg`, `image/webp` only. No SVG (XSS vector via inline `<script>`).
- No executable MIME types: reject `application/javascript`, `text/html`, `application/x-shockwave-flash`, etc.

**Size limits:**
| Creative Type | Max File Size | Max Duration | Max Resolution |
|---------------|--------------|-------------|----------------|
| Pre-roll video | 50 MB | 30 seconds | 1920x1080 |
| Mid-roll video | 100 MB | 60 seconds | 1920x1080 |
| Overlay image | 2 MB | N/A | 1920x200 |

**Content scanning:**
- Strip EXIF/metadata from uploaded images (prevent location/PII leakage).
- Validate MP4 container structure — reject files with embedded JavaScript in metadata atoms (`moov`, `udta` atoms).
- In production: integrate with a media scanning service to detect malware in uploaded creatives.

**Validation implementation (service layer):**
```python
ALLOWED_VIDEO_MIMES = {"video/mp4"}
ALLOWED_IMAGE_MIMES = {"image/png", "image/jpeg", "image/webp"}
MAX_CREATIVE_SIZES = {
    "pre_roll": 50 * 1024 * 1024,   # 50 MB
    "mid_roll": 100 * 1024 * 1024,  # 100 MB
    "overlay": 2 * 1024 * 1024,     # 2 MB
}

def validate_creative_upload(file_bytes: bytes, content_type: str, slot_type: str) -> None:
    """Raises ValueError if creative fails validation."""
    if slot_type in ("pre_roll", "mid_roll"):
        if content_type not in ALLOWED_VIDEO_MIMES:
            raise ValueError(f"Invalid video MIME type: {content_type}")
    elif slot_type == "overlay":
        if content_type not in ALLOWED_IMAGE_MIMES:
            raise ValueError(f"Invalid image MIME type: {content_type}")

    max_size = MAX_CREATIVE_SIZES.get(slot_type, 50 * 1024 * 1024)
    if len(file_bytes) > max_size:
        raise ValueError(f"Creative exceeds {max_size} byte limit for {slot_type}")
```

### 6.5 Impression Fraud Prevention

**Bot detection heuristics** (applied at the impression endpoint):

1. **User-Agent validation**: Reject impressions from known bot User-Agents (Googlebot, curl, wget, etc.). Store a denylist in settings.
2. **Session duration check**: Reject impressions from sessions created < 5 seconds ago (bot farms create sessions and immediately fire impressions).
3. **Impression velocity check**: If a user submits > 10 impression events within 5 seconds, flag the session for review and reject further impressions for 60 seconds.
4. **Playback token validation** (production): Issue a signed, single-use playback token when `GET /ads/placement/{id}` is called. The impression endpoint requires this token. Prevents replay attacks and out-of-band impression fabrication.

```python
# Impression velocity check pseudocode
def _check_impression_velocity(user_id: str) -> bool:
    """Returns True if user is sending impressions too fast."""
    cache_key = f"ad_imp_velocity:{user_id}"
    recent_count = _increment_sliding_window(cache_key, window_seconds=5)
    return recent_count > 10
```

**Deduplication strategy** (future enhancement):

```
Dedup key: VIDEO#{video_id}#USER#{user_id}#SLOT#{slot_index}#DATE#{YYYY-MM-DD}

DynamoDB conditional write:
    ConditionExpression: "attribute_not_exists(pk)"

Effect: Each user can only generate ONE impression per slot per video per day.
Revenue is credited only on the first complete event per dedup key.
```

### 6.6 CORS for Ad Creative Loading

Ad creatives are served from the same origin in dev mode (`/static/ads/`). In production with CDN-served creatives:

- Set `Access-Control-Allow-Origin: <player-origin>` on the CDN/S3 bucket.
- Do NOT use `Access-Control-Allow-Origin: *` — restrict to known frontend domains.
- Set `Cross-Origin-Resource-Policy: cross-origin` for video assets to allow `<video>` element loading.
- Set `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks on creative assets.

**Backend CORS headers for ad creative proxy:**
```python
@router.get("/ads/creative/{creative_id}")
def serve_ad_creative(creative_id: str, response: Response):
    # ... serve creative ...
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "public, max-age=3600"
    response.headers["Content-Security-Policy"] = "default-src 'none'; media-src 'self'"
```

### 6.7 XSS Prevention in Ad Overlay HTML

Overlay ads render inside the player DOM. Prevent XSS from malicious creative metadata:

1. **Never render raw HTML from ad metadata**. All text fields (`title`, `description`, `cta_text`) are rendered via React's JSX text interpolation (`{slot.title}`), which auto-escapes HTML entities.
2. **creative_url validation**: Must match `^https?://` or `^/static/`. Reject `javascript:`, `data:`, `blob:` URLs.
3. **CSP for ad iframe** (future): If third-party ad HTML is ever supported, render inside a sandboxed iframe with `sandbox="allow-scripts"` (no `allow-same-origin`).
4. **Sanitize creative metadata on ingest**: Strip any HTML tags from `title` and `description` fields before storing to DDB.

```typescript
// Frontend: validate creative URL before rendering
function isValidCreativeUrl(url: string): boolean {
  return /^(https?:\/\/|\/static\/)/.test(url);
}
```

---

## 7. Migration & Rollback Plan

### 7.1 DDB Changes

- New table: `ad_impressions` (additive, no existing data affected)
- New fields on VideoMetadata: `ad_config`, `ads_free_for_subscribers`, `ad_revenue_cents`, `ad_impression_count` — all default to None/0/False, backward compatible

### 7.2 Feature Flag Stages

The rollout uses a multi-stage feature flag to control risk:

**Stage 0 — Code deployed, feature off (default):**
```bash
VOD_ADS_ENABLED=0        # Ad endpoints return 404
VOD_ADS_FRONTEND=0       # Player does not check for ad placements
```

**Stage 1 — Backend only (internal testing):**
```bash
VOD_ADS_ENABLED=1        # Ad endpoints active
VOD_ADS_FRONTEND=0       # Player still does not render ads
```
- Allows API testing via curl/Playwright without affecting any viewer.
- Creators can configure `ad_supported` mode but viewers see free playback (no ads).

**Stage 2 — Backend + frontend for staff only:**
```bash
VOD_ADS_ENABLED=1
VOD_ADS_FRONTEND=1
VOD_ADS_STAFF_ONLY=1     # Only staff/admin users see ads (for QA)
```
- Frontend checks `ads_enabled` from the video detail response but only renders ad player components if user has staff flag or if `VOD_ADS_STAFF_ONLY=0`.

**Stage 3 — Full rollout:**
```bash
VOD_ADS_ENABLED=1
VOD_ADS_FRONTEND=1
VOD_ADS_STAFF_ONLY=0
```

**Settings implementation:**
```python
# app/core/settings.py
vod_ads_enabled: bool = os.environ.get("VOD_ADS_ENABLED", "0") not in ("0", "false", "False")
vod_ads_frontend: bool = os.environ.get("VOD_ADS_FRONTEND", "0") not in ("0", "false", "False")
vod_ads_staff_only: bool = os.environ.get("VOD_ADS_STAFF_ONLY", "0") not in ("0", "false", "False")
```

### 7.3 Backward Compatibility with Existing Access Modes

Existing access modes (`free`, `ppv`, `subscriber_only`, `subscriber_free`) are completely unaffected:

| Scenario | Behavior |
|----------|----------|
| Existing `free` video | No change. `check_vod_access()` returns `entitled=True, reason="free"`, no ads. |
| Existing `ppv` video | No change. Purchase check unchanged. |
| Existing `subscriber_only` video | No change. Subscription check unchanged. |
| New `ad_supported` video, feature flag OFF | **Caution**: The step 2 behavioral change (`or` -> `and`) means ad_supported videos with `price_cents=0` will NOT be caught as "free" — they will fall through to the purchase check and be treated as not entitled. When the ad feature flag is OFF, the ad_supported branch (step 2.5) should be gated behind the flag. If the flag is OFF and step 2.5 is skipped, a guard must be added to treat `ad_supported` with `price_cents=0` as free to avoid breaking access. |
| New `ad_supported` video, feature flag ON | `check_vod_access()` returns `entitled=True, reason="ad", ads_enabled=True`. Ad placement + impression endpoints active. |

**Video metadata migration**: No schema migration needed. New fields (`ad_config`, `ads_free_for_subscribers`, `ad_revenue_cents`, `ad_impression_count`) are Optional/default-zero. DynamoDB is schemaless — existing items simply lack these attributes, and the code handles `None`/missing with defaults.

### 7.4 Videos Mid-Transition

A creator may change a video's access mode while viewers are actively watching. Scenarios and handling:

| Transition | Impact | Handling |
|-----------|--------|---------|
| `free` -> `ad_supported` | Active viewers have no ad placements loaded | Next play session loads ads. No interruption to current viewers. |
| `ad_supported` -> `free` | Active viewers have ad placements loaded | Ads play out for current session. Next session is ad-free. |
| `ad_supported` -> `ppv` | Active viewers are ad-entitled | Current session continues with ads. Next session requires purchase. Existing ad impressions preserved. |
| `ppv` -> `ad_supported` | Purchasers have perpetual access | Purchasers continue ad-free (owner/purchaser check runs before ad check). Non-purchasers get ad-supported access. |
| `ad_supported` -> `subscriber_only` | Non-subscribers lose access | Current ad-supported session plays out. Next request fails entitlement (must subscribe). |

**Key design principle**: Ad placements are resolved at play-start time. Mode changes take effect on the next playback session, not mid-stream. This avoids the complexity of pushing mode changes to active players via SSE/WebSocket.

### 7.5 Rollback Procedure for Ad Config Changes

**Full feature rollback:**
1. Set `VOD_ADS_ENABLED=0` in `.env.local` (or production env).
2. Restart backend. All ad endpoints return 404.
3. Frontend ad player components check `ads_enabled` from video detail response — since the backend no longer sets `ads_enabled=True`, no ads render.
4. Existing `ad_supported` videos play as free content (no paywall, no ads).
5. Ad impression data in `ad_impressions` table is preserved for analytics/billing reconciliation.
6. Creator ad revenue already credited to billing ledger is NOT reversed (earned revenue stands).

**Per-video ad config rollback (creator action):**
1. Creator changes `access_mode` back to `free` via the video settings UI.
2. Backend clears `ad_config` and sets `ads_free_for_subscribers=False`.
3. `ad_revenue_cents` and `ad_impression_count` remain on the video metadata for historical reporting.

**Emergency ad creative removal:**
1. Admin deletes or replaces the offending creative in `app/static/ads/` (dev) or S3 (production).
2. The `DEV_AD_CREATIVES` list is updated and backend restarted.
3. Active ad placement responses (cached in browser) may still reference the old URL. The player handles 404 creatives gracefully (skips the ad slot, logs error, proceeds to content).

---

## 8. Performance & Capacity Planning

### 8.1 Expected Throughput

| Operation | Estimate |
|-----------|----------|
| Ad placement requests/sec | 50 (one per video play) |
| Ad impression events/sec | 150 (multiple per video: impression + complete/skip per slot) |
| Ad config updates/sec | 0.1 (infrequent) |
| Revenue queries/sec | 1 (creator dashboard) |

### 8.2 Impression Volume Estimates

Detailed capacity modeling based on platform growth projections:

**Scenario A — Early stage (1K DAU):**
| Metric | Value | Calculation |
|--------|-------|-------------|
| Daily video plays | 5,000 | 5 plays/user avg |
| % ad-supported plays | 30% | 1,500 ad-supported plays |
| Avg ad slots per play | 2.5 | 1 pre-roll + 1.5 mid-rolls avg |
| Daily impression events | 3,750 | 1,500 x 2.5 |
| Daily tracking events total | 7,500 | x2 (impression + complete/skip per slot) |
| Peak events/sec | 2 | Assuming 80% of plays in 8-hour window |
| DDB write cost/day | $0.01 | 7,500 x $1.25/million WCU |

**Scenario B — Growth stage (50K DAU):**
| Metric | Value | Calculation |
|--------|-------|-------------|
| Daily video plays | 250,000 | 5 plays/user avg |
| % ad-supported plays | 40% | 100,000 ad-supported plays |
| Avg ad slots per play | 2.5 | |
| Daily impression events | 250,000 | |
| Daily tracking events total | 500,000 | |
| Peak events/sec | 50 | |
| DDB write cost/day | $0.63 | |

**Scenario C — Scale stage (500K DAU):**
| Metric | Value | Calculation |
|--------|-------|-------------|
| Daily video plays | 2,500,000 | |
| % ad-supported plays | 50% | 1,250,000 ad-supported plays |
| Daily tracking events total | 6,250,000 | |
| Peak events/sec | 500 | |
| DDB write cost/day | $7.81 | |
| Monthly DDB cost | ~$235 | |

### 8.3 DDB Capacity

**ad_impressions (on-demand):**
- Write: 1 WCU per event. At 150 events/sec = 150 WCU.
- PK `AD_IMP#{date}` creates one partition per day. At 150 writes/sec per partition, well within 1000 WCU per-partition limit.

**Hot partition mitigation (Scenario C and beyond):**
At 500+ writes/sec, a single date partition approaches the 1000 WCU DynamoDB per-partition limit. Mitigation strategies:

1. **Write sharding**: Change PK to `AD_IMP#{date}#{shard}` where `shard = hash(video_id) % 10`. Distributes writes across 10 partitions per day. Analytics queries must scatter-gather across shards.

2. **Buffered writes**: Batch impression events client-side (buffer for 5 seconds, send batch). Backend writes batch in a `BatchWriteItem` call. Reduces write frequency by 5x at the cost of slight reporting delay.

3. **TTL-based cleanup**: Set `ttl` attribute on impression records (e.g., 90 days). DynamoDB auto-deletes expired items, keeping the table from growing unbounded.

```python
# TTL on impression records
T.ad_impressions.put_item(
    Item={
        "pk": f"AD_IMP#{_date_str(ts)}",
        "sk": f"VIDEO#{video_id}#{user_id}#{ts}",
        # ... other fields ...
        "ttl": ts + (90 * 86400),  # 90 days from now
    }
)
```

**Video metadata updates:**
- `ad_impression_count` and `ad_revenue_cents` use atomic `ADD` operations.
- At high concurrency, many writers update the same video item. DDB handles this with optimistic locking internally, but throughput on a single item is limited to ~1000 writes/sec. For viral videos, batch the counter updates: accumulate in a per-video counter buffer (e.g., Redis or in-memory) and flush to DDB every 10 seconds.

### 8.4 S3 Bandwidth for Creative Serving

**Dev mode**: Creatives served from local filesystem (`app/static/ads/`). No S3 bandwidth concern.

**Production estimates:**
| Creative | File Size | Daily Serves (50K DAU) | Daily Bandwidth |
|----------|-----------|----------------------|-----------------|
| Pre-roll video (15s, 720p) | ~5 MB | 100,000 | 500 GB |
| Mid-roll video (30s, 720p) | ~10 MB | 150,000 | 1.5 TB |
| Overlay image | ~200 KB | 50,000 | 10 GB |
| **Total** | | | **~2 TB/day** |

**Cost at S3 pricing**: ~$180/month for 2 TB/day. CloudFront reduces this significantly via edge caching.

### 8.5 CDN Caching Strategy for Ad Assets

Ad creative assets are ideal CDN candidates (static, cacheable, frequently accessed):

```
Cache hierarchy:
  Browser cache (Cache-Control: max-age=3600)
    → CloudFront edge (TTL: 24h)
      → S3 origin

Cache-Control headers:
  Video creatives: public, max-age=3600, s-maxage=86400
  Image creatives: public, max-age=3600, s-maxage=86400, immutable
  Ad placement JSON: private, no-cache (personalized per user/subscriber status)
  Impression POST: no-store (fire-and-forget, never cached)
```

**Cache invalidation**: When a creative is updated or removed, issue CloudFront invalidation for `/ads/creative/{creative_id}`. The `creative_id` includes a version hash (e.g., `dev_ad_preroll_15s_v2`) so old and new versions coexist during rollout.

**Browser preloading**: The player can preload the next ad creative during content playback:
```typescript
// Preload mid-roll creative 30 seconds before the mid-roll timestamp
useEffect(() => {
  const nextMidRoll = slots.find(s => s.type === "mid_roll" && s.timestamp_seconds > currentTime);
  if (nextMidRoll && currentTime >= nextMidRoll.timestamp_seconds - 30) {
    const link = document.createElement("link");
    link.rel = "preload";
    link.as = "video";
    link.href = nextMidRoll.creative_url;
    document.head.appendChild(link);
  }
}, [currentTime]);
```

### 8.6 Latency Budget

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| GET /ads/placement/{id} | 15ms | 50ms | Single DDB read + subscriber check |
| POST /ads/impression | 10ms | 30ms | Single DDB write (fire-and-forget revenue credit) |
| PATCH /{id}/ad-config | 15ms | 30ms | Single DDB update |
| GET /ads/revenue/{id} | 15ms | 50ms | Single DDB read |
| Ad creative load (CDN) | 50ms | 200ms | CDN edge cache hit |
| Ad creative load (origin) | 200ms | 500ms | S3 origin fetch (cache miss) |
| Pre-roll start-to-play | 100ms | 300ms | Creative load + video decode |

---

## 9. Dependency Analysis

### 9.1 Blocked By

| Ticket | Dependency |
|--------|-----------|
| MON-001 | Access mode infrastructure on VideoMetadataModel |
| MON-005 | Subscription check for ads_free_for_subscribers |

### 9.2 Blocks

No downstream tickets directly blocked.

### 9.3 Integration Points

- **Entitlement cascade** (`app/services/vod_purchase.py`): New `ad_supported` branch. Must not break existing modes.
- **Billing ledger** (`T.billing`): Ad revenue credits use the same `LEDGER` entry pattern.
- **Subscription access** (`app/services/subscription_access.py`): `has_active_subscription()` called for subscriber ad-free check.
- **Video metadata store**: New fields serialized/deserialized alongside existing ones.
- **MON-003** (Creator Earnings): Ad revenue ledger entries aggregated in earnings dashboard.

---

## 10. Acceptance Criteria

### API & Backend (pass/fail)

1. `"ad_supported"` is a valid `access_mode` value accepted by `PATCH /ui/videos/{id}/pricing`. Sending any other value outside the allowed set returns 422.
2. Ad-supported videos are always entitled (`entitled=true`) with `access_reason="ad"` and `ads_enabled=true` for non-subscribers.
3. Creators can configure ad placements via `PATCH /ui/videos/{id}/ad-config`. Non-owners receive 403.
4. Default ad config auto-generates pre-roll only for videos < 10 minutes; pre-roll + mid-rolls every 5 minutes for videos >= 10 minutes.
5. Mid-roll intervals are validated: max 1 per 5 minutes of content, each timestamp must be >= 30s and < (duration - 30s). Out-of-range timestamps are silently dropped.
6. `skip_after_seconds` is clamped to the range [0, 30]. Values outside this range are corrected without error.
7. `GET /ui/ads/placement/{video_id}` returns resolved ad slots with creative URLs for ad-supported videos, and `{"slots": [], "ad_free": true}` for all other access modes.
8. Subscribers with `ads_free_for_subscribers=true` get `ad_free=true` and an empty `slots` array. The subscription check uses `has_active_subscription()`.
9. `POST /ui/ads/impression` with `event_type=impression` writes a record to the `ad_impressions` DDB table with all required fields (`event_id`, `video_id`, `user_id`, `slot_type`, `slot_index`, `creative_id`, `created_at`).
10. `POST /ui/ads/impression` with `event_type=complete` credits the creator's billing ledger with `entry_type="ad_revenue_credit"`, `reason="Ad revenue"`, and `state="settled"`.
11. `POST /ui/ads/impression` with `event_type=skip` does NOT generate a billing ledger entry. The `ad_revenue_cents` on video metadata remains unchanged.
12. `ad_impression_count` on video metadata is atomically incremented on every impression event (impression, complete, or skip).
13. `ad_revenue_cents` on video metadata is atomically incremented only on `complete` events.
14. `GET /ui/ads/revenue/{video_id}` returns `ad_revenue_cents`, `ad_impression_count`, and `estimated_cpm_cents` for the video owner. Non-owners receive 403.
15. Ad placement requests for a video with `access_mode != "ad_supported"` return empty slots regardless of any `ad_config` stored on the video.
16. The `VodAccessResult.to_dict()` output includes `ads_enabled` as a boolean field.
17. Feature flag `VOD_ADS_ENABLED=0` causes all ad endpoints (`/ui/ads/*`, `/ui/videos/{id}/ad-config`) to return 404.

### Frontend & Player (pass/fail)

18. The video player shows a pre-roll ad before content starts. Content playback does not begin until the pre-roll completes or is skipped.
19. The pre-roll displays a "Skip in Xs" countdown that decrements each second. The "Skip Ad" button appears only after the countdown reaches zero.
20. Mid-roll ads pause content at the configured timestamp, play the ad, then resume content at the same position.
21. The player displays an "Ad" badge in the top-left corner during all ad playback phases.
22. If the viewer is a subscriber with `ad_free=true`, the player skips all ad phases and plays content directly.
23. When ads are shown, a "Watch ad-free with a subscription" upsell CTA is displayed below the player.
24. Video gallery cards display a "Free with Ads" badge for videos with `access_mode="ad_supported"`.

### E2E Tests (pass/fail)

25. All E2E tests in `frontend/e2e/ad-supported-video.spec.ts` pass (minimum 8 tests across sections 134-135).
26. All existing E2E tests in the VOD, subscription, and billing test suites continue to pass (no regressions).

---

## 11. Related Tickets

- **MON-001**: VOD pay-per-view (access mode infrastructure)
- **MON-005**: Subscription-gated VOD (subscriber ad-free check)
- **MON-003**: Creator earnings dashboard (will aggregate ad revenue credits)
- **VOD-017**: Video gallery hub (gallery cards show "Free with Ads" badge for ad_supported videos)

---

## 12. Detailed Sequence Diagrams

### 12.1 Creator Configures Ads on a Video

```
Creator Browser                     Backend (FastAPI)                    DynamoDB
    │                                     │                                 │
    │  (1) Creator opens video settings   │                                 │
    │  GET /ui/videos/{video_id}          │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  get_video(video_id)            │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │  video.owner_user_id == user?   │
    │<────────────────────────────────────│                                 │
    │  200 { video details,               │                                 │
    │        access_mode: "free",         │                                 │
    │        ad_config: null }            │                                 │
    │                                     │                                 │
    │  (2) Creator sets access_mode       │                                 │
    │  PATCH /ui/videos/{video_id}/pricing│                                 │
    │  { access_mode: "ad_supported" }    │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  validate regex pattern         │
    │                                     │  "ad_supported" matches ✓       │
    │                                     │  verify ownership               │
    │                                     │  UPDATE video_metadata          │
    │                                     │  SET access_mode=:am            │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │  200 { ok: true }                   │                                 │
    │                                     │                                 │
    │  (3) Creator configures ad slots    │                                 │
    │  PATCH /ui/videos/{video_id}/       │                                 │
    │        ad-config                    │                                 │
    │  { pre_roll: true,                  │                                 │
    │    mid_roll_intervals_seconds:      │                                 │
    │      [300, 600],                    │                                 │
    │    overlay_enabled: false,          │                                 │
    │    skip_after_seconds: 5,           │                                 │
    │    ads_free_for_subscribers: true } │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  verify ownership               │
    │                                     │  validate_ad_config(body,       │
    │                                     │    duration_seconds)            │
    │                                     │    ├─ pre_roll: bool ✓          │
    │                                     │    ├─ mid_rolls: [300,600]      │
    │                                     │    │  max_mid_rolls =           │
    │                                     │    │  duration/300 = 4 ✓        │
    │                                     │    │  each >= 30? ✓             │
    │                                     │    │  each < dur-30? ✓          │
    │                                     │    ├─ skip: clamp(5,0,30)=5 ✓   │
    │                                     │    └─ overlay: bool ✓           │
    │                                     │                                 │
    │                                     │  UPDATE video_metadata          │
    │                                     │  SET ad_config=:ac,             │
    │                                     │      ads_free_for_subscribers   │
    │                                     │      =:afs, updated_at=:ua     │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │  200 { ok: true,                    │                                 │
    │        ad_config: { validated },    │                                 │
    │        ads_free_for_subscribers:    │                                 │
    │          true }                     │                                 │
    │                                     │                                 │
```

### 12.2 Viewer Hits Play: Ad Placement Resolution and Playback

```
Viewer Browser                      Backend (FastAPI)                    DynamoDB
    │                                     │                                 │
    │  (1) Viewer navigates to video page │                                 │
    │  GET /ui/videos/{video_id}          │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  get_video(video_id)            │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │                                 │
    │                                     │  check_vod_access(              │
    │                                     │    user_id, video_id, video)    │
    │                                     │  ├─ owner? No                   │
    │                                     │  ├─ free? No (ad_supported)     │
    │                                     │  ├─ ad_supported? Yes           │
    │                                     │  │  └─ ads_free_for_subs? Yes   │
    │                                     │  │     has_active_subscription()│
    │                                     │  │     ──────────────────────> │
    │                                     │  │     <────── False ────────  │
    │                                     │  │     ads_enabled = True      │
    │                                     │  └─ return entitled=True,      │
    │                                     │       reason="ad",             │
    │                                     │       ads_enabled=True         │
    │<────────────────────────────────────│                                 │
    │  200 { entitled: true,              │                                 │
    │        access_reason: "ad",         │                                 │
    │        ads_enabled: true,           │                                 │
    │        playback_url: "..." }        │                                 │
    │                                     │                                 │
    │  (2) Player fetches ad placements   │                                 │
    │  GET /ui/ads/placement/{video_id}   │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  get_video(video_id)            │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │  access_mode=="ad_supported"? ✓ │
    │                                     │  check subscriber ad-free?      │
    │                                     │    → not subscriber → show ads  │
    │                                     │  ad_config = video.ad_config    │
    │                                     │  resolve creatives:             │
    │                                     │    slot 0: pre_roll, 15s,       │
    │                                     │      dev_ad_preroll_15s         │
    │                                     │    slot 1: mid_roll @300s, 30s, │
    │                                     │      dev_ad_midroll_30s         │
    │                                     │    slot 2: mid_roll @600s, 30s, │
    │                                     │      dev_ad_midroll_30s         │
    │<────────────────────────────────────│                                 │
    │  200 { slots: [                     │                                 │
    │    { type:"pre_roll", ts:0,         │                                 │
    │      duration:15, skip_after:5,     │                                 │
    │      creative_url:"/.../preroll",   │                                 │
    │      slot_index:0 },                │                                 │
    │    { type:"mid_roll", ts:300, ...   │                                 │
    │      slot_index:1 },                │                                 │
    │    { type:"mid_roll", ts:600, ...   │                                 │
    │      slot_index:2 }                 │                                 │
    │  ], ad_free: false }                │                                 │
    │                                     │                                 │
    │  (3) Player enters PRE-ROLL phase   │                                 │
    │  ┌──────────────────────────────┐   │                                 │
    │  │ AdPreRoll component mounts   │   │                                 │
    │  │ Loads creative video URL     │   │                                 │
    │  │ Shows "Ad" badge top-left    │   │                                 │
    │  │ Shows "Skip in 5s" countdown │   │                                 │
    │  │ Content video is PAUSED      │   │                                 │
    │  └──────────────────────────────┘   │                                 │
    │                                     │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { event_type:"impression",         │                                 │
    │    slot_type:"pre_roll",            │                                 │
    │    slot_index:0, ... }              │                                 │
    │────────────────────────────────────>│  (fire-and-forget)              │
    │                                     │────────────────────────────────>│
    │                                     │  write ad_impressions record    │
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │  200 { ok: true, event_id: "..." }  │                                 │
    │                                     │                                 │
    │  ... 5 seconds elapse ...           │                                 │
    │  ┌──────────────────────────────┐   │                                 │
    │  │ "Skip Ad" button appears     │   │                                 │
    │  │ Viewer can skip or wait      │   │                                 │
    │  └──────────────────────────────┘   │                                 │
    │                                     │                                 │
    │  (4a) Viewer watches to completion  │                                 │
    │  ... 15s ad ends naturally ...      │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { event_type:"complete", ... }     │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  record impression + credit     │
    │                                     │  revenue to creator (see 12.4)  │
    │<────────────────────────────────────│                                 │
    │                                     │                                 │
    │  ─── OR ───                         │                                 │
    │                                     │                                 │
    │  (4b) Viewer clicks "Skip Ad"       │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { event_type:"skip", ... }         │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  record impression, NO revenue  │
    │<────────────────────────────────────│                                 │
    │                                     │                                 │
    │  (5) Content playback begins        │                                 │
    │  ┌──────────────────────────────┐   │                                 │
    │  │ HLS player starts content    │   │                                 │
    │  │ Player monitors currentTime  │   │                                 │
    │  │ for mid-roll timestamps      │   │                                 │
    │  └──────────────────────────────┘   │                                 │
    │                                     │                                 │
    │  ... content plays to 300s ...      │                                 │
    │                                     │                                 │
    │  (6) MID-ROLL at 300s               │                                 │
    │  ┌──────────────────────────────┐   │                                 │
    │  │ Content PAUSES at 300s       │   │                                 │
    │  │ MidRollInterstitial mounts   │   │                                 │
    │  │ Shows mid-roll creative      │   │                                 │
    │  │ Shows "Ad" badge + countdown │   │                                 │
    │  └──────────────────────────────┘   │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { event_type:"impression",         │                                 │
    │    slot_type:"mid_roll",            │                                 │
    │    slot_index:1, ... }              │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  (same tracking flow)           │
    │                                     │                                 │
    │  ... mid-roll completes/skipped ... │                                 │
    │                                     │                                 │
    │  (7) Content resumes at 300s        │                                 │
    │  ┌──────────────────────────────┐   │                                 │
    │  │ Content resumes from 300s    │   │                                 │
    │  │ (same position, no seek)     │   │                                 │
    │  └──────────────────────────────┘   │                                 │
    │                                     │                                 │
    │  ... plays to 600s → another        │                                 │
    │      mid-roll (same flow) ...       │                                 │
    │                                     │                                 │
    │  ... content plays to end ...       │                                 │
```

### 12.3 Impression and Completion Tracking Flow

```
Player (JS)                         Backend                             DynamoDB
    │                                     │                                 │
    │  ═══ AD STARTS PLAYING ═══          │                                 │
    │                                     │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { video_id: "v123",                │                                 │
    │    slot_type: "pre_roll",           │                                 │
    │    slot_index: 0,                   │                                 │
    │    creative_id: "dev_preroll_15s",  │                                 │
    │    event_type: "impression" }       │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  (A) Generate event_id          │
    │                                     │  event_id = "adimp_<uuid>"      │
    │                                     │                                 │
    │                                     │  (B) Write impression record    │
    │                                     │  PUT ad_impressions             │
    │                                     │  pk: AD_IMP#2026-05-27          │
    │                                     │  sk: VIDEO#v123#bob#1748380000  │
    │                                     │  event_type: "impression"       │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │                                 │
    │                                     │  (C) Increment counter          │
    │                                     │  UPDATE video_metadata          │
    │                                     │  Key: { video_id: "v123" }      │
    │                                     │  ADD ad_impression_count +1     │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │                                 │
    │                                     │  (D) event_type != "complete"   │
    │                                     │      → skip revenue credit      │
    │                                     │                                 │
    │<────────────────────────────────────│                                 │
    │  200 { ok: true,                    │                                 │
    │        event_id: "adimp_abc123" }   │                                 │
    │                                     │                                 │
    │  ═══ AD FINISHES (viewer watched    │                                 │
    │      entire ad) ═══                 │                                 │
    │                                     │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { ..., event_type: "complete" }    │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  (A) Generate event_id          │
    │                                     │  (B) Write impression record    │
    │                                     │      event_type: "complete"     │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │  (C) Increment counter (+1)     │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │                                     │  (D) event_type == "complete"   │
    │                                     │      → trigger revenue credit   │
    │                                     │      → call _credit_ad_revenue  │
    │                                     │      (see diagram 12.4)         │
    │<────────────────────────────────────│                                 │
    │  200 { ok: true, event_id: "..." }  │                                 │
    │                                     │                                 │
    │  ═══ ALTERNATE: VIEWER SKIPS AD ═══ │                                 │
    │                                     │                                 │
    │  POST /ui/ads/impression            │                                 │
    │  { ..., event_type: "skip" }        │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │  (A-C) Same as above            │
    │                                     │  (D) event_type == "skip"       │
    │                                     │      → NO revenue credit        │
    │                                     │      → counter still increments │
    │<────────────────────────────────────│                                 │
    │  200 { ok: true, event_id: "..." }  │                                 │
```

### 12.4 Revenue Crediting to Creator Ledger

```
_credit_ad_revenue()                Backend (internal)                  DynamoDB
    │                                     │                                 │
    │  Called from record_ad_impression   │                                 │
    │  when event_type == "complete"      │                                 │
    │                                     │                                 │
    │  (1) Fetch video to get creator_id  │                                 │
    │  get_video(video_id)                │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │  video.owner_user_id = "alice"      │                                 │
    │                                     │                                 │
    │  (2) Calculate revenue              │                                 │
    │  cpm = S.ad_cpm_cents (500)         │                                 │
    │  revenue_per_impression =           │                                 │
    │    max(1, cpm // 1000)              │                                 │
    │    = max(1, 500 // 1000)            │                                 │
    │    = max(1, 0) = 1 cent             │                                 │
    │                                     │                                 │
    │  (3) Increment ad_revenue_cents     │                                 │
    │  on video metadata                  │                                 │
    │  UPDATE video_metadata              │                                 │
    │  Key: { video_id: "v123" }          │                                 │
    │  SET ad_revenue_cents =             │                                 │
    │    if_not_exists(ad_revenue_cents,   │                                 │
    │    0) + 1                           │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │                                     │                                 │
    │  (4) Write billing ledger credit    │                                 │
    │  new_ledger_entry(                  │                                 │
    │    key_name="pk",                   │                                 │
    │    key_value="USER#alice",          │                                 │
    │    entry_type="ad_revenue_credit",  │                                 │
    │    amount_cents=1,                  │                                 │
    │    state="settled",                 │                                 │
    │    reason="Ad revenue",             │                                 │
    │    meta={                           │                                 │
    │      video_id: "v123",              │                                 │
    │      event_id: "adimp_abc123",      │                                 │
    │      creative_type:                 │                                 │
    │        "completed_view"             │                                 │
    │    })                               │                                 │
    │                                     │                                 │
    │  PUT billing table                  │                                 │
    │  pk: USER#alice                     │                                 │
    │  sk: LEDGER#<timestamp>#<uuid>      │                                 │
    │  entry_type: ad_revenue_credit      │                                 │
    │  amount_cents: 1                    │                                 │
    │  state: settled                     │                                 │
    │  reason: "Ad revenue"               │                                 │
    │────────────────────────────────────>│                                 │
    │                                     │────────────────────────────────>│
    │                                     │<────────────────────────────────│
    │<────────────────────────────────────│                                 │
    │                                     │                                 │
    │  (5) Return (best-effort, errors    │                                 │
    │      are logged but not surfaced    │                                 │
    │      to the viewer)                 │                                 │
```

---

## 13. Error Handling Matrix

### 13.1 Ad Configuration Errors

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery |
|---------------|-------------|------------|---------------------|----------|
| Non-owner attempts ad config | 403 | `not_your_video` | "You do not have permission to configure ads on this video" | User must own the video |
| Video not found | 404 | `video_not_found` | "Video not found" | Verify video ID |
| Invalid `skip_after_seconds` (> 30 or < 0) | 200 (auto-clamped) | N/A | N/A (silently corrected) | Value clamped to [0, 30] |
| Mid-roll timestamp > video duration | 200 (auto-filtered) | N/A | N/A (silently dropped) | Invalid timestamps removed from list |
| Too many mid-roll timestamps | 200 (auto-truncated) | N/A | N/A (excess dropped) | Excess beyond max_mid_rolls silently dropped |
| Malformed ad_config JSON | 422 | `validation_error` | "Invalid ad configuration format" | Send valid JSON matching `AdConfigIn` schema |
| `access_mode` not set to `ad_supported` | 200 | N/A | Config saved but ads will not serve | Creator must first set access_mode to ad_supported |
| Video has no `duration_seconds` | 200 (uses default 60s) | N/A | N/A | Duration defaults to 60s for config validation |
| Feature flag `VOD_ADS_ENABLED=0` | 404 | `not_found` | "Not found" | Enable feature flag |
| Missing CSRF token (cookie auth) | 403 | `csrf_invalid` | "Invalid CSRF token" | Include `x-csrf-token` header |

### 13.2 Ad Placement Resolution Errors

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery |
|---------------|-------------|------------|---------------------|----------|
| Video not found | 404 | `video_not_found` | "Video not found" | Verify video ID |
| Video is not ad_supported | 200 | N/A | Returns `{ slots: [], ad_free: true }` | Normal behavior for non-ad content |
| Ad creative file missing on disk | 200 (slot omitted) | N/A | N/A | Slot silently excluded from response; player sees fewer ads |
| Ad server timeout (future: real ad network) | 200 (fallback) | N/A | N/A | Return dev placeholder creatives as fallback |
| Subscriber check fails (DDB timeout) | 200 (show ads) | N/A | N/A | Fail-open: show ads if subscription check fails (viewer can report) |
| Concurrent placement requests (same user, same video) | 200 | N/A | N/A | Each request independently resolves placements; no conflict |
| Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Log in |

### 13.3 Impression Tracking Errors

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery |
|---------------|-------------|------------|---------------------|----------|
| Invalid `slot_type` (not pre_roll/mid_roll/overlay) | 422 | `validation_error` | "Invalid slot type" | Use valid slot_type value |
| Invalid `event_type` (not impression/complete/skip) | 422 | `validation_error` | "Invalid event type" | Use valid event_type value |
| `slot_index` < 0 | 422 | `validation_error` | "slot_index must be >= 0" | Use non-negative integer |
| DDB write failure (ad_impressions table) | 200 | N/A | N/A (best-effort) | Logged server-side; impression lost but playback continues |
| DDB counter update failure (video metadata) | 200 | N/A | N/A (best-effort) | Logged server-side; counter may be slightly behind |
| Revenue ledger write failure | 200 | N/A | N/A (best-effort) | Logged server-side; revenue reconciled in periodic batch job |
| Video not found (stale impression) | 200 | N/A | N/A (best-effort) | Impression recorded but revenue credit skipped |
| Rate limit exceeded (> 120/min) | 429 | `rate_limited` | "Too many requests" | Wait and retry |
| Impression for non-ad video | 200 | N/A | Impression recorded but no revenue (video access_mode check in _credit) | No action needed |
| Duplicate impression (same user, same slot, same session) | 200 | N/A | Duplicate recorded (no dedup in MVP) | Future: dedup key prevents double-counting |
| Bot-detected impression | 429 | `bot_detected` | "Request rejected" | N/A (automated traffic blocked) |

### 13.4 Subscriber Ad-Skip Race Condition

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Subscription expires mid-video | Ads not shown (placement resolved at play-start) | Placement is a point-in-time check; no mid-stream re-evaluation |
| Subscription activated mid-video | Ads still shown for current session | Same as above; next play session will be ad-free |
| Subscription check returns stale data | Fail-open: show ads | Better to show ads to a subscriber (minor annoyance) than to skip ads for a non-subscriber (revenue loss) |
| Concurrent subscription cancel + ad placement request | Race condition possible | The `has_active_subscription()` call is eventually consistent; may return True briefly after cancel. Ads may be skipped for one more session. |

### 13.5 Frontend Error Handling

| Error Scenario | Player Behavior | User Experience |
|---------------|----------------|-----------------|
| Ad creative URL returns 404 | Skip the ad slot, proceed to next slot or content | Viewer sees brief loading state, then content plays |
| Ad creative fails to decode (corrupt video) | `<video>` element fires `onerror`, skip slot | Viewer sees brief error, then content plays |
| Ad placement API returns 500 | Player plays content without ads | Viewer gets ad-free experience (revenue loss accepted) |
| Ad placement API times out (> 5s) | Player abandons ad check, plays content | Same as above |
| Impression POST fails (network error) | Retry once after 2s, then abandon | Viewer experience unaffected; impression may be lost |
| Ad creative loads but never fires `onended` | Watchdog timer (duration + 5s) auto-completes | Viewer is not stuck indefinitely on a broken ad |
| Browser ad blocker intercepts creative URL | `<video>` fires `onerror`, skip slot | Viewer gets ad-free experience (detected via `onerror`) |

---

## 14. Operational Runbook

### 14.1 Metrics

The following Prometheus-style metrics should be emitted by the ad service (using the existing `app/metrics.py` pattern):

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ad_impressions_total` | Counter | `slot_type`, `event_type`, `creative_id` | Total ad impression events recorded |
| `ad_completions_total` | Counter | `slot_type`, `creative_id` | Total ads watched to completion |
| `ad_skips_total` | Counter | `slot_type`, `creative_id` | Total ads skipped by viewers |
| `ad_revenue_cents_total` | Counter | `creator_id` | Total ad revenue credited (cents) |
| `ad_placement_requests_total` | Counter | `result` (`served`, `ad_free`, `error`) | Total ad placement resolution requests |
| `ad_load_latency_ms` | Histogram | `slot_type` | Time from placement request to first ad frame rendered (client-reported) |
| `ad_placement_latency_ms` | Histogram | N/A | Server-side latency for GET /ads/placement/{id} |
| `ad_impression_write_latency_ms` | Histogram | N/A | DDB write latency for impression records |
| `ad_creative_load_errors_total` | Counter | `creative_id`, `error_type` | Creative load failures (404, decode error, timeout) |
| `ad_revenue_ledger_failures_total` | Counter | N/A | Failed billing ledger writes for ad revenue |

**Metric emission example:**
```python
from app.metrics import counter, histogram

AD_IMPRESSIONS = counter("ad_impressions_total", "Ad impression events", ["slot_type", "event_type", "creative_id"])
AD_PLACEMENT_LATENCY = histogram("ad_placement_latency_ms", "Ad placement resolution latency")

def record_ad_impression(...):
    AD_IMPRESSIONS.labels(slot_type=slot_type, event_type=event_type, creative_id=creative_id).inc()
    # ...
```

### 14.2 Alerts

| Alert Name | Condition | Severity | Response |
|-----------|-----------|----------|----------|
| `AdCompletionRateLow` | `ad_completions_total / ad_impressions_total < 0.3` over 1h | WARNING | Investigate: are creatives broken? Is skip_after_seconds too low? |
| `AdCompletionRateCritical` | `ad_completions_total / ad_impressions_total < 0.1` over 30m | CRITICAL | Likely creative load failure. Check `ad_creative_load_errors_total`. May need to disable ads. |
| `AdRevenueAnomaly` | `ad_revenue_cents_total` drops > 50% vs same hour yesterday | WARNING | Check if ad traffic dropped or if revenue crediting is broken. |
| `AdRevenueZero` | `ad_revenue_cents_total` = 0 for > 2h during business hours | CRITICAL | Revenue pipeline broken. Check DDB write errors, billing table health. |
| `AdCreativeLoadFailureSpike` | `ad_creative_load_errors_total` > 100 in 5m | WARNING | Creative files may be missing or CDN is down. Check S3/static file availability. |
| `AdPlacementLatencyHigh` | `ad_placement_latency_ms` p99 > 200ms for 10m | WARNING | DDB read latency elevated. Check DDB throttling, table capacity. |
| `AdImpressionWriteFailures` | `ad_revenue_ledger_failures_total` > 50 in 5m | WARNING | DDB write capacity may be exhausted. Check ad_impressions table metrics. |
| `AdFraudVelocityAlert` | Single user_id generates > 1000 impressions in 1h | CRITICAL | Likely bot. Block user_id, investigate session, consider IP ban. |

### 14.3 Debugging Common Issues

#### Blank ad screen (ad overlay visible but no video/image playing)

**Symptoms**: Player shows "Ad" badge and "Skip in Xs" but the creative area is blank/black.

**Diagnosis steps**:
1. Check browser Network tab for creative URL request. Is it 404? 403? Timeout?
2. Check `app/static/ads/` directory — are placeholder files present?
3. Check browser console for `<video>` element errors (codec not supported, CORS blocked).
4. Verify `creative_url` in the placement response points to a valid path.

**Resolution**:
- If files missing: regenerate with `ffmpeg -f lavfi -i color=c=blue:s=1280x720:d=15 -c:v libx264 app/static/ads/placeholder_preroll.mp4`
- If CORS: check that the backend serves static files with correct headers.
- If codec: ensure MP4 uses H.264 baseline profile (broadest browser compatibility).

#### Mid-roll not triggering at configured timestamp

**Symptoms**: Content plays past the mid-roll timestamp without interruption.

**Diagnosis steps**:
1. Check placement response — does it include the mid-roll slot at the expected `timestamp_seconds`?
2. Check frontend `currentTime` monitoring — is the `timeupdate` event handler registered?
3. Check if the mid-roll timestamp was filtered by `validate_ad_config` (timestamp < 30 or >= duration - 30).
4. Check browser console for JavaScript errors in the ad state machine.

**Resolution**:
- If timestamp filtered: adjust the mid-roll to be within [30, duration-30].
- If handler not firing: verify `useEffect` dependency array includes `slots`.
- If already consumed: check if `playedMidRolls` set already contains the slot_index.

#### Revenue mismatch (creator sees less revenue than expected)

**Symptoms**: Creator reports fewer ad revenue credits than their video's impression count suggests.

**Diagnosis steps**:
1. Query `ad_impressions` table: count `event_type="complete"` vs `event_type="impression"` for the video.
2. If completions << impressions: viewers are skipping ads (normal behavior).
3. Query `billing` table for `entry_type="ad_revenue_credit"` entries matching the video_id in meta.
4. Compare `ad_revenue_cents` on video metadata vs sum of billing ledger entries.
5. Check `ad_revenue_ledger_failures_total` metric for write failures.

**Resolution**:
- If ledger entries < metadata counter: some ledger writes failed (best-effort). Run reconciliation script.
- If metadata counter > expected: possible duplicate impressions (no dedup in MVP). This inflates the counter but not actual ledger entries.
- If both are correct but creator expected more: explain CPM math (see section 16).

#### Ads showing for subscribers who should be ad-free

**Symptoms**: A subscriber sees ads on a video with `ads_free_for_subscribers=true`.

**Diagnosis steps**:
1. Verify the subscription is active: `GET /api/creators/{creator_id}/subscriptions?subscriber_id={user_id}`
2. Check `ads_free_for_subscribers` on the video metadata (may not be set).
3. Check if subscription expired between page load and play start.
4. Check `has_active_subscription()` logs for errors.

**Resolution**:
- If subscription is active but flag is false: creator must enable `ads_free_for_subscribers` on the video.
- If subscription check threw an error: fail-open shows ads. Fix the underlying DDB/subscription issue.
- If subscription just expired: expected behavior (subscriber needs to renew).

---

## 15. Ad Network Integration Design

### 15.1 Architecture: Adapter Pattern

The ad placement service uses an adapter pattern that isolates the ad resolution logic behind an interface. The current implementation uses a `DevAdProvider` that returns static placeholder creatives. Future integrations swap in real ad network adapters without changing the placement resolution flow.

```
                  Ad Placement Service
                         │
                         ▼
              ┌─────────────────────┐
              │  AdProvider (ABC)   │
              │                     │
              │  resolve_creatives( │
              │    video_id,        │
              │    user_id,         │
              │    slot_configs     │
              │  ) → List[Creative] │
              └────────┬────────────┘
                       │
          ┌────────────┼────────────────┐
          │            │                │
          ▼            ▼                ▼
   ┌─────────┐  ┌───────────┐  ┌──────────────┐
   │  Dev     │  │  VAST     │  │  Header      │
   │  Provider│  │  Provider │  │  Bidding     │
   │          │  │           │  │  Provider    │
   │ (static  │  │ (parses   │  │              │
   │  files)  │  │  VAST XML)│  │ (Prebid.js   │
   │          │  │           │  │  adapter)    │
   └─────────┘  └───────────┘  └──────────────┘
```

### 15.2 Provider Interface

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class AdCreative:
    """Resolved ad creative ready for player rendering."""
    creative_id: str
    creative_type: str       # "video" | "image"
    url: str                 # Direct URL to the creative asset
    duration_seconds: int    # Expected play duration
    title: str               # Human-readable title (for accessibility)
    click_through_url: Optional[str] = None  # Advertiser landing page
    tracking_urls: Optional[Dict[str, str]] = None  # {event: url} for 3rd-party tracking


class AdProvider(ABC):
    """Abstract base class for ad creative resolution."""

    @abstractmethod
    def resolve_creatives(
        self,
        *,
        video_id: str,
        user_id: str,
        slot_configs: List[Dict[str, Any]],
        targeting: Optional[Dict[str, Any]] = None,
    ) -> List[AdCreative]:
        """Resolve ad creatives for the given slot configurations.

        Args:
            video_id: The video being played (for content-category targeting).
            user_id: The viewer (for audience targeting, if consent given).
            slot_configs: List of slot dicts with keys:
                type ("pre_roll"|"mid_roll"|"overlay"),
                timestamp_seconds, duration_seconds.
            targeting: Optional targeting data (content category, viewer
                demographics, device type). None in MVP.

        Returns:
            List of AdCreative objects, one per slot. If a slot cannot be
            filled, it is omitted (player skips that slot).
        """
        ...

    @abstractmethod
    def report_event(
        self,
        *,
        creative_id: str,
        event_type: str,
        metadata: Dict[str, Any],
    ) -> None:
        """Report an impression/completion/skip event to the ad network.

        Called alongside the internal impression tracking. For third-party
        ad networks, this fires tracking pixels or VAST event URLs.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging and metrics."""
        ...
```

### 15.3 Dev Provider Implementation

```python
class DevAdProvider(AdProvider):
    """Development ad provider using static placeholder creatives."""

    @property
    def name(self) -> str:
        return "dev"

    def resolve_creatives(
        self,
        *,
        video_id: str,
        user_id: str,
        slot_configs: List[Dict[str, Any]],
        targeting: Optional[Dict[str, Any]] = None,
    ) -> List[AdCreative]:
        creatives = []
        for slot in slot_configs:
            slot_type = slot["type"]
            if slot_type in ("pre_roll", "mid_roll"):
                idx = 0 if slot_type == "pre_roll" else 1
                dev = DEV_AD_CREATIVES[idx]
            elif slot_type == "overlay":
                dev = DEV_AD_CREATIVES[2]
            else:
                continue
            creatives.append(AdCreative(
                creative_id=dev["creative_id"],
                creative_type=dev["type"],
                url=dev["url"],
                duration_seconds=dev["duration_seconds"],
                title=dev["title"],
            ))
        return creatives

    def report_event(self, *, creative_id: str, event_type: str, metadata: Dict[str, Any]) -> None:
        logger.debug("dev_ad_event", extra={"creative_id": creative_id, "event_type": event_type})
```

### 15.4 VAST/VPAID Compatibility (Future)

VAST (Video Ad Serving Template) is the IAB standard for video ad serving. A `VASTAdProvider` would:

1. **Request VAST XML** from the ad server with targeting parameters.
2. **Parse VAST XML** to extract `MediaFile` URLs, tracking events, click-through URLs.
3. **Select best media file** based on viewer's device/bandwidth (VAST XML contains multiple renditions).
4. **Map VAST tracking events** to our impression system:

| VAST Event | Our Event | Notes |
|-----------|-----------|-------|
| `impression` | `impression` | Fired when ad starts |
| `complete` | `complete` | Fired when ad plays to 100% |
| `skip` | `skip` | Fired when viewer clicks skip |
| `firstQuartile` | (not tracked in MVP) | 25% progress |
| `midpoint` | (not tracked in MVP) | 50% progress |
| `thirdQuartile` | (not tracked in MVP) | 75% progress |
| `clickThrough` | (not tracked in MVP) | Viewer clicks ad |

**VAST XML parsing (sketch):**
```python
class VASTAdProvider(AdProvider):
    def __init__(self, vast_endpoint: str, timeout_seconds: float = 3.0):
        self.vast_endpoint = vast_endpoint
        self.timeout = timeout_seconds

    def resolve_creatives(self, *, video_id, user_id, slot_configs, targeting=None):
        creatives = []
        for slot in slot_configs:
            try:
                resp = httpx.get(
                    self.vast_endpoint,
                    params={"slot_type": slot["type"], "content_id": video_id},
                    timeout=self.timeout,
                )
                vast_xml = resp.text
                creative = self._parse_vast(vast_xml)
                if creative:
                    creatives.append(creative)
            except httpx.TimeoutException:
                logger.warning("vast_timeout", extra={"slot_type": slot["type"]})
                # Fallback: skip this slot (no ad for this break)
        return creatives
```

### 15.5 Waterfall Bidding (Future)

Waterfall bidding tries multiple ad providers in priority order until one fills the slot:

```
Slot request
    │
    ▼
┌─────────────────┐
│ Provider A       │── fill? ── Yes → use creative
│ (highest CPM)   │
└────────┬────────┘
         │ No fill
         ▼
┌─────────────────┐
│ Provider B       │── fill? ── Yes → use creative
│ (medium CPM)    │
└────────┬────────┘
         │ No fill
         ▼
┌─────────────────┐
│ Dev Provider     │── always fills (fallback placeholder)
│ (zero CPM)      │
└─────────────────┘
```

**Configuration:**
```python
AD_PROVIDER_WATERFALL = [
    VASTAdProvider(endpoint="https://ads.premium-network.com/vast", timeout_seconds=2.0),
    VASTAdProvider(endpoint="https://ads.backup-network.com/vast", timeout_seconds=1.5),
    DevAdProvider(),  # Always-available fallback
]
```

### 15.6 Header Bidding Placeholder (Future)

Header bidding (Prebid.js) runs client-side auctions before requesting ad creatives. The integration point is a `HeaderBiddingProvider` that wraps Prebid.js:

```typescript
// Frontend: Prebid.js integration point (future)
interface PrebidAdUnit {
  code: string;           // Slot identifier
  mediaTypes: {
    video: {
      playerSize: [number, number];
      mimes: string[];
      protocols: number[];
    };
  };
  bids: Array<{
    bidder: string;       // e.g., "appnexus", "rubicon"
    params: Record<string, unknown>;
  }>;
}

// The HeaderBiddingProvider would:
// 1. Initialize Prebid.js with ad unit configs
// 2. Request bids from configured demand partners
// 3. Select winning bid
// 4. Return winning creative URL to the ad player
// 5. Fire billing/tracking events via the winning demand partner's API
```

The adapter pattern ensures this integration requires zero changes to the core ad placement service, the impression tracking pipeline, or the revenue crediting logic.

---

## 16. Revenue Model Details

### 16.1 CPM Calculation

CPM (Cost Per Mille) is the revenue earned per 1,000 completed ad impressions.

**Default CPM**: $5.00 (500 cents) -- configurable via `S.ad_cpm_cents`.

**Revenue per completed impression:**
```
revenue_per_impression = cpm_cents / 1000
                       = 500 / 1000
                       = 0.5 cents per impression
```

Since the system uses integer cents, the MVP rounds up: `max(1, cpm // 1000)` = 1 cent per completed impression. This means the effective CPM in MVP is $10.00 (1 cent x 1000). A future enhancement should use sub-cent tracking (microcents or fractional accumulation).

### 16.2 Revenue Examples

| Scenario | Monthly Views | Completion Rate | Completed Impressions | Avg Slots/Video | Revenue (MVP) | Revenue (True CPM) |
|----------|--------------|----------------|-----------------------|-----------------|---------------|---------------------|
| Small creator | 1,000 | 60% | 600 | 1.5 | $9.00 | $4.50 |
| Medium creator | 10,000 | 55% | 5,500 | 2.0 | $110.00 | $55.00 |
| Large creator | 100,000 | 50% | 50,000 | 2.5 | $1,250.00 | $625.00 |
| Viral video | 1,000,000 | 45% | 450,000 | 2.0 | $9,000.00 | $4,500.00 |

**Notes:**
- "Completed Impressions" = views x completion rate x avg slots per video.
- "Revenue (MVP)" uses 1 cent/impression (the `max(1, ...)` floor).
- "Revenue (True CPM)" uses 0.5 cents/impression ($5 CPM).
- Multi-slot videos (pre-roll + mid-rolls) multiply revenue per view.

### 16.3 Platform Fee Breakdown

The platform takes a percentage of gross ad revenue before crediting the creator:

| Component | Percentage | Destination | Notes |
|-----------|-----------|-------------|-------|
| Creator share | 70% | Creator's billing ledger | Credited per-impression as `ad_revenue_credit` |
| Platform fee | 25% | Platform revenue account | Covers infrastructure, ad serving, support |
| Payment processing reserve | 5% | Held for payout fees | Covers Stripe/PayPal transfer fees at payout |

**MVP simplification**: In MVP, 100% is credited to the creator (no platform fee split). The platform fee split is deferred to production when real ad networks provide actual revenue. The `_credit_ad_revenue` function can be updated to apply the split:

```python
CREATOR_SHARE_PERCENT = 70  # Configurable

def _credit_ad_revenue(*, video_id, event_id, ts):
    # ... calculate gross revenue ...
    creator_revenue = gross_revenue * CREATOR_SHARE_PERCENT // 100
    platform_revenue = gross_revenue - creator_revenue
    # Credit creator
    new_ledger_entry(key_value=user_pk(video.owner_user_id), amount_cents=creator_revenue, ...)
    # Credit platform
    new_ledger_entry(key_value=user_pk("PLATFORM"), amount_cents=platform_revenue, ...)
```

### 16.4 Minimum Payout Thresholds

Ad revenue accumulates in the creator's billing ledger. Payouts are triggered when the balance exceeds a minimum threshold:

| Payout Method | Minimum Threshold | Payout Frequency | Processing Fee |
|---------------|------------------|-----------------|----------------|
| Stripe Connect | $25.00 | Weekly (if threshold met) | 0.25% + $0.25 |
| PayPal | $50.00 | Bi-weekly | 2% (capped at $1.00) |
| Bank Transfer (ACH) | $100.00 | Monthly | $0.00 |

**Threshold check query:**
```python
def get_ad_revenue_balance(creator_id: str) -> int:
    """Sum all ad_revenue_credit entries minus ad_revenue_payout entries."""
    credits = query_ledger_entries(
        user_id=creator_id,
        entry_type="ad_revenue_credit",
        state="settled",
    )
    payouts = query_ledger_entries(
        user_id=creator_id,
        entry_type="ad_revenue_payout",
        state="settled",
    )
    return sum(e.amount_cents for e in credits) - sum(e.amount_cents for e in payouts)
```

### 16.5 Revenue Reporting in Creator Earnings Dashboard

Integration with MON-003 (Creator Earnings Dashboard):

**New dashboard sections:**
- "Ad Revenue" card showing total ad revenue for the selected period.
- Per-video ad revenue breakdown table (sortable by revenue, impressions, completion rate).
- Revenue trend chart (daily ad revenue over 30 days).

**API extension for MON-003:**
```python
class CreatorEarningsOut(BaseModel):
    # ... existing fields from MON-003 ...
    ad_revenue_cents: int = 0           # Total ad revenue for period
    ad_impression_count: int = 0        # Total impressions for period
    ad_completion_count: int = 0        # Total completions for period
    ad_completion_rate: float = 0.0     # completions / impressions
    ad_revenue_by_video: List[VideoAdRevenueOut] = []  # Per-video breakdown

class VideoAdRevenueOut(BaseModel):
    video_id: str
    video_title: str
    ad_revenue_cents: int
    ad_impression_count: int
    ad_completion_rate: float
```

### 16.6 Currency Handling

All monetary values in the ad system use integer cents (USD):
- `ad_revenue_cents`: accumulated on video metadata
- `amount_cents`: in billing ledger entries
- `ad_cpm_cents`: CPM rate in settings
- `estimated_cpm_cents`: in revenue summary response

**Multi-currency considerations (future):**
- All internal accounting is in USD cents.
- If ad networks report revenue in other currencies, convert to USD at the exchange rate at time of crediting.
- Store `currency: "USD"` on ledger entries for forward compatibility.
- Display currency is determined by the creator's locale preference (handled by the frontend earnings dashboard).

---

## 17. Frontend Player Integration Details

### 17.1 TypeScript Component Interfaces

```typescript
/** Props for the ad overlay container that wraps the video player */
export interface AdOverlayProps {
  /** The resolved ad placement data from GET /ads/placement/{video_id} */
  placement: AdPlacementResponse;
  /** The video element ref for controlling content playback */
  videoRef: React.RefObject<HTMLVideoElement>;
  /** Called when all pre-roll ads complete (content can start) */
  onPreRollComplete: () => void;
  /** Called when a mid-roll ad completes (content resumes) */
  onMidRollComplete: (slotIndex: number) => void;
  /** Video ID for impression tracking */
  videoId: string;
}

/** Props for the pre-roll ad player component */
export interface PreRollPlayerProps {
  /** The ad slot to play */
  slot: AdSlot;
  /** Called when the ad finishes naturally */
  onComplete: () => void;
  /** Called when the viewer clicks "Skip Ad" */
  onSkip: () => void;
  /** Video ID for impression tracking */
  videoId: string;
}

/** Props for the mid-roll interstitial component */
export interface MidRollInterstitialProps {
  /** The mid-roll ad slot to play */
  slot: AdSlot;
  /** Called when the mid-roll ad finishes or is skipped */
  onFinish: (skipped: boolean) => void;
  /** Video ID for impression tracking */
  videoId: string;
  /** The content timestamp where playback will resume */
  resumeTimestamp: number;
}

/** Props for the skip button component */
export interface SkipButtonProps {
  /** Seconds until skip is allowed (0 = skip allowed now) */
  countdown: number;
  /** Called when viewer clicks skip (only fires when countdown <= 0) */
  onSkip: () => void;
  /** Whether the button is in "waiting" mode (shows countdown) or "ready" mode */
  canSkip: boolean;
}

/** Props for the overlay banner ad component */
export interface OverlayBannerProps {
  /** The overlay ad slot */
  slot: AdSlot;
  /** Called when the overlay duration expires or viewer dismisses it */
  onDismiss: () => void;
  /** Video ID for impression tracking */
  videoId: string;
}
```

### 17.2 Ad Playback State Machine

The ad player follows a deterministic state machine to manage transitions between content and ad phases:

```
                              ┌──────────────────┐
                              │                  │
                   ┌─────────>│    IDLE          │
                   │          │ (no ads / done)  │
                   │          └────────┬─────────┘
                   │                   │
                   │                   │ placement.slots.length > 0
                   │                   │ && has pre_roll slot
                   │                   ▼
                   │          ┌──────────────────┐
                   │          │                  │
                   │          │  PRE_ROLL_LOADING│ ─── creative URL fetch
                   │          │                  │     starts
                   │          └────────┬─────────┘
                   │                   │
                   │                   │ <video> canplay event
                   │                   ▼
                   │          ┌──────────────────┐
                   │          │                  │
                   │          │  PRE_ROLL_PLAYING│ ─── impression event fired
                   │          │                  │     countdown ticking
                   │          └────┬────────┬────┘
                   │               │        │
                   │    ad ended   │        │ skip clicked
                   │    naturally  │        │ (after countdown)
                   │               ▼        ▼
                   │          ┌──────────────────┐
                   │          │                  │
                   │          │  PRE_ROLL_DONE   │ ─── complete/skip event
                   │          │                  │     fired
                   │          └────────┬─────────┘
                   │                   │
                   │                   │ transition to content
                   │                   ▼
                   │          ┌──────────────────┐
                   │          │                  │
                   │          │  CONTENT_PLAYING │ ─── content video plays
                   │          │                  │     currentTime monitored
                   │          └────┬────────┬────┘
                   │               │        │
                   │  content ends │        │ currentTime hits
                   │               │        │ mid-roll timestamp
                   │               ▼        ▼
                   │          ┌────────┐ ┌──────────────────┐
                   │          │  DONE  │ │                  │
                   └──────────┤        │ │ MID_ROLL_LOADING │
                              └────────┘ │                  │
                                         └────────┬─────────┘
                                                  │
                                                  │ canplay
                                                  ▼
                                         ┌──────────────────┐
                                         │                  │
                                         │ MID_ROLL_PLAYING │
                                         │                  │
                                         └────┬────────┬────┘
                                              │        │
                                   ad ended   │        │ skip
                                              ▼        ▼
                                         ┌──────────────────┐
                                         │                  │
                                         │  MID_ROLL_DONE   │
                                         │                  │
                                         └────────┬─────────┘
                                                  │
                                                  │ resume content
                                                  │ at saved timestamp
                                                  ▼
                                         ┌──────────────────┐
                                         │ CONTENT_PLAYING  │
                                         │ (loop back)      │
                                         └──────────────────┘
```

**State machine implementation:**
```typescript
type AdPlaybackState =
  | "IDLE"
  | "PRE_ROLL_LOADING"
  | "PRE_ROLL_PLAYING"
  | "PRE_ROLL_DONE"
  | "CONTENT_PLAYING"
  | "MID_ROLL_LOADING"
  | "MID_ROLL_PLAYING"
  | "MID_ROLL_DONE"
  | "DONE";

interface AdPlaybackContext {
  state: AdPlaybackState;
  currentSlotIndex: number | null;
  playedSlots: Set<number>;       // Slot indices already played
  contentResumeTime: number;      // Content timestamp to resume after mid-roll
  skipCountdown: number;          // Seconds until skip is allowed
}

function adPlaybackReducer(
  ctx: AdPlaybackContext,
  action:
    | { type: "CREATIVE_LOADED" }
    | { type: "AD_ENDED" }
    | { type: "SKIP_CLICKED" }
    | { type: "CONTENT_TIME_UPDATE"; currentTime: number }
    | { type: "CONTENT_ENDED" }
    | { type: "COUNTDOWN_TICK" }
): AdPlaybackContext {
  switch (ctx.state) {
    case "IDLE":
      // No transitions from IDLE (terminal state or initial)
      return ctx;

    case "PRE_ROLL_LOADING":
      if (action.type === "CREATIVE_LOADED") {
        return { ...ctx, state: "PRE_ROLL_PLAYING" };
      }
      return ctx;

    case "PRE_ROLL_PLAYING":
      if (action.type === "AD_ENDED") {
        return { ...ctx, state: "PRE_ROLL_DONE" };
      }
      if (action.type === "SKIP_CLICKED" && ctx.skipCountdown <= 0) {
        return { ...ctx, state: "PRE_ROLL_DONE" };
      }
      if (action.type === "COUNTDOWN_TICK") {
        return { ...ctx, skipCountdown: Math.max(0, ctx.skipCountdown - 1) };
      }
      return ctx;

    case "PRE_ROLL_DONE":
      return {
        ...ctx,
        state: "CONTENT_PLAYING",
        playedSlots: new Set([...ctx.playedSlots, ctx.currentSlotIndex!]),
        currentSlotIndex: null,
      };

    // ... MID_ROLL states follow same pattern ...

    default:
      return ctx;
  }
}
```

### 17.3 Keyboard Handling

During ad playback, keyboard shortcuts must be intercepted to prevent viewers from bypassing the non-skippable period:

| Key | During Non-Skippable Ad | During Skippable Ad | During Content |
|-----|------------------------|--------------------|----|
| Space | Blocked (no pause) | Triggers skip | Play/Pause |
| Enter | Blocked | Triggers skip | N/A |
| Arrow Right | Blocked (no seek) | Blocked (no seek) | Seek +10s |
| Arrow Left | Blocked (no seek) | Blocked (no seek) | Seek -10s |
| Escape | Blocked | Triggers skip | Exit fullscreen |
| `F` | Allowed (fullscreen toggle) | Allowed | Allowed |
| `M` | Allowed (mute toggle) | Allowed | Allowed |

```typescript
useEffect(() => {
  if (state !== "PRE_ROLL_PLAYING" && state !== "MID_ROLL_PLAYING") return;

  const handler = (e: KeyboardEvent) => {
    const blocked = ["Space", "ArrowRight", "ArrowLeft", "Enter"];
    if (blocked.includes(e.code)) {
      e.preventDefault();
      e.stopPropagation();

      // If skip is allowed and viewer presses Space/Enter, treat as skip
      if (canSkip && (e.code === "Space" || e.code === "Enter")) {
        dispatch({ type: "SKIP_CLICKED" });
      }
    }
  };

  document.addEventListener("keydown", handler, { capture: true });
  return () => document.removeEventListener("keydown", handler, { capture: true });
}, [state, canSkip]);
```

### 17.4 Accessibility

**Screen reader announcements for ad breaks:**

```typescript
// Announce ad break start
useEffect(() => {
  if (state === "PRE_ROLL_PLAYING" || state === "MID_ROLL_PLAYING") {
    const msg = state.startsWith("PRE_ROLL")
      ? `Advertisement playing. ${skipCountdown > 0 ? `You can skip in ${skipCountdown} seconds.` : "Press Enter or Space to skip."}`
      : `Mid-roll advertisement. Content will resume after this ad.`;

    announceToScreenReader(msg);
  }
}, [state, skipCountdown]);

function announceToScreenReader(message: string) {
  const el = document.getElementById("ad-live-region");
  if (el) el.textContent = message;
}
```

**ARIA attributes:**
```tsx
{/* Live region for screen reader announcements */}
<div id="ad-live-region" role="status" aria-live="polite" className="sr-only" />

{/* Skip button */}
<Button
  onClick={onSkip}
  disabled={!canSkip}
  aria-label={canSkip ? "Skip this advertisement" : `Skip available in ${countdown} seconds`}
  aria-disabled={!canSkip}
>
  {canSkip ? "Skip Ad" : `Skip in ${countdown}s`}
</Button>

{/* Ad badge */}
<Badge aria-label="Advertisement" role="status">
  Ad
</Badge>

{/* Ad video element */}
<video
  src={slot.creative_url}
  autoPlay
  aria-label={`Advertisement: ${slot.creative_id}`}
  onEnded={handleComplete}
/>
```

**Focus management:**
- When pre-roll starts, focus moves to the ad container (so keyboard events are captured).
- When ad completes, focus moves back to the content player controls.
- The "Skip Ad" button receives focus as soon as it becomes interactive (countdown reaches 0).

**Reduced motion preference:**
```typescript
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// If reduced motion is preferred, skip animated countdown
// and show a static "Skip Ad" button immediately (but still enforce the delay server-side)
```

### 17.5 Ad Player Error Recovery

```typescript
function AdVideoPlayer({ slot, onComplete, onSkip, videoId }: PreRollPlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const watchdogRef = useRef<number>();

  // Watchdog: if ad doesn't complete within expected duration + 5s buffer, auto-skip
  useEffect(() => {
    watchdogRef.current = window.setTimeout(() => {
      console.warn("Ad watchdog triggered: auto-completing stuck ad");
      recordAdImpression({ videoId, slotType: slot.type, slotIndex: slot.slot_index,
        creativeId: slot.creative_id, eventType: "complete" });
      onComplete();
    }, (slot.duration_seconds + 5) * 1000);

    return () => clearTimeout(watchdogRef.current);
  }, []);

  const handleError = () => {
    console.error("Ad creative load/playback error");
    clearTimeout(watchdogRef.current);
    // Skip broken ad, proceed to content
    onSkip();
  };

  return (
    <video
      ref={videoRef}
      src={slot.creative_url}
      autoPlay
      onEnded={() => { clearTimeout(watchdogRef.current); onComplete(); }}
      onError={handleError}
    />
  );
}
```
