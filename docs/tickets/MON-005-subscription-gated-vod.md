# MON-005: Subscription-Gated VOD — Subscriber Access to Creator Video Content

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 4-6 days  
**Dependencies**: MON-001 (VOD pay-per-view)

---

## 1. Overview & Motivation

### The Gap

After MON-001, the VOD system supports individual video purchases through pay-per-view. However, the subscription system (`app/services/subscription_access.py`, `app/routers/subscription_server.py`) and the VOD system are **completely disconnected**. A viewer who pays $9.99/month for a creator's subscription still has to pay individually for every video that creator uploads.

The subscription access service has `has_active_subscription()` (subscription_access.py, line 55) which checks whether a subscriber has an active subscription to a given creator, and `can_access_creator()` (line 72) which gates catalog access. But these are never called in the VOD playback path. The entitlement check in MON-001 (`check_vod_entitlement()`) only looks at the `vod_entitlements` table for explicit purchase records — it has no awareness of subscription status.

Additionally, creators need flexibility in how subscriptions interact with their video catalog:
- Some videos should be **subscriber-only** (no individual purchase option)
- Some should be **subscriber-free** (subscribers watch free, non-subscribers can still buy)
- Some should remain **pay-per-view only** (subscription does not help)
- Some should be **free** for everyone

The `access_mode` field added in MON-001 on `VideoMetadataModel` provides the schema for this, but no code implements the subscription-aware logic.

### Why This Is Needed

1. **Subscription value proposition**: The primary reason viewers subscribe is to access content. If subscriptions do not unlock VOD, the subscription product is significantly less attractive.

2. **Creator flexibility**: Different creators have different business models. A fitness instructor might make all workout videos subscriber-only. A musician might offer subscribers free access to back-catalog while selling new releases individually. The `access_mode` system supports all these models.

3. **Entitlement cascade**: The correct entitlement check order — (1) already purchased, (2) active subscription, (3) show purchase/subscribe dialog — is standard in the creator economy and expected by both creators and viewers.

### Architecture After This Change

```
Viewer requests video playback
            │
            ▼
    ┌───────────────────┐
    │ Is viewer the      │──── Yes ──→ PLAY (always entitled)
    │ video owner?       │
    └───────┬────────────┘
            │ No
            ▼
    ┌───────────────────┐
    │ Is video free?     │──── Yes ──→ PLAY (no purchase needed)
    │ (price=0 or null   │
    │  or access_mode=   │
    │  free/null)        │
    └───────┬────────────┘
            │ No
            ▼
    ┌───────────────────┐
    │ Already purchased? │──── Yes ──→ PLAY (explicit entitlement)
    │ (vod_entitlements  │
    │  table lookup)     │
    └───────┬────────────┘
            │ No
            ▼
    ┌───────────────────┐
    │ Active subscription│
    │ to this creator?   │
    │                    │
    │ access_mode check: │
    │ ├─ subscriber_only │──── Yes ──→ PLAY (subscription grants access)
    │ ├─ subscriber_free │──── Yes ──→ PLAY (subscription grants access)
    │ └─ ppv             │──── No  ──→ (subscription does NOT help)
    └───────┬────────────┘
            │ No subscription (or ppv mode)
            ▼
    ┌───────────────────┐
    │ access_mode?       │
    │                    │
    │ subscriber_only ───│──→ SHOW "Subscribe to watch" CTA
    │                    │
    │ ppv ───────────────│──→ SHOW purchase dialog
    │                    │
    │ subscriber_free ───│──→ SHOW purchase dialog + "Subscribe for free access" upsell
    └────────────────────┘
```

### Detailed Data Flow per Endpoint

```
── GET /ui/videos/{video_id} (subscription-aware) ───────────────────────

Browser                           Backend (vod.py)                      DDB
  │                                  │                                    │
  │── GET /ui/videos/{id} ──────────>│                                    │
  │   (cookies: ui_session,          │── get_video(id) ──────────────────>│
  │    ui_access_token, ui_csrf)     │<── VideoMetadataModel ─────────────│
  │                                  │                                    │
  │                                  │── check_vod_entitlement ──────────>│
  │                                  │   PK=USER#{user_id}               │
  │                                  │   SK=VIDEO#{video_id}             │
  │                                  │<── Item or None ──────────────────│
  │                                  │                                    │
  │                                  │ [if not entitled & access_mode     │
  │                                  │  in (subscriber_only,              │
  │                                  │  subscriber_free)]                 │
  │                                  │                                    │
  │                                  │── has_active_subscription ────────>│
  │                                  │   PK=SUBSCRIBER#{user_id}         │
  │                                  │   SK begins_with("SUB#")          │
  │                                  │   filter: creator_id == owner_id  │
  │                                  │<── True/False ────────────────────│
  │                                  │                                    │
  │                                  │ [if subscription grants access]    │
  │                                  │── _record_subscription_access ───>│
  │                                  │   PK=USER#{user_id}               │
  │                                  │   SK=VIDEO#{video_id}             │
  │                                  │   source="subscription"           │
  │                                  │   ConditionExpression:             │
  │                                  │     attribute_not_exists(pk)       │
  │                                  │<── ok (or condition fail) ────────│
  │                                  │                                    │
  │<── 200 { entitled, access_reason,│                                    │
  │     subscription_available,      │                                    │
  │     purchase_available,          │                                    │
  │     subscription_upsell,         │                                    │
  │     playback_url (if entitled) } │                                    │

── GET /ui/videos/by-creator/{creator_id} (batch with subscription) ─────

Browser                           Backend (vod.py)                      DDB
  │                                  │                                    │
  │── GET /ui/videos/by-creator/X -->│                                    │
  │                                  │── list_videos_by_creator_public ──>│
  │                                  │   GSI: ByOwnerCreatedAt            │
  │                                  │   PK=creator_id                   │
  │                                  │<── {items, cursor} ──────────────│
  │                                  │                                    │
  │                                  │── has_active_subscription ────────>│
  │                                  │   (SINGLE call for all videos)     │
  │                                  │<── True/False ────────────────────│
  │                                  │                                    │
  │                                  │── _batch_check_entitlements ──────>│
  │                                  │   batch_get_item (up to 100 keys) │
  │                                  │<── Set[purchased_video_ids] ──────│
  │                                  │                                    │
  │                                  │ [build per-video access flags]     │
  │<── 200 { videos: [...],          │                                    │
  │     viewer_has_subscription }    │                                    │

── POST /ui/videos/{video_id}/purchase (subscription guard) ─────────────

Browser                           Backend (vod.py)                      DDB
  │                                  │                                    │
  │── POST /videos/{id}/purchase ──>│                                    │
  │   {payment_method_id}            │── get_video(id) ──────────────────>│
  │                                  │<── video ─────────────────────────│
  │                                  │                                    │
  │                                  │ [if access_mode == subscriber_only]│
  │                                  │<── 403 "subscriber only" ──────────│
  │                                  │                                    │
  │                                  │ [if access_mode == subscriber_free]│
  │                                  │── has_active_subscription ────────>│
  │                                  │<── True ──────────────────────────│
  │                                  │<── 400 "already have access" ──────│
  │                                  │                                    │
  │                                  │ [otherwise: proceed with purchase] │
```

### DDB Partition Key Distribution Diagram

```
vod_entitlements table — key distribution after MON-005:

  PK (HASH)                   SK (RANGE)              source        amount_cents
  ─────────────────────────────────────────────────────────────────────────────
  USER#alice123                VIDEO#vid_001           purchase      999
  USER#alice123                VIDEO#vid_002           subscription  0
  USER#alice123                VIDEO#vid_003           purchase      1499
  USER#bob456                  VIDEO#vid_001           subscription  0
  USER#bob456                  VIDEO#vid_004           purchase      499
  USER#charlie789              VIDEO#vid_002           subscription  0
  USER#charlie789              VIDEO#vid_005           subscription  0

  ByVideo GSI:
  video_id (HASH)              purchased_at (RANGE)    user_id
  ─────────────────────────────────────────────────────────────
  vid_001                      1716700000              alice123      (purchase)
  vid_001                      1716700100              bob456        (subscription)
  vid_002                      1716700200              alice123      (subscription)
  vid_002                      1716700300              charlie789    (subscription)

  ByCreatorPurchasedAt GSI:
  creator_id (HASH)            purchased_at (RANGE)    user_id       video_id
  ─────────────────────────────────────────────────────────────────────────────
  creator_A                    1716700000              alice123      vid_001
  creator_A                    1716700100              bob456        vid_001
  creator_A                    1716700200              alice123      vid_002
  creator_B                    1716700300              charlie789    vid_005

  subscriptions table — key patterns queried by MON-005:

  PK (HASH)                    SK (RANGE)              Fields
  ─────────────────────────────────────────────────────────────────────────────
  SUBSCRIBER#bob456            SUB#sub_001             creator_id=creator_A, status=active
  SUBSCRIBER#bob456            SUB#sub_002             creator_id=creator_B, status=cancelled
  SUBSCRIBER#charlie789        SUB#sub_003             creator_id=creator_A, status=trialing
  PLAN#plan_001                META                    creator_id=creator_A, price_cents=999
  CREATOR#creator_A            PLAN#plan_001           (creator's plans index)
  CREATOR#creator_A            SETTINGS                require_subscription=True
```

### Entitlement Cascade State Machine

```
                    ┌──────────────┐
                    │  VIDEO       │
                    │  REQUESTED   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
              Yes   │  Is Owner?   │   No
            ┌───────┤              ├──────────┐
            │       └──────────────┘          │
            ▼                          ┌──────▼───────┐
     ┌──────────┐                Yes   │  Is Free?    │   No
     │ ENTITLED │              ┌───────┤              ├──────────┐
     │ (owner)  │              │       └──────────────┘          │
     └──────────┘              ▼                          ┌──────▼───────┐
                        ┌──────────┐                Yes   │  Purchased?  │   No
                        │ ENTITLED │              ┌───────┤              ├──────────┐
                        │ (free)   │              │       └──────────────┘          │
                        └──────────┘              ▼                                 │
                                           ┌──────────┐                     ┌──────▼───────┐
                                           │ ENTITLED │                     │  Has Active  │
                                           │(purchase)│                     │  Sub + Mode  │
                                           └──────────┘                     │  Compatible? │
                                                                            └──────┬───────┘
                                                                         Yes │           │ No
                                                                      ┌──────▼────┐  ┌──▼──────────┐
                                                                      │ ENTITLED  │  │NOT ENTITLED │
                                                                      │(sub)      │  │(determine   │
                                                                      │+ record   │  │ options)    │
                                                                      │ access    │  └─────────────┘
                                                                      └───────────┘
                                                                                      │
                                                              ┌───────────────────────┼────────────────┐
                                                              │                       │                │
                                                     ┌────────▼──────┐    ┌───────────▼─┐   ┌─────────▼────────┐
                                                     │subscriber_only│    │    ppv       │   │subscriber_free   │
                                                     │→ Subscribe CTA│    │→ Purchase    │   │→ Purchase +      │
                                                     └───────────────┘    │   dialog     │   │  Subscribe upsell│
                                                                          └─────────────┘   └──────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Subscription Access Service (`app/services/subscription_access.py`)

This 83-line module provides the subscription access layer:

```python
# Line 55
def has_active_subscription(subscriber_id: str, creator_id: str) -> bool:
    resp = T.subscriptions.query(
        KeyConditionExpression=Key("pk").eq(_pk_subscriber(subscriber_id)) & Key("sk").begins_with("SUB#"),
    )
    items = resp.get("Items", [])
    for item in items:
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        if status in {"active", "past_due", "trialing"}:
            return True
    return False

# Line 72
def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    if subscriber_id == creator_id:
        return True
    if not creator_requires_subscription(creator_id):
        return True
    return has_active_subscription(subscriber_id, creator_id)
```

**Key observations:**
- `has_active_subscription()` queries `T.subscriptions` by `SUBSCRIBER#{subscriber_id}` PK, filtering for items where `creator_id` matches and status is active/past_due/trialing.
- The function considers `past_due` as active (grace period — subscriber retains access while payment is retried).
- `can_access_creator()` is used for catalog-level gating but is **never called in the VOD path**.

**DDB access pattern analysis for `has_active_subscription()`:**
```python
# Query pattern:
#   Table: T.subscriptions (from app/core/tables.py, line 109)
#   PK: SUBSCRIBER#{subscriber_id}
#   SK: begins_with("SUB#")
#
# This returns ALL subscriptions for the subscriber across ALL creators.
# The function then filters in-memory for creator_id match.
#
# Performance concern: If a subscriber has subscriptions to 100 creators,
# all 100 items are returned from DDB, but only 1 matches. This is
# acceptable for current scale (subscribers average 1-5 subscriptions).
#
# Potential optimization for future: Add a GSI on subscriber_id + creator_id
# to allow direct lookup without in-memory filtering. Not needed at current scale.
```

**Error handling:** The `has_active_subscription()` function wraps the DDB query in a try/except (line 60), returning `False` on any exception. This is a **fail-closed** pattern -- if DDB is unreachable, no subscription access is granted. This is the correct behavior for a monetization path.

### 2.2 Subscription Server Router (`app/routers/subscription_server.py`)

The subscription server manages plans, subscriptions, and billing:

- Plan creation: stores plans under `PK=PLAN#{plan_id}` with `price_cents`, `interval` (month/year), `annual_price_cents`
- Subscribe: creates subscription under `PK=SUBSCRIBER#{subscriber_id}, SK=SUB#{sub_id}` with `creator_id`, `status`, `price_cents`
- Plans have `creator_id` linking them to the content creator
- `attach_creator_profile()` (line 147) enriches plan records with creator identity

**Subscription lifecycle state transitions:**
```
  Created ──→ Trialing ──→ Active ──→ Past_due ──→ Cancelled
                │                       │              │
                │                       └──→ Active    │
                │                        (retry ok)    │
                └──→ Active                            │
                 (trial ends)                          ▼
                                                   Expired
```

**Integration with billing table:** Each subscription payment writes a LEDGER entry in `T.billing` with `reason="Subscription payment"`. The subscription server manages this. MON-005 does NOT write billing entries for subscription-based VOD access -- the subscriber already paid via the subscription.

### 2.3 VOD Entitlement Check (MON-001)

After MON-001, `check_vod_entitlement()` in `app/services/vod_purchase.py`:

```python
def check_vod_entitlement(*, user_id: str, video_id: str) -> bool:
    resp = T.vod_entitlements.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
    )
    item = resp.get("Item")
    if not item:
        return False
    ttl = int(item.get("ttl", 0))
    if ttl > 0 and ttl < now_ts():
        return False
    return True
```

This only checks the `vod_entitlements` table — no subscription awareness.

**Implementation detail:** The `check_vod_entitlement()` function uses `get_item()` (strong consistent read by default for the base table). This means a purchase is immediately visible. However, subscription-based entitlement records written by `_record_subscription_access()` use `put_item` with a `ConditionExpression`, which is also strongly consistent. Both paths deliver immediate consistency.

### 2.4 VideoMetadataModel (`app/models_video.py`)

After MON-001, the model includes (at approximately lines 89-91 after the entitlement_sku field):

```python
price_cents: Optional[int] = None
access_mode: Optional[str] = None    # free | ppv | subscriber_only | subscriber_free
```

The `access_mode` field is stored on each video but only used for display — no backend logic enforces it.

**Existing field interactions with access_mode:**
- `visibility: VideoVisibility = "private"` (line 93): Controls whether the video appears in listings. Orthogonal to access_mode -- a `public` + `subscriber_only` video is listed publicly but only playable by subscribers.
- `drm_enabled: bool = False` (line 85): DRM encryption is orthogonal to access gating. A subscriber-only video with DRM requires both subscription status AND a valid DRM license.
- `entitlement_sku: Optional[str] = None` (line 90): Legacy field intended for external entitlement systems. Not used by MON-005.
- `allow_download: bool = False` (line 98): Download access should follow the same entitlement cascade as playback. A subscriber who can watch should also be able to download (if enabled).

### 2.5 Video Detail Endpoint (MON-001)

After MON-001, `GET /ui/videos/{video_id}` computes `entitled` as:

```python
is_free = not video.price_cents or video.price_cents == 0 or video.access_mode in (None, "free")
entitled = is_owner or is_free or check_vod_entitlement(user_id=user_sub, video_id=video_id)
```

This is missing the subscription check between `is_free` and `check_vod_entitlement`.

**Line-by-line analysis of what changes:**
- The simple `entitled` boolean is replaced by a `VodAccessResult` object from `check_vod_access()`.
- The response model `VideoDetailOut` gains 4 new fields: `access_reason`, `subscription_available`, `purchase_available`, `subscription_upsell`.
- The frontend uses these fields to render the appropriate CTA (subscribe, purchase, or both).

### 2.6 Subscriptions DDB Table Schema

From `scripts/local-ddb-init.py` (line 73):

```python
TableDef(_resolve_table_name(S.subscriptions_table_name, "subscriptions"), "pk", "sk")
```

PK/SK patterns:
- `PLAN#{plan_id}` / `META` — plan record
- `CREATOR#{creator_id}` / `PLAN#{plan_id}` — creator's plans index
- `CREATOR#{creator_id}` / `SETTINGS` — creator subscription settings
- `SUBSCRIBER#{subscriber_id}` / `SUB#{subscription_id}` — subscriber's subscriptions
- `SUB#{subscription_id}` / `META` — subscription detail record

**Query pattern used by `has_active_subscription()`:**
```
KeyConditionExpression: pk = "SUBSCRIBER#bob456" AND begins_with(sk, "SUB#")

Returns all subscription items for bob456:
  {pk: "SUBSCRIBER#bob456", sk: "SUB#sub_001", creator_id: "alice123", status: "active", ...}
  {pk: "SUBSCRIBER#bob456", sk: "SUB#sub_002", creator_id: "charlie789", status: "cancelled", ...}

In-memory filter: item["creator_id"] == target_creator_id AND item["status"] in {"active","past_due","trialing"}
```

**Table size considerations:** The subscriptions table has no GSI for direct subscriber+creator lookup. For MON-005, this is acceptable because the in-memory filter operates on a small result set (subscribers typically have 1-5 subscriptions). If the platform scales to subscribers with 100+ subscriptions, a GSI on `(subscriber_id, creator_id)` should be added.

---

## 3. Technical Design

### 3.1 Unified Entitlement Check: `check_vod_access()`

Replace the simple `check_vod_entitlement()` call in the video detail endpoint with a comprehensive access check:

```python
# In app/services/vod_purchase.py (extended)

from app.services.subscription_access import has_active_subscription


class VodAccessResult:
    """Result of a VOD access check.

    This class encapsulates the full entitlement decision for a single
    video+viewer pair. It is used by:
    - GET /ui/videos/{video_id} — single video detail
    - GET /ui/videos/by-creator/{creator_id} — bulk list (via loop)
    - Frontend to determine which CTA to display

    Fields:
        entitled: Whether the viewer can watch right now.
        reason: Why they can (or cannot) watch.
            "owner" — video creator always has access
            "free" — video is free (price=0 or access_mode=free/null)
            "purchased" — viewer has explicit purchase in vod_entitlements
            "subscription" — viewer has active subscription + compatible mode
            "none" — not entitled; see subscription_available/purchase_available
        subscription_available: True if subscribing to the creator would grant
            access to this video. Used by frontend to show "Subscribe" CTA.
        purchase_available: True if individual purchase is an option for this
            video. Used by frontend to show "Purchase" dialog.
        price_cents: The video's price, if purchase is available.
        subscription_upsell: True specifically for subscriber_free videos
            when the viewer is NOT subscribed. The frontend shows both
            purchase and subscribe options with "Or subscribe for free access"
            messaging.
    """

    def __init__(
        self,
        *,
        entitled: bool,
        reason: str,                    # "owner" | "free" | "purchased" | "subscription" | "none"
        subscription_available: bool = False,  # True if subscribing would grant access
        purchase_available: bool = False,       # True if individual purchase is an option
        price_cents: Optional[int] = None,
        subscription_upsell: bool = False,      # True for subscriber_free videos to non-subscribers
    ):
        self.entitled = entitled
        self.reason = reason
        self.subscription_available = subscription_available
        self.purchase_available = purchase_available
        self.price_cents = price_cents
        self.subscription_upsell = subscription_upsell

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for inclusion in API response.

        Used by the video detail endpoint to spread access fields
        into VideoDetailOut.
        """
        return {
            "entitled": self.entitled,
            "access_reason": self.reason,
            "subscription_available": self.subscription_available,
            "purchase_available": self.purchase_available,
            "price_cents": self.price_cents,
            "subscription_upsell": self.subscription_upsell,
        }


def check_vod_access(
    *,
    user_id: str,
    video_id: str,
    video: "VideoMetadataModel",
) -> VodAccessResult:
    """Comprehensive VOD access check with entitlement cascade.

    Check order:
    1. Owner → always entitled
    2. Free video → entitled
    3. Explicit purchase → entitled
    4. Active subscription + compatible access_mode → entitled
    5. Not entitled → determine available options

    Performance notes:
    - Steps 1 and 2 are pure in-memory checks (no DDB calls).
    - Step 3 is a single DDB get_item (~10ms p99).
    - Step 4 is a DDB query on subscriptions table (~15ms p99).
    - Steps are ordered by likelihood of short-circuit. Most requests
      will return at step 1 (owner viewing own video) or step 2 (free
      content). Steps 3 and 4 only run for non-free, non-owned videos.
    """
    creator_id = video.owner_user_id
    access_mode = video.access_mode or "free"
    price = video.price_cents or 0

    # 1. Owner check
    if user_id == creator_id:
        return VodAccessResult(entitled=True, reason="owner")

    # 2. Free video check
    if price == 0 or access_mode == "free":
        return VodAccessResult(entitled=True, reason="free")

    # 3. Explicit purchase check
    if check_vod_entitlement(user_id=user_id, video_id=video_id):
        return VodAccessResult(entitled=True, reason="purchased")

    # 4. Subscription check
    has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id)

    if has_sub and access_mode in ("subscriber_only", "subscriber_free"):
        # Write a "subscription" entitlement record for caching / audit
        _record_subscription_access(
            user_id=user_id,
            video_id=video_id,
            creator_id=creator_id,
        )
        return VodAccessResult(entitled=True, reason="subscription")

    # 5. Not entitled — determine options
    if access_mode == "subscriber_only":
        # Only subscribing grants access — no individual purchase
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=True,
            purchase_available=False,
            price_cents=None,
        )
    elif access_mode == "ppv":
        # Only individual purchase — subscription does not help
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=False,
            purchase_available=True,
            price_cents=price,
        )
    elif access_mode == "subscriber_free":
        # Both options available — show purchase + subscription upsell
        return VodAccessResult(
            entitled=False,
            reason="none",
            subscription_available=True,
            purchase_available=True,
            price_cents=price,
            subscription_upsell=True,
        )

    # Fallback: treat as ppv
    return VodAccessResult(
        entitled=False,
        reason="none",
        purchase_available=True,
        price_cents=price,
    )


def _record_subscription_access(
    *,
    user_id: str,
    video_id: str,
    creator_id: str,
) -> None:
    """Write a subscription-based entitlement record for audit trail.

    This does NOT count as a purchase — it's a soft record that can be
    invalidated when the subscription lapses.

    The ConditionExpression ensures we never overwrite a paid purchase
    record with a subscription record. If a user first purchases a video
    and later subscribes to the creator, the purchase record (with
    amount_cents > 0) is preserved.

    Implementation details:
    - Uses T.vod_entitlements (app/core/tables.py, line 148 pending MON-001)
    - PK/SK pattern matches check_vod_entitlement() so the same get_item
      lookup finds both purchase and subscription records.
    - amount_cents=0 distinguishes subscription access from paid purchases
      in the ByCreatorPurchasedAt GSI for revenue reporting.
    - source="subscription" is used by MON-003 to exclude these from
      purchase revenue aggregation.
    """
    try:
        ts = now_ts()
        T.vod_entitlements.put_item(
            Item={
                "pk": f"USER#{user_id}",
                "sk": f"VIDEO#{video_id}",
                "user_id": user_id,
                "video_id": video_id,
                "creator_id": creator_id,
                "purchased_at": ts,
                "source": "subscription",
                "amount_cents": 0,
                "currency": "USD",
            },
            ConditionExpression="attribute_not_exists(pk)",  # Don't overwrite paid purchases
        )
    except Exception:
        pass  # Ignore — this is an optimization, not critical
```

### 3.2 Update Video Detail Endpoint

**File**: `app/routers/vod.py` (modified from MON-001)

Replace the simple entitled check with the cascade:

```python
@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(video_id: str, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.status not in ("published", "approved") and video.owner_user_id != user_sub:
        raise HTTPException(404, "Video not found")

    # Comprehensive access check
    access = check_vod_access(user_id=user_sub, video_id=video_id, video=video)

    out = VideoDetailOut(
        video_id=video.id,
        owner_user_id=video.owner_user_id,
        title=video.title,
        description=video.description,
        status=video.status,
        created_at=video.created_at,
        updated_at=video.updated_at,
        duration_seconds=video.duration_seconds,
        thumbnail_url=video.thumbnail_url,
        visibility=video.visibility,
        price_cents=video.price_cents,
        access_mode=video.access_mode,
        entitled=access.entitled,
        access_reason=access.reason,
        subscription_available=access.subscription_available,
        purchase_available=access.purchase_available,
        subscription_upsell=access.subscription_upsell,
        purchase_count=video.purchase_count,
        is_owner=(user_sub == video.owner_user_id),
    )

    if access.entitled and video.hls_manifest_url:
        pb = mint_vod_playback_url(video_id=video.id, tenant_id=video.owner_user_id)
        out.playback_url = pb.url
        out.playback_expires_at = pb.expires_at

    return out
```

**Line-by-line changes for `app/routers/vod.py`:**
- After the existing upload endpoints (line 279), add import: `from app.services.vod_purchase import check_vod_access, check_vod_entitlement, VodAccessResult`
- After the existing import of `has_active_subscription` from `subscription_access`, add it to the check
- In `get_video_detail()`: Replace the 3-line `is_free/entitled` computation with a single `check_vod_access()` call
- Update `VideoDetailOut(...)` constructor to use `access.entitled`, `access.reason`, etc. instead of the old boolean
- Playback URL minting gate changes from `if entitled:` to `if access.entitled:`

### 3.3 Update Purchase Endpoint

**File**: `app/routers/vod.py`

The purchase endpoint must respect `access_mode`:

```python
@router.post("/{video_id}/purchase", response_model=VodPurchaseOut)
def purchase_video(video_id: str, inp: VodPurchaseIn, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    # ... existing validations (404, self-purchase, free, already purchased) ...

    # Block purchase for subscriber-only videos
    if video.access_mode == "subscriber_only":
        raise HTTPException(403, "This video is only available to subscribers — individual purchase is not available")

    # If viewer has active subscription and video is subscriber_free, inform them
    if video.access_mode == "subscriber_free":
        if has_active_subscription(subscriber_id=user_sub, creator_id=video.owner_user_id):
            raise HTTPException(400, "You already have access via your subscription")

    # ... rest of purchase logic (PM validation, ledger write, entitlement write) ...
```

**Detailed guard logic:**
```python
# Guard 1: subscriber_only — no purchase option exists
# HTTP 403 is intentional (not 400) because the resource exists but
# the action is forbidden for this access_mode. The frontend should
# never send this request (the Purchase button is hidden for
# subscriber_only videos), but the backend must enforce it.

# Guard 2: subscriber_free with active subscription — redundant purchase
# HTTP 400 because the request is technically valid but pointless.
# The subscriber already has access. Charging them would be wrong.
# The frontend should hide the Purchase button for entitled subscribers,
# but the backend must enforce it.

# Guard 3: ppv with subscription — subscription does NOT block purchase
# A subscriber CAN purchase a ppv video. Subscriptions have no effect
# on ppv videos. This is intentional — the creator marked the video
# as ppv to exclude it from subscription bundles (e.g., premium content
# sold separately even to subscribers).
```

### 3.4 Video Listing Endpoints

Add subscription-aware entitlement status to video list endpoints:

```python
# GET /ui/videos/by-creator/{creator_id}
# Returns list of videos with per-viewer access info

class VideoListItemOut(BaseModel):
    video_id: str
    title: str
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    entitled: bool
    access_reason: str                  # "free" | "purchased" | "subscription" | "none"
    created_at: int

class VideoListOut(BaseModel):
    videos: List[VideoListItemOut]
    viewer_has_subscription: bool       # True if viewer subscribes to this creator
    next_cursor: Optional[str] = None
```

The list endpoint checks subscription status once for the creator, then applies it to all videos:

```python
@router.get("/by-creator/{creator_id}", response_model=VideoListOut)
def list_creator_videos(creator_id: str, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    result = list_videos_by_creator_public(creator_id)   # returns {"items": List[VideoMetadataModel], "cursor": ...}
    videos = result["items"]

    has_sub = has_active_subscription(subscriber_id=user_sub, creator_id=creator_id)

    # Batch check purchases
    purchased_ids = set()
    if user_sub != creator_id:
        purchased_ids = _batch_check_entitlements(user_id=user_sub, video_ids=[v.id for v in videos])

    items = []
    for v in videos:
        access_mode = v.access_mode or "free"
        price = v.price_cents or 0
        is_free = price == 0 or access_mode == "free"
        is_purchased = v.id in purchased_ids
        sub_grants = has_sub and access_mode in ("subscriber_only", "subscriber_free")

        entitled = (user_sub == creator_id) or is_free or is_purchased or sub_grants
        reason = "owner" if user_sub == creator_id else \
                 "free" if is_free else \
                 "purchased" if is_purchased else \
                 "subscription" if sub_grants else "none"

        items.append(VideoListItemOut(
            video_id=v.id,
            title=v.title,
            description=v.description,
            thumbnail_url=v.thumbnail_url,
            duration_seconds=v.duration_seconds,
            price_cents=v.price_cents,
            access_mode=v.access_mode,
            entitled=entitled,
            access_reason=reason,
            created_at=v.created_at,
        ))

    return VideoListOut(
        videos=items,
        viewer_has_subscription=has_sub,
    )
```

**Performance analysis of list endpoint:**
```
For a creator with 50 videos and a logged-in subscriber:
  1. list_videos_by_creator_public() — 1 DDB query via ByOwnerCreatedAt GSI (~15ms)
  2. has_active_subscription() — 1 DDB query on subscriptions table (~15ms)
  3. _batch_check_entitlements() — 1 DDB batch_get_item for up to 50 keys (~20ms)
  4. In-memory loop to build VideoListItemOut — negligible

Total: ~50ms for 50 videos. Compare with the naive approach of calling
check_vod_access() per video (50 * 25ms = 1250ms). The batch approach is 25x faster.
```

### 3.5 Batch Entitlement Check

For efficiency in list endpoints, add a batch entitlement check:

```python
def _batch_check_entitlements(*, user_id: str, video_ids: List[str]) -> set:
    """Check multiple video entitlements in a single DDB batch_get_item call.

    Args:
        user_id: The viewer's user ID.
        video_ids: List of video IDs to check (max 100 per batch due to
            DDB batch_get_item limit).

    Returns:
        Set of video IDs that the user has entitlements for (either
        purchase or subscription-based).

    Implementation notes:
    - DDB batch_get_item supports max 100 keys per request.
    - For lists >100 videos, callers must chunk. The list endpoint
      paginates at 50 videos, so this is not an issue in practice.
    - ProjectionExpression="sk" minimizes response size (we only need
      the video ID, not the full entitlement record).
    - Returns empty set on any exception (fail-closed for list display;
      individual video detail endpoint still runs full check_vod_access).
    - TTL-expired entitlements are included in the batch response but
      should ideally be filtered. For simplicity, we include them —
      the full check_vod_access() on the video detail page handles
      TTL expiry correctly.
    """
    if not video_ids:
        return set()

    pk = f"USER#{user_id}"
    keys = [{"pk": pk, "sk": f"VIDEO#{vid}"} for vid in video_ids[:100]]  # DDB batch limit

    try:
        resp = T.vod_entitlements.meta.client.batch_get_item(
            RequestItems={
                T.vod_entitlements.table_name: {
                    "Keys": keys,
                    "ProjectionExpression": "sk",
                }
            }
        )
        items = resp.get("Responses", {}).get(T.vod_entitlements.table_name, [])
        return {item["sk"].replace("VIDEO#", "") for item in items}
    except Exception:
        return set()
```

**Chunked version for future use (>100 videos):**
```python
def _batch_check_entitlements_chunked(*, user_id: str, video_ids: List[str]) -> set:
    """Batch check with automatic chunking for large video lists."""
    result = set()
    for i in range(0, len(video_ids), 100):
        chunk = video_ids[i:i + 100]
        result |= _batch_check_entitlements(user_id=user_id, video_ids=chunk)
    return result
```

### 3.6 Subscription Lapse Handling

When a subscription lapses (status changes from active to cancelled/expired), subscription-based VOD entitlements should be invalidated. Two approaches:

**Option A: Lazy invalidation (recommended)**
The `check_vod_access()` function always calls `has_active_subscription()` for non-purchased access. If the subscription has lapsed, the function returns `entitled=False` even if a subscription-source entitlement record exists. The stale record in `vod_entitlements` is harmless — it is never trusted without a live subscription check.

```
Lazy invalidation flow:

  1. Bob subscribes to Alice (status=active)
  2. Bob watches Alice's subscriber_only video
     → check_vod_access() calls has_active_subscription() → True
     → _record_subscription_access() writes {source: "subscription"} record
     → entitled=True, reason="subscription"
  3. Bob's subscription lapses (status=cancelled)
  4. Bob tries to watch the same video
     → check_vod_access() calls check_vod_entitlement() → True (stale record exists)
       BUT the source is "subscription", and the function needs to re-verify...

  WAIT: check_vod_entitlement() returns True for ANY record (purchase or subscription).
  This means the stale subscription record would grant access!

  FIX: check_vod_entitlement() must check the `source` field. If source="subscription",
  it must also verify the subscription is still active.

  ALTERNATIVE FIX (simpler): check_vod_entitlement() ignores subscription records.
  The subscription check runs independently in step 4 of check_vod_access().
```

**Revised check_vod_entitlement() to handle subscription records:**
```python
def check_vod_entitlement(*, user_id: str, video_id: str) -> bool:
    """Check for a PURCHASE entitlement (not subscription-based).

    Returns True only for records where source != "subscription".
    Subscription-based access is handled separately by check_vod_access()
    via has_active_subscription().
    """
    resp = T.vod_entitlements.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
    )
    item = resp.get("Item")
    if not item:
        return False
    # Subscription records are NOT trusted here — they need live subscription check
    if item.get("source") == "subscription":
        return False
    ttl = int(item.get("ttl", 0))
    if ttl > 0 and ttl < now_ts():
        return False
    return True
```

**Option B: Eager cleanup**
A background job runs when a subscription is cancelled, scanning and deleting all `source="subscription"` entitlement records for that creator+subscriber pair. This is complex and unnecessary given Option A.

**Decision**: Option A with the revised `check_vod_entitlement()`. The live subscription check is authoritative. The `source="subscription"` entitlement record is purely for audit trail and can be ignored if the subscription is no longer active.

### 3.7 Updated VideoDetailOut Response Model

```python
class VideoDetailOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: int
    updated_at: int
    duration_seconds: Optional[float] = None
    thumbnail_url: Optional[str] = None
    visibility: str
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    # Access info
    entitled: bool
    access_reason: str                     # "owner" | "free" | "purchased" | "subscription" | "none"
    subscription_available: bool = False   # True if subscribing would grant access
    purchase_available: bool = False       # True if individual purchase is possible
    subscription_upsell: bool = False      # True for subscriber_free — show both options
    # Stats
    purchase_count: int = 0
    is_owner: bool = False
    # Playback (only when entitled)
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None
```

**Pydantic model validators:**
```python
class VideoDetailOut(BaseModel):
    # ... fields as above ...

    @model_validator(mode="after")
    def validate_access_consistency(self) -> "VideoDetailOut":
        """Ensure access fields are logically consistent.

        If entitled=True, access_reason must be one of the entitled reasons.
        If entitled=False, subscription_available or purchase_available should be True
        (otherwise the viewer has no path to access).
        """
        entitled_reasons = {"owner", "free", "purchased", "subscription"}
        if self.entitled and self.access_reason not in entitled_reasons:
            raise ValueError(f"entitled=True but access_reason={self.access_reason}")
        if not self.entitled and self.access_reason != "none":
            raise ValueError(f"entitled=False but access_reason={self.access_reason}")
        return self
```

### 3.8 Frontend Updates

#### VideoPlayerPage Changes

The player page needs to handle three distinct non-entitled states:

```typescript
// frontend/src/pages/vod/VideoPlayerPage.tsx

function VideoAccessGate({ video }: { video: VideoDetailResponse }) {
  if (video.entitled) {
    return <VideoPlayer url={video.playback_url!} />;
  }

  // Subscriber-only: only show subscribe CTA
  if (video.access_mode === "subscriber_only") {
    return (
      <SubscribeCTA
        creatorId={video.owner_user_id}
        message="Subscribe to watch this video"
      />
    );
  }

  // Subscriber-free with upsell: show purchase + subscribe option
  if (video.subscription_upsell) {
    return (
      <div className="space-y-4">
        <PurchaseDialog
          videoId={video.video_id}
          priceCents={video.price_cents!}
        />
        <Separator />
        <SubscribeCTA
          creatorId={video.owner_user_id}
          message="Or subscribe for free access to all videos"
          variant="outline"
        />
      </div>
    );
  }

  // PPV: only show purchase dialog
  return (
    <PurchaseDialog
      videoId={video.video_id}
      priceCents={video.price_cents!}
    />
  );
}
```

#### SubscribeCTA Component

New component that links to the creator's subscription page:

```typescript
function SubscribeCTA({ creatorId, message, variant }: {
  creatorId: string;
  message: string;
  variant?: "default" | "outline";
}) {
  const { data: plans } = useQuery(
    ["creator-plans", creatorId],
    () => getCreatorPlans(creatorId),
  );

  const cheapestPlan = plans?.sort((a, b) => a.price_cents - b.price_cents)[0];

  return (
    <Card>
      <CardContent className="text-center py-8">
        <p className="text-lg mb-4">{message}</p>
        {cheapestPlan && (
          <p className="text-muted-foreground mb-4">
            Starting at ${(cheapestPlan.price_cents / 100).toFixed(2)}/month
          </p>
        )}
        <Button variant={variant} asChild>
          <Link to={`/subscriptions?creator=${creatorId}`}>
            View Plans
          </Link>
        </Button>
      </CardContent>
    </Card>
  );
}
```

#### Video List Cards

In the video listing, show badges indicating access status:

```typescript
function VideoCard({ video }: { video: VideoListItemOut }) {
  return (
    <Card>
      <img src={video.thumbnail_url} />
      <CardContent>
        <h3>{video.title}</h3>
        {video.entitled ? (
          <Badge variant="success">
            {video.access_reason === "subscription" ? "Included" : "Unlocked"}
          </Badge>
        ) : video.access_mode === "subscriber_only" ? (
          <Badge variant="secondary">Subscribers Only</Badge>
        ) : (
          <Badge variant="outline">${(video.price_cents! / 100).toFixed(2)}</Badge>
        )}
      </CardContent>
    </Card>
  );
}
```

### 3.9 Frontend Types

```typescript
// Add to frontend/src/api/types.ts

export interface VideoDetailResponse {
  video_id: string;
  owner_user_id: string;
  title: string;
  description?: string;
  status: string;
  created_at: number;
  updated_at: number;
  duration_seconds?: number;
  thumbnail_url?: string;
  visibility: string;
  price_cents?: number;
  access_mode?: string;
  entitled: boolean;
  access_reason: string;
  subscription_available: boolean;
  purchase_available: boolean;
  subscription_upsell: boolean;
  purchase_count: number;
  is_owner: boolean;
  playback_url?: string;
  playback_expires_at?: number;
}

export interface VideoListItemOut {
  video_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  price_cents?: number;
  access_mode?: string;
  entitled: boolean;
  access_reason: string;
  created_at: number;
}

export interface VideoListResponse {
  videos: VideoListItemOut[];
  viewer_has_subscription: boolean;
  next_cursor?: string;
}
```

### 3.10 Frontend API Endpoint Wrappers

```typescript
// frontend/src/api/endpoints/vod.ts

import client from "../client";
import type { VideoDetailResponse, VideoListResponse } from "../types";

export async function getVideoDetail(videoId: string): Promise<VideoDetailResponse> {
  const { data } = await client.get<VideoDetailResponse>(`/ui/videos/${videoId}`);
  return data;
}

export async function listCreatorVideos(creatorId: string, cursor?: string): Promise<VideoListResponse> {
  const params = cursor ? { cursor } : {};
  const { data } = await client.get<VideoListResponse>(
    `/ui/videos/by-creator/${creatorId}`,
    { params },
  );
  return data;
}

export async function getCreatorPlans(creatorId: string) {
  // GET /api/creators/{id}/plans is public (no auth needed)
  const { data } = await client.get(`/api/creators/${creatorId}/plans`);
  return data;
}
```

### 3.11 Frontend Component Tree

```
VideoPlayerPage
├── useQuery(["video", videoId], () => getVideoDetail(videoId))
├── VideoAccessGate
│   ├── [entitled] VideoPlayer
│   │   ├── HLS.js player
│   │   ├── DRM license negotiation (if drm_enabled)
│   │   └── Playback token refresh loop
│   │
│   ├── [subscriber_only && !entitled] SubscribeCTA
│   │   ├── Card
│   │   │   ├── CardContent
│   │   │   │   ├── <p> "Subscribe to watch this video"
│   │   │   │   ├── <p> "Starting at $X.XX/month"
│   │   │   │   └── Button → Link to /subscriptions?creator={id}
│   │   │   └── useQuery(["creator-plans", creatorId])
│   │   └── (shimmer loading state while plans load)
│   │
│   ├── [subscriber_free && !entitled] PurchaseWithUpsell
│   │   ├── PurchaseDialog (same as MON-001)
│   │   │   ├── Dialog
│   │   │   │   ├── DialogHeader: "Purchase Video"
│   │   │   │   ├── PaymentMethodSelector
│   │   │   │   └── DialogFooter: Cancel / Confirm
│   │   │   └── useMutation(purchaseVideo)
│   │   ├── Separator
│   │   └── SubscribeCTA (variant="outline")
│   │       └── "Or subscribe for free access to all videos"
│   │
│   └── [ppv && !entitled] PurchaseDialog (same as MON-001)
│
├── VideoMetadata
│   ├── title, description, duration
│   ├── VideoPriceBadge
│   │   ├── [free] Badge(variant="success"): "Free"
│   │   ├── [purchased] Badge(variant="success"): "Purchased"
│   │   ├── [subscription] Badge(variant="default"): "Included"
│   │   ├── [subscriber_only] Badge(variant="secondary"): "Subscribers Only"
│   │   └── [ppv] Badge(variant="outline"): "$X.XX"
│   └── purchase_count display (owner only)
│
└── VideoListPage (creator's video catalog)
    ├── useQuery(["creator-videos", creatorId], () => listCreatorVideos(creatorId))
    ├── SubscriptionBanner (if viewer_has_subscription)
    │   └── "You're subscribed! Subscriber content is included."
    └── Grid of VideoCard components
        └── VideoCard
            ├── thumbnail
            ├── title
            ├── duration_seconds formatted
            ├── VideoPriceBadge
            └── Link to /videos/{video_id}
```

---

## 4. Implementation Plan

### Step 1: Extend VOD Purchase Service

**File**: `app/services/vod_purchase.py` (from MON-001)

Add `VodAccessResult` class and `check_vod_access()` function. Add `_record_subscription_access()` helper. Add `_batch_check_entitlements()` for list endpoints. Modify `check_vod_entitlement()` to skip subscription-source records.

**Line-by-line changes:**
- After existing imports, add: `from app.services.subscription_access import has_active_subscription`
- After the existing `check_vod_entitlement()` function: Insert the `VodAccessResult` class definition (~50 lines)
- After `VodAccessResult`: Insert `check_vod_access()` function (~70 lines)
- After `check_vod_access()`: Insert `_record_subscription_access()` function (~25 lines)
- After `_record_subscription_access()`: Insert `_batch_check_entitlements()` function (~25 lines)
- Modify `check_vod_entitlement()`: Add `source` field check — if `item.get("source") == "subscription"`, return `False`
- After `_batch_check_entitlements()`: Insert `_batch_check_entitlements_chunked()` for future use (~5 lines)

Estimated: ~180 lines added, ~5 lines modified

### Step 2: Update Video Detail Endpoint

**File**: `app/routers/vod.py`

Replace simple `entitled` boolean with `check_vod_access()` call. Update `VideoDetailOut` model to include `access_reason`, `subscription_available`, `purchase_available`, `subscription_upsell`.

**Line-by-line changes:**
- Import line: Add `check_vod_access, VodAccessResult` to import from `vod_purchase`
- Import line: Add `from app.services.subscription_access import has_active_subscription`
- In `get_video_detail()` body: Replace `is_free = ...` and `entitled = ...` (3 lines) with `access = check_vod_access(...)` (1 line)
- In `VideoDetailOut(...)` constructor: Replace `entitled=entitled` with `entitled=access.entitled`, add `access_reason=access.reason`, `subscription_available=access.subscription_available`, `purchase_available=access.purchase_available`, `subscription_upsell=access.subscription_upsell`
- In playback URL gating: Replace `if entitled:` with `if access.entitled:`

### Step 3: Add Video List Endpoint

**File**: `app/routers/vod.py`

Add `GET /ui/videos/by-creator/{creator_id}` endpoint with batch entitlement check and subscription-aware access flags.

**New code after existing endpoints (line 279):**
- `VideoListItemOut` model definition (~12 lines)
- `VideoListOut` model definition (~5 lines)
- `list_creator_videos()` endpoint function (~40 lines)

### Step 4: Update Purchase Endpoint Guards

**File**: `app/routers/vod.py`

Add `access_mode` validation:
- Block purchase for `subscriber_only` videos
- Block purchase for subscribers viewing `subscriber_free` videos (they already have access)

**New code in `purchase_video()` function, after existing validations:**
- `subscriber_only` check + 403 response (~3 lines)
- `subscriber_free` + active subscription check + 400 response (~4 lines)

### Step 5: Frontend Types

**File**: `frontend/src/api/types.ts`

Update `VideoDetailResponse` with new access fields. Add `VideoListItemOut` and `VideoListResponse`.

**Changes:**
- Add 4 fields to `VideoDetailResponse`: `access_reason`, `subscription_available`, `purchase_available`, `subscription_upsell`
- Add `VideoListItemOut` interface (~12 lines)
- Add `VideoListResponse` interface (~5 lines)

### Step 6: Frontend VideoPlayerPage

**File**: `frontend/src/pages/vod/VideoPlayerPage.tsx`

Add `VideoAccessGate` component with three non-entitled states. Add `SubscribeCTA` component.

**New components:**
- `VideoAccessGate` (~30 lines)
- `SubscribeCTA` (~25 lines)
- `VideoPriceBadge` (~20 lines)

### Step 7: Frontend Video List

**File**: `frontend/src/pages/vod/VideoListPage.tsx` (or equivalent)

Add subscription-aware badges to video cards. Show "Included with subscription" for subscriber_only/subscriber_free videos when viewer has active subscription.

**New/modified components:**
- `VideoCard` update for access badges (~15 lines)
- `SubscriptionBanner` component (~10 lines)

### Step 8: Vite Proxy

No changes needed — `/ui/videos` already proxied.

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/vod_purchase.py` | Extend with subscription-aware check | ~180 |
| `app/routers/vod.py` | Update detail, add list, update purchase | ~150 |
| `frontend/src/api/types.ts` | Update/add types | ~30 |
| `frontend/src/api/endpoints/vod.ts` | Add API wrappers | ~25 |
| `frontend/src/pages/vod/VideoPlayerPage.tsx` | Access gate + subscribe CTA | ~100 |
| `frontend/src/pages/vod/VideoListPage.tsx` | Subscription badges | ~50 |
| **Total** | | **~535** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_vod_subscription_access.py`)

New file, ~600 lines. Moto-mocked DynamoDB with seeded subscription and VOD data.

**Test setup fixture:**
```python
@pytest.fixture(autouse=True)
def setup_ddb(moto_ddb):
    """Create vod_entitlements and subscriptions tables for testing.

    Uses moto to mock DynamoDB. Seeds:
    - Creator: user_creator (owns all videos)
    - Subscriber: user_sub (has active subscription to user_creator)
    - Non-subscriber: user_nosub (no subscription)
    - 4 videos: vid_free (free), vid_ppv (ppv, $9.99), vid_subonly
      (subscriber_only, $9.99), vid_subfree (subscriber_free, $9.99)
    """
    # Create tables
    moto_ddb.create_table(
        TableName="vod_entitlements",
        KeySchema=[{"AttributeName": "pk", ...}, {"AttributeName": "sk", ...}],
        ...
    )
    moto_ddb.create_table(
        TableName="subscriptions",
        KeySchema=[{"AttributeName": "pk", ...}, {"AttributeName": "sk", ...}],
        ...
    )
    # Seed subscription: user_sub has active sub to user_creator
    moto_ddb.Table("subscriptions").put_item(Item={
        "pk": "SUBSCRIBER#user_sub",
        "sk": "SUB#sub_001",
        "creator_id": "user_creator",
        "status": "active",
        "price_cents": 999,
    })
    yield
```

**Entitlement Cascade (10 tests)**:

```python
def test_owner_always_entitled():
    """Video owner is entitled regardless of price/access_mode."""
    video = make_video(access_mode="ppv", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_creator", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "owner"

def test_free_video_always_entitled():
    """price=0 videos are entitled for any viewer."""
    video = make_video(access_mode="free", price_cents=0, owner="user_creator")
    result = check_vod_access(user_id="user_nosub", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "free"

def test_explicit_purchase_grants_access():
    """Viewer with purchase record in vod_entitlements is entitled."""
    video = make_video(access_mode="ppv", price_cents=999, owner="user_creator")
    seed_purchase(user_id="user_nosub", video_id=video.id)
    result = check_vod_access(user_id="user_nosub", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "purchased"

def test_subscription_grants_subscriber_only():
    """Active subscriber can access subscriber_only videos."""
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_sub", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "subscription"

def test_subscription_grants_subscriber_free():
    """Active subscriber can access subscriber_free videos."""
    video = make_video(access_mode="subscriber_free", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_sub", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "subscription"

def test_subscription_does_not_grant_ppv():
    """Active subscriber is NOT entitled to ppv videos via subscription."""
    video = make_video(access_mode="ppv", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_sub", video_id=video.id, video=video)
    assert result.entitled is False
    assert result.subscription_available is False
    assert result.purchase_available is True

def test_no_sub_subscriber_only_options():
    """Non-subscriber for subscriber_only: subscription_available=True, purchase_available=False."""
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_nosub", video_id=video.id, video=video)
    assert result.entitled is False
    assert result.subscription_available is True
    assert result.purchase_available is False
    assert result.price_cents is None

def test_no_sub_ppv_options():
    """Non-subscriber for ppv: subscription_available=False, purchase_available=True."""
    video = make_video(access_mode="ppv", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_nosub", video_id=video.id, video=video)
    assert result.entitled is False
    assert result.subscription_available is False
    assert result.purchase_available is True
    assert result.price_cents == 999

def test_no_sub_subscriber_free_options():
    """Non-subscriber for subscriber_free: both options + upsell."""
    video = make_video(access_mode="subscriber_free", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_nosub", video_id=video.id, video=video)
    assert result.entitled is False
    assert result.subscription_available is True
    assert result.purchase_available is True
    assert result.subscription_upsell is True
    assert result.price_cents == 999

def test_trialing_subscription_counts_as_active():
    """Subscription with status='trialing' grants access."""
    seed_subscription(user_id="user_trial", creator_id="user_creator", status="trialing")
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_trial", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "subscription"
```

**Subscription Lapse (4 tests)**:

```python
def test_cancelled_subscription_no_access():
    """Cancelled subscription does not grant VOD access."""
    seed_subscription(user_id="user_cancelled", creator_id="user_creator", status="cancelled")
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_cancelled", video_id=video.id, video=video)
    assert result.entitled is False
    assert result.subscription_available is True

def test_expired_subscription_no_access():
    """Expired subscription does not grant VOD access."""
    seed_subscription(user_id="user_expired", creator_id="user_creator", status="expired")
    video = make_video(access_mode="subscriber_free", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_expired", video_id=video.id, video=video)
    assert result.entitled is False

def test_past_due_subscription_grants_access():
    """Past-due subscription grants access (grace period)."""
    seed_subscription(user_id="user_pastdue", creator_id="user_creator", status="past_due")
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_pastdue", video_id=video.id, video=video)
    assert result.entitled is True
    assert result.reason == "subscription"

def test_subscription_to_different_creator_no_access():
    """Subscription to creator_B does not grant access to creator_A's videos."""
    seed_subscription(user_id="user_other", creator_id="creator_B", status="active")
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    result = check_vod_access(user_id="user_other", video_id=video.id, video=video)
    assert result.entitled is False
```

**Purchase Restrictions (4 tests)**:

```python
def test_cannot_purchase_subscriber_only(client):
    """POST /purchase for subscriber_only video returns 403."""
    resp = client.post(f"/ui/videos/{vid_subonly}/purchase", json={"payment_method_id": "pm_1"})
    assert resp.status_code == 403
    assert "subscribers" in resp.json()["detail"].lower()

def test_subscriber_cannot_purchase_subscriber_free(client):
    """Subscriber purchasing subscriber_free returns 400 (already has access)."""
    resp = client.post(
        f"/ui/videos/{vid_subfree}/purchase",
        json={"payment_method_id": "pm_1"},
        headers={"X-User-Id": "user_sub"},
    )
    assert resp.status_code == 400
    assert "already have access" in resp.json()["detail"]

def test_non_subscriber_can_purchase_subscriber_free(client):
    """Non-subscriber can purchase subscriber_free video normally."""
    seed_payment_method("user_nosub", "pm_1")
    resp = client.post(
        f"/ui/videos/{vid_subfree}/purchase",
        json={"payment_method_id": "pm_1"},
        headers={"X-User-Id": "user_nosub"},
    )
    assert resp.status_code == 200

def test_ppv_purchasable_regardless_of_subscription(client):
    """Subscriber can purchase ppv video (subscription does not affect ppv)."""
    seed_payment_method("user_sub", "pm_1")
    resp = client.post(
        f"/ui/videos/{vid_ppv}/purchase",
        json={"payment_method_id": "pm_1"},
        headers={"X-User-Id": "user_sub"},
    )
    assert resp.status_code == 200
```

**Batch Entitlement Check (3 tests)**:

```python
def test_batch_check_returns_purchased_ids():
    """Batch check returns set of video IDs with entitlements."""
    seed_purchase("user_x", "vid_a")
    seed_purchase("user_x", "vid_c")
    result = _batch_check_entitlements(user_id="user_x", video_ids=["vid_a", "vid_b", "vid_c", "vid_d", "vid_e"])
    assert result == {"vid_a", "vid_c"}

def test_batch_check_empty_list():
    """Batch check with empty video_ids returns empty set."""
    result = _batch_check_entitlements(user_id="user_x", video_ids=[])
    assert result == set()

def test_batch_check_handles_ddb_error(monkeypatch):
    """Batch check returns empty set on DDB error."""
    monkeypatch.setattr(T.vod_entitlements.meta.client, "batch_get_item", _raise)
    result = _batch_check_entitlements(user_id="user_x", video_ids=["vid_a"])
    assert result == set()
```

**Subscription Access Record (3 tests)**:

```python
def test_subscription_access_writes_audit_record():
    """check_vod_access() for subscriber writes source='subscription' record."""
    video = make_video(access_mode="subscriber_only", price_cents=999, owner="user_creator")
    check_vod_access(user_id="user_sub", video_id=video.id, video=video)
    item = T.vod_entitlements.get_item(
        Key={"pk": "USER#user_sub", "sk": f"VIDEO#{video.id}"}
    ).get("Item")
    assert item is not None
    assert item["source"] == "subscription"
    assert int(item["amount_cents"]) == 0

def test_audit_record_does_not_overwrite_purchase():
    """Subscription record does not overwrite existing purchase record."""
    video = make_video(access_mode="subscriber_free", price_cents=999, owner="user_creator")
    seed_purchase("user_sub", video.id, amount_cents=999)
    check_vod_access(user_id="user_sub", video_id=video.id, video=video)
    item = T.vod_entitlements.get_item(
        Key={"pk": "USER#user_sub", "sk": f"VIDEO#{video.id}"}
    ).get("Item")
    assert item["source"] != "subscription"  # Purchase record preserved
    assert int(item["amount_cents"]) == 999

def test_audit_record_amount_is_zero():
    """Subscription access records always have amount_cents=0."""
    video = make_video(access_mode="subscriber_free", price_cents=1499, owner="user_creator")
    _record_subscription_access(user_id="user_sub", video_id=video.id, creator_id="user_creator")
    item = T.vod_entitlements.get_item(
        Key={"pk": "USER#user_sub", "sk": f"VIDEO#{video.id}"}
    ).get("Item")
    assert int(item["amount_cents"]) == 0
    assert item["currency"] == "USD"
```

**Entitlement Source Filtering (3 tests)**:

```python
def test_check_vod_entitlement_skips_subscription_records():
    """check_vod_entitlement() returns False for source='subscription' records."""
    T.vod_entitlements.put_item(Item={
        "pk": "USER#user_x", "sk": "VIDEO#vid_1",
        "source": "subscription", "amount_cents": 0,
    })
    assert check_vod_entitlement(user_id="user_x", video_id="vid_1") is False

def test_check_vod_entitlement_accepts_purchase_records():
    """check_vod_entitlement() returns True for source='purchase' records."""
    T.vod_entitlements.put_item(Item={
        "pk": "USER#user_x", "sk": "VIDEO#vid_2",
        "source": "purchase", "amount_cents": 999,
    })
    assert check_vod_entitlement(user_id="user_x", video_id="vid_2") is True

def test_check_vod_entitlement_accepts_no_source_records():
    """check_vod_entitlement() returns True for legacy records with no source field."""
    T.vod_entitlements.put_item(Item={
        "pk": "USER#user_x", "sk": "VIDEO#vid_3",
        "amount_cents": 999,
    })
    assert check_vod_entitlement(user_id="user_x", video_id="vid_3") is True
```

### 5.2 E2E Tests (`frontend/e2e/vod-subscription.spec.ts`)

New file, ~600 lines.

**Section 101: Subscription + VOD Access API (8 tests)**:

```typescript
test.describe("101: Subscription + VOD Access API", () => {
  test("Subscriber sees entitled=true for subscriber_only video", async ({ request }) => {
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB }, // Bob has active subscription to Alice
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.entitled).toBe(true);
    expect(body.access_reason).toBe("subscription");
  });

  test("Subscriber sees entitled=true for subscriber_free video", async ({ request }) => {
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_FREE}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(true);
    expect(body.access_reason).toBe("subscription");
  });

  test("Subscriber sees entitled=false for ppv video", async ({ request }) => {
    const resp = await request.get(`/ui/videos/${VIDEO_PPV}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(false);
    expect(body.purchase_available).toBe(true);
    expect(body.subscription_available).toBe(false);
  });

  test("Non-subscriber sees entitled=false for subscriber_only video", async ({ request }) => {
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(false);
    expect(body.subscription_available).toBe(true);
    expect(body.purchase_available).toBe(false);
  });

  test("Non-subscriber can purchase subscriber_free video", async ({ request }) => {
    // Seed PM for Charlie, then purchase
    const resp = await request.post(`/ui/videos/${VIDEO_SUB_FREE}/purchase`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
      data: { payment_method_id: PM_CHARLIE },
    });
    expect(resp.status()).toBe(200);
  });

  test("Non-subscriber cannot purchase subscriber_only video (403)", async ({ request }) => {
    const resp = await request.post(`/ui/videos/${VIDEO_SUB_ONLY}/purchase`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
      data: { payment_method_id: PM_CHARLIE },
    });
    expect(resp.status()).toBe(403);
  });

  test("Subscriber already entitled cannot purchase subscriber_free video (400)", async ({ request }) => {
    const resp = await request.post(`/ui/videos/${VIDEO_SUB_FREE}/purchase`, {
      headers: { "X-User-Id": BOB_SUB },
      data: { payment_method_id: PM_BOB },
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("already have access");
  });

  test("access_reason=subscription in video detail response", async ({ request }) => {
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.access_reason).toBe("subscription");
    expect(body.entitled).toBe(true);
    // Verify playback URL is present for entitled viewer
    expect(body.playback_url).toBeTruthy();
  });
});
```

**Section 102: Video Listing with Subscriptions (5 tests)**:

```typescript
test.describe("102: Video Listing with Subscriptions", () => {
  test("Video list includes viewer_has_subscription flag", async ({ request }) => {
    const resp = await request.get(`/ui/videos/by-creator/${ALICE_CREATOR}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.viewer_has_subscription).toBe(true);
  });

  test("Subscriber sees 'subscription' access_reason on subscriber_free videos", async ({ request }) => {
    const resp = await request.get(`/ui/videos/by-creator/${ALICE_CREATOR}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    const subFree = body.videos.find((v: any) => v.video_id === VIDEO_SUB_FREE);
    expect(subFree.entitled).toBe(true);
    expect(subFree.access_reason).toBe("subscription");
  });

  test("Non-subscriber sees price on subscriber_free videos", async ({ request }) => {
    const resp = await request.get(`/ui/videos/by-creator/${ALICE_CREATOR}`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
    });
    const body = await resp.json();
    const subFree = body.videos.find((v: any) => v.video_id === VIDEO_SUB_FREE);
    expect(subFree.entitled).toBe(false);
    expect(subFree.price_cents).toBe(999);
  });

  test("subscriber_only videos show correct access_reason for non-subscriber", async ({ request }) => {
    const resp = await request.get(`/ui/videos/by-creator/${ALICE_CREATOR}`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
    });
    const body = await resp.json();
    const subOnly = body.videos.find((v: any) => v.video_id === VIDEO_SUB_ONLY);
    expect(subOnly.entitled).toBe(false);
    expect(subOnly.access_reason).toBe("none");
  });

  test("Batch entitlement correctly marks purchased videos", async ({ request }) => {
    // Charlie purchased VIDEO_SUB_FREE in section 101
    const resp = await request.get(`/ui/videos/by-creator/${ALICE_CREATOR}`, {
      headers: { "X-User-Id": CHARLIE_NOSUB },
    });
    const body = await resp.json();
    const purchased = body.videos.find((v: any) => v.video_id === VIDEO_SUB_FREE);
    expect(purchased.entitled).toBe(true);
    expect(purchased.access_reason).toBe("purchased");
  });
});
```

**Section 103: Subscription Lapse (4 tests)**:

```typescript
test.describe("103: Subscription Lapse", () => {
  test("Active subscriber has access", async ({ request }) => {
    // Bob's subscription is active (seeded in beforeAll)
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(true);
  });

  test("Cancelled subscriber loses access", async ({ request }) => {
    // Update Bob's subscription status to cancelled via DDB
    await updateSubscriptionStatus(BOB_SUB, ALICE_CREATOR, "cancelled");
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(false);
    expect(body.subscription_available).toBe(true);
  });

  test("Re-subscribed viewer regains access", async ({ request }) => {
    // Restore Bob's subscription to active
    await updateSubscriptionStatus(BOB_SUB, ALICE_CREATOR, "active");
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(true);
    expect(body.access_reason).toBe("subscription");
  });

  test("Past-due subscriber retains access", async ({ request }) => {
    await updateSubscriptionStatus(BOB_SUB, ALICE_CREATOR, "past_due");
    const resp = await request.get(`/ui/videos/${VIDEO_SUB_ONLY}`, {
      headers: { "X-User-Id": BOB_SUB },
    });
    const body = await resp.json();
    expect(body.entitled).toBe(true);
    expect(body.access_reason).toBe("subscription");
    // Restore for subsequent tests
    await updateSubscriptionStatus(BOB_SUB, ALICE_CREATOR, "active");
  });
});
```

**Section 104: VOD Subscription UI (5 tests)**:

```typescript
test.describe("104: VOD Subscription UI", () => {
  test("subscriber_only video shows 'Subscribe to watch' CTA", async ({ page }) => {
    await injectAuth(page, CHARLIE_NOSUB);
    await page.goto(`/videos/${VIDEO_SUB_ONLY}`);
    await expect(page.getByText("Subscribe to watch this video")).toBeVisible();
    await expect(page.getByRole("link", { name: "View Plans" })).toBeVisible();
    // No purchase dialog should be shown
    await expect(page.getByText("Purchase")).not.toBeVisible();
  });

  test("subscriber_free video shows purchase + subscribe options", async ({ page }) => {
    await injectAuth(page, CHARLIE_NOSUB);
    await page.goto(`/videos/${VIDEO_SUB_FREE}`);
    // Purchase dialog should be visible
    await expect(page.getByRole("button", { name: /purchase/i })).toBeVisible();
    // Subscription upsell should also be visible
    await expect(page.getByText(/subscribe for free access/i)).toBeVisible();
  });

  test("ppv video shows only purchase dialog", async ({ page }) => {
    await injectAuth(page, CHARLIE_NOSUB);
    await page.goto(`/videos/${VIDEO_PPV}`);
    await expect(page.getByRole("button", { name: /purchase/i })).toBeVisible();
    // No subscription CTA
    await expect(page.getByText("Subscribe")).not.toBeVisible();
  });

  test("After subscribing, video player becomes visible", async ({ page }) => {
    await injectAuth(page, BOB_SUB);
    await page.goto(`/videos/${VIDEO_SUB_ONLY}`);
    // Bob is subscribed — should see the player, not the CTA
    await expect(page.getByText("Subscribe to watch")).not.toBeVisible();
    // Player element should be present
    await expect(page.locator("video, [data-testid='video-player']")).toBeVisible();
  });

  test("Subscriber sees 'Included' badge on video list", async ({ page }) => {
    await injectAuth(page, BOB_SUB);
    await page.goto(`/creators/${ALICE_CREATOR}/videos`);
    // The subscriber_free video should show "Included" badge
    await expect(page.getByText("Included").first()).toBeVisible();
  });
});
```

**Test Setup (beforeAll):**
- Seed sessions for Alice (creator) and Bob (viewer)
- Create subscription plan for Alice via subscription server API
- Upload and publish 4 videos with different access_modes:
  - video_free: access_mode=free
  - video_ppv: access_mode=ppv, price_cents=999
  - video_sub_only: access_mode=subscriber_only, price_cents=999
  - video_sub_free: access_mode=subscriber_free, price_cents=999
- Bob subscribes to Alice's plan in some tests, not in others

```typescript
test.describe.configure({ mode: "serial" });

let VIDEO_FREE: string;
let VIDEO_PPV: string;
let VIDEO_SUB_ONLY: string;
let VIDEO_SUB_FREE: string;

const ALICE_CREATOR = "alice_creator_" + Date.now();
const BOB_SUB = "bob_subscriber_" + Date.now();
const CHARLIE_NOSUB = "charlie_nosub_" + Date.now();

test.beforeAll(async ({ request }) => {
  // 1. Create test users via DDB seeding
  await seedUser(ALICE_CREATOR);
  await seedUser(BOB_SUB);
  await seedUser(CHARLIE_NOSUB);

  // 2. Create subscription plan for Alice
  const planResp = await request.post("/api/subscription/plans", {
    headers: { "X-User-Id": ALICE_CREATOR },
    data: { name: "Alice Premium", price_cents: 999, interval: "month" },
  });
  const plan = await planResp.json();

  // 3. Bob subscribes to Alice's plan
  await request.post("/api/subscription/subscribe", {
    headers: { "X-User-Id": BOB_SUB },
    data: { plan_id: plan.plan_id },
  });

  // 4. Upload 4 videos with different access_modes
  VIDEO_FREE = await createTestVideo(request, ALICE_CREATOR, {
    title: "Free Video", access_mode: "free", price_cents: 0,
  });
  VIDEO_PPV = await createTestVideo(request, ALICE_CREATOR, {
    title: "PPV Video", access_mode: "ppv", price_cents: 999,
  });
  VIDEO_SUB_ONLY = await createTestVideo(request, ALICE_CREATOR, {
    title: "Sub Only Video", access_mode: "subscriber_only", price_cents: 999,
  });
  VIDEO_SUB_FREE = await createTestVideo(request, ALICE_CREATOR, {
    title: "Sub Free Video", access_mode: "subscriber_free", price_cents: 999,
  });

  // 5. Seed payment methods for purchase tests
  await seedPaymentMethod(BOB_SUB, PM_BOB);
  await seedPaymentMethod(CHARLIE_NOSUB, PM_CHARLIE);
});
```

### 5.3 Edge Cases to Cover

1. **Subscription check latency**: `has_active_subscription()` queries DynamoDB on every video detail request. For list endpoints with many videos, the subscription check is done once and reused. Ensure no N+1 query pattern.

2. **Race condition: subscribe + immediate watch**: After subscribing, the subscription record is immediately visible in DynamoDB (strong consistency). The video detail endpoint should reflect access instantly.

3. **Multiple subscriptions to same creator**: A viewer could have multiple subscription records (e.g., cancelled old one, started new one). `has_active_subscription()` already handles this — it looks for any item with active status.

4. **Creator changes access_mode after subscription**: If a creator changes a video from subscriber_free to ppv, existing subscribers lose free access to that specific video. The access check always uses the current `access_mode`, not a historical snapshot. This is the correct behavior — the creator controls their pricing.

5. **Free trial subscribers**: Subscriptions with status="trialing" should grant VOD access (same as active). Verify `has_active_subscription()` includes "trialing" in the valid statuses set — it does (line 67 of subscription_access.py).

6. **Subscription-based entitlement record collision**: If a viewer first accesses a video via subscription (writing a source="subscription" record), then later purchases it, the purchase should overwrite the subscription record. The `grant_vod_entitlement()` function from MON-001 uses `put_item` (unconditional overwrite), while `_record_subscription_access()` uses `attribute_not_exists(pk)` condition — so a purchase always wins.

7. **DDB batch_get_item limit**: Batch get supports max 100 items per request. For creators with >100 videos, the list endpoint must chunk the batch check. The `_batch_check_entitlements()` function should handle this.

### 5.4 Performance Considerations

1. **Subscription check caching**: For a single page load showing 20+ videos from the same creator, the subscription check should be called once and reused. The list endpoint already does this.

2. **Entitlement batch check**: Using `batch_get_item` for entitlement checks is O(1) per item (vs O(N) individual get_items). For 100 videos, this is 1 DDB call instead of 100.

3. **Response size**: Video list responses include access info per video. For creators with hundreds of videos, pagination (limit=50 default) keeps response sizes manageable.

### 5.5 Related Tickets

- **MON-001**: VOD pay-per-view (required — provides purchase flow and entitlement table)
- **MON-003**: Creator earnings dashboard (subscription VOD revenue shows in earnings)
- **MON-004**: Creator payouts (subscription-granted access does not generate direct payout-eligible credits — only subscription payments do)

---

## 6. Security Considerations

### 6.1 Authentication & Authorization Edge Cases

- **Entitlement cascade is fail-closed**: If the DDB query in `has_active_subscription()` throws an exception (line 60 of subscription_access.py), it returns `False`. Combined with `check_vod_entitlement()` which also returns `False` on error, a DDB outage results in denied access, never granted access. This is the correct behavior for a monetization path.
- **Owner bypass is server-side only**: The `is_owner` check compares `video.owner_user_id` to the authenticated `user_sub` from the session cookie JWT. A client cannot forge ownership because `user_sub` comes from the server-signed JWT.
- **Subscription status is authoritative**: The `source="subscription"` record in `vod_entitlements` is an audit artifact, NOT an authorization grant. The live `has_active_subscription()` call is the only thing that grants subscription-based access. A user cannot gain access by writing a fake subscription entitlement record because `check_vod_entitlement()` now skips records with `source="subscription"`.
- **CSRF on purchase endpoint**: `POST /ui/videos/{id}/purchase` uses cookie auth via `require_ui_session`, so the `x-csrf-token` header is mandatory for cookie-authenticated requests. The subscription check added by MON-005 does not change the CSRF requirement.

### 6.2 Input Validation

- `access_mode`: Constrained to exactly 4 valid values (`free`, `ppv`, `subscriber_only`, `subscriber_free`) via Pydantic regex or Literal type. Any other value in PATCH requests returns HTTP 422.
- `creator_id` in list endpoint: String path parameter. If the creator does not exist, the list returns an empty video list (not an error). No information leakage about user existence.
- Subscription status values: The `has_active_subscription()` function compares against an explicit set `{"active", "past_due", "trialing"}`. Any other status string (including SQL injection attempts or malicious values stored in DDB) is rejected by the set membership check.

### 6.3 Rate Limiting

- **Video list endpoint**: Should be rate-limited to 30 requests per minute per user to prevent scraping entire creator catalogs. Use the existing rate-limit pattern from `app/core/settings.py`.
- **Subscription check amplification**: The list endpoint calls `has_active_subscription()` once per request (not per video). This prevents an attacker from amplifying DDB load by requesting large video lists.
- **Entitlement batch check**: Limited to 100 keys per batch by DDB constraints. The list endpoint paginates at 50, so no amplification vector.

### 6.4 Abuse Vectors

- **Subscription sharing**: If Bob shares his session cookies with Charlie, Charlie can access Bob's subscription-gated content. This is an inherent limitation of session-based auth. Mitigation: concurrent session limits (existing feature).
- **Rapid subscribe/cancel to access content**: A user could subscribe, download all subscriber-only videos, then cancel. The subscription lapse handling (lazy invalidation) prevents ongoing access after cancellation. Actual video file downloads are gated by the download entitlement check (same cascade). Downloaded files cannot be un-downloaded, which is standard for content platforms.
- **access_mode downgrade attack**: A malicious creator could set `access_mode=free` temporarily to boost views/SEO, then switch back to `ppv`. This is not a security issue (creator controls their pricing), but it could confuse viewers. Consider adding `access_mode_changed_at` timestamp for transparency.

### 6.5 Data Privacy

- Subscription status is never exposed to other users. The `viewer_has_subscription` flag in the video list response is visible only to the requesting viewer.
- The `_record_subscription_access()` audit records contain `user_id`, `video_id`, `creator_id` but no payment information (amount_cents=0).
- The `access_reason` field in `VideoDetailOut` tells the viewer WHY they have access. This is safe to expose because it only reveals the viewer's own access state.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Changes

No new tables are created in MON-005. All changes use existing tables:
- **`vod_entitlements`** (created in MON-001): New records with `source="subscription"` are additive. Schema is unchanged.
- **`subscriptions`** (existing): Read-only access via `has_active_subscription()`. No schema changes.
- **`video_metadata`** (existing): The `access_mode` field was added in MON-001. MON-005 adds backend logic that reads this field but does not add new fields.

### 7.2 Code Changes Are Non-Breaking

- The `check_vod_access()` function is NEW. It does not replace or modify any existing function signature. The old `check_vod_entitlement()` function is modified to skip subscription records, but this only affects newly-written records (existing purchase records have no `source` field or `source="purchase"`, both of which pass the new check).
- The `VideoDetailOut` response model gains new OPTIONAL fields with defaults (`subscription_available=False`, etc.). Existing frontend code that ignores these fields will continue to work.
- The list endpoint (`GET /ui/videos/by-creator/{creator_id}`) is entirely new. No existing endpoint is modified.

### 7.3 Feature Flag Rollout

Reuse the `VOD_PPV_ENABLED` flag from MON-001. MON-005's subscription-aware logic only runs when a video has a non-free `access_mode`, which can only be set when PPV is enabled.

Alternatively, add a separate flag:
```python
# In app/core/settings.py
vod_subscription_gating_enabled: bool = os.environ.get("VOD_SUBSCRIPTION_GATING_ENABLED", "0") not in ("0", "false", "False")
```

Gate the subscription check in `check_vod_access()`:
```python
# Step 4: Subscription check (only when feature flag is enabled)
if S.vod_subscription_gating_enabled:
    has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id)
    if has_sub and access_mode in ("subscriber_only", "subscriber_free"):
        _record_subscription_access(user_id=user_id, video_id=video_id, creator_id=creator_id)
        return VodAccessResult(entitled=True, reason="subscription")
```

### 7.4 Rollback Steps

1. Set `VOD_SUBSCRIPTION_GATING_ENABLED=0`. The subscription check is skipped; `check_vod_access()` behaves exactly as the MON-001 version (owner/free/purchased only).
2. Subscription-source records in `vod_entitlements` become inert. `check_vod_entitlement()` already skips them (source check), and the subscription branch in `check_vod_access()` is disabled.
3. Frontend continues to show the old behavior (ppv purchase only). The new `subscription_available`, `subscription_upsell` fields default to `False`, so the `SubscribeCTA` component never renders.
4. No data loss. All records are preserved. Re-enabling the flag restores full functionality.

### 7.5 Zero-Downtime Deployment

- All new endpoints are additive (new route handlers on existing router).
- The `check_vod_access()` function is backward-compatible with `check_vod_entitlement()` when the subscription feature flag is off.
- No database migrations required.
- Frontend changes are behind the same `access_reason` / `subscription_available` response fields -- if the backend returns the old shape (no new fields), React components degrade gracefully (fields default to undefined/false).

### 7.6 Deployment Order

1. Deploy backend with `VOD_SUBSCRIPTION_GATING_ENABLED=0` -- code is deployed but subscription check is off.
2. Deploy frontend -- new components exist but `subscription_available=false` means they never render.
3. Enable `VOD_SUBSCRIPTION_GATING_ENABLED=1` on staging for integration testing.
4. Enable in production -- subscription-gated access goes live.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vod_access_check_total` | Counter | `result={owner,free,purchased,subscription,none}` | Entitlement cascade outcomes |
| `vod_subscription_check_total` | Counter | `result={active,inactive,error}` | Subscription check outcomes |
| `vod_subscription_check_latency_seconds` | Histogram | | DDB query latency for subscription check |
| `vod_batch_entitlement_check_total` | Counter | `result={success,error}` | Batch check outcomes |
| `vod_subscription_access_record_total` | Counter | `result={written,skipped,error}` | Audit record writes |
| `vod_purchase_blocked_total` | Counter | `reason={subscriber_only,already_subscribed}` | Purchase guard blocks |

Add to `app/metrics.py` following the existing `record_playback_entitlement_event` pattern.

### 8.2 Alerting Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Subscription check error rate > 2% | `rate(vod_subscription_check_total{result=error}[5m]) / rate(vod_subscription_check_total[5m]) > 0.02` | Critical |
| Subscription check latency p99 > 100ms | Histogram quantile | Medium |
| All access checks returning "none" (0 entitled) | `rate(vod_access_check_total{result=subscription}[15m]) == 0 AND rate(vod_access_check_total{result=none}[15m]) > 0` | High |
| Batch entitlement error rate > 5% | `rate(vod_batch_entitlement_check_total{result=error}[5m]) / rate(vod_batch_entitlement_check_total[5m]) > 0.05` | Medium |
| Purchase blocked by subscriber_only > 10/min | `rate(vod_purchase_blocked_total{reason=subscriber_only}[1m]) > 10` | Low (frontend bug) |

### 8.3 Common Debugging Scenarios

**Scenario: Subscriber reports "Subscribe to watch" on a video they should have access to**
1. Verify subscription status: Query `T.subscriptions` for `PK=SUBSCRIBER#{user_id}`, find the item with matching `creator_id`. Check `status` field.
2. If status is not in `{active, past_due, trialing}`, the subscription has lapsed. The viewer must re-subscribe.
3. If status IS active, check the video's `access_mode`. If it is `ppv`, subscriptions do not grant access (by design). The creator set this video as pay-per-view only.
4. If access_mode is `subscriber_only` or `subscriber_free` AND subscription is active, check if `has_active_subscription()` is being called. Verify the feature flag `VOD_SUBSCRIPTION_GATING_ENABLED=1`.

**Scenario: Subscriber sees "Included" badge but video does not play**
1. The entitlement check returned `entitled=True, reason="subscription"` (badge shows "Included").
2. Check if `playback_url` is null in the response. This would mean the video has no `hls_manifest_url` (transcoding incomplete or failed).
3. Verify video status is `published` or `approved`.
4. Check playback entitlement minting -- the `mint_vod_playback_url()` call may have failed.

**Scenario: Stale subscription access records accumulating**
1. Query `vod_entitlements` via ByCreatorPurchasedAt GSI for the creator.
2. Filter for `source="subscription"`. Count records.
3. These records are harmless (not used for authorization). If cleanup is desired, a one-time script can delete records where the corresponding subscription is no longer active.

**Scenario: Creator changed access_mode but subscriber still has old badge**
1. Access badges are computed from the current `access_mode` on each request. There is no caching.
2. If the viewer's page is stale (React Query cache), the old badge persists until the query refetches.
3. Hard refresh clears the cache. No backend action needed.

### 8.4 Log Patterns to Watch

```
# Subscription grants VOD access
{"level": "info", "event": "vod_access_granted_subscription", "user_id": "...", "video_id": "...", "creator_id": "..."}

# Subscription lapse — access denied
{"level": "info", "event": "vod_access_denied_subscription_lapsed", "user_id": "...", "video_id": "...", "creator_id": "..."}

# Purchase blocked — subscriber_only
{"level": "info", "event": "vod_purchase_blocked_subscriber_only", "user_id": "...", "video_id": "..."}

# Purchase blocked — already subscribed
{"level": "info", "event": "vod_purchase_blocked_already_subscribed", "user_id": "...", "video_id": "..."}

# Subscription check error
{"level": "warning", "event": "vod_subscription_check_error", "user_id": "...", "creator_id": "...", "error": "..."}

# Batch entitlement check error
{"level": "warning", "event": "vod_batch_entitlement_error", "user_id": "...", "video_count": 50, "error": "..."}
```

### 8.5 Health Check

The subscription-gated VOD path can be validated with a synthetic check:
1. Ensure a test subscription exists (status=active) for a known test user + test creator.
2. Ensure a test video exists with `access_mode=subscriber_only`.
3. Call `GET /ui/videos/{test_video_id}` with the test subscriber's auth.
4. Verify `entitled=true` and `access_reason="subscription"` in the response.

This validates: DDB connectivity (subscriptions table + vod_entitlements table), the `has_active_subscription()` query, the `check_vod_access()` cascade, and the response serialization.

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Metric | Estimate | Basis |
|--------|----------|-------|
| Video detail requests/sec | 100 | Main browse/watch flow |
| Subscription checks/sec | 50 | ~50% of video details are for non-free, non-owned videos |
| Video list requests/sec | 20 | Creator profile browsing |
| Batch entitlement checks/sec | 20 | 1:1 with video list requests |
| Subscription access record writes/sec | 10 | First-time views by subscribers |

### 9.2 DDB Capacity

**subscriptions table (additional read load from MON-005):**
- 1 query per subscription check (~50/sec worst case)
- Each query returns 1-5 items (subscriber's subscriptions) at ~200 bytes each → 1 RCU
- 50 additional RCU at peak. On-demand billing handles this easily.

**vod_entitlements table (additional load):**
- Read: 1 get_item per `check_vod_entitlement()` (100/sec) → 100 RCU
- Read: 1 batch_get_item per list request (20/sec), up to 50 keys each → 20 * 50 = 1000 RCU in individual terms, but batch_get is more efficient (~20 RCU actual)
- Write: ~10 subscription access records/sec → 10 WCU (small items)

**Total additional DDB load per second:**
- Subscriptions table: +50 RCU
- vod_entitlements table: +120 RCU, +10 WCU
- All within on-demand capacity for moderate traffic

### 9.3 Hot Partition Analysis

- **subscriptions PK `SUBSCRIBER#{id}`**: One user's subscriptions are all under one PK. A single user viewing many videos only hits their PK once per request (subscription check is done once in the list endpoint). No hot partition risk.
- **vod_entitlements PK `USER#{id}`**: Batch get reads multiple SKs under one PK. DDB partitions by PK hash, so reads are distributed across users. A single user viewing a list of 50 videos is 50 get_item reads on the same PK — this is fine (DDB supports 3000 RCU per partition per second).
- **subscription access record writes**: Distributed across user PKs. First-time views are spread over time. No write hot partition risk.

### 9.4 Caching Strategy

- **Subscription check**: Could cache `has_active_subscription()` result in-memory with a 60-second TTL per (subscriber_id, creator_id) pair. This would reduce subscription DDB reads by ~95% for users browsing multiple videos from the same creator. Implementation: `@functools.lru_cache(maxsize=10000)` with TTL wrapper. However, this delays subscription lapse detection by up to 60 seconds. Acceptable trade-off.
- **Batch entitlement check**: No caching needed. Each list request fetches fresh data. The batch_get_item is already efficient.
- **Video list response**: Could cache the full `VideoListOut` response per (creator_id, viewer_id) pair with a 30-second TTL. This is more aggressive and would need cache invalidation on purchase/subscription change. Not recommended for initial implementation.

### 9.5 Latency Budget

| Operation | Target p99 | Components |
|-----------|-----------|------------|
| GET /videos/{id} (with subscription check) | 60ms | get_video (15ms) + entitlement check (10ms) + subscription check (15ms) + playback URL mint (10ms) |
| GET /videos/by-creator/{id} (50 videos) | 80ms | list_videos (20ms) + subscription check (15ms) + batch entitlement check (25ms) + response build (10ms) |
| POST /videos/{id}/purchase (with guards) | 220ms | get_video (15ms) + entitlement check (10ms) + subscription check (15ms) + PM validation (10ms) + entitlement write (15ms) + 2 ledger writes (30ms) + counter update (15ms) |

**Latency comparison with/without MON-005:**
```
                         Without MON-005    With MON-005    Increase
GET /videos/{id}         35ms p99           60ms p99        +25ms (subscription check)
GET /by-creator/{id}     45ms p99           80ms p99        +35ms (subscription + batch)
POST .../purchase        200ms p99          220ms p99       +20ms (subscription guard)
```

The 25ms increase on video detail is the subscription DDB query. This is acceptable for a monetization decision that determines whether the viewer sees a video player or a paywall.

---

## 10. Dependency Analysis

### 10.1 Blocked By

| Ticket | Dependency | Status |
|--------|-----------|--------|
| MON-001 | VOD pay-per-view provides `vod_entitlements` table, `check_vod_entitlement()`, `access_mode` field, `VideoDetailOut` model, purchase endpoint | Required |

### 10.2 Blocks

| Ticket | Dependency |
|--------|-----------|
| None | MON-005 is a leaf node — no other ticket depends on it |

### 10.3 Integration Points

- **Subscription access service** (`app/services/subscription_access.py`, line 55): `has_active_subscription()` is the core dependency. MON-005 calls this function but does not modify it. The function's contract (returns bool, fails closed, considers past_due as active) is relied upon.
- **VOD purchase service** (`app/services/vod_purchase.py`): Extended with `check_vod_access()` and helper functions. The existing `check_vod_entitlement()` is modified to skip subscription-source records.
- **VOD router** (`app/routers/vod.py`): Existing endpoints are modified (video detail, purchase). New endpoint added (video list by creator).
- **Billing table** (`T.billing`): NOT written to by MON-005. Subscription-based VOD access does not generate billing entries. Only MON-001 purchases write billing entries.
- **Video metadata table** (`T.video_metadata`): Read-only. MON-005 reads the `access_mode` field added by MON-001. No new fields are added.
- **Playback entitlements** (`app/services/playback_entitlements.py`): Called after the entitlement cascade passes. No changes to this service.

### 10.4 API Contract Commitments

Once shipped, these response shapes become commitments:
- `VideoDetailOut.access_reason` (string enum) — consumers will use this to render access badges
- `VideoDetailOut.subscription_available` (bool) — consumers will use this to show/hide SubscribeCTA
- `VideoDetailOut.subscription_upsell` (bool) — consumers will use this to show the dual CTA layout
- `VideoListOut.viewer_has_subscription` (bool) — consumers will use this for list-level messaging

### 10.5 Cross-Ticket Interaction Matrix

```
                MON-001     MON-002     MON-003     MON-004     MON-005
MON-001         -           none        read ledger read ledger  REQUIRED BY
MON-002         none        -           read ledger read ledger  none
MON-003         reads       reads       -           reads        none
MON-004         reads       reads       reads       -            none
MON-005         DEPENDS ON  none        none        none         -
```

---

## 11. Acceptance Criteria

1. A subscriber viewing `GET /ui/videos/{id}` for a `subscriber_only` video sees `entitled: true`, `access_reason: "subscription"`.
2. A subscriber viewing a `subscriber_free` video sees `entitled: true`, `access_reason: "subscription"`.
3. A subscriber viewing a `ppv` video sees `entitled: false`, `purchase_available: true`, `subscription_available: false` (subscription does not help for ppv).
4. A non-subscriber viewing a `subscriber_only` video sees `entitled: false`, `subscription_available: true`, `purchase_available: false`.
5. A non-subscriber viewing a `subscriber_free` video sees `entitled: false`, `subscription_available: true`, `purchase_available: true`, `subscription_upsell: true`.
6. `POST /ui/videos/{id}/purchase` for a `subscriber_only` video returns HTTP 403.
7. `POST /ui/videos/{id}/purchase` for a `subscriber_free` video by an active subscriber returns HTTP 400 ("already have access via subscription").
8. A non-subscriber can successfully purchase a `subscriber_free` video via `POST .../purchase`.
9. A cancelled subscriber no longer has access to `subscriber_only` videos.
10. A past_due subscriber retains access (grace period).
11. A trialing subscriber has access (same as active).
12. The video list endpoint (`GET /ui/videos/by-creator/{id}`) includes `viewer_has_subscription` and per-video `entitled`/`access_reason`.
13. The list endpoint calls `has_active_subscription()` exactly once per request (not per video).
14. The batch entitlement check handles up to 100 video IDs per request.
15. The `_record_subscription_access()` audit record has `source="subscription"` and `amount_cents=0`.
16. The subscription audit record does NOT overwrite an existing purchase record (ConditionExpression enforced).
17. `check_vod_entitlement()` skips subscription-source records (only purchase records grant entitlement through that function).
18. The frontend shows "Subscribe to watch" CTA for `subscriber_only` non-entitled videos.
19. The frontend shows both Purchase and Subscribe options for `subscriber_free` non-entitled videos.
20. The frontend shows only Purchase for `ppv` non-entitled videos.
21. The frontend shows "Included" badge for subscriber-entitled videos in the list view.
22. All 27 unit tests and 22 E2E tests pass.
23. The feature flag `VOD_SUBSCRIPTION_GATING_ENABLED` can disable all subscription-aware logic without breaking existing PPV functionality.

---

## 12. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-----------|-------------|------------|---------------------|-----------------|
| GET /videos/{id} | Subscription check DDB error | 200 | N/A | `entitled: false, subscription_available: true` (fail-closed, shows subscribe CTA) | Retry request |
| GET /videos/{id} | Subscription check timeout | 200 | N/A | `entitled: false` (fail-closed) | Retry request |
| GET /videos/{id} | Video has invalid access_mode value | 200 | N/A | Treated as ppv (fallback branch) | Creator fixes access_mode |
| GET /videos/{id} | Subscription access record write fails | 200 | N/A | Access still granted (record is optional audit trail) | No action needed |
| POST /videos/{id}/purchase | access_mode=subscriber_only | 403 | `subscriber_only` | "This video is only available to subscribers" | Subscribe to creator |
| POST /videos/{id}/purchase | Subscriber purchasing subscriber_free | 400 | `already_subscribed` | "You already have access via your subscription" | Watch directly |
| POST /videos/{id}/purchase | Subscription check fails during guard | 200 | N/A | Purchase proceeds (fail-open for purchase guard) | N/A |
| GET /videos/by-creator/{id} | Subscription check DDB error | 200 | N/A | `viewer_has_subscription: false` (fail-closed) | Retry |
| GET /videos/by-creator/{id} | Batch entitlement check DDB error | 200 | N/A | All videos show `entitled: false` (fail-closed for purchases) | Retry |
| GET /videos/by-creator/{id} | Creator has 0 published videos | 200 | N/A | `videos: []` | N/A |
| GET /videos/by-creator/{id} | Creator ID does not exist | 200 | N/A | `videos: [], viewer_has_subscription: false` | N/A |

**Error handling philosophy:**
- **Subscription check errors**: Always fail-closed (deny access). The viewer sees a "Subscribe to watch" or "Purchase" CTA instead of a free pass. This protects creator revenue.
- **Purchase guard errors**: Fail-open (allow purchase). If the subscription check fails during the purchase endpoint, the purchase proceeds normally. The worst case is a subscriber paying for a video they could watch for free -- this is a minor inconvenience, not a revenue loss.
- **Audit record write errors**: Silently ignored. The `_record_subscription_access()` function catches all exceptions. The audit record is optional; the live subscription check is authoritative.

---

## 13. Frontend Component Specifications

### 13.1 VideoAccessGate Component

```typescript
interface VideoAccessGateProps {
  video: VideoDetailResponse;
  onPurchaseComplete: () => void;  // callback to invalidate query
}
```

**State management:**
- Uses `useQuery(["video", videoId])` for video data (from parent)
- No local state -- rendering is purely driven by `video.entitled`, `video.access_mode`, and `video.subscription_upsell`
- `onPurchaseComplete` callback triggers `queryClient.invalidateQueries(["video", videoId])`

**Responsive breakpoints:**
- Mobile (<640px): Full-width CTA cards, stacked vertically
- Tablet (640-1024px): Side-by-side purchase + subscribe CTAs for subscriber_free
- Desktop (>1024px): Standard video player layout with sidebar CTAs

**Accessibility (ARIA):**
- Subscribe CTA: `aria-label="Subscribe to creator for $X.XX per month"`
- Price badge: `role="status"`, `aria-live="polite"` (updates after purchase/subscribe)
- After entitlement: Focus moves to the video player element

**Keyboard navigation:**
- Tab order: video thumbnail → price badge → primary CTA → secondary CTA (if present)
- Enter/Space activates buttons
- Escape closes any open dialog

### 13.2 SubscribeCTA Component

```typescript
interface SubscribeCTAProps {
  creatorId: string;
  message: string;
  variant?: "default" | "outline";
}
```

**Component tree:**
```
SubscribeCTA
  ├── Card
  │   └── CardContent (className="text-center py-8")
  │       ├── <p className="text-lg mb-4"> message prop
  │       ├── [plans loaded] <p className="text-muted-foreground mb-4">
  │       │   └── "Starting at $X.XX/month"
  │       ├── [plans loading] Skeleton (height=20, width=150)
  │       └── Button (variant prop, asChild)
  │           └── Link to="/subscriptions?creator={creatorId}"
  │               └── "View Plans"
  └── useQuery(["creator-plans", creatorId], () => getCreatorPlans(creatorId))
```

**Query keys used:**
- `["creator-plans", creatorId]` — fetches creator's subscription plans via `GET /api/creators/{creatorId}/plans` (public endpoint, no auth required per existing implementation)

**Loading state:**
- While plans are loading, show a skeleton placeholder for the price line
- The "View Plans" button is always visible (it navigates to the subscription page regardless of plan data)

**Error state:**
- If plans fail to load, hide the price line entirely but still show the "View Plans" button
- Do not show an error message -- the subscription page itself will handle plan display

### 13.3 VideoPriceBadge Component

```typescript
interface VideoPriceBadgeProps {
  priceCents?: number;
  accessMode?: string;
  entitled: boolean;
  accessReason?: string;
}
```

Renders:
- Free video (`accessMode="free"` or `!priceCents`): Green "Free" badge
- Entitled via purchase (`entitled && accessReason="purchased"`): Green "Purchased" badge
- Entitled via subscription (`entitled && accessReason="subscription"`): Blue "Included" badge
- Entitled as owner (`entitled && accessReason="owner"`): No badge (owner sees management UI instead)
- Not entitled, subscriber_only: Secondary "Subscribers Only" badge
- Not entitled, ppv: Outline badge "$9.99"
- Not entitled, subscriber_free: Outline badge "$9.99" + small "or subscribe" text

**Implementation:**
```typescript
function VideoPriceBadge({ priceCents, accessMode, entitled, accessReason }: VideoPriceBadgeProps) {
  if (entitled) {
    if (accessReason === "owner") return null;
    if (accessReason === "subscription") return <Badge variant="default">Included</Badge>;
    if (accessReason === "purchased") return <Badge variant="success">Purchased</Badge>;
    return <Badge variant="success">Free</Badge>;
  }

  if (accessMode === "subscriber_only") {
    return <Badge variant="secondary">Subscribers Only</Badge>;
  }

  const priceStr = priceCents ? `$${(priceCents / 100).toFixed(2)}` : "Free";

  if (accessMode === "subscriber_free") {
    return (
      <div className="flex items-center gap-1.5">
        <Badge variant="outline">{priceStr}</Badge>
        <span className="text-xs text-muted-foreground">or subscribe</span>
      </div>
    );
  }

  return <Badge variant="outline">{priceStr}</Badge>;
}
```

### 13.4 VideoCard Component (List View)

```typescript
interface VideoCardProps {
  video: VideoListItemOut;
  viewerHasSubscription: boolean;
}
```

**Component tree:**
```
VideoCard
  ├── Card (className="overflow-hidden")
  │   ├── Link to="/videos/{video.video_id}" (wraps entire card)
  │   ├── AspectRatio (ratio=16/9)
  │   │   ├── img (src=video.thumbnail_url, alt=video.title)
  │   │   └── [video.duration_seconds] DurationBadge (absolute bottom-right)
  │   └── CardContent
  │       ├── h3 (className="font-semibold line-clamp-2") video.title
  │       ├── VideoPriceBadge (priceCents, accessMode, entitled, accessReason)
  │       └── [viewerHasSubscription && video.access_mode in (subscriber_only, subscriber_free)]
  │           └── <span className="text-xs text-green-600">Included with your subscription</span>
  └── (no query keys — data comes from parent list query)
```

### 13.5 SubscriptionBanner Component (List Header)

```typescript
interface SubscriptionBannerProps {
  viewerHasSubscription: boolean;
  creatorName?: string;
}
```

Renders a banner above the video grid when the viewer has an active subscription:
```
┌─────────────────────────────────────────────────────────────────┐
│ ✦ You're subscribed to {creatorName}! Subscriber content        │
│   is included with your subscription.                           │
└─────────────────────────────────────────────────────────────────┘
```

When NOT subscribed, renders nothing (returns null). The subscribe CTA is on individual videos, not at the list level.

---

## 14. Related Tickets

- **MON-001**: VOD pay-per-view (required — provides purchase flow and entitlement table)
- **MON-002**: Tip ledger integration (same LEDGER# pattern; unrelated to subscription gating)
- **MON-003**: Creator earnings dashboard (subscription VOD revenue shows in earnings via subscription payment LEDGER entries, NOT via subscription access records)
- **MON-004**: Creator payouts (subscription-granted access does not generate direct payout-eligible credits — only subscription payments do, and those are handled by the subscription billing system)

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/services/vod_purchase.py` | 21, 131 | ALREADY IMPLEMENTS subscription check: imports `has_active_subscription` from `subscription_access` (line 21); `check_vod_access` (line 131) already combines purchase entitlement + subscription check + access_mode logic |
| `app/services/subscription_access.py` | 55, 72, 77 | EXISTS: `has_active_subscription` (55), `can_access_creator` (72) — already used by vod_purchase.py |
| `app/models_video.py` | 94 | EXISTS: `access_mode: Optional[str]` with values `"free"`, `"ppv"`, `"subscriber_only"`, `"subscriber_free"` — already defined |
| `app/services/vod_purchase.py` | 241 | EXISTS: `_record_subscription_access()` — records subscription-based access events |
| `scripts/local-ddb-init.py` | 584 | EXISTS: `VodEntitlements` table with GSIs |
| `app/core/settings.py` | 1076 | EXISTS: `vod_entitlements_table_name` setting |
<!-- NOTE: MON-005's core functionality (subscription-aware entitlement checks via access_mode) is ALREADY IMPLEMENTED in app/services/vod_purchase.py check_vod_access(). The ticket should be marked as Complete or verified against remaining frontend work. -->

---

## Testing Strategy

### Unit Tests (`tests/test_subscription_gated_vod.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_subscriber_access_free` | Subscriber access free |
| 2 | `test_non_subscriber_requires_purchase` | Non subscriber requires purchase |
| 3 | `test_subscriber_only_mode_blocks_purchase` | Subscriber only mode blocks purchase |
| 4 | `test_access_mode_free_for_all` | Access mode free for all |
| 5 | `test_ppv_only_ignores_subscription` | Ppv only ignores subscription |
| 6 | `test_expired_subscription_no_access` | Expired subscription no access |
| 7 | `test_entitlement_check_priority_order` | Entitlement check priority order |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/subscription-gated-vod.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~12 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `SUBSCRIPTION_VOD_GATING_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| MON-001 | VOD Pay-Per-View for entitlement infrastructure | Hard |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Sequential -- requires MON-001 merged first. Extends check_vod_entitlement() with subscription awareness.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: SUBSCRIPTION_VOD_GATING_ENABLED=true
- [ ] Service file created/modified: `app/services/vod_entitlements.py (extended)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/subscription-gated-vod.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_subscription_gated_vod.py`
