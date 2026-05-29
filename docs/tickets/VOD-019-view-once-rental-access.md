# VOD-019: View-Once / Rental / Download Access Tiers — Granular Purchase Options

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 6-9 days  
**Dependencies**: MON-001 (VOD pay-per-view), VOD-012 (MP4 download)

---

## 1. Overview & Motivation

### The Gap

The pay-per-view system (MON-001) treats all purchases identically: a viewer pays `price_cents`, receives a permanent entitlement, and can re-watch indefinitely. The `purchase_video()` function (`app/services/vod_purchase.py`, line 398) writes an entitlement record with no expiry and no view limit. The `check_entitlement_purchase_only()` function (line 316) returns `True` for any record that exists, regardless of age or usage.
<!-- NOTE: Line numbers updated — purchase_video is at line 398 (was 263 in original spec), check_entitlement_purchase_only is at line 316 (was 219). Both functions now implement VOD-019 purchase tiers with purchase_type, views_remaining, expires_at, and download_allowed support. -->

This one-size-fits-all model misses common video commerce patterns:

1. **View-once (rental)**: Pay less, watch exactly once. Common for live event replays, premium tutorials, and exclusive drops. After the single playback completes, access is revoked.

2. **Time-limited rental**: Pay a lower price for access during a limited window (e.g., 48 hours). Common for movie rentals (iTunes, Google Play, Amazon).

3. **Permanent purchase**: The current behavior — pay full price, own forever. This becomes the "buy" option alongside cheaper rent/view-once options.

4. **Download purchase**: Permanent access plus a downloadable MP4 file. VOD-012 added download infrastructure (`download_mp4_key`, `download_mp4_status`, `mint_video_download_url`), but there is no purchase tier that explicitly grants download rights. Currently, `allow_download` is a global video setting, not a per-entitlement permission.

The `vod_entitlements` table has a `ttl` field (mentioned in the MON-001 spec but set to 0 for all purchases), and the existing `check_entitlement_purchase_only()` does not check TTL at all — it was deferred from MON-001. The infrastructure is partially there but not wired up.

### Why This Is Needed

1. **Price discrimination**: Creators can offer the same video at multiple price points. A viewer willing to pay $2.99 for a single watch generates revenue that would be lost if the only option is $9.99 permanent purchase.

2. **Urgency and scarcity**: View-once and rental create urgency ("watch before your window expires"), driving faster purchase decisions.

3. **Download monetization**: Creators can charge a premium for downloadable content. The download includes the MP4 generation cost and gives buyers an offline copy.

4. **Industry standard**: Apple TV+, Google Play, Amazon Prime Video all offer rent vs. buy vs. download tiers. Not supporting them puts the platform at a competitive disadvantage.

### Architecture After This Change

```
                     Purchase Type Decision Tree
                     ──────────────────────────────

Viewer selects purchase option
          │
          ▼
  ┌───────────────────────────────────────────────────────────┐
  │  Available Purchase Types (creator-configured per video)  │
  │                                                           │
  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │
  │  │ View Once   │  │  Rental      │  │  Permanent      │  │
  │  │ $1.99       │  │  $2.99       │  │  $9.99          │  │
  │  │ 1 playback  │  │  48 hours    │  │  Unlimited      │  │
  │  └──────┬──────┘  └──────┬───────┘  └──────┬──────────┘  │
  │         │                │                  │             │
  │  ┌──────┴────────────────┴──────────────────┴──────────┐  │
  │  │              ┌───────────────────┐                   │  │
  │  │              │  Download         │                   │  │
  │  │              │  $12.99           │                   │  │
  │  │              │  Unlimited + MP4  │                   │  │
  │  │              └───────────────────┘                   │  │
  │  └─────────────────────────────────────────────────────┘  │
  └───────────────────────────────────────────────────────────┘
          │
          ▼
  ┌───────────────────┐
  │ Entitlement Record│
  │                   │
  │ purchase_type:    │
  │   view_once       │──→ views_remaining=1, short TTL
  │   rental          │──→ expires_at = now + rental_hours
  │   permanent       │──→ no expiry, no view limit
  │   download        │──→ no expiry + download_allowed=true
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐
  │ Playback Check    │
  │                   │
  │ view_once:        │──→ views_remaining > 0 ? PLAY : REVOKED
  │ rental:           │──→ expires_at > now ? PLAY : EXPIRED
  │ permanent:        │──→ PLAY (always)
  │ download:         │──→ PLAY + download enabled
  └───────────────────┘
```

### Detailed Data Flow — View-Once Purchase + Playback

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── POST /ui/videos/{id}/purchase  >│                                    │
  │   {payment_method_id,             │                                    │
  │    purchase_type: "view_once"}    │                                    │
  │                                   │── get_video(id) ─────────────────>│
  │                                   │<── video ─────────────────────────│
  │                                   │                                    │
  │                                   │── validate:                        │
  │                                   │   "view_once" in available_types  │
  │                                   │   view_once_price_cents > 0       │
  │                                   │   PM valid                        │
  │                                   │                                    │
  │                                   │── write entitlement ─────────────>│
  │                                   │   purchase_type: "view_once"       │
  │                                   │   views_remaining: 1               │
  │                                   │   expires_at: 0 (no time limit)    │
  │                                   │   download_allowed: false          │
  │                                   │                                    │
  │                                   │── write LEDGER debit + credit ───>│
  │                                   │                                    │
  │<── 200 { purchase_id,             │                                    │
  │     purchase_type: "view_once",   │                                    │
  │     views_remaining: 1,           │                                    │
  │     expires_at: null }            │                                    │
  │                                   │                                    │
  │── GET /ui/videos/{id} ───────────>│                                    │
  │                                   │── check_entitlement ─────────────>│
  │                                   │   views_remaining=1 > 0 → entitled│
  │                                   │── issue playback token ───────────│
  │                                   │   (single-use flag)               │
  │<── 200 { entitled: true,          │                                    │
  │     views_remaining: 1,           │                                    │
  │     playback_url }                │                                    │
  │                                   │                                    │
  │── [viewer watches video] ─────────│                                    │
  │                                   │                                    │
  │── POST /ui/videos/{id}/           │                                    │
  │   playback-complete ─────────────>│                                    │
  │                                   │── update entitlement ────────────>│
  │                                   │   SET views_remaining = 0          │
  │                                   │<── ok ────────────────────────────│
  │                                   │                                    │
  │<── 200 { views_remaining: 0 }     │                                    │
  │                                   │                                    │
  │── GET /ui/videos/{id} ───────────>│                                    │
  │                                   │── check_entitlement ─────────────>│
  │                                   │   views_remaining=0 → NOT entitled│
  │<── 200 { entitled: false,         │                                    │
  │     access_reason: "view_once_    │                                    │
  │     consumed" }                   │                                    │
```

### Detailed Data Flow — Rental Expiry

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── POST /ui/videos/{id}/purchase  >│                                    │
  │   {purchase_type: "rental"}       │                                    │
  │                                   │── write entitlement ─────────────>│
  │                                   │   purchase_type: "rental"          │
  │                                   │   expires_at: now + 48h            │
  │                                   │   views_remaining: -1 (unlimited)  │
  │                                   │                                    │
  │<── 200 { expires_at: 1748563200 } │                                    │
  │                                   │                                    │
  │── [within 48h] GET /videos/{id} ->│                                    │
  │                                   │── check_entitlement ─────────────>│
  │                                   │   expires_at > now → entitled      │
  │<── 200 { entitled: true,          │                                    │
  │     rental_expires_at: 1748563200,│                                    │
  │     rental_remaining_seconds: ... }│                                   │
  │                                   │                                    │
  │── [after 48h] GET /videos/{id} -->│                                    │
  │                                   │── check_entitlement ─────────────>│
  │                                   │   expires_at < now → NOT entitled  │
  │<── 200 { entitled: false,         │                                    │
  │     access_reason: "rental_       │                                    │
  │     expired" }                    │                                    │
```

### DDB Partition Key Distribution

```
vod_entitlements table — after VOD-019:

  PK (HASH)                   SK (RANGE)              purchase_type    views_remaining  expires_at
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  USER#alice123                VIDEO#vid_001           permanent        -1               0
  USER#alice123                VIDEO#vid_002           rental           -1               1748563200
  USER#bob456                  VIDEO#vid_001           view_once        0                0
  USER#bob456                  VIDEO#vid_003           download         -1               0
  USER#charlie789              VIDEO#vid_001           rental           -1               1748649600
  USER#charlie789              VIDEO#vid_004           view_once        1                0

  Key observations:
  - views_remaining = -1 means unlimited (rental/permanent/download)
  - views_remaining = 0 means consumed (view_once after watching)
  - views_remaining = 1 means 1 view left (view_once before watching)
  - expires_at = 0 means no expiry (permanent/view_once/download)
  - expires_at > 0 means time-limited (rental)
  - download_allowed only true for "download" purchase_type
```

---

## 2. Current State Analysis

### 2.1 Entitlement Record Schema (MON-001)

From `app/services/vod_purchase.py`, `purchase_video()` (line 398+):
<!-- NOTE: Line number updated from 298 to 398; function now includes purchase_type, views_remaining, expires_at, download_allowed fields -->

```python
entitlement_item: Dict[str, Any] = {
    "pk": pk,                          # USER#{buyer_id}
    "sk": sk,                          # VIDEO#{video_id}
    "video_id": video_id,
    "buyer_id": buyer_id,
    "seller_id": seller_id,
    "purchase_id": purchase_id,
    "amount_cents": price_cents,
    "currency": "USD",
    "grant_type": "purchase",
    "created_at": ts,
}
```

Missing fields for VOD-019: `purchase_type`, `views_remaining`, `expires_at`, `download_allowed`.

### 2.2 Entitlement Check (MON-001 + MON-005)

From `app/services/vod_purchase.py`, `check_entitlement_purchase_only()` (line 316+):
<!-- NOTE: Line number updated from 219 to 316; function now returns EntitlementStatus (not bool), validating views_remaining and expires_at -->

```python
def check_entitlement_purchase_only(*, user_id: str, video_id: str) -> bool:
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")
    if not item:
        return False
    if item.get("grant_type") == "subscription":
        return False
    return True
```

This function returns `True` for any non-subscription entitlement without checking `views_remaining` or `expires_at`. After VOD-019, it must validate both.

### 2.3 VideoMetadataModel Pricing Fields (MON-001)

From `app/models_video.py` (lines 92-96):

```python
price_cents: Optional[int] = None
access_mode: Optional[str] = None
purchase_count: int = 0
revenue_cents: int = 0
```

Only `price_cents` exists — a single price for all purchase types. VOD-019 adds per-type pricing fields.

### 2.4 Purchase Endpoint (MON-001)

From `app/routers/video_listing.py`, `purchase_video_endpoint()` (line 1117):
<!-- NOTE: Line number updated from 509 to 1117; VodPurchaseIn now at line 1023 with purchase_type field -->

```python
class VodPurchaseIn(BaseModel):
    payment_method_id: Optional[str] = None
    idempotency_key: Optional[str] = None
```

No `purchase_type` field. The purchase endpoint creates a permanent entitlement regardless.

### 2.5 Download Infrastructure (VOD-012)

From `app/models_video.py` (lines 103-108):

```python
allow_download: bool = False
download_mp4_key: str = ""
download_mp4_size_bytes: int = 0
download_mp4_status: str = ""  # "", "generating", "ready", "failed"
download_count: int = 0
```

The `allow_download` flag is a global video setting. The download endpoint (`GET /ui/videos/{id}/download`, `app/routers/video_listing.py` line 773) checks `video.allow_download` but does NOT check whether the viewer's entitlement includes download rights.
<!-- NOTE: Line number updated from 369 to 773 -->

### 2.6 Playback Token Issuance

From `app/routers/video_listing.py`, `_try_issue_playback_token()` (line 283):
<!-- NOTE: Line number updated from 224 to 283 -->

```python
def _try_issue_playback_token(video: VideoMetadataModel, user_sub: str):
    result = issue_playback_entitlement(
        tenant_id=video.owner_user_id,
        asset_id=video.id,
        session_id=f"web_{user_sub}",
        device_id="browser",
        profile="auto",
        audience="playback",
        ttl_seconds=ttl,
    )
```

No concept of single-use tokens or purchase-type-aware TTL. For view-once, the token TTL should be limited to the video duration + buffer.

---

## 3. Technical Design

### 3.1 VideoMetadataModel Pricing Changes

Add per-type pricing fields:

```python
class VideoMetadataModel(BaseModel):
    # ... existing fields ...

    # Purchase tiers (VOD-019)
    available_purchase_types: List[str] = Field(default_factory=list)
    # Valid types: "view_once", "rental", "permanent", "download"
    # Empty list = only "permanent" (backward compatible)

    view_once_price_cents: Optional[int] = None
    rental_price_cents: Optional[int] = None
    rental_duration_hours: int = 48          # Default: 48-hour rental
    download_price_cents: Optional[int] = None
    # price_cents remains the "permanent" price (backward compatible)
```

Add validation:

```python
@model_validator(mode="after")
def _validate_purchase_types(self) -> "VideoMetadataModel":
    valid_types = {"view_once", "rental", "permanent", "download"}
    for pt in self.available_purchase_types:
        if pt not in valid_types:
            raise ValueError(f"Invalid purchase type: {pt}")

    # Download price must be >= permanent price
    if (self.download_price_cents is not None
        and self.price_cents is not None
        and self.download_price_cents < self.price_cents):
        raise ValueError("download_price_cents must be >= price_cents (permanent price)")

    # Rental duration range: 1-720 hours (1 hour to 30 days)
    if self.rental_duration_hours < 1 or self.rental_duration_hours > 720:
        raise ValueError("rental_duration_hours must be between 1 and 720")

    return self
```

### 3.2 Entitlement Record Schema Update

Add fields to the entitlement item written by `purchase_video()`:

```python
entitlement_item: Dict[str, Any] = {
    "pk": pk,
    "sk": sk,
    "video_id": video_id,
    "buyer_id": buyer_id,
    "seller_id": seller_id,
    "purchase_id": purchase_id,
    "amount_cents": price_cents,
    "currency": "USD",
    "grant_type": "purchase",
    "created_at": ts,
    # VOD-019 additions:
    "purchase_type": purchase_type,          # "view_once" | "rental" | "permanent" | "download"
    "views_remaining": views_remaining,       # -1 = unlimited, 1 = one view left, 0 = consumed
    "expires_at": expires_at,                 # 0 = no expiry, >0 = Unix timestamp
    "download_allowed": download_allowed,     # True only for "download" purchase type
}
```

**Backward compatibility**: Existing entitlement records lack `purchase_type`, `views_remaining`, `expires_at`, `download_allowed`. The updated check function treats missing fields as the permanent defaults: `purchase_type="permanent"`, `views_remaining=-1`, `expires_at=0`, `download_allowed=False`.

### 3.3 Updated Entitlement Check

**File**: `app/services/vod_purchase.py`

Replace `check_entitlement_purchase_only()` with a richer check that validates view count and expiry:

```python
class EntitlementStatus:
    """Rich entitlement check result (VOD-019).

    Extends the simple boolean check with purchase type details
    so the frontend can display rental countdown, view-once badge,
    or download button.
    """
    def __init__(
        self,
        *,
        entitled: bool,
        purchase_type: str = "permanent",      # "view_once" | "rental" | "permanent" | "download"
        views_remaining: int = -1,              # -1 = unlimited
        expires_at: int = 0,                    # 0 = no expiry
        download_allowed: bool = False,
        reason: str = "valid",                  # "valid" | "consumed" | "expired" | "not_purchased"
    ):
        self.entitled = entitled
        self.purchase_type = purchase_type
        self.views_remaining = views_remaining
        self.expires_at = expires_at
        self.download_allowed = download_allowed
        self.reason = reason


def check_entitlement_purchase_only(*, user_id: str, video_id: str) -> EntitlementStatus:
    """Check for a PURCHASE entitlement with VOD-019 validations.

    Returns EntitlementStatus with:
    - entitled=True if purchase exists AND is still valid (not consumed, not expired)
    - entitled=False if no purchase, consumed (view_once), or expired (rental)
    - Subscription records are skipped (checked separately by check_vod_access).

    Backward compatible: Records without purchase_type/views_remaining/expires_at
    are treated as permanent (unlimited, no expiry).
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")

    if not item:
        return EntitlementStatus(entitled=False, reason="not_purchased")

    # Skip subscription records
    if item.get("grant_type") == "subscription":
        return EntitlementStatus(entitled=False, reason="not_purchased")

    purchase_type = item.get("purchase_type", "permanent")
    views_remaining = int(item.get("views_remaining", -1))
    expires_at = int(item.get("expires_at", 0))
    download_allowed = bool(item.get("download_allowed", False))

    # Check view-once consumption
    if purchase_type == "view_once" and views_remaining == 0:
        return EntitlementStatus(
            entitled=False,
            purchase_type="view_once",
            views_remaining=0,
            reason="consumed",
        )

    # Check rental expiry
    if purchase_type == "rental" and expires_at > 0 and expires_at < now_ts():
        return EntitlementStatus(
            entitled=False,
            purchase_type="rental",
            expires_at=expires_at,
            reason="expired",
        )

    return EntitlementStatus(
        entitled=True,
        purchase_type=purchase_type,
        views_remaining=views_remaining,
        expires_at=expires_at,
        download_allowed=download_allowed,
        reason="valid",
    )
```

### 3.4 Updated check_vod_access()

The cascade's step 3 changes from a simple boolean to an `EntitlementStatus`:

```python
def check_vod_access(
    *,
    user_id: str,
    video_id: str,
    video: "VideoMetadataModel",
) -> VodAccessResult:
    # ... steps 1, 2 unchanged ...

    # 3. Explicit purchase check (with VOD-019 validations)
    ent_status = check_entitlement_purchase_only(user_id=user_id, video_id=video_id)
    if ent_status.entitled:
        return VodAccessResult(
            entitled=True,
            reason="purchased",
            purchase_type=ent_status.purchase_type,
            views_remaining=ent_status.views_remaining,
            expires_at=ent_status.expires_at,
            download_allowed=ent_status.download_allowed,
        )

    # If entitlement exists but is consumed/expired, store the reason
    # for the frontend to show appropriate messaging
    consumed_reason = ent_status.reason if ent_status.reason in ("consumed", "expired") else None

    # 4. Subscription check ... (unchanged)

    # 5. Not entitled — include consumed/expired reason if applicable
    result = VodAccessResult(
        entitled=False,
        reason="none",
        # ... existing fields ...
    )
    if consumed_reason:
        result.reason = consumed_reason
    return result
```

Add `purchase_type`, `views_remaining`, `expires_at`, `download_allowed` to `VodAccessResult`:

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
        ads_enabled: bool = False,
        # VOD-019:
        purchase_type: str = "permanent",
        views_remaining: int = -1,
        expires_at: int = 0,
        download_allowed: bool = False,
    ):
        # ... existing ...
        self.purchase_type = purchase_type
        self.views_remaining = views_remaining
        self.expires_at = expires_at
        self.download_allowed = download_allowed
```

### 3.5 Updated Purchase Flow

**File**: `app/services/vod_purchase.py`, `purchase_video()` function

```python
def purchase_video(
    *,
    buyer_id: str,
    video_id: str,
    price_cents: int,
    seller_id: str,
    payment_method_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    purchase_type: str = "permanent",        # VOD-019
    rental_duration_hours: int = 48,          # VOD-019
) -> Dict[str, Any]:
    """Purchase a video with purchase type support (VOD-019).

    Purchase types:
    - "view_once": views_remaining=1, expires_at=0
    - "rental": views_remaining=-1, expires_at=now+rental_hours
    - "permanent": views_remaining=-1, expires_at=0
    - "download": views_remaining=-1, expires_at=0, download_allowed=True
    """
    # ... existing idempotency check ...

    ts = now_ts()
    purchase_id = f"vpurch_{uuid.uuid4().hex}"

    # Compute entitlement fields based on purchase type
    views_remaining = -1   # unlimited by default
    expires_at = 0         # no expiry by default
    download_allowed = False

    if purchase_type == "view_once":
        views_remaining = 1
    elif purchase_type == "rental":
        expires_at = ts + (rental_duration_hours * 3600)
    elif purchase_type == "download":
        download_allowed = True

    entitlement_item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "video_id": video_id,
        "buyer_id": buyer_id,
        "seller_id": seller_id,
        "purchase_id": purchase_id,
        "amount_cents": price_cents,
        "currency": "USD",
        "grant_type": "purchase",
        "created_at": ts,
        # VOD-019:
        "purchase_type": purchase_type,
        "views_remaining": views_remaining,
        "expires_at": expires_at,
        "download_allowed": download_allowed,
    }

    # ... rest of purchase flow (write entitlement, ledger entries, counters) ...

    return {
        "video_id": video_id,
        "already_owned": False,
        "granted_at": ts,
        "grant_type": "purchase",
        "amount_cents": price_cents,
        "purchase_id": purchase_id,
        # VOD-019:
        "purchase_type": purchase_type,
        "views_remaining": views_remaining,
        "expires_at": expires_at if expires_at > 0 else None,
        "download_allowed": download_allowed,
    }
```

### 3.6 Playback Complete Endpoint

New endpoint to consume a view-once entitlement:

```python
@router.post("/{video_id}/playback-complete")
def record_playback_complete(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Record that a viewer has completed playback (VOD-019).

    For view_once purchases: decrements views_remaining to 0, revoking access.
    For other purchase types: no-op (logged for analytics).

    Called by the frontend video player when the video ends or when
    the player detects sufficient playback progress (>90% watched).
    """
    user_sub = user["user_sub"]
    pk = f"USER#{user_sub}"
    sk = f"VIDEO#{video_id}"

    # Get current entitlement
    resp = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")

    if not item:
        raise HTTPException(404, "No entitlement found")

    purchase_type = item.get("purchase_type", "permanent")
    views_remaining = int(item.get("views_remaining", -1))

    if purchase_type == "view_once" and views_remaining > 0:
        # Consume the view
        T.vod_entitlements.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET views_remaining = :zero, consumed_at = :ca",
            ExpressionAttributeValues={
                ":zero": 0,
                ":ca": now_ts(),
            },
            ConditionExpression="views_remaining > :zero_check",
            ExpressionAttributeValues={
                ":zero": 0,
                ":ca": now_ts(),
                ":zero_check": 0,
            },
        )
        return {"ok": True, "views_remaining": 0, "purchase_type": "view_once"}

    return {"ok": True, "views_remaining": views_remaining, "purchase_type": purchase_type}
```

**Concurrency safety**: The `ConditionExpression="views_remaining > :zero_check"` ensures that if two concurrent playback-complete requests arrive (e.g., duplicate network call), only one succeeds in decrementing. The second request gets a `ConditionalCheckFailedException`, which is caught and returned as a no-op `views_remaining=0` response.

### 3.7 Updated Purchase Endpoint

**File**: `app/routers/video_listing.py`

```python
class VodPurchaseIn(BaseModel):
    payment_method_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    purchase_type: str = Field(
        default="permanent",
        pattern=r"^(view_once|rental|permanent|download)$"
    )


@router.post("/{video_id}/purchase", response_model=VodPurchaseOut)
def purchase_video_endpoint(video_id: str, body: VodPurchaseIn, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    # ... existing ownership/free/status/subscriber checks ...

    # VOD-019: Validate purchase type is available for this video
    available_types = getattr(video, "available_purchase_types", []) or ["permanent"]
    if body.purchase_type not in available_types:
        raise HTTPException(400, f"Purchase type '{body.purchase_type}' not available for this video")

    # VOD-019: Resolve price based on purchase type
    price = _resolve_price(video, body.purchase_type)
    if price is None or price <= 0:
        raise HTTPException(400, f"No price configured for purchase type '{body.purchase_type}'")

    # VOD-019: For "download" type, verify download infrastructure exists
    if body.purchase_type == "download":
        if not video.allow_download or video.download_mp4_status != "ready":
            raise HTTPException(400, "Download not available for this video")

    result = purchase_video(
        buyer_id=user_sub,
        video_id=video_id,
        price_cents=price,
        seller_id=video.owner_user_id,
        payment_method_id=body.payment_method_id,
        idempotency_key=body.idempotency_key,
        purchase_type=body.purchase_type,
        rental_duration_hours=getattr(video, "rental_duration_hours", 48),
    )
    return VodPurchaseOut(**result)


def _resolve_price(video, purchase_type: str) -> Optional[int]:
    """Resolve the correct price for a purchase type."""
    if purchase_type == "view_once":
        return getattr(video, "view_once_price_cents", None)
    elif purchase_type == "rental":
        return getattr(video, "rental_price_cents", None)
    elif purchase_type == "download":
        return getattr(video, "download_price_cents", None)
    else:  # permanent
        return video.price_cents
```

### 3.8 Updated Download Endpoint

**File**: `app/routers/video_listing.py`, `download_video_endpoint()` (line 369)

Add entitlement check for download permission:

```python
@router.get("/{video_id}/download")
def download_video_endpoint(video_id: str, user=Depends(require_ui_session)):
    # ... existing checks ...

    user_sub = user["user_sub"]
    is_owner = video.owner_user_id == user_sub

    if not is_owner:
        # VOD-019: Check download entitlement
        ent = check_entitlement_purchase_only(user_id=user_sub, video_id=video_id)
        if not ent.entitled or not ent.download_allowed:
            raise HTTPException(403, "Download access not included in your purchase")

    # ... rest of download logic ...
```

### 3.9 Playback Token TTL Adjustment

For view-once purchases, the playback token TTL should be limited:

```python
def _try_issue_playback_token(video, user_sub, entitlement_status=None):
    # Determine TTL based on purchase type
    ttl = getattr(S, "video_playback_token_ttl_seconds", 300) or 300

    if entitlement_status and entitlement_status.purchase_type == "view_once":
        # View-once: token TTL = video duration + 30 min buffer
        duration = video.duration_seconds or 3600  # default 1 hour
        ttl = int(duration) + 1800  # 30 min buffer

    result = issue_playback_entitlement(
        # ... existing params ...
        ttl_seconds=ttl,
    )
    return result.get("token"), result.get("expires_at_epoch")
```

**Call site update**: The existing call at `app/routers/video_listing.py` line 313 uses `_try_issue_playback_token(video, user_sub)`. It must be updated to pass `entitlement_status` so the TTL adjustment takes effect. Section 12.3 extends this signature further with `client_ip` and `user_agent` parameters, which also require updating the same call site.

### 3.10 Updated VideoDetailOut Response

Add purchase tier fields:

```python
class VideoDetailOut(BaseModel):
    # ... existing fields ...

    # Purchase tiers (VOD-019)
    available_purchase_types: List[str] = Field(default_factory=list)
    view_once_price_cents: Optional[int] = None
    rental_price_cents: Optional[int] = None
    rental_duration_hours: int = 48
    download_price_cents: Optional[int] = None
    # Entitlement details (when entitled)
    purchase_type: str = "permanent"
    views_remaining: int = -1
    rental_expires_at: Optional[int] = None
    rental_remaining_seconds: Optional[int] = None
    download_allowed: bool = False
```

### 3.11 Updated Video Pricing Endpoint

**File**: `app/routers/video_listing.py`, `set_video_pricing()` (line 1220)
<!-- NOTE: Line number updated from 566 to 1220 -->

```python
class VodPricingIn(BaseModel):
    price_cents: Optional[int] = Field(default=None, ge=0)
    access_mode: Optional[str] = Field(
        default=None,
        pattern=r"^(free|ppv|subscriber_only|subscriber_free|ad_supported)$"
    )
    # VOD-019:
    available_purchase_types: Optional[List[str]] = None
    view_once_price_cents: Optional[int] = Field(default=None, ge=0)
    rental_price_cents: Optional[int] = Field(default=None, ge=0)
    rental_duration_hours: Optional[int] = Field(default=None, ge=1, le=720)
    download_price_cents: Optional[int] = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_pricing(self) -> "VodPricingIn":
        valid_types = {"view_once", "rental", "permanent", "download"}
        if self.available_purchase_types:
            for pt in self.available_purchase_types:
                if pt not in valid_types:
                    raise ValueError(f"Invalid purchase type: {pt}")

        # Download price must be >= permanent price if both are set
        if (self.download_price_cents is not None
            and self.price_cents is not None
            and self.download_price_cents < self.price_cents):
            raise ValueError("download_price_cents must be >= price_cents")

        return self
```

### 3.12 Frontend Types

```typescript
export interface VideoDetailResponse {
  // ... existing fields ...

  // Purchase tiers (VOD-019)
  available_purchase_types: string[];
  view_once_price_cents?: number;
  rental_price_cents?: number;
  rental_duration_hours: number;
  download_price_cents?: number;
  // Entitlement details
  purchase_type: string;
  views_remaining: number;
  rental_expires_at?: number;
  rental_remaining_seconds?: number;
  download_allowed: boolean;
}

export interface VodPurchaseRequest {
  payment_method_id?: string;
  idempotency_key?: string;
  purchase_type: "view_once" | "rental" | "permanent" | "download";
}

export interface VodPurchaseResponse {
  video_id: string;
  already_owned: boolean;
  granted_at: number;
  grant_type: string;
  amount_cents: number;
  purchase_id: string;
  purchase_type: string;
  views_remaining: number;
  expires_at?: number;
  download_allowed: boolean;
}
```

### 3.13 Frontend Purchase Options UI

```
PurchaseOptionsPanel
├── useQuery(["video", videoId])
│
├── [available_purchase_types includes "view_once"]
│   └── PurchaseCard
│       ├── title: "Watch Once"
│       ├── price: "$1.99"
│       ├── description: "Single viewing — access revoked after playback"
│       └── Button: "Rent for $1.99"
│
├── [available_purchase_types includes "rental"]
│   └── PurchaseCard
│       ├── title: "48-Hour Rental"
│       ├── price: "$2.99"
│       ├── description: "Unlimited views for 48 hours"
│       └── Button: "Rent for $2.99"
│
├── [available_purchase_types includes "permanent"]
│   └── PurchaseCard
│       ├── title: "Own Forever"
│       ├── price: "$9.99"
│       ├── description: "Unlimited views, no expiration"
│       └── Button: "Buy for $9.99"
│
├── [available_purchase_types includes "download"]
│   └── PurchaseCard
│       ├── title: "Own + Download"
│       ├── price: "$12.99"
│       ├── description: "Unlimited views + downloadable MP4"
│       └── Button: "Buy + Download for $12.99"
│
└── PaymentMethodSelector (shared across all options)
```

Entitlement status badges on the video player page:

```
[view_once, views_remaining=1] → Badge: "1 view remaining"
[view_once, views_remaining=0] → Badge: "View consumed" + re-purchase CTA
[rental, expires_at > now]     → Badge: "Access expires in 47h 23m" (countdown)
[rental, expires_at < now]     → Badge: "Rental expired" + re-purchase CTA
[permanent]                    → Badge: "Owned"
[download]                     → Badge: "Owned" + "Download MP4" button
```

---

## 4. Implementation Plan

<!-- NOTE: All steps below have been implemented. Key existing code:
- `app/models_video.py:143-147` — available_purchase_types, view_once_price_cents, rental_price_cents, rental_duration_hours, download_price_cents all exist
- `app/services/vod_purchase.py:32-55` — EntitlementStatus class exists with purchase_type, views_remaining, expires_at, download_allowed
- `app/services/vod_purchase.py:61-128` — VodAccessResult class exists with purchase_type, views_remaining, expires_at, download_allowed fields
- `app/services/vod_purchase.py:316` — check_entitlement_purchase_only() returns EntitlementStatus (not bool)
- `app/services/vod_purchase.py:398` — purchase_video() accepts purchase_type, rental_duration_hours params
- `app/services/vod_purchase.py:636` — record_playback_complete() function exists
- `app/routers/video_listing.py:1023` — VodPurchaseIn model includes purchase_type field
- `app/routers/video_listing.py:1027` — purchase_type Field with pattern validation
- `app/routers/video_listing.py:1104` — _resolve_price() helper function exists
- `app/routers/video_listing.py:1198-1199` — POST /{video_id}/playback-complete endpoint exists
- `app/routers/video_listing.py:112` — VideoDetailOut includes available_purchase_types
- `app/routers/video_listing.py:117` — VideoDetailOut includes purchase_type
- `app/routers/video_listing.py:1068` — VodPricingIn includes available_purchase_types
- E2E: `frontend/e2e/vod-purchase-tiers.spec.ts` exists
-->

### Step 1: Extend VideoMetadataModel

**File**: `app/models_video.py`

Add after `revenue_cents` (line 96):
<!-- NOTE: These fields now exist at app/models_video.py:143-147 -->
```python
# Purchase tiers (VOD-019)
available_purchase_types: List[str] = Field(default_factory=list)
view_once_price_cents: Optional[int] = None
rental_price_cents: Optional[int] = None
rental_duration_hours: int = 48
download_price_cents: Optional[int] = None
```

### Step 2: Update Video Metadata Store Serialization

**File**: `app/services/video_metadata_store.py`

Add `"view_once_price_cents"`, `"rental_price_cents"`, `"rental_duration_hours"`, `"download_price_cents"` to numeric fields. Handle `available_purchase_types` (list of strings) in serialization.

### Step 3: Update Entitlement Check

**File**: `app/services/vod_purchase.py`

- Add `EntitlementStatus` class
- Replace `check_entitlement_purchase_only()` return type from `bool` to `EntitlementStatus`
- Update callers in `check_vod_access()` to use `.entitled` property
- Update `purchase_video()` to accept and apply `purchase_type`
- Add `views_remaining`, `expires_at`, `download_allowed` to `VodAccessResult`

### Step 4: Add Playback Complete Endpoint

**File**: `app/routers/video_listing.py`

Add `POST /ui/videos/{video_id}/playback-complete` after the existing purchase endpoints.

### Step 5: Update Purchase Endpoint

**File**: `app/routers/video_listing.py`

- Add `purchase_type` to `VodPurchaseIn`
- Add `_resolve_price()` helper
- Add purchase type validation against `available_purchase_types`
- Add download infrastructure check for `download` type

### Step 6: Update Download Endpoint

**File**: `app/routers/video_listing.py`

Add entitlement check for `download_allowed` in `download_video_endpoint()`.

### Step 7: Update Pricing Endpoint

**File**: `app/routers/video_listing.py`

Extend `VodPricingIn` with per-type pricing fields and `available_purchase_types`.

### Step 8: Update VideoDetailOut

**File**: `app/routers/video_listing.py`

Add purchase tier fields to `VideoDetailOut` and populate them in `_video_to_detail()`.

### Step 9: Frontend Types and API

**File**: `frontend/src/api/types.ts` — Add/update purchase tier types  
**File**: `frontend/src/api/endpoints/vod.ts` — Add `playbackComplete()` API wrapper, update `purchaseVideo()` to include `purchase_type`

### Step 10: Frontend Purchase Options UI

**File**: `frontend/src/pages/vod/VideoPlayerPage.tsx` — Add `PurchaseOptionsPanel` with multi-tier cards, rental countdown timer, view-once badge, download button

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/models_video.py` | Add pricing tier fields | ~10 |
| `app/services/video_metadata_store.py` | Serialize new fields | ~20 |
| `app/services/vod_purchase.py` | EntitlementStatus + purchase_type support | ~120 |
| `app/routers/video_listing.py` | Playback-complete + pricing + download checks | ~150 |
| `frontend/src/api/types.ts` | Update types | ~30 |
| `frontend/src/api/endpoints/vod.ts` | Add playbackComplete, update purchase | ~15 |
| `frontend/src/pages/vod/VideoPlayerPage.tsx` | Purchase options + status badges | ~200 |
| **Total** | | **~545** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_vod_purchase_tiers.py`)

New file, ~600 lines.

```python
# ── Purchase Type Configuration ──

def test_configure_view_once_price(ddb_tables, seed_video):
    """Creator can set view_once_price_cents on a video."""
    resp = client.patch(f"/ui/videos/{seed_video}/pricing",
        json={"view_once_price_cents": 199, "available_purchase_types": ["view_once", "permanent"]},
        headers=alice_headers())
    assert resp.status_code == 200

def test_download_price_gte_permanent(ddb_tables, seed_video):
    """download_price_cents must be >= price_cents."""
    resp = client.patch(f"/ui/videos/{seed_video}/pricing",
        json={"price_cents": 999, "download_price_cents": 500,
              "available_purchase_types": ["permanent", "download"]},
        headers=alice_headers())
    assert resp.status_code == 422

def test_invalid_purchase_type(ddb_tables, seed_video):
    """Invalid purchase type in available_purchase_types returns 422."""
    resp = client.patch(f"/ui/videos/{seed_video}/pricing",
        json={"available_purchase_types": ["invalid_type"]},
        headers=alice_headers())
    assert resp.status_code == 422

def test_rental_duration_range(ddb_tables, seed_video):
    """rental_duration_hours must be 1-720."""
    resp = client.patch(f"/ui/videos/{seed_video}/pricing",
        json={"rental_duration_hours": 0}, headers=alice_headers())
    assert resp.status_code == 422


# ── View-Once Lifecycle ──

def test_view_once_purchase(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """View-once purchase sets views_remaining=1."""
    resp = client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "view_once"},
        headers=bob_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["purchase_type"] == "view_once"
    assert data["views_remaining"] == 1

def test_view_once_entitled_before_watch(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """After view_once purchase, viewer is entitled (views_remaining=1)."""
    client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "view_once"},
        headers=bob_headers())
    resp = client.get(f"/ui/videos/{seed_video_with_tiers}", headers=bob_headers())
    data = resp.json()
    assert data["is_entitled"] is True
    assert data["views_remaining"] == 1

def test_view_once_consumed_after_playback(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """After playback-complete, views_remaining=0 and not entitled."""
    client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "view_once"},
        headers=bob_headers())
    client.post(f"/ui/videos/{seed_video_with_tiers}/playback-complete",
        headers=bob_headers())
    ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id=seed_video_with_tiers)
    assert ent.entitled is False
    assert ent.reason == "consumed"

def test_view_once_playback_complete_idempotent(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """Double playback-complete does not cause errors."""
    client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "view_once"},
        headers=bob_headers())
    client.post(f"/ui/videos/{seed_video_with_tiers}/playback-complete",
        headers=bob_headers())
    resp = client.post(f"/ui/videos/{seed_video_with_tiers}/playback-complete",
        headers=bob_headers())
    assert resp.status_code == 200
    assert resp.json()["views_remaining"] == 0


# ── Rental Lifecycle ──

def test_rental_purchase_sets_expiry(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """Rental purchase sets expires_at to now + rental_hours."""
    resp = client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "rental"},
        headers=bob_headers())
    data = resp.json()
    assert data["purchase_type"] == "rental"
    assert data["expires_at"] is not None
    assert data["expires_at"] > now_ts()

def test_rental_entitled_within_window(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """Within rental window, viewer is entitled."""
    client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "rental"},
        headers=bob_headers())
    ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id=seed_video_with_tiers)
    assert ent.entitled is True
    assert ent.purchase_type == "rental"

def test_rental_expired(ddb_tables, seed_video_with_tiers):
    """Expired rental is not entitled."""
    # Seed entitlement with expires_at in the past
    T.vod_entitlements.put_item(Item={
        "pk": f"USER#{BOB_ID}", "sk": f"VIDEO#{seed_video_with_tiers}",
        "video_id": seed_video_with_tiers, "buyer_id": BOB_ID,
        "grant_type": "purchase", "purchase_type": "rental",
        "views_remaining": -1, "expires_at": now_ts() - 3600,
        "created_at": now_ts() - 7200, "amount_cents": 299,
    })
    ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id=seed_video_with_tiers)
    assert ent.entitled is False
    assert ent.reason == "expired"


# ── Download Purchase ──

def test_download_purchase_grants_download(ddb_tables, seed_video_with_download, seed_bob_pm):
    """Download purchase sets download_allowed=True."""
    resp = client.post(f"/ui/videos/{seed_video_with_download}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "download"},
        headers=bob_headers())
    data = resp.json()
    assert data["purchase_type"] == "download"
    assert data["download_allowed"] is True

def test_download_endpoint_requires_download_entitlement(ddb_tables, seed_video_with_download, seed_bob_pm):
    """GET /download returns 403 without download entitlement."""
    # Purchase permanent (not download)
    client.post(f"/ui/videos/{seed_video_with_download}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "permanent"},
        headers=bob_headers())
    resp = client.get(f"/ui/videos/{seed_video_with_download}/download",
        headers=bob_headers())
    assert resp.status_code == 403

def test_download_endpoint_succeeds_with_download_entitlement(ddb_tables, seed_video_with_download, seed_bob_pm):
    """GET /download succeeds with download entitlement."""
    client.post(f"/ui/videos/{seed_video_with_download}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "download"},
        headers=bob_headers())
    resp = client.get(f"/ui/videos/{seed_video_with_download}/download",
        headers=bob_headers())
    assert resp.status_code == 200


# ── Backward Compatibility ──

def test_legacy_entitlement_treated_as_permanent(ddb_tables):
    """Entitlement records without purchase_type are treated as permanent."""
    T.vod_entitlements.put_item(Item={
        "pk": f"USER#{BOB_ID}", "sk": "VIDEO#vid_legacy",
        "video_id": "vid_legacy", "buyer_id": BOB_ID,
        "grant_type": "purchase", "created_at": now_ts(),
        "amount_cents": 999,
        # No purchase_type, views_remaining, expires_at, download_allowed
    })
    ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="vid_legacy")
    assert ent.entitled is True
    assert ent.purchase_type == "permanent"
    assert ent.views_remaining == -1
    assert ent.download_allowed is False

def test_purchase_type_not_available(ddb_tables, seed_video_with_tiers, seed_bob_pm):
    """Purchase type not in available_purchase_types returns 400."""
    # seed_video_with_tiers has available_purchase_types=["view_once", "rental", "permanent"]
    resp = client.post(f"/ui/videos/{seed_video_with_tiers}/purchase",
        json={"payment_method_id": seed_bob_pm, "purchase_type": "download"},
        headers=bob_headers())
    assert resp.status_code == 400

def test_default_purchase_type_is_permanent(ddb_tables, seed_video, seed_bob_pm):
    """When purchase_type is omitted, defaults to 'permanent'."""
    resp = client.post(f"/ui/videos/{seed_video}/purchase",
        json={"payment_method_id": seed_bob_pm},
        headers=bob_headers())
    assert resp.json()["purchase_type"] == "permanent"
```

### 5.2 E2E Tests (`frontend/e2e/vod-purchase-tiers.spec.ts`)

New file, ~600 lines.

**Section 136: Purchase Type Configuration (4 tests)**

1. `Creator configures multiple purchase types` — PATCH pricing with `available_purchase_types: ["view_once", "rental", "permanent", "download"]` and per-type prices, verify 200
2. `Creator sets rental duration to 72 hours` — PATCH with `rental_duration_hours: 72`, verify stored
3. `Download price must be >= permanent price` — PATCH with download < permanent, verify 422
4. `Invalid purchase type rejected` — PATCH with `available_purchase_types: ["invalid"]`, verify 422

**Section 137: View-Once + Rental Entitlement Lifecycle (5 tests)**

1. `View-once purchase: viewer entitled with views_remaining=1` — POST purchase with `purchase_type: "view_once"`, GET detail, verify `views_remaining: 1`, `is_entitled: true`
2. `View-once: playback-complete consumes view` — POST playback-complete, GET detail, verify `views_remaining: 0`, `is_entitled: false`
3. `View-once: consumed viewer can re-purchase` — After consumption, POST new purchase (different idempotency key), verify new entitlement with `views_remaining: 1`
4. `Rental purchase: entitled within window` — POST with `purchase_type: "rental"`, GET detail, verify `is_entitled: true`, `rental_expires_at > now`
5. `Rental: shows remaining time` — GET detail, verify `rental_remaining_seconds > 0`

**Section 138: Download Purchase + Access (3 tests)**

1. `Download purchase: entitled with download_allowed=true` — POST with `purchase_type: "download"`, verify `download_allowed: true`
2. `Download endpoint succeeds with download entitlement` — GET /download, verify 200 with presigned URL
3. `Download endpoint blocked for permanent-only purchase` — POST with `purchase_type: "permanent"`, GET /download, verify 403

**Test setup (beforeAll):**
- Seed sessions for Alice (creator) and Bob (viewer)
- Create and publish a video as Alice with download infrastructure ready
- Configure `available_purchase_types: ["view_once", "rental", "permanent", "download"]`
- Set per-type pricing: view_once=199, rental=299, permanent=999, download=1299
- Add payment method for Bob

---

## 6. Security Considerations

### 6.1 Playback Token for View-Once

View-once playback tokens should have a short TTL (video duration + 30 minutes) to prevent token sharing. A leaked view-once playback URL is usable for a limited time, but the entitlement is consumed server-side on playback-complete regardless.

**Race condition**: If a viewer copies the playback URL and opens it in a second tab before playback-complete is called, both tabs could play the video. Mitigation: the `playback-complete` callback uses `ConditionExpression` to atomically decrement `views_remaining`. Only one playback-complete succeeds; the second is a no-op. The viewer gets one "legitimate" full view plus however much they watched in the second tab before the token expires.

For stronger enforcement, integrate with the `issue_playback_entitlement()` replay protection (session_id dedup). This is out of scope for VOD-019 but noted as a future improvement.

### 6.2 Rental Clock Manipulation

The rental `expires_at` is computed server-side (`now_ts() + hours * 3600`). Clients cannot extend or reset the clock. The entitlement check reads `expires_at` from DDB and compares to `now_ts()` — both server-side.

### 6.3 Download Entitlement Persistence

The `download_allowed=true` flag on the entitlement record is permanent. Once a viewer purchases the download tier, they retain the download right even if the creator later changes the video's `available_purchase_types` to remove "download". This is intentional — the viewer paid for download at purchase time.

### 6.4 Re-Purchase After Consumption

A viewer whose view-once entitlement is consumed can purchase again (any tier). The new purchase overwrites the existing entitlement record (same PK/SK). The new record has the new purchase type's fields. The original purchase is preserved in the billing ledger.

**Implementation detail**: The `purchase_video()` function's existing idempotency check (`get_item` before `put_item`) must be updated to allow re-purchase of consumed/expired entitlements. Currently it returns `already_owned=True` for any existing record. After VOD-019, it should check whether the existing entitlement is still valid — if consumed or expired, allow a new purchase:

```python
existing = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
if existing:
    # Allow re-purchase if consumed or expired
    existing_type = existing.get("purchase_type", "permanent")
    views = int(existing.get("views_remaining", -1))
    exp = int(existing.get("expires_at", 0))
    if existing_type == "view_once" and views == 0:
        pass  # Allow re-purchase
    elif existing_type == "rental" and exp > 0 and exp < now_ts():
        pass  # Allow re-purchase
    else:
        return {"already_owned": True, ...}
```

### 6.5 Rate Limiting

- Purchase endpoint: Existing rate limits apply (10 per minute per user).
- Playback-complete: 60 per minute per user (one per video watch).
- Pricing endpoint: 10 per minute per user.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Changes

No new tables. New fields (`purchase_type`, `views_remaining`, `expires_at`, `download_allowed`) are added to existing `vod_entitlements` items. New pricing fields added to `VideoMetadata` items.

### 7.2 Backward Compatibility

- Existing entitlement records lack `purchase_type`, `views_remaining`, `expires_at`, `download_allowed`. The updated `check_entitlement_purchase_only()` treats missing fields as permanent defaults.
- Existing videos lack `available_purchase_types`, `view_once_price_cents`, etc. They default to empty/None, which means only "permanent" is available.
- The `purchase_video()` function defaults `purchase_type` to `"permanent"` if not specified.

### 7.3 Feature Flag

```python
vod_purchase_tiers_enabled: bool = os.environ.get("VOD_PURCHASE_TIERS_ENABLED", "0") not in ("0", "false", "False")
```

When disabled:
- `VodPurchaseIn.purchase_type` validation rejects anything except "permanent"
- `VodPricingIn` rejects `available_purchase_types`, per-type pricing fields
- `check_entitlement_purchase_only()` ignores `views_remaining` and `expires_at`
- Existing permanent entitlements continue to work normally

### 7.4 Rollback

Set `VOD_PURCHASE_TIERS_ENABLED=0`. Purchase endpoint only accepts "permanent". Existing tier-specific entitlements:
- View-once (consumed): Already consumed, no access. No change.
- View-once (unconsumed): Still entitled (check ignores views_remaining when flag off). Viewer retains access permanently — acceptable for rollback.
- Rental (active): Still entitled (check ignores expires_at). Viewer retains access permanently — acceptable for rollback.
- Rental (expired): Still entitled (check ignores expires_at). Viewer regains access — minor issue, acceptable for rollback.
- Download: download_allowed not checked when flag off. Download access reverts to `video.allow_download` global flag.

---

## 8. Performance & Capacity Planning

### 8.1 Expected Throughput

| Operation | Estimate |
|-----------|----------|
| Purchase requests/sec | 5 (same as MON-001) |
| Entitlement checks/sec | 100 (same as MON-001) |
| Playback-complete/sec | 10 (one per video watch completion) |
| Pricing updates/sec | 0.1 |

### 8.2 DDB Capacity

No additional tables. The `vod_entitlements` table gains ~30 bytes per item (new fields). The `video_metadata` table gains ~40 bytes per item (new pricing fields). Both are negligible.

The `playback-complete` endpoint writes one `update_item` per video watch — 10 WCU/sec additional at peak. Minimal impact.

### 8.3 Latency Budget

| Operation | Target p99 | Components |
|-----------|-----------|------------|
| POST /purchase (with type) | 200ms | Same as MON-001 (no additional DDB calls) |
| POST /playback-complete | 30ms | Single conditional update_item |
| GET /videos/{id} (with tier info) | 50ms | Same as MON-001 (entitlement check enriched in-memory) |

---

## 9. Dependency Analysis

### 9.1 Blocked By

| Ticket | Dependency |
|--------|-----------|
| MON-001 | Entitlement table, purchase flow, pricing infrastructure |
| VOD-012 | MP4 download infrastructure (download_mp4_key, mint_video_download_url) |

### 9.2 Blocks

No downstream tickets directly blocked.

### 9.3 Integration Points

- **Entitlement check** (`app/services/vod_purchase.py`): `check_entitlement_purchase_only()` return type changes from `bool` to `EntitlementStatus`. All callers must update.
- **Download endpoint** (`app/routers/video_listing.py`): Adds `download_allowed` check. Must not break existing download flow for video owners.
- **Billing ledger**: Purchase entries gain `purchase_type` in the meta field for auditing. No schema change to ledger entries themselves.
- **Playback entitlements** (`app/services/playback_entitlements.py`): Token TTL adjusted for view-once. No changes to the entitlement service itself.
- **Frontend video player**: Must call `POST /playback-complete` when video finishes for view-once tracking. Must display rental countdown timer. Must show download button when `download_allowed=true`.

### 9.4 API Contract Changes

The `check_entitlement_purchase_only()` return type change is **breaking** for any internal caller that expects `bool`. Callers must be updated to use `.entitled` property. These callers are:
- `check_vod_access()` in `vod_purchase.py` (line 105) — update to `ent_status.entitled`
- `_batch_check_entitlements()` in `vod_purchase.py` (line 186) — **change needed**. This function uses raw `batch_get_item` with `ProjectionExpression="sk, grant_type"` and does NOT call `check_entitlement_purchase_only()`. It returns any video ID with a non-subscription `grant_type` as "entitled." After VOD-019, consumed view-once entitlements (`views_remaining=0`) and expired rental entitlements (`expires_at < now`) would still appear as entitled in `list_creator_videos_with_access` (line 656). Fix: add `views_remaining` and `expires_at` to the `ProjectionExpression`, then filter in memory: exclude items where `purchase_type == "view_once" and views_remaining == 0`, and exclude items where `purchase_type == "rental" and expires_at > 0 and expires_at < now_ts()`. Without this fix, the creator video listing page will incorrectly show consumed/expired videos as accessible.

---

## 10. Acceptance Criteria

1. Creators can configure `available_purchase_types` on a video with per-type pricing via `PATCH /ui/videos/{id}/pricing`.
2. `download_price_cents` must be >= `price_cents` (permanent price). Violation returns 422.
3. `rental_duration_hours` must be between 1 and 720. Violation returns 422.
4. Viewers can purchase a video with `purchase_type` in the request body. Default is "permanent".
5. Purchase type must be in the video's `available_purchase_types`. Invalid type returns 400.
6. **View-once**: `views_remaining=1` after purchase. Entitled until playback-complete. After playback-complete, `views_remaining=0` and not entitled.
7. **Rental**: `expires_at` set to `now + rental_duration_hours`. Entitled while `expires_at > now`. After expiry, not entitled.
8. **Permanent**: No expiry, unlimited views. Same as current MON-001 behavior.
9. **Download**: Same as permanent + `download_allowed=true`. `GET /download` succeeds only with download entitlement.
10. `GET /download` returns 403 for viewers with permanent (non-download) entitlement.
11. `POST /ui/videos/{id}/playback-complete` atomically consumes view-once entitlement (idempotent).
12. Consumed/expired entitlements allow re-purchase (new entitlement overwrites old).
13. Legacy entitlement records without `purchase_type` are treated as "permanent" (backward compatible).
14. Video detail response includes `purchase_type`, `views_remaining`, `rental_expires_at`, `rental_remaining_seconds`, `download_allowed` for entitled viewers.
15. Frontend shows purchase tier cards with per-type pricing and descriptions.
16. Frontend shows rental countdown timer for active rentals.
17. Frontend shows "1 view remaining" badge for view-once entitlements.
18. All 12 E2E tests pass.

---

## 11. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Message |
|----------|-----------|-------------|---------------|
| POST /purchase | purchase_type not in available_types | 400 | "Purchase type 'X' not available for this video" |
| POST /purchase | No price for purchase_type | 400 | "No price configured for purchase type 'X'" |
| POST /purchase | download type + MP4 not ready | 400 | "Download not available for this video" |
| POST /purchase | Existing valid entitlement | 200 | `already_owned: true` (not an error) |
| POST /purchase | Consumed/expired entitlement | 200 | New purchase (overwrites) |
| POST /playback-complete | No entitlement | 404 | "No entitlement found" |
| POST /playback-complete | Already consumed | 200 | `views_remaining: 0` (idempotent) |
| GET /download | No download entitlement | 403 | "Download access not included in your purchase" |
| PATCH /pricing | download_price < permanent | 422 | Pydantic validation error |
| PATCH /pricing | rental_duration out of range | 422 | Pydantic validation error |
| PATCH /pricing | Invalid purchase type | 422 | Pydantic validation error |

---

## 12. Anti-Piracy Measures for View-Once Content

### 12.1 Screen Recording Detection (Limited)

Detecting screen recording is inherently limited because the browser does not expose reliable APIs for this purpose. The following best-effort measures are implemented:

**Visibility API monitoring**: When the user switches tabs or minimizes the browser during view-once playback, the `visibilitychange` event fires. While this does not detect screen recording, it logs suspicious patterns:

```typescript
useEffect(() => {
  if (purchaseType !== "view_once") return;

  const handler = () => {
    if (document.hidden) {
      // Log suspicious activity — user left the tab during view-once playback
      reportPlaybackAnomaly(videoId, "tab_hidden_during_view_once");
    }
  };
  document.addEventListener("visibilitychange", handler);
  return () => document.removeEventListener("visibilitychange", handler);
}, [purchaseType, videoId]);
```

**Display capture API detection**: The `navigator.mediaDevices.getDisplayMedia` API is used to initiate screen capture. While we cannot intercept other applications that call it, we can detect if a `MediaStream` is active in the current browsing context:

```typescript
// Check if any display capture tracks are active (limited — only detects same-origin capture)
const checkDisplayCapture = async () => {
  // This is a heuristic — screen recording apps bypass browser APIs entirely
  if ("getDisplayMedia" in navigator.mediaDevices) {
    // Log capability presence; actual detection is not reliable
  }
};
```

**Limitation acknowledgment**: Screen recording software (OBS, native OS tools) operates at the OS level and is undetectable from within the browser. These measures provide deterrence, not prevention. DRM (Section 12.4) is the only effective technical countermeasure.

### 12.2 Dynamic Watermarking with User ID

For view-once and rental content, a semi-transparent forensic watermark is overlaid on the video player. If a recording is leaked, the watermark identifies the purchaser.

**Visible watermark** (CSS overlay):

```typescript
// Applied in the video player component for view-once/rental purchases
<div className="absolute inset-0 pointer-events-none select-none opacity-10 text-white">
  <div className="absolute top-4 right-4 text-xs font-mono rotate-[-15deg]">
    {userId.slice(0, 8)} | {new Date().toISOString().slice(0, 10)}
  </div>
  <div className="absolute bottom-4 left-4 text-xs font-mono rotate-[15deg]">
    {purchaseId.slice(0, 12)}
  </div>
</div>
```

**Configuration**:
```python
# app/core/settings.py
vod_watermark_enabled: bool = os.environ.get("VOD_WATERMARK_ENABLED", "1") not in ("0", "false", "False")
vod_watermark_opacity: float = float(os.environ.get("VOD_WATERMARK_OPACITY", "0.08"))
```

The watermark is rendered client-side (CSS overlay) rather than burned into the video stream. This is faster and avoids re-encoding but can be bypassed by recording the raw video stream. For stronger protection, server-side watermarking via ffmpeg is available as an opt-in enhancement (see Section 12.5).

### 12.3 Playback Token Binding to IP and Device Fingerprint

View-once playback tokens are bound to the requesting client's IP address and a lightweight device fingerprint to prevent token sharing.

**Token issuance** (enhanced for view-once):

**Call site update required**: The existing call at `app/routers/video_listing.py` line 313 uses the old 2-argument signature: `_try_issue_playback_token(video, user_sub)`. This must be updated to pass `entitlement_status` (from the enriched `check_vod_access()` result), `client_ip` (from `request.client.host`), and `user_agent` (from `request.headers.get("user-agent")`). The function definition is at line 224 of the same file.

```python
def _try_issue_playback_token(video, user_sub, entitlement_status, client_ip, user_agent):
    token_metadata = {
        "user_sub": user_sub,
        "video_id": video.id,
        "purchase_type": entitlement_status.purchase_type,
    }

    if entitlement_status.purchase_type == "view_once":
        # Bind token to client context
        token_metadata["bound_ip"] = client_ip
        token_metadata["bound_ua_hash"] = hashlib.sha256(
            (user_agent or "").encode()
        ).hexdigest()[:16]

    result = issue_playback_entitlement(
        # ... existing params ...
        metadata=token_metadata,
    )
    return result
```

**Token validation** (at playback):

```python
def _validate_playback_token(token_metadata, request_ip, request_ua):
    if token_metadata.get("purchase_type") == "view_once":
        if token_metadata.get("bound_ip") and token_metadata["bound_ip"] != request_ip:
            raise HTTPException(403, "Playback token is bound to a different network")
        bound_ua = token_metadata.get("bound_ua_hash", "")
        request_ua_hash = hashlib.sha256((request_ua or "").encode()).hexdigest()[:16]
        if bound_ua and bound_ua != request_ua_hash:
            raise HTTPException(403, "Playback token is bound to a different device")
```

### 12.4 DRM Integration for View-Once Content

For maximum protection, view-once content can be delivered via Widevine (Chrome/Android) or FairPlay (Safari/iOS) DRM. DRM prevents direct access to the raw video stream, making screen recording the only circumvention vector.

**DRM license policy for view-once**:

```json
{
  "license_type": "streaming",
  "playback_duration": 0,
  "rental_duration": 0,
  "persistence": "TEMPORARY",
  "security_level": "SW_SECURE_DECODE",
  "allowed_track_types": ["SD", "HD"],
  "hdcp_required": false,
  "view_count": 1
}
```

**Integration point**: The license server (external service, e.g., PallyCon, BuyDRM, or self-hosted) issues a license with `view_count=1`. After one playback session, the license expires and the CDM (Content Decryption Module) will not decrypt the content again.

**Scope**: DRM integration is a significant infrastructure addition (license server, content encryption pipeline, CDM integration). It is scoped as a future enhancement, not part of the initial VOD-019 implementation. The ticket documents the integration points for future work.

### 12.5 Server-Side Forensic Watermark Overlay

For high-value view-once content, a per-viewer watermark can be burned into the video stream during HLS segment delivery:

```bash
# FFmpeg command to overlay a text watermark on each HLS segment
ffmpeg -i segment.ts \
  -vf "drawtext=text='${USER_ID} ${PURCHASE_ID}':fontsize=12:fontcolor=white@0.05:x=10:y=10" \
  -c:v libx264 -preset ultrafast -c:a copy \
  watermarked_segment.ts
```

This is computationally expensive (real-time transcoding per viewer) and is reserved for premium content where piracy risk justifies the cost. Configuration:

```python
vod_forensic_watermark_enabled: bool = False  # Opt-in per video
```

---

## 13. Rental Extension and Re-Purchase Flow

### 13.1 Rental Expiry UX

When a rental expires, the viewer's access is immediately revoked. The video detail page shows:

```
┌────────────────────────────────────────────┐
│  Your 48-hour rental has expired            │
│                                             │
│  Watch progress: 75% (1h 30m of 2h)        │
│                                             │
│  [Rent Again — $2.99 for 48 hours]          │
│  [Buy — $9.99 (own forever)]                │
│                                             │
│  * Extend within 1 hour of expiry           │
│    at the same price: $2.99                 │
│    (grace period active for 23 more minutes)│
└────────────────────────────────────────────┘
```

### 13.2 Re-Rental at Same or Different Tier

A viewer whose rental has expired can re-purchase at any available tier. The new purchase overwrites the existing entitlement record (same PK/SK):

```python
# In purchase_video():
existing = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
if existing:
    existing_type = existing.get("purchase_type", "permanent")
    exp = int(existing.get("expires_at", 0))
    views = int(existing.get("views_remaining", -1))

    # Allow re-purchase if rental expired
    if existing_type == "rental" and exp > 0 and exp < now_ts():
        pass  # Allow re-purchase
    # Allow re-purchase if view-once consumed
    elif existing_type == "view_once" and views == 0:
        pass  # Allow re-purchase
    # Allow upgrade (e.g., rental -> permanent)
    elif body.purchase_type in ("permanent", "download") and existing_type in ("view_once", "rental"):
        pass  # Allow upgrade
    else:
        return {"already_owned": True, ...}
```

**Re-rental preserves watch progress**: The video player stores the viewer's last playback position in `localStorage` (keyed by `video_id`). Re-renting does not clear this position, so the viewer can resume where they left off. The backend does not track watch progress (it only tracks entitlement state).

### 13.3 Grace Period for Rental Extension

Within 1 hour after a rental expires, the viewer can extend at the original rental price instead of paying the full re-rental price. This grace period is designed to handle situations where the viewer was mid-watch when the rental expired.

```python
RENTAL_GRACE_PERIOD_SECONDS = 3600  # 1 hour

def _is_in_grace_period(entitlement_item: Dict) -> bool:
    """Check if an expired rental is within the grace period."""
    expires_at = int(entitlement_item.get("expires_at", 0))
    if expires_at <= 0:
        return False
    return now_ts() - expires_at <= RENTAL_GRACE_PERIOD_SECONDS


def extend_rental(
    user_id: str,
    video_id: str,
    payment_method_id: str,
    additional_hours: int = 48,
) -> Dict[str, Any]:
    """Extend an active or grace-period rental.

    For active rentals: extends expires_at by additional_hours.
    For grace-period rentals: sets expires_at to now + additional_hours.
    """
    pk = f"USER#{user_id}"
    sk = f"VIDEO#{video_id}"
    item = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")

    if not item or item.get("purchase_type") != "rental":
        raise HTTPException(404, "No rental entitlement found")

    expires_at = int(item.get("expires_at", 0))
    is_active = expires_at > now_ts()
    is_grace = not is_active and _is_in_grace_period(item)

    if not is_active and not is_grace:
        raise HTTPException(409, "Rental expired beyond grace period. Please re-purchase.")

    # Calculate new expiry
    if is_active:
        new_expires = expires_at + additional_hours * 3600
    else:
        new_expires = now_ts() + additional_hours * 3600

    T.vod_entitlements.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET expires_at = :exp",
        ExpressionAttributeValues={":exp": new_expires},
    )

    return {"expires_at": new_expires, "extended": True}
```

### 13.4 Re-Purchase Pricing Rules

| Scenario | Price | Rationale |
|----------|-------|-----------|
| Active rental extension | Rental price | Adding time to existing rental |
| Grace period extension | Rental price | Same as active extension (incentive to extend) |
| Expired rental re-purchase | Rental price | New rental period starts from now |
| Expired rental upgrade to permanent | Permanent price (no credit for rental) | Separate purchase |
| View-once re-purchase (same tier) | View-once price | New single-view entitlement |
| View-once upgrade to permanent | Permanent price | Separate purchase |
| Any tier upgrade to download | Download price | Download includes permanent access |

---

## 14. Offline/Download DRM and Protection

### 14.1 Download Watermarking

When a viewer with a download entitlement requests the MP4 file, the download includes a metadata watermark embedded in the file's MP4 atom structure:

```python
def _embed_download_watermark(
    mp4_path: str,
    user_id: str,
    purchase_id: str,
) -> None:
    """Embed purchaser identification in the MP4 metadata.

    Uses the 'udta' (user data) atom to store a JSON payload.
    This is invisible during playback but recoverable with ffprobe.
    """
    import subprocess

    metadata = json.dumps({
        "platform": "testlogon",
        "purchaser_id": user_id[:16],
        "purchase_id": purchase_id[:24],
        "downloaded_at": now_ts(),
    })

    subprocess.run([
        get_ffmpeg_path(),
        "-i", mp4_path,
        "-c", "copy",
        "-metadata", f"comment={metadata}",
        "-movflags", "+faststart",
        f"{mp4_path}.tmp",
    ], check=True, timeout=60)

    os.replace(f"{mp4_path}.tmp", mp4_path)
```

### 14.2 Terms of Use Acceptance Before Download

Before initiating a download, the frontend displays a terms acceptance dialog:

```
┌──────────────────────────────────────────┐
│  Download Terms                           │
│                                           │
│  By downloading this video, you agree:    │
│  - This file is for personal use only     │
│  - You may not redistribute or share it   │
│  - The file contains identifying metadata │
│  - Violation may result in account ban    │
│                                           │
│  [Cancel]   [I Agree — Download]          │
└──────────────────────────────────────────┘
```

The download endpoint requires a `terms_accepted: true` parameter:

```python
@router.get("/{video_id}/download")
def download_video_endpoint(
    video_id: str,
    terms_accepted: bool = Query(False),
    user=Depends(require_ui_session),
):
    if not terms_accepted:
        raise HTTPException(400, "You must accept the download terms")
    # ... existing download logic ...
```

### 14.3 Download Count Limits

Each download purchase allows a maximum of 3 downloads. This prevents a single purchase from being used to distribute the file to many devices.

```python
# In download_video_endpoint():
ent = check_entitlement_purchase_only(user_id=user_sub, video_id=video_id)
if not ent.download_allowed:
    raise HTTPException(403, "Download access not included in your purchase")

# Check download count
download_count = int(entitlement_item.get("download_count", 0))
max_downloads = int(entitlement_item.get("max_downloads", 3))

if download_count >= max_downloads:
    raise HTTPException(403, f"Download limit reached ({max_downloads} downloads used)")

# Increment download count atomically
T.vod_entitlements.update_item(
    Key={"pk": pk, "sk": sk},
    UpdateExpression="SET download_count = if_not_exists(download_count, :zero) + :one",
    ExpressionAttributeValues={":zero": 0, ":one": 1},
    ConditionExpression="attribute_not_exists(download_count) OR download_count < :max",
    ExpressionAttributeValues={":zero": 0, ":one": 1, ":max": max_downloads},
)
```

### 14.4 Re-Download After Device Change

If a viewer reaches the download limit and needs to download on a new device (e.g., phone replacement), they can request a download count reset through the support ticket system. The support agent verifies the request and resets `download_count` to 0 via an admin endpoint:

```python
@router.post("/{video_id}/reset-download-count", dependencies=[Depends(require_admin_session)])
def reset_download_count(video_id: str, user_id: str = Query(...)):
    T.vod_entitlements.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"},
        UpdateExpression="SET download_count = :zero",
        ExpressionAttributeValues={":zero": 0},
    )
    return {"ok": True, "download_count": 0}
```

---

## 15. Refund Policy Integration

### 15.1 Refund Rules by Purchase Type

| Purchase Type | Refund Condition | Refund Amount | Implementation |
|---------------|------------------|---------------|----------------|
| View-once | Never watched (views_remaining = 1) | Full refund | Refund entire `amount_cents`; delete entitlement |
| View-once | Already watched (views_remaining = 0) | No refund | Reject refund request |
| Rental | Within rental window, < 10% watched | Full refund | Refund `amount_cents`; delete entitlement |
| Rental | Within rental window, >= 10% watched | Prorated refund | Refund = `amount_cents * (remaining_seconds / total_seconds)` |
| Rental | Expired | No refund | Reject refund request |
| Permanent | Within 24 hours AND < 50% watched | Full refund | Refund `amount_cents`; delete entitlement |
| Permanent | After 24 hours OR >= 50% watched | No refund | Reject refund request |
| Download | Before any download (download_count = 0) | Full refund | Refund `amount_cents`; delete entitlement |
| Download | After at least 1 download | No refund | Reject refund request |

### 15.2 Refund Endpoint

```python
@router.post("/{video_id}/refund")
def request_refund(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Request a refund for a video purchase.

    Automatically processes refund if eligible based on purchase type rules.
    If not eligible, returns 409 with reason.
    """
    user_sub = user["user_sub"]
    pk = f"USER#{user_sub}"
    sk = f"VIDEO#{video_id}"

    item = T.vod_entitlements.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if not item:
        raise HTTPException(404, "No purchase found")

    purchase_type = item.get("purchase_type", "permanent")
    created_at = int(item.get("created_at", 0))
    amount_cents = int(item.get("amount_cents", 0))

    # Determine refund eligibility and amount
    refund_amount, rejection_reason = _calculate_refund(
        purchase_type=purchase_type,
        item=item,
        created_at=created_at,
        amount_cents=amount_cents,
    )

    if refund_amount <= 0:
        raise HTTPException(409, f"Refund not available: {rejection_reason}")

    # Process refund: write CREDIT for viewer, DEBIT for creator
    _write_refund_ledger(
        viewer_id=user_sub,
        creator_id=item.get("seller_id", ""),
        amount_cents=refund_amount,
        video_id=video_id,
        purchase_type=purchase_type,
        original_purchase_id=item.get("purchase_id", ""),
    )

    # Delete entitlement
    T.vod_entitlements.delete_item(Key={"pk": pk, "sk": sk})

    return {
        "ok": True,
        "refund_amount_cents": refund_amount,
        "purchase_type": purchase_type,
    }


def _calculate_refund(
    purchase_type: str,
    item: Dict,
    created_at: int,
    amount_cents: int,
) -> tuple[int, str]:
    """Calculate refund amount and rejection reason.

    Returns (refund_amount_cents, rejection_reason).
    refund_amount_cents = 0 means not eligible.
    """
    ts = now_ts()

    if purchase_type == "view_once":
        views_remaining = int(item.get("views_remaining", -1))
        if views_remaining > 0:
            return amount_cents, ""
        return 0, "Video has already been watched"

    elif purchase_type == "rental":
        expires_at = int(item.get("expires_at", 0))
        if expires_at <= ts:
            return 0, "Rental has already expired"
        total_seconds = expires_at - created_at
        remaining_seconds = expires_at - ts
        # Prorated refund based on time remaining
        if total_seconds > 0:
            pct_remaining = remaining_seconds / total_seconds
            prorated = int(amount_cents * pct_remaining)
            return max(prorated, 0), ""
        return 0, "Cannot calculate prorated refund"

    elif purchase_type == "permanent":
        hours_since_purchase = (ts - created_at) / 3600
        if hours_since_purchase > 24:
            return 0, "Refund window (24 hours) has passed"
        return amount_cents, ""

    elif purchase_type == "download":
        download_count = int(item.get("download_count", 0))
        if download_count > 0:
            return 0, "File has already been downloaded"
        return amount_cents, ""

    return 0, f"Unknown purchase type: {purchase_type}"
```

### 15.3 Refund Impact on Creator Earnings

When a refund is processed, the creator's wallet is debited for the refund amount. The billing ledger records both the original credit (at purchase time) and the refund debit (at refund time), providing a complete audit trail.

For prorated rental refunds, the creator retains the consumed portion. For example, if a 48-hour rental is refunded at the halfway mark, the creator keeps 50% of the purchase price.

### 15.4 Abuse Prevention

- Refunds are limited to 3 per user per 30-day rolling window.
- After 3 refunds, subsequent requests are routed to manual review via the MOD-003 appeals system.
- A `refund_count` attribute is tracked on the user's billing profile.
- Creators can flag users with excessive refund history via the admin dashboard.

---

## 12. Related Tickets

- **MON-001**: VOD pay-per-view (entitlement table, purchase flow — extended by VOD-019)
- **MON-005**: Subscription-gated VOD (entitlement cascade — VOD-019 enriches step 3)
- **VOD-012**: MP4 download (download infrastructure used by "download" purchase type)
- **MON-003**: Creator earnings dashboard (will show revenue by purchase type)
- **VOD-017**: Video gallery hub (gallery cards show price range: "From $1.99")

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `available_purchase_types` field | `app/models_video.py` | 143 | VERIFIED |
| `view_once_price_cents` field | `app/models_video.py` | 144 | VERIFIED |
| `rental_price_cents` field | `app/models_video.py` | 145 | VERIFIED |
| `rental_duration_hours` field | `app/models_video.py` | 146 | VERIFIED |
| `download_price_cents` field | `app/models_video.py` | 147 | VERIFIED |
| `EntitlementStatus` class | `app/services/vod_purchase.py` | 32-55 | VERIFIED |
| `VodAccessResult` class | `app/services/vod_purchase.py` | 61-128 | VERIFIED |
| `check_vod_access()` | `app/services/vod_purchase.py` | 131 | VERIFIED |
| `_batch_check_entitlements()` | `app/services/vod_purchase.py` | 271 | VERIFIED |
| `check_entitlement_purchase_only()` returns `EntitlementStatus` | `app/services/vod_purchase.py` | 316 | VERIFIED |
| `check_entitlement()` | `app/services/vod_purchase.py` | 372 | VERIFIED |
| `purchase_video()` with purchase_type param | `app/services/vod_purchase.py` | 398 | VERIFIED |
| `record_playback_complete()` | `app/services/vod_purchase.py` | 636 | VERIFIED |
| `VodPurchaseIn` model with purchase_type | `app/routers/video_listing.py` | 1023 | VERIFIED |
| `_resolve_price()` helper | `app/routers/video_listing.py` | 1104 | VERIFIED |
| `POST /{video_id}/playback-complete` endpoint | `app/routers/video_listing.py` | 1198 | VERIFIED |
| `VideoDetailOut.available_purchase_types` | `app/routers/video_listing.py` | 112 | VERIFIED |
| `VideoDetailOut.purchase_type` | `app/routers/video_listing.py` | 117 | VERIFIED |
| `VodPricingIn.available_purchase_types` | `app/routers/video_listing.py` | 1068 | VERIFIED |
| `_video_to_detail` passes purchase_type | `app/routers/video_listing.py` | 270-275 | VERIFIED |
| VodEntitlements DDB table | `scripts/local-ddb-init.py` | 583-591 | VERIFIED |
| `vod_entitlements_table_name` setting | `app/core/settings.py` | 1076 | VERIFIED |
| E2E test file | `frontend/e2e/vod-purchase-tiers.spec.ts` | — | VERIFIED |
