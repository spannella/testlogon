# MON-001: VOD Pay-Per-View — Entitlement-Gated Video Playback

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 5-8 days

---

## 1. Overview & Motivation

### The Gap

The VOD system currently supports video upload, transcoding, playback URL generation, and DRM encryption, but there is **no monetization layer**. Every published video is freely accessible to any authenticated user. Creators have no mechanism to charge viewers for individual video access.

The `VideoMetadataModel` (in `app/models_video.py`, line 36) has an `entitlement_sku` field (line 90) that hints at future entitlement gating, but no purchase flow, entitlement storage, or price enforcement exists. The playback entitlement system (`app/services/playback_entitlements.py`) issues time-limited JWTs for playback sessions but performs no purchase verification — it trusts the caller.

### Why This Is Needed

1. **Creator revenue**: Creators need to monetize individual videos. Subscriptions (MON-005) cover recurring access, but many creators sell individual premium content (tutorials, exclusive recordings, event replays) on a per-video basis.

2. **Billing integration**: The platform has a mature billing infrastructure (`T.billing` table, payment method management, ledger entries, wallet system) but VOD is entirely disconnected from it. Adding pay-per-view creates the first VOD-to-billing bridge.

3. **Entitlement enforcement**: Without server-side purchase verification before issuing playback URLs or DRM licenses, any user who discovers a video ID can watch it. This ticket adds a mandatory entitlement check in the playback path.

4. **Foundation for MON-005**: Subscription-gated VOD (MON-005) depends on the entitlement check infrastructure built here. MON-001 establishes the entitlement lookup; MON-005 adds subscription-based grants to the same lookup.

### Architecture After This Change

```
Viewer Browser                      Backend                           DynamoDB
     |                                 |                                 |
     |-- GET /videos/{id} ------------>|                                 |
     |                                 |-- get_video(id) --------------->|
     |                                 |<-- VideoMetadataModel ----------|
     |                                 |                                 |
     |                                 |-- check_vod_entitlement ------->|
     |                                 |   (T.vod_entitlements)          |
     |                                 |<-- entitled=false --------------|
     |                                 |                                 |
     |<-- 200 {video, price_cents,     |                                 |
     |     entitled: false}            |                                 |
     |                                 |                                 |
     |-- POST /videos/{id}/purchase -->|                                 |
     |   {payment_method_id}           |                                 |
     |                                 |-- validate PM in T.billing ---->|
     |                                 |<-- PM valid -------------------|
     |                                 |                                 |
     |                                 |-- write LEDGER entry ---------->|
     |                                 |-- write VOD_ENT entry -------->|
     |                                 |<-- ok -------------------------|
     |                                 |                                 |
     |<-- 200 {purchase_id,            |                                 |
     |     entitled: true}             |                                 |
     |                                 |                                 |
     |-- GET /videos/{id}/play ------->|                                 |
     |                                 |-- check_vod_entitlement ------->|
     |                                 |<-- entitled=true ---------------|
     |                                 |                                 |
     |                                 |-- mint_vod_playback_url ------->|
     |<-- 200 {playback_url,          ---|                                 |
     |     playback_expires_at}        |                                 |
```

---

## 2. Current State Analysis

### 2.1 Video Metadata Model (`app/models_video.py`, lines 36-103)

The `VideoMetadataModel` currently has no `price_cents` field. Relevant existing fields:

- `entitlement_sku: Optional[str] = None` (line 90) — placeholder for entitlement integration, currently unused
- `drm_enabled: bool = False` (line 85) — DRM flag, orthogonal to pay-per-view
- `visibility: VideoVisibility = "private"` (line 93) — controls listing, not access gating
- `allow_download: bool = False` (line 98) — download toggle (VOD-012)

`CreateVideoIn` (line 105) and `UpdateVideoIn` (line 119) also lack a `price_cents` field.

### 2.2 Video Metadata Store (`app/services/video_metadata_store.py`)

- `video_to_item()` (line 21) serializes `VideoMetadataModel` to DDB item dict. It handles optional string and numeric fields but has no price serialization.
- `video_from_item()` (line 116) deserializes with `_int_or_none()` and `_float_or_none()` helpers for safe numeric coercion.
- `create_video()` (line 185) accepts keyword args mapped directly from `CreateVideoIn`.
- `update_video()` (line 234) applies partial updates from `UpdateVideoIn`.

### 2.3 VOD Router (`app/routers/vod.py`, 279 lines)

Currently only has upload endpoints:
- `POST /ui/videos/upload/presign` (line 87) — presigned S3 upload URL
- `POST /ui/videos/{video_id}/upload/complete` (line 166) — confirm upload

There are **no** video retrieval, listing, or playback endpoints in this router. Video listing is served by other endpoints (possibly catalog or direct DDB queries from the frontend).

### 2.4 Playback Entitlements (`app/services/playback_entitlements.py`)

The `issue_playback_entitlement()` function (line 200) mints a signed JWT for playback sessions. It accepts `tenant_id`, `asset_id`, `session_id`, `device_id`, `profile`, `audience`, and `ttl_seconds`. It performs replay protection and revocation checks but **does not verify purchase status**. Any caller with the right parameters can obtain a playback token.

### 2.5 Billing Table Schema (`scripts/local-ddb-init.py`, line 59)

```python
TableDef(_resolve_table_name(S.billing_table_name, "billing"), "pk", "sk")
```

PK: `USER#{user_sub}`, SK patterns:
- `PM#{pm_id}` — payment methods
- `BILLING` — user billing settings (default PM, autopay, currency)
- `LEDGER#{ts}#{entry_id}` — billing ledger entries (debit/credit records)
- `WALLET` — wallet balance
- `SUB#{subscription_id}` — subscription records
- `PAY#{payment_intent_id}` — payment records

Existing ledger entry structure (from messaging.py, line 7631):
```python
{
    "pk": f"USER#{user_id}",
    "sk": f"LEDGER#{ts}#{entry_id}",
    "entry_id": entry_id,
    "ts": ts,
    "type": "debit",
    "amount_cents": amount_cents,
    "currency": "USD",
    "state": "settled",
    "reason": "Tip attached to message",
    "meta": {...},
}
```

### 2.6 VideoMetadata DDB Table (`scripts/local-ddb-init.py`, lines 645-665)

```python
TableDef(
    _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
    "video_id",
    gsi=[
        {"index_name": "ByOwnerCreatedAt", "partition_key": "owner_user_id", "sort_key": "created_at"},
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "BySourceBroadcast", "partition_key": "source_broadcast_session_id"},
    ],
    attr_types={"created_at": "N"},
)
```

PK: `video_id` (simple primary key, no sort key).

---

## 3. Technical Design

### 3.1 VideoMetadataModel Changes

Add `price_cents` and `access_mode` to `VideoMetadataModel`:

```python
class VideoMetadataModel(BaseModel):
    # ... existing fields ...

    # Pay-per-view (MON-001)
    price_cents: Optional[int] = None          # None or 0 = free
    access_mode: Optional[str] = None          # "free" | "ppv" | "subscriber_only" | "subscriber_free"
    purchase_count: int = 0                     # number of purchases
    revenue_cents: int = 0                      # total revenue from this video
```

`access_mode` semantics:
- `"free"` or `None` — no purchase required (default, backward compatible)
- `"ppv"` — pay-per-view only; subscription does not grant access
- `"subscriber_only"` — only accessible via subscription (no individual purchase)
- `"subscriber_free"` — subscribers get free access; non-subscribers can purchase

Add to `CreateVideoIn`:
```python
class CreateVideoIn(BaseModel):
    # ... existing fields ...
    price_cents: Optional[int] = Field(default=None, ge=0, le=100_000_00)  # max $100,000
    access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free)$")
```

Add to `UpdateVideoIn`:
```python
class UpdateVideoIn(BaseModel):
    # ... existing fields ...
    price_cents: Optional[int] = Field(default=None, ge=0, le=100_000_00)
    access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free)$")
```

Full Pydantic validation detail for `CreateVideoIn` with all validators:

```python
class CreateVideoIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: VideoSourceType = "upload"
    source_file_node_id: Optional[str] = None
    source_broadcast_session_id: Optional[str] = None
    source_s3_key: Optional[str] = None
    encoding_profile_id: Optional[str] = None
    visibility: VideoVisibility = "private"
    drm_enabled: bool = False
    drm_policy_id: Optional[str] = None
    entitlement_sku: Optional[str] = None
    # MON-001 additions:
    price_cents: Optional[int] = Field(default=None, ge=0, le=100_000_00)
    access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free)$")

    @model_validator(mode="after")
    def _validate_ppv_requires_price(self) -> "CreateVideoIn":
        if self.access_mode == "ppv" and (self.price_cents is None or self.price_cents <= 0):
            raise ValueError("access_mode 'ppv' requires price_cents > 0")
        if self.access_mode == "subscriber_only" and self.price_cents and self.price_cents > 0:
            raise ValueError("subscriber_only videos should not have a price_cents (they are not purchasable)")
        return self
```

### 3.2 VOD Entitlements DDB Table

New table for storing per-user per-video purchase records:

```python
TableDef(
    "vod_entitlements",
    "pk",    # USER#{user_sub}
    "sk",    # VIDEO#{video_id}
    gsi=[
        {
            "index_name": "ByVideo",
            "partition_key": "video_id",
            "sort_key": "purchased_at",
        },
        {
            "index_name": "ByCreatorPurchasedAt",
            "partition_key": "creator_id",
            "sort_key": "purchased_at",
        },
    ],
    attr_types={"purchased_at": "N"},
)
```

Entitlement item schema:
```python
{
    "pk": f"USER#{viewer_user_id}",
    "sk": f"VIDEO#{video_id}",
    "user_id": viewer_user_id,
    "video_id": video_id,
    "creator_id": creator_user_id,
    "purchase_id": purchase_id,           # unique purchase transaction ID
    "amount_cents": amount_cents,
    "currency": "USD",
    "payment_method_id": payment_method_id,
    "purchased_at": ts,                   # Unix timestamp (int)
    "source": "purchase",                 # "purchase" | "subscription" | "promo" | "admin_grant"
    "ledger_entry_id": ledger_entry_id,
    "ttl": 0,                             # 0 = permanent; non-zero for rental/temporary grants
}
```

#### DDB Partition Key Distribution

```
vod_entitlements table
  PK = USER#{user_sub}          SK = VIDEO#{video_id}
  ────────────────────────────────────────────────────
  USER#alice123                  VIDEO#vid_abc1
  USER#alice123                  VIDEO#vid_def2
  USER#bob456                    VIDEO#vid_abc1
  USER#charlie789                VIDEO#vid_ghi3

  GSI: ByVideo
    PK = video_id               SK = purchased_at (N)
    ────────────────────────────────────────────────────
    vid_abc1                     1716681600
    vid_abc1                     1716768000

  GSI: ByCreatorPurchasedAt
    PK = creator_id             SK = purchased_at (N)
    ────────────────────────────────────────────────────
    creator_alice                1716681600
    creator_alice                1716768000
```

Hot partition risk: Popular creators with many sales concentrate on a single `creator_id` partition in the GSI. For the ByCreatorPurchasedAt GSI, a creator with >1000 purchases/second would hit the 1000 WCU per-partition limit. This is unlikely at platform scale; the GSI is read-mostly (used for creator dashboards in MON-003).

### 3.3 New Service: `app/services/vod_purchase.py`

```python
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _validate_payment_method(user_id: str, payment_method_id: str) -> Dict[str, Any]:
    """Validate that the given payment method exists and belongs to the user.
    
    Queries T.billing with PK=USER#{user_id}, SK=PM#{payment_method_id}.
    Raises HTTPException(400) if not found or if the PM is expired/deleted.
    """
    resp = T.billing.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(400, "Payment method not found")
    if item.get("deleted_at"):
        raise HTTPException(400, "Payment method has been removed")
    return item


def check_vod_entitlement(*, user_id: str, video_id: str) -> bool:
    """Check if user has purchased (or been granted) access to a video.
    
    Performs a DDB get_item on vod_entitlements with:
      PK = USER#{user_id}
      SK = VIDEO#{video_id}
    
    Returns False if:
      - No item exists
      - Item has a non-zero TTL that has expired (rental model)
      - Any DDB read error occurs (fail-closed for security)
    """
    try:
        resp = T.vod_entitlements.get_item(
            Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
        )
        item = resp.get("Item")
        if not item:
            return False
        # Check TTL-based expiry for rental entitlements
        ttl = int(item.get("ttl", 0))
        if ttl > 0 and ttl < now_ts():
            return False
        return True
    except Exception:
        logger.warning("vod_entitlement_check_failed", extra={"user_id": user_id, "video_id": video_id})
        return False


def grant_vod_entitlement(
    *,
    user_id: str,
    video_id: str,
    creator_id: str,
    amount_cents: int,
    currency: str = "USD",
    payment_method_id: Optional[str] = None,
    source: str = "purchase",
    ttl: int = 0,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Grant VOD access and write billing ledger entry. Returns purchase record.
    
    Steps:
      1. Write entitlement record to vod_entitlements (with condition to prevent duplicates)
      2. Write billing ledger DEBIT for the viewer
      3. Write billing ledger CREDIT for the creator
      4. Increment purchase_count and revenue_cents on video metadata
    
    All ledger/counter writes are best-effort. The entitlement write is the
    critical operation; if it succeeds, the purchase is committed.
    
    Args:
        user_id: The viewer purchasing access
        video_id: The video being purchased
        creator_id: The video owner who receives payment
        amount_cents: Purchase price in cents
        currency: ISO 4217 currency code (default "USD")
        payment_method_id: Optional PM used for the purchase
        source: Entitlement source - "purchase", "subscription", "promo", "admin_grant"
        ttl: Unix timestamp when entitlement expires (0 = permanent)
        idempotency_key: Optional client-provided dedup key
    
    Returns:
        Dict containing the full entitlement item written to DDB.
    
    Raises:
        No exceptions - entitlement write uses conditional put, returns existing
        record if already granted.
    """
    ts = now_ts()
    purchase_id = f"vpurch_{uuid.uuid4().hex}"
    ledger_entry_id = uuid.uuid4().hex

    # 1. Write entitlement record (conditional to prevent double-purchase)
    ent_item = {
        "pk": f"USER#{user_id}",
        "sk": f"VIDEO#{video_id}",
        "user_id": user_id,
        "video_id": video_id,
        "creator_id": creator_id,
        "purchase_id": purchase_id,
        "amount_cents": amount_cents,
        "currency": currency,
        "payment_method_id": payment_method_id,
        "purchased_at": ts,
        "source": source,
        "ledger_entry_id": ledger_entry_id,
    }
    if ttl > 0:
        ent_item["ttl"] = ttl
    if idempotency_key:
        ent_item["idempotency_key"] = idempotency_key

    try:
        T.vod_entitlements.put_item(
            Item=ent_item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.vod_entitlements.meta.client.exceptions.ConditionalCheckFailedException:
        # Already purchased -- return existing record instead of double-billing
        existing = T.vod_entitlements.get_item(
            Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
        ).get("Item", {})
        return existing
    except Exception:
        # Unexpected DDB error -- still try to write since entitlement is critical
        T.vod_entitlements.put_item(Item=ent_item)

    # 2. Write billing ledger debit for the viewer
    if amount_cents > 0:
        try:
            T.billing.put_item(Item={
                "pk": f"USER#{user_id}",
                "sk": f"LEDGER#{ts}#{ledger_entry_id}",
                "entry_id": ledger_entry_id,
                "ts": ts,
                "type": "debit",
                "amount_cents": amount_cents,
                "currency": currency,
                "state": "settled",
                "reason": "VOD purchase",
                "meta": {
                    "video_id": video_id,
                    "creator_id": creator_id,
                    "purchase_id": purchase_id,
                    "payment_method_id": payment_method_id,
                },
            })
        except Exception:
            logger.warning("vod_purchase_debit_failed", extra={"user_id": user_id, "video_id": video_id})

        # 3. Write billing ledger credit for the creator
        try:
            creator_led_id = uuid.uuid4().hex
            T.billing.put_item(Item={
                "pk": f"USER#{creator_id}",
                "sk": f"LEDGER#{ts}#{creator_led_id}",
                "entry_id": creator_led_id,
                "ts": ts,
                "type": "credit",
                "amount_cents": amount_cents,
                "currency": currency,
                "state": "settled",
                "reason": "VOD sale",
                "meta": {
                    "video_id": video_id,
                    "buyer_id": user_id,
                    "purchase_id": purchase_id,
                },
            })
        except Exception:
            logger.warning("vod_purchase_credit_failed", extra={"creator_id": creator_id, "video_id": video_id})

    # 4. Increment purchase counter on video
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET purchase_count = if_not_exists(purchase_count, :z) + :one, "
                            "revenue_cents = if_not_exists(revenue_cents, :z) + :amt",
            ExpressionAttributeValues={":z": 0, ":one": 1, ":amt": amount_cents},
        )
    except Exception:
        logger.warning("vod_purchase_counter_update_failed", extra={"video_id": video_id})

    return ent_item


def revoke_vod_entitlement(*, user_id: str, video_id: str, reason: str = "admin_revoke") -> bool:
    """Revoke a VOD entitlement. Used by admins for fraud/chargeback scenarios.
    
    Deletes the entitlement record from DDB. Does NOT reverse ledger entries
    (that requires a separate refund flow).
    """
    try:
        T.vod_entitlements.delete_item(
            Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
        )
        logger.info("vod_entitlement_revoked", extra={"user_id": user_id, "video_id": video_id, "reason": reason})
        return True
    except Exception:
        logger.warning("vod_entitlement_revoke_failed", extra={"user_id": user_id, "video_id": video_id})
        return False


def list_user_vod_purchases(*, user_id: str, limit: int = 100) -> list:
    """List all videos a user has purchased.
    
    Query pattern:
      PK = USER#{user_id}
      SK begins_with VIDEO#
      ScanIndexForward = False (newest first by SK lexicographic order)
    """
    resp = T.vod_entitlements.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"USER#{user_id}"},
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def list_video_purchasers(*, video_id: str, limit: int = 100) -> list:
    """List all users who purchased a specific video. Used by creator dashboards.
    
    Uses GSI ByVideo:
      PK = video_id
      SK = purchased_at (numeric, descending)
    """
    resp = T.vod_entitlements.query(
        IndexName="ByVideo",
        KeyConditionExpression=Key("video_id").eq(video_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
```

### 3.4 API Endpoints

#### 3.4.1 Get Video Details (with entitlement status)

```
GET /ui/videos/{video_id}
```

Returns video metadata enriched with viewer-specific entitlement status.

**Data flow diagram:**
```
Request → require_ui_session → get_video(video_id) → 404 if not found/not published
   │
   ├── Determine is_owner (video.owner_user_id == user_sub)
   ├── Determine is_free (price_cents=None/0 or access_mode=free/None)
   ├── check_vod_entitlement(user_id, video_id) → DDB get_item
   │
   ├── entitled = is_owner OR is_free OR has_entitlement
   │
   ├── IF entitled AND video.hls_manifest_url:
   │       mint_vod_playback_url() → signed JWT token
   │
   └── Return VideoDetailOut
```

**Response model:**
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
    entitled: bool                          # viewer-specific: True if purchased or free
    purchase_count: int = 0
    is_owner: bool = False
    # Playback fields only populated when entitled=True
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None
```

**Handler logic:**
```python
@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(video_id: str, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.status not in ("published", "approved") and video.owner_user_id != user_sub:
        raise HTTPException(404, "Video not found")

    is_owner = video.owner_user_id == user_sub
    is_free = not video.price_cents or video.price_cents == 0 or video.access_mode in (None, "free")
    entitled = is_owner or is_free or check_vod_entitlement(user_id=user_sub, video_id=video_id)

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
        entitled=entitled,
        purchase_count=video.purchase_count,
        is_owner=is_owner,
    )

    if entitled and video.hls_manifest_url:
        pb = mint_vod_playback_url(video_id=video.id, tenant_id=video.owner_user_id)
        out.playback_url = pb.url
        out.playback_expires_at = pb.expires_at

    return out
```

#### 3.4.2 Purchase Video

```
POST /ui/videos/{video_id}/purchase
```

**Data flow diagram:**
```
Request {payment_method_id, idempotency_key}
   │
   ├── require_ui_session → user_sub
   ├── get_video(video_id) → 404 if not found
   │
   ├── VALIDATE:
   │   ├── video.status in (published, approved) → else 404
   │   ├── video.owner_user_id != user_sub → else 400 "cannot purchase own"
   │   ├── video.price_cents > 0 → else 400 "video is free"
   │   ├── video.access_mode != subscriber_only → else 403
   │   └── NOT already purchased → else 409
   │
   ├── _validate_payment_method(user_sub, pm_id) → 400 if invalid
   │
   ├── grant_vod_entitlement():
   │   ├── put_item to vod_entitlements (conditional)
   │   ├── put_item LEDGER debit for viewer
   │   ├── put_item LEDGER credit for creator
   │   └── update_item video metadata counters
   │
   └── Return VodPurchaseOut {purchase_id, video_id, amount_cents, currency, entitled=true}
```

**Request model:**
```python
class VodPurchaseIn(BaseModel):
    payment_method_id: str = Field(..., min_length=1, max_length=200)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
```

**Response model:**
```python
class VodPurchaseOut(BaseModel):
    purchase_id: str
    video_id: str
    amount_cents: int
    currency: str
    entitled: bool = True
```

**Handler logic:**
```python
@router.post("/{video_id}/purchase", response_model=VodPurchaseOut)
def purchase_video(video_id: str, inp: VodPurchaseIn, user=Depends(require_ui_session)):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.status not in ("published", "approved"):
        raise HTTPException(404, "Video not available for purchase")
    if video.owner_user_id == user_sub:
        raise HTTPException(400, "Cannot purchase your own video")
    if not video.price_cents or video.price_cents == 0:
        raise HTTPException(400, "Video is free — no purchase required")
    if video.access_mode == "subscriber_only":
        raise HTTPException(403, "This video is only available to subscribers")

    # Check if already purchased
    if check_vod_entitlement(user_id=user_sub, video_id=video_id):
        raise HTTPException(409, "Already purchased")

    # Validate payment method
    _validate_payment_method(user_sub, inp.payment_method_id)

    # Grant entitlement + write billing entries
    ent = grant_vod_entitlement(
        user_id=user_sub,
        video_id=video_id,
        creator_id=video.owner_user_id,
        amount_cents=video.price_cents,
        payment_method_id=inp.payment_method_id,
        source="purchase",
        idempotency_key=inp.idempotency_key,
    )

    return VodPurchaseOut(
        purchase_id=ent["purchase_id"],
        video_id=video_id,
        amount_cents=video.price_cents,
        currency="USD",
    )
```

#### 3.4.3 List User Purchases

```
GET /ui/videos/purchases
```

**Response model:**
```python
class VodPurchaseListOut(BaseModel):
    purchases: List[VodPurchaseItemOut]

class VodPurchaseItemOut(BaseModel):
    video_id: str
    creator_id: str
    purchase_id: str
    amount_cents: int
    currency: str
    purchased_at: int
    source: str
```

#### 3.4.4 Set Video Price (Creator)

```
PATCH /ui/videos/{video_id}/pricing
```

**Request model:**
```python
class VodPricingIn(BaseModel):
    price_cents: Optional[int] = Field(default=None, ge=0, le=100_000_00)
    access_mode: Optional[str] = Field(
        default=None,
        pattern=r"^(free|ppv|subscriber_only|subscriber_free)$"
    )
```

Only the video owner can set pricing. Validates ownership via `video.owner_user_id == user_sub`.

### 3.5 Error Handling

| Scenario | HTTP Status | Error Code |
|----------|-------------|------------|
| Video not found | 404 | `video_not_found` |
| Video not published | 404 | `video_not_found` |
| Purchase own video | 400 | `cannot_purchase_own` |
| Video is free | 400 | `video_is_free` |
| Already purchased | 409 | `already_purchased` |
| PM not found | 400 | `payment_method_not_found` |
| Subscriber-only video | 403 | `subscriber_only` |
| Not entitled (playback) | 403 | `not_entitled` |
| Price set on non-owned video | 403 | `not_owner` |

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

```typescript
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
  purchase_count: number;
  is_owner: boolean;
  playback_url?: string;
  playback_expires_at?: number;
}

export interface VodPurchaseRequest {
  payment_method_id: string;
  idempotency_key?: string;
}

export interface VodPurchaseResponse {
  purchase_id: string;
  video_id: string;
  amount_cents: number;
  currency: string;
  entitled: boolean;
}
```

### 3.7 Frontend Purchase Flow

The `VideoPlayerPage` component should:

1. Fetch `GET /ui/videos/{id}` — receive `entitled`, `price_cents`, `access_mode`
2. If `entitled=true` — render the video player with `playback_url`
3. If `entitled=false` and `price_cents > 0`:
   - Show video thumbnail, title, description
   - Show price badge (e.g., "$9.99")
   - Show "Purchase" button opening a `PurchaseDialog`
   - `PurchaseDialog` lists user's payment methods (from `["billing", "payment-methods"]` query)
   - On confirm: `POST /ui/videos/{id}/purchase` with selected PM
   - On success: invalidate `["video", id]` query, player becomes playable
4. If `access_mode=subscriber_only` — show "Subscribe to {creator}" CTA instead of purchase button

---

## 4. Implementation Plan

### Step 1: Extend VideoMetadataModel

**File**: `app/models_video.py`

Add fields after `download_count` (line 102):
```python
# Pay-per-view (MON-001)
price_cents: Optional[int] = None
access_mode: Optional[str] = None    # free | ppv | subscriber_only | subscriber_free
purchase_count: int = 0
revenue_cents: int = 0
```

Update `CreateVideoIn` and `UpdateVideoIn` to include `price_cents` and `access_mode`.

**Line-by-line changes for `app/models_video.py`:**
- Line 102: After `download_count: int = 0`, insert 4 new field declarations
- Line 117: Inside `CreateVideoIn`, after `entitlement_sku`, add `price_cents` and `access_mode` fields
- Line 128: Inside `UpdateVideoIn`, after `allow_download`, add `price_cents` and `access_mode` fields
- After `UpdateVideoIn`: Add `@model_validator` for ppv/price cross-validation

### Step 2: Update Video Metadata Store Serialization

**File**: `app/services/video_metadata_store.py`

- Line 36-57: Add `"access_mode"` to `_optional_str_fields` list (after `"entitlement_sku"` on line 56)
- Line 64-77: Add `"price_cents"`, `"purchase_count"`, `"revenue_cents"` to `_optional_num_fields` list
- In `video_from_item()` (~line 116): Add `price_cents=_int_or_none(item.get("price_cents"))`, `access_mode=item.get("access_mode")`, `purchase_count=int(item.get("purchase_count", 0))`, `revenue_cents=int(item.get("revenue_cents", 0))`
- In `create_video()` (~line 185): Accept `price_cents` and `access_mode` kwargs, pass through to `VideoMetadataModel(...)`
- In `update_video()` (~line 234): Handle `price_cents` and `access_mode` in the partial update dict

### Step 3: Create VOD Entitlements Table

**File**: `scripts/local-ddb-init.py`

Add after the VideoMetadata table definition (line 665):
```python
TableDef(
    "vod_entitlements",
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByVideo", "partition_key": "video_id", "sort_key": "purchased_at"},
        {"index_name": "ByCreatorPurchasedAt", "partition_key": "creator_id", "sort_key": "purchased_at"},
    ],
    attr_types={"purchased_at": "N"},
),
```

**File**: `app/core/settings.py` — Add `vod_entitlements_table_name` setting:
```python
# After video_metadata_table_name (search for it in settings.py)
vod_entitlements_table_name: str = os.environ.get("VOD_ENTITLEMENTS_TABLE_NAME", "vod_entitlements")
```

**File**: `app/core/tables.py` — Add `vod_entitlements` table handle:
```python
# In the Tables dataclass, after video_metadata:
vod_entitlements: Any

# In the T = Tables(...) instantiation, after video_metadata=...:
vod_entitlements=ddb.Table(S.vod_entitlements_table_name),
```

### Step 4: Create VOD Purchase Service

**File**: `app/services/vod_purchase.py` (new file, ~200 lines)

Functions: `_validate_payment_method()`, `check_vod_entitlement()`, `grant_vod_entitlement()`, `revoke_vod_entitlement()`, `list_user_vod_purchases()`, `list_video_purchasers()`.

### Step 5: Add Router Endpoints

**File**: `app/routers/vod.py`

Add four endpoints after the existing upload endpoints (line 279):
- `GET /ui/videos/{video_id}` — video detail with entitlement check
- `POST /ui/videos/{video_id}/purchase` — purchase flow
- `GET /ui/videos/purchases` — list user's purchases
- `PATCH /ui/videos/{video_id}/pricing` — set price (owner only)

Register any new Pydantic models at the top of the file. Import `check_vod_entitlement`, `grant_vod_entitlement`, `_validate_payment_method` from `app.services.vod_purchase`.

### Step 6: Frontend Types and API

**File**: `frontend/src/api/types.ts` — Add `VideoDetailResponse`, `VodPurchaseRequest`, `VodPurchaseResponse`  
**File**: `frontend/src/api/endpoints/vod.ts` (new) — Add `getVideoDetail()`, `purchaseVideo()`, `listPurchases()`, `setVideoPricing()`

### Step 7: Frontend Purchase UI

**File**: `frontend/src/pages/vod/VideoPlayerPage.tsx` (modify existing)

- Wrap the player in an entitlement gate
- Add `PurchaseDialog` component with PM selection
- Add price badge to video metadata display
- Add "My Purchases" section to library page

### Step 8: Register New Table

**File**: `app/main.py` — No changes needed if table handle is added to `T`

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/models_video.py` | Add price/access fields | ~15 |
| `app/services/video_metadata_store.py` | Serialize new fields | ~20 |
| `app/services/vod_purchase.py` | New service | ~200 |
| `app/routers/vod.py` | Add 4 endpoints + models | ~200 |
| `app/core/settings.py` | Add table name setting | ~3 |
| `app/core/tables.py` | Add table handle | ~5 |
| `scripts/local-ddb-init.py` | Add table definition | ~15 |
| `frontend/src/api/types.ts` | Add TypeScript types | ~30 |
| `frontend/src/api/endpoints/vod.ts` | New API wrappers | ~40 |
| `frontend/src/pages/vod/VideoPlayerPage.tsx` | Purchase gate UI | ~100 |
| **Total** | | **~628** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_vod_purchase.py`)

New file, ~400 lines. Uses moto-mocked DynamoDB via the FastAPI test client.

**Test function signatures and detailed assertions:**

```python
import pytest
from unittest.mock import patch
from moto import mock_dynamodb
from app.services.vod_purchase import (
    check_vod_entitlement,
    grant_vod_entitlement,
    list_user_vod_purchases,
    revoke_vod_entitlement,
    _validate_payment_method,
)


@pytest.fixture
def ddb_tables():
    """Create moto-mocked vod_entitlements + billing + video_metadata tables."""
    # ... setup code creating all three tables with correct schemas ...


def test_free_video_no_purchase_required(client, ddb_tables, seed_video_free):
    """Free video: no purchase required."""
    resp = client.get(f"/ui/videos/{seed_video_free}", headers=alice_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["entitled"] is True
    assert data["price_cents"] is None
    assert data["playback_url"] is not None  # Free = immediate playback


def test_paid_video_not_purchased(client, ddb_tables, seed_video_paid):
    """Paid video: not purchased -> entitled=false."""
    resp = client.get(f"/ui/videos/{seed_video_paid}", headers=bob_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["entitled"] is False
    assert data["price_cents"] == 999
    assert data["playback_url"] is None


def test_purchase_flow_happy_path(client, ddb_tables, seed_video_paid, seed_bob_pm):
    """Purchase flow: happy path."""
    resp = client.post(
        f"/ui/videos/{seed_video_paid}/purchase",
        json={"payment_method_id": seed_bob_pm},
        headers=bob_headers(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["purchase_id"].startswith("vpurch_")
    assert data["amount_cents"] == 999
    assert data["currency"] == "USD"
    assert data["entitled"] is True

    # Verify entitlement record exists
    assert check_vod_entitlement(user_id=BOB_ID, video_id=seed_video_paid) is True


def test_purchase_creates_debit_for_buyer(client, ddb_tables, seed_video_paid, seed_bob_pm):
    """Purchase creates billing ledger debit for buyer."""
    client.post(f"/ui/videos/{seed_video_paid}/purchase",
                json={"payment_method_id": seed_bob_pm}, headers=bob_headers())
    # Query billing table for Bob
    items = query_billing_ledger(user_id=BOB_ID)
    debits = [i for i in items if i["type"] == "debit" and i["reason"] == "VOD purchase"]
    assert len(debits) == 1
    assert int(debits[0]["amount_cents"]) == 999
    assert debits[0]["meta"]["video_id"] == seed_video_paid


def test_purchase_creates_credit_for_creator(client, ddb_tables, seed_video_paid, seed_bob_pm):
    """Purchase creates billing ledger credit for creator."""
    client.post(f"/ui/videos/{seed_video_paid}/purchase",
                json={"payment_method_id": seed_bob_pm}, headers=bob_headers())
    items = query_billing_ledger(user_id=ALICE_ID)
    credits = [i for i in items if i["type"] == "credit" and i["reason"] == "VOD sale"]
    assert len(credits) == 1
    assert int(credits[0]["amount_cents"]) == 999
    assert credits[0]["meta"]["buyer_id"] == BOB_ID


def test_duplicate_purchase_returns_409(client, ddb_tables, seed_video_paid, seed_bob_pm):
    """Duplicate purchase returns 409."""
    client.post(f"/ui/videos/{seed_video_paid}/purchase",
                json={"payment_method_id": seed_bob_pm}, headers=bob_headers())
    resp = client.post(f"/ui/videos/{seed_video_paid}/purchase",
                       json={"payment_method_id": seed_bob_pm}, headers=bob_headers())
    assert resp.status_code == 409
    assert "Already purchased" in resp.json()["detail"]


def test_cannot_purchase_own_video(client, ddb_tables, seed_video_paid, seed_alice_pm):
    """Cannot purchase own video."""
    resp = client.post(f"/ui/videos/{seed_video_paid}/purchase",
                       json={"payment_method_id": seed_alice_pm}, headers=alice_headers())
    assert resp.status_code == 400


def test_invalid_payment_method(client, ddb_tables, seed_video_paid):
    """Invalid payment method returns 400."""
    resp = client.post(f"/ui/videos/{seed_video_paid}/purchase",
                       json={"payment_method_id": "pm_nonexistent"}, headers=bob_headers())
    assert resp.status_code == 400


def test_video_not_published(client, ddb_tables, seed_video_encoding):
    """Video in encoding status -> 404 for non-owner."""
    resp = client.get(f"/ui/videos/{seed_video_encoding}", headers=bob_headers())
    assert resp.status_code == 404


def test_owner_always_entitled(client, ddb_tables, seed_video_paid):
    """Owner always entitled regardless of price."""
    resp = client.get(f"/ui/videos/{seed_video_paid}", headers=alice_headers())
    assert resp.status_code == 200
    assert resp.json()["entitled"] is True
    assert resp.json()["is_owner"] is True


def test_set_pricing_owner(client, ddb_tables, seed_video_free):
    """Owner can set price."""
    resp = client.patch(f"/ui/videos/{seed_video_free}/pricing",
                        json={"price_cents": 1999, "access_mode": "ppv"}, headers=alice_headers())
    assert resp.status_code == 200


def test_set_pricing_non_owner_rejected(client, ddb_tables, seed_video_free):
    """Non-owner cannot set pricing."""
    resp = client.patch(f"/ui/videos/{seed_video_free}/pricing",
                        json={"price_cents": 1999}, headers=bob_headers())
    assert resp.status_code == 403


def test_subscriber_only_blocks_purchase(client, ddb_tables, seed_video_sub_only, seed_bob_pm):
    """access_mode=subscriber_only blocks purchase."""
    resp = client.post(f"/ui/videos/{seed_video_sub_only}/purchase",
                       json={"payment_method_id": seed_bob_pm}, headers=bob_headers())
    assert resp.status_code == 403


def test_free_video_price_zero(client, ddb_tables, seed_video_price_zero):
    """Free video (price_cents=0): entitled without purchase."""
    resp = client.get(f"/ui/videos/{seed_video_price_zero}", headers=bob_headers())
    assert resp.json()["entitled"] is True


def test_entitlement_with_expired_ttl(ddb_tables):
    """Entitlement with TTL in the past is not valid."""
    grant_vod_entitlement(user_id=BOB_ID, video_id="vid_ttl", creator_id=ALICE_ID,
                          amount_cents=0, ttl=1000000)  # far in past
    assert check_vod_entitlement(user_id=BOB_ID, video_id="vid_ttl") is False
```

**Mock setup code pattern for unit tests:**

```python
@pytest.fixture
def seed_video_paid():
    """Seed a paid video owned by Alice."""
    video_id = f"vid_paid_{uuid.uuid4().hex[:8]}"
    T.video_metadata.put_item(Item={
        "video_id": video_id,
        "owner_user_id": ALICE_ID,
        "title": "Test Paid Video",
        "status": "published",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "price_cents": 999,
        "access_mode": "ppv",
        "visibility": "public",
        "hls_manifest_url": f"https://cdn.example.com/{video_id}/manifest.m3u8",
    })
    return video_id

@pytest.fixture
def seed_bob_pm():
    """Seed a payment method for Bob."""
    pm_id = f"pm_{uuid.uuid4().hex[:8]}"
    T.billing.put_item(Item={
        "pk": f"USER#{BOB_ID}",
        "sk": f"PM#{pm_id}",
        "pm_id": pm_id,
        "type": "card",
        "brand": "visa",
        "last4": "4242",
        "created_at": now_ts(),
    })
    return pm_id
```

### 5.2 E2E Tests (`frontend/e2e/vod-purchase.spec.ts`)

New file, ~500 lines.

**Section 90: VOD Purchase API (8 tests)**:

1. `Creator sets video price to $9.99` — PATCH pricing, verify 200
2. `Viewer sees price and entitled=false` — GET detail as non-owner
3. `Viewer purchases video with PM` — POST purchase, verify 200
4. `Viewer is entitled after purchase` — GET detail, entitled=true
5. `Duplicate purchase returns 409` — POST again, verify 409
6. `Billing ledger contains debit entry` — query billing table
7. `Creator billing ledger contains credit entry` — query billing table
8. `Cannot purchase own video` — POST as creator, verify 400

**Section 91: VOD Pricing API (5 tests)**:

1. `Create video with price_cents in upload` — POST with price
2. `Update price after creation` — PATCH pricing
3. `Set access_mode to subscriber_only` — PATCH, verify
4. `Non-owner cannot set pricing` — 403
5. `Price 0 makes video free` — PATCH price_cents=0, GET → entitled=true

**Section 92: VOD Player UI (5 tests)**:

1. `Free video shows player immediately` — navigate, verify player visible
2. `Paid video shows purchase dialog` — navigate, verify price badge + button
3. `Purchase dialog shows payment methods` — click purchase, verify PM list
4. `After purchase, player becomes visible` — complete purchase flow
5. `Subscriber-only shows subscribe CTA` — verify "Subscribe" button visible

**Test Setup (beforeAll)**:
- Seed sessions for Alice (creator) and Bob (viewer)
- Create a video as Alice via upload presign + complete
- Transition video to published status
- Add payment method for Bob in billing table

### 5.3 Edge Cases to Cover

1. **Concurrent purchases**: Two requests for the same video + user. The DDB `put_item` for entitlement is idempotent (same PK/SK overwrites), but the ledger write would create duplicate debits. Solution: use `attribute_not_exists(pk)` condition on the entitlement write; if it fails, return 409 without writing ledger.

2. **Price change after purchase**: If creator raises price after viewer purchased at lower price, existing entitlement remains valid. The `amount_cents` on the entitlement record captures the historical purchase price.

3. **Video deletion after purchase**: Soft-deleted videos should still honor existing entitlements for re-published content. The entitlement check is independent of video status.

4. **Payment method deleted after purchase**: Entitlement persists. The PM ID on the entitlement record is for audit trail only.

5. **Zero-price video with access_mode="ppv"**: Should behave as free — entitled without purchase. Enforce: `price_cents > 0` required when `access_mode="ppv"`.

6. **DDB Decimal coercion**: `price_cents` stored as DynamoDB Number will deserialize as `Decimal`. The `_int_or_none()` helper in `video_from_item()` already handles this pattern.

---

## 6. Security Considerations

### 6.1 Authentication & Authorization Edge Cases

- **Entitlement check is fail-closed**: If the DDB query in `check_vod_entitlement()` throws an exception, it returns `False` (deny access). This is critical -- a DDB outage must not grant free access to paid content.
- **Owner bypass is server-side only**: The `is_owner` check compares `video.owner_user_id` to the authenticated `user_sub` from the session cookie JWT. A client cannot forge ownership.
- **CSRF on purchase endpoint**: `POST /ui/videos/{id}/purchase` uses cookie auth via `require_ui_session`, so the `x-csrf-token` header is mandatory for cookie-authenticated requests. Bearer-auth requests (API clients) skip CSRF per the existing pattern in `app/auth/deps.py`.

### 6.2 Input Validation

- `video_id` path parameter: No regex validation needed -- `get_video()` performs a DDB `get_item` that returns None for invalid IDs. Sanitized via Pydantic `str` type.
- `payment_method_id`: Max length 200 chars, min length 1. Validated against DDB lookup.
- `price_cents`: Constrained to `ge=0, le=100_000_00` (max $100,000) via Pydantic `Field`.
- `access_mode`: Constrained to exactly 4 valid values via regex pattern.
- `idempotency_key`: Max 128 chars, optional. Stored but not enforced at the DDB level (future enhancement).

### 6.3 Rate Limiting

- Purchase endpoint should be rate-limited to prevent automated bulk purchasing attacks. Suggested: 10 purchases per minute per user. Use the existing `admin_action_max_per_window` / `admin_action_window_seconds` pattern from `app/core/settings.py` (lines 157-158) adapted for purchase actions.
- Pricing endpoint (PATCH): Rate-limited to prevent rapid price oscillation (5 updates per minute per video).

### 6.4 Abuse Vectors

- **Price manipulation race**: Creator sets price to $0.01, friend purchases, creator sets price back to $9.99. The entitlement captures the historical price. This is not a security issue (creator chose to set the price), but the billing ledger provides audit trail.
- **Entitlement farming**: A user could create many accounts to purchase at promotional prices. Each account needs a valid payment method, providing some friction. Future enhancement: link entitlements to PM fingerprints.
- **Refund abuse**: No refund endpoint is defined in this ticket. Future refund flow should revoke the entitlement AND write a reversal ledger entry.

### 6.5 Data Privacy

- Payment method IDs are stored in entitlement records for audit trail. The actual card numbers are stored (encrypted) in the billing table, not in entitlements.
- Purchase history (`list_user_vod_purchases`) is scoped to the authenticated user. No user can view another user's purchases.
- Creator-side view (`list_video_purchasers`) shows buyer IDs but should NOT expose buyer payment method details. The ByVideo GSI response should be filtered to exclude `payment_method_id`.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

The `vod_entitlements` table is new and has no existing data. Creation is additive and non-destructive.

**Script addition to `scripts/local-ddb-init.py`:**
```python
TableDef(
    "vod_entitlements", "pk", "sk",
    gsi=[
        {"index_name": "ByVideo", "partition_key": "video_id", "sort_key": "purchased_at"},
        {"index_name": "ByCreatorPurchasedAt", "partition_key": "creator_id", "sort_key": "purchased_at"},
    ],
    attr_types={"purchased_at": "N"},
),
```

**Production DDB creation (CloudFormation/CDK):**
```yaml
VodEntitlementsTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: vod_entitlements
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - { AttributeName: pk, AttributeType: S }
      - { AttributeName: sk, AttributeType: S }
      - { AttributeName: video_id, AttributeType: S }
      - { AttributeName: purchased_at, AttributeType: N }
      - { AttributeName: creator_id, AttributeType: S }
    KeySchema:
      - { AttributeName: pk, KeyType: HASH }
      - { AttributeName: sk, KeyType: RANGE }
    GlobalSecondaryIndexes:
      - IndexName: ByVideo
        KeySchema:
          - { AttributeName: video_id, KeyType: HASH }
          - { AttributeName: purchased_at, KeyType: RANGE }
        Projection: { ProjectionType: ALL }
      - IndexName: ByCreatorPurchasedAt
        KeySchema:
          - { AttributeName: creator_id, KeyType: HASH }
          - { AttributeName: purchased_at, KeyType: RANGE }
        Projection: { ProjectionType: ALL }
```

### 7.2 Data Backfill

No backfill needed. This is a net-new feature. Existing videos default to `price_cents=None` and `access_mode=None`, which means "free" -- backward compatible.

### 7.3 Feature Flag Rollout

Add a feature flag to `app/core/settings.py`:
```python
vod_ppv_enabled: bool = os.environ.get("VOD_PPV_ENABLED", "0") not in ("0", "false", "False")
```

Rollout stages:
1. **Stage 1**: Deploy backend code with `VOD_PPV_ENABLED=0`. New endpoints exist but return 404 when flag is off.
2. **Stage 2**: Enable for internal testing (`VOD_PPV_ENABLED=1` on staging).
3. **Stage 3**: Enable in production for beta creators (flag per-user if needed).
4. **Stage 4**: GA rollout (`VOD_PPV_ENABLED=1` in production).

### 7.4 Rollback Steps

If issues are found post-deployment:
1. Set `VOD_PPV_ENABLED=0` -- all purchase endpoints return 404, video detail stops showing price/purchase options.
2. Existing entitlements remain in DDB and are still honored for playback (entitlement check still runs).
3. No data loss -- all ledger entries and entitlement records are preserved.
4. If table schema changes caused issues, the `vod_entitlements` table can be deleted without affecting any other table.

### 7.5 Zero-Downtime Deployment

- The new fields on `VideoMetadataModel` (`price_cents`, `access_mode`) default to `None`, so existing video items in DDB do not need updating.
- The `video_from_item()` deserializer uses `_int_or_none()` which returns `None` for missing attributes -- no `KeyError`.
- New endpoints are additive (new route handlers), not modifications of existing routes.
- The `vod_entitlements` table is independent; its creation does not lock or modify any existing table.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vod_purchase_total` | Counter | `status={success,failure,conflict}` | Total purchase attempts |
| `vod_purchase_amount_cents` | Histogram | `creator_id` | Purchase amounts distribution |
| `vod_entitlement_check_total` | Counter | `result={entitled,not_entitled,error}` | Entitlement check outcomes |
| `vod_entitlement_check_latency_seconds` | Histogram | | DDB get_item latency |
| `vod_pricing_update_total` | Counter | `access_mode` | Pricing update events |

Add to `app/metrics.py` following the existing `record_playback_entitlement_event` pattern (imported in `app/services/playback_entitlements.py`, line 13).

### 8.2 Alerting Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Purchase failure rate > 5% | `rate(vod_purchase_total{status=failure}[5m]) / rate(vod_purchase_total[5m]) > 0.05` | High |
| Entitlement check error rate > 1% | Similar ratio on `vod_entitlement_check_total{result=error}` | Critical |
| Entitlement check latency p99 > 200ms | Histogram quantile | Medium |
| Zero purchases in 1 hour (during business hours) | `increase(vod_purchase_total[1h]) == 0` | Low |

### 8.3 Common Debugging Scenarios

**Scenario: User reports "already purchased" but cannot watch**
1. Query `vod_entitlements` for `PK=USER#{user_id}, SK=VIDEO#{video_id}`.
2. Check if item exists. If yes, check `ttl` field -- if non-zero and expired, the rental has lapsed.
3. Check `source` field -- if "subscription" and subscription has lapsed, access is denied.
4. Verify video status is "published" or "approved".

**Scenario: Creator reports purchase count is wrong**
1. Query `vod_entitlements` via ByVideo GSI for `video_id`. Count items.
2. Compare to `purchase_count` on video metadata. If mismatched, the counter increment failed (best-effort).
3. Fix: manual `update_item` on `video_metadata` to set correct count.

**Scenario: Ledger debit exists but no credit for creator**
1. The credit write is best-effort. Check CloudWatch logs for `vod_purchase_credit_failed`.
2. Manually write the credit entry using the debit entry's `meta` fields.

### 8.4 Log Patterns to Watch

```
# Successful purchase
{"level": "info", "event": "vod_purchase_completed", "user_id": "...", "video_id": "...", "amount_cents": 999}

# Failed credit write
{"level": "warning", "event": "vod_purchase_credit_failed", "creator_id": "...", "video_id": "..."}

# Entitlement check error
{"level": "warning", "event": "vod_entitlement_check_failed", "user_id": "...", "video_id": "..."}

# Counter update failure
{"level": "warning", "event": "vod_purchase_counter_update_failed", "video_id": "..."}
```

### 8.5 Health Check

No dedicated health check endpoint needed. The existing `/docs` (Swagger UI) and DDB table health are sufficient. The purchase endpoint itself serves as a synthetic health check target -- a 200 response with `entitled=true` for a known test video confirms the full path is working.

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Metric | Estimate | Basis |
|--------|----------|-------|
| Video detail requests/sec | 100 | Main browse/watch flow |
| Purchase requests/sec | 5 | ~5% conversion rate |
| Entitlement checks/sec | 100 | 1:1 with video detail |
| Pricing updates/sec | 0.1 | Infrequent creator action |

### 9.2 DDB Capacity

**vod_entitlements table (on-demand billing):**
- Read: 1 RCU per entitlement check (single `get_item`, ~100 bytes per item → 1 RCU)
- Write: 1 WCU per purchase (single `put_item`, ~200 bytes per item → 1 WCU)
- GSI reads: ByVideo GSI used only for creator dashboards (low frequency)

**billing table (additional load):**
- 2 additional writes per purchase (debit + credit ledger entries)
- ~150 bytes per ledger entry → 1 WCU each

**video_metadata table (additional load):**
- 1 additional write per purchase (counter increment via `update_item`)

**Total per purchase: 1 vod_ent write + 2 billing writes + 1 video_metadata write = 4 WCUs + 1 RCU**

At 5 purchases/sec: 20 WCU + 5 RCU additional load. Well within on-demand capacity.

### 9.3 Hot Partition Analysis

- **vod_entitlements PK**: Partitioned by `USER#`. Users typically purchase 1-10 videos. No hot partition risk.
- **ByVideo GSI**: Partitioned by `video_id`. A viral video could receive 100+ purchases/second, but GSI writes are async and buffered. DDB on-demand mode handles this.
- **ByCreatorPurchasedAt GSI**: Partitioned by `creator_id`. Top creators with many concurrent purchases could see write throttling. Monitor via CloudWatch `ThrottledWriteRequests`.

### 9.4 Caching Strategy

- **Entitlement check**: No caching. The check is a single DDB `get_item` (1-2ms latency). Caching would complicate revocation and add staleness.
- **Video metadata**: Could cache in-memory with 60s TTL for the `get_video()` call, but price changes would be delayed. Acceptable for browse; the purchase handler always reads fresh.
- **Payment method validation**: No caching. Must verify PM existence at purchase time.

### 9.5 Latency Budget

| Operation | Target p99 | Components |
|-----------|-----------|------------|
| GET /videos/{id} | 50ms | get_video (15ms) + entitlement check (10ms) + playback URL mint (10ms) |
| POST /videos/{id}/purchase | 200ms | get_video (15ms) + entitlement check (10ms) + PM validation (10ms) + entitlement write (15ms) + 2 ledger writes (30ms) + counter update (15ms) |

---

## 10. Dependency Analysis

### 10.1 Blocked By

- None. MON-001 is the foundational ticket. It depends only on existing infrastructure (billing table, video metadata, playback entitlements).

### 10.2 Blocks

| Ticket | Dependency |
|--------|-----------|
| MON-005 | Subscription-gated VOD depends on `check_vod_entitlement()` and the `access_mode` field |
| MON-003 | Creator earnings dashboard aggregates VOD purchase credits from the billing ledger |
| MON-004 | Payout system includes VOD purchase credits in available balance |

### 10.3 Integration Points

- **Billing table** (`T.billing`): Writes LEDGER debit/credit entries. Schema must be compatible with existing ledger query patterns used by billing.py and MON-003.
- **Video metadata table** (`T.video_metadata`): Adds `price_cents`, `access_mode`, `purchase_count`, `revenue_cents` fields. Must not break existing `video_from_item()` deserialization for items lacking these fields.
- **Playback URL generation** (`app/services/vod_playback_url.py`): `mint_vod_playback_url()` is called after entitlement check passes. No changes to this service are needed.
- **Subscription access** (`app/services/subscription_access.py`): MON-005 will add `has_active_subscription()` call to the entitlement check. MON-001 prepares the `access_mode` field but does not call subscription_access.

### 10.4 API Contract Commitments

Once shipped, these response shapes become commitments:
- `VideoDetailOut.entitled` (boolean) -- consumers will key purchase UX on this
- `VideoDetailOut.price_cents` (int or null) -- displayed in UI
- `VodPurchaseOut.purchase_id` (string starting with `vpurch_`) -- stored in client receipts

---

## 11. Acceptance Criteria

1. A creator can set a `price_cents` and `access_mode` on any video they own via `PATCH /ui/videos/{id}/pricing`.
2. A viewer requesting `GET /ui/videos/{id}` for a priced video sees `entitled: false` and `price_cents` in the response.
3. A viewer can purchase a video via `POST /ui/videos/{id}/purchase` with a valid payment method, receiving a `purchase_id`.
4. After purchase, `GET /ui/videos/{id}` returns `entitled: true` and a valid `playback_url`.
5. Duplicate purchase attempts return HTTP 409.
6. The viewer's billing ledger contains a debit entry with `reason: "VOD purchase"` and correct `amount_cents`.
7. The creator's billing ledger contains a credit entry with `reason: "VOD sale"` and correct `amount_cents`.
8. The video's `purchase_count` is incremented after each successful purchase.
9. A creator cannot purchase their own video (HTTP 400).
10. A video with `access_mode: "subscriber_only"` cannot be purchased individually (HTTP 403).
11. Free videos (`price_cents=0` or `access_mode="free"`) return `entitled: true` without purchase.
12. The video owner always sees `entitled: true` regardless of price settings.
13. The frontend shows a purchase dialog for non-entitled paid videos and a player for entitled videos.
14. Entitlements with an expired TTL are treated as invalid (rental expiry).
15. All 15 unit tests and 18 E2E tests pass.

---

## 12. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-----------|-------------|------------|---------------------|-----------------|
| GET /videos/{id} | Video ID not in DDB | 404 | `video_not_found` | "Video not found" | Verify URL |
| GET /videos/{id} | Video status is "encoding" and viewer is not owner | 404 | `video_not_found` | "Video not found" | Wait for processing |
| GET /videos/{id} | DDB read error on entitlement check | 200 | N/A | `entitled: false` (fail-closed) | Retry request |
| POST /videos/{id}/purchase | Video not found | 404 | `video_not_found` | "Video not available for purchase" | Verify URL |
| POST /videos/{id}/purchase | Purchasing own video | 400 | `cannot_purchase_own` | "Cannot purchase your own video" | N/A |
| POST /videos/{id}/purchase | Video is free (price 0 or null) | 400 | `video_is_free` | "Video is free -- no purchase required" | Access directly |
| POST /videos/{id}/purchase | access_mode=subscriber_only | 403 | `subscriber_only` | "This video is only available to subscribers" | Subscribe to creator |
| POST /videos/{id}/purchase | Already purchased | 409 | `already_purchased` | "Already purchased" | Refresh page |
| POST /videos/{id}/purchase | PM not found in DDB | 400 | `payment_method_not_found` | "Payment method not found" | Add a payment method |
| POST /videos/{id}/purchase | PM marked as deleted | 400 | `payment_method_not_found` | "Payment method has been removed" | Add a new PM |
| PATCH /videos/{id}/pricing | Not video owner | 403 | `not_owner` | "You do not own this video" | N/A |
| PATCH /videos/{id}/pricing | price_cents > 10,000,000 | 422 | `validation_error` | Pydantic error | Reduce price |
| PATCH /videos/{id}/pricing | Invalid access_mode | 422 | `validation_error` | Pydantic error | Use valid mode |

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
- Uses `useMutation` for purchase action
- Local state: `showPurchaseDialog: boolean`

**Responsive breakpoints:**
- Mobile (<640px): Full-width price badge, stacked purchase button below thumbnail
- Tablet (640-1024px): Side-by-side thumbnail + info panel
- Desktop (>1024px): Standard video player layout with sidebar

**Accessibility (ARIA):**
- Purchase button: `aria-label="Purchase video for $9.99"`
- Price badge: `role="status"`, `aria-live="polite"`
- After purchase: Focus moves to the video player element

**Keyboard navigation:**
- Tab order: thumbnail → price badge → Purchase button
- Enter/Space on Purchase button opens dialog
- Escape closes dialog

### 13.2 PurchaseDialog Component

```typescript
interface PurchaseDialogProps {
  videoId: string;
  priceCents: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: (purchaseId: string) => void;
}
```

**Component tree:**
```
PurchaseDialog
  ├── Dialog (shadcn/ui)
  │   ├── DialogHeader
  │   │   └── DialogTitle: "Purchase Video"
  │   ├── DialogDescription: "You will be charged $X.XX"
  │   ├── PaymentMethodSelector
  │   │   ├── RadioGroup (one per PM)
  │   │   │   └── RadioGroupItem: "Visa ****4242"
  │   │   └── Button: "Add Payment Method" (links to /billing)
  │   └── DialogFooter
  │       ├── Button[variant=outline]: "Cancel"
  │       └── Button[variant=default]: "Confirm Purchase"
  └── (loading overlay when mutation is pending)
```

**Query keys used:**
- `["billing", "payment-methods"]` -- fetches user's PMs
- `["video", videoId]` -- invalidated on purchase success

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
- Free video: Green "Free" badge
- Entitled (purchased): Green "Purchased" badge
- Entitled (subscription): Blue "Included" badge
- Not entitled (ppv): Outline badge "$9.99"
- Not entitled (subscriber_only): Secondary "Subscribers Only" badge

---

## 14. Related Tickets

- **MON-002**: Tip ledger integration (same LEDGER# pattern used here for purchase records)
- **MON-003**: Creator earnings dashboard (will aggregate VOD purchase credits alongside tips)
- **MON-005**: Subscription-gated VOD (extends `check_vod_entitlement` with subscription lookup)

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/models_video.py` | 36, 93-96 | EXISTS: `VideoMetadataModel` already has `price_cents` (93), `access_mode` (94), `purchase_count` (95), `revenue_cents` (96) fields |
| `app/services/vod_purchase.py` | 40-674 | ALREADY EXISTS (674 lines): `check_vod_access` (131), `check_entitlement_purchase_only` (316), `check_entitlement` (372), `purchase_video` (398), `list_purchases` (563), `grant_entitlement` (591), `record_playback_complete` (636) |
| `app/routers/video_listing.py` | 661, 1116-1117, 1184-1185, 1219 | ALREADY EXISTS: `get_video_detail` (661), `purchase_video_endpoint` (1116), `list_purchases_endpoint` (1184), `PATCH /{video_id}/pricing` (1219) — endpoints are in `video_listing.py`, NOT in `vod.py` as this ticket proposes |
| `scripts/local-ddb-init.py` | 584 | EXISTS: `VodEntitlements` table definition |
| `app/core/settings.py` | 1076 | EXISTS: `vod_entitlements_table_name` setting |
| `app/core/tables.py` | 84, 208 | EXISTS: `T.vod_entitlements` table handle |
| `app/services/playback_entitlements.py` | 234 | EXISTS: `PLAYBACKJWT` for playback token signing |
| `app/services/billing_shared.py` | — | EXISTS: billing table access patterns |
| `app/services/subscription_access.py` | 55, 72 | EXISTS: `has_active_subscription` (55), `can_access_creator` (72) — already imported by vod_purchase.py |
<!-- NOTE: This ticket's service design (vod_purchase.py) and data model changes (price_cents, access_mode on VideoMetadataModel) have been FULLY IMPLEMENTED. The router endpoints exist in video_listing.py rather than vod.py. The ticket should be marked as Complete or moved to verification status. -->

---

## Testing Strategy

### Unit Tests (`tests/test_vod_ppv.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_set_video_price` | Set video price |
| 2 | `test_purchase_creates_entitlement` | Purchase creates entitlement |
| 3 | `test_check_entitlement_returns_true` | Check entitlement returns true |
| 4 | `test_check_entitlement_no_purchase` | Check entitlement no purchase |
| 5 | `test_playback_gated_without_entitlement` | Playback gated without entitlement |
| 6 | `test_billing_ledger_debit_written` | Billing ledger debit written |
| 7 | `test_creator_credit_written` | Creator credit written |
| 8 | `test_free_video_no_entitlement_needed` | Free video no entitlement needed |
| 9 | `test_idempotent_purchase` | Idempotent purchase |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/vod-ppv.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~16 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `VOD_PPV_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| MEDIA-001 | Shared player for VOD playback | Soft |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| MON-005 | Subscription-gated VOD extends entitlement check |

### Merge Strategy
**Independent -- new entitlement table and endpoints. Playback path extended with entitlement check (additive). Feature-flag-gated.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: VOD_PPV_ENABLED=true
- [ ] Service file created/modified: `app/services/vod_entitlements.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/vod-ppv.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_vod_ppv.py`
