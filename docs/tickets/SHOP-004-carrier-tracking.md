# SHOP-004: Order Tracking -- Carrier Integration

**Ticket**: SHOP-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 5-7 days

---

## 1. Executive Summary

The platform has order tracking infrastructure: `TransactionDetail.tsx` displays carrier name and tracking number (lines 435-445), `ShippingTimeline.tsx` renders a visual 4-step timeline (Ordered -> Shipped -> Delivered -> Completed), and the `PUT /ui/purchase-history/transactions/{id}/shipping` endpoint (purchase_history.py:70-78) allows manual shipping updates. There is also a UPS integration stub (`app/services/ups.py`, 101 lines) with label generation and quote endpoints, and a UPS tracking webhook receiver (`app/routers/ups.py:91-121`).

However, tracking updates are entirely manual -- there is no automatic polling of carrier APIs for status changes, no tracking URL construction (tracking numbers are displayed as plain text), and the webhook receiver only logs events to an audit table without updating the order's shipping status. This feature adds carrier API polling for automatic status updates, tracking URL construction for clickable links, and wires the existing webhook receiver to update order records.

The business impact is significant: manual tracking updates require sellers to constantly check carrier websites and manually update each order's status. This is error-prone, labor-intensive, and leads to poor buyer experience (buyers see stale "Shipped" status for days). Automatic carrier tracking eliminates this operational burden, improves buyer confidence, and enables automated delivery confirmation workflows (e.g., auto-complete orders 48 hours after delivery confirmation).

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Clickable Tracking Link**

| Field | Value |
|-------|-------|
| Actor | Buyer |
| Story | As a buyer, I want to click my tracking number and see the carrier's tracking page so I can monitor my package in real-time. |
| Preconditions | Order has shipping info with carrier name and tracking number. |
| Acceptance Criteria | 1. Tracking number rendered as a clickable link in `TransactionDetail.tsx`. 2. Link opens carrier tracking page in new tab. 3. URL correctly constructed for UPS, FedEx, USPS, and DHL. 4. Falls back to plain text if carrier is unknown. |

**US-2: Automatic Status Updates**

| Field | Value |
|-------|-------|
| Actor | Buyer |
| Story | As a buyer, I want my order status to update automatically when the carrier scans my package so I always know where it is. |
| Preconditions | Order has been shipped with a valid tracking number from a supported carrier. |
| Acceptance Criteria | 1. Shipping status updates from "shipped" to "in_transit" to "out_for_delivery" to "delivered" without manual intervention. 2. Updates happen within 30 minutes of carrier scan. 3. Each status transition is timestamped and logged. 4. No duplicate updates for the same event. |

**US-3: Delivery Notification**

| Field | Value |
|-------|-------|
| Actor | Seller |
| Story | As a seller, I want to be notified when a package is delivered so I can follow up with the buyer or auto-complete the order. |
| Preconditions | Order has tracking with automatic updates enabled. |
| Acceptance Criteria | 1. Alert sent to seller when carrier reports delivery. 2. Alert includes order ID, buyer name, and delivery timestamp. 3. Alert sent via existing alerts system (`create_alert`). |

**US-4: Carrier Auto-Detection**

| Field | Value |
|-------|-------|
| Actor | Seller |
| Story | As a seller, I want to enter a tracking number and have the carrier auto-detected so I don't have to manually select UPS/FedEx/USPS. |
| Preconditions | Tracking number follows standard carrier format patterns. |
| Acceptance Criteria | 1. UPS tracking numbers (1Z + 16 alphanum chars) auto-detected. 2. FedEx tracking numbers (12/15/20/22 digit numeric) auto-detected. 3. USPS tracking numbers (20/22/30/34 digit numeric) auto-detected. 4. Unknown formats leave carrier field empty (manual selection required). 5. Auto-detection runs on the backend when shipping info is updated. |

**US-5: Admin Delivery Metrics**

| Field | Value |
|-------|-------|
| Actor | Admin |
| Story | As an admin, I want to see delivery rates and average transit times so I can evaluate carrier performance. |
| Preconditions | Historical shipping data with timestamps. |
| Acceptance Criteria | 1. Delivery rate metric available (orders delivered / orders shipped). 2. Average transit time metric (shipped_at to delivered_at). 3. Breakdown by carrier. (Deferred to analytics ticket -- not in scope for this ticket.) |

### 2.2 Pain Points

1. **Tracking numbers are dead text**: `TransactionDetail.tsx:444` renders tracking numbers as `<dd className="font-mono text-xs">` with no link. Users must manually copy-paste into carrier websites.
2. **No automatic updates**: Sellers must manually call `PUT /transactions/{id}/shipping` for every status change. With 50+ orders per day, this is unsustainable.
3. **Webhook data is wasted**: UPS webhooks are received (`ups.py:91`) but only logged to an audit table (`user_sub="UPS_TRACKING"`), never applied to order records.
4. **No carrier detection**: The system stores a `carrier` field but does not auto-detect from tracking number format, requiring sellers to manually specify the carrier.
5. **No intermediate states**: `ShippingTimeline.tsx` only has 4 steps (Ordered/Shipped/Delivered/Completed). Real carrier tracking has 5-7 intermediate states that provide useful information.

---

## 3. Current State Analysis

### 3.1 Transaction Shipping Display

`frontend/src/pages/purchases/TransactionDetail.tsx` displays shipping info inside a conditional block (lines 431-459):

```typescript
{/* Shipping details */}
{txn.shipping && (
  <div className="mt-4 border-t pt-4">
    <h4 className="mb-2 text-sm font-medium">Shipping</h4>
    <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
      {txn.shipping.carrier && (
        <div>
          <dt className="text-muted-foreground">Carrier</dt>
          <dd>{txn.shipping.carrier}</dd>
        </div>
      )}
      {txn.shipping.tracking_number && (
        <div>
          <dt className="text-muted-foreground">Tracking</dt>
          <dd className="font-mono text-xs">{txn.shipping.tracking_number}</dd>
        </div>
      )}
      {txn.shipping.shipped_at && (
        <div>
          <dt className="text-muted-foreground">Shipped</dt>
          <dd>{formatDate(txn.shipping.shipped_at)}</dd>
        </div>
      )}
      {txn.shipping.delivered_at && (
        <div>
          <dt className="text-muted-foreground">Delivered</dt>
          <dd>{formatDate(txn.shipping.delivered_at)}</dd>
        </div>
      )}
    </dl>
  </div>
)}
```

Key observations:
- Tracking number is plain `<dd>` text -- no `<a>` element.
- No `tracking_url` field is referenced.
- No carrier events or intermediate status displayed.

**Citations**:
- `frontend/src/pages/purchases/TransactionDetail.tsx:431-459` -- shipping detail block
- `frontend/src/pages/purchases/TransactionDetail.tsx:444` -- tracking number as plain text

### 3.2 Shipping Timeline

`frontend/src/pages/purchases/ShippingTimeline.tsx` (189 lines) renders a 4-step visual timeline with status resolution:

```typescript
function resolveStep(
  label: string,
  icon: React.ReactNode,
  isComplete: boolean,
  isCurrent: boolean,
  date?: string,
): Step {
  if (isComplete) return { label, icon, status: "complete", date };
  if (isCurrent) return { label, icon, status: "current", date };
  return { label, icon, status: "upcoming" };
}
```

The 4 steps are:
1. **Ordered** (always complete, uses `createdAt`)
2. **Shipped** (complete when `shippedAt` exists)
3. **Delivered** (complete when `deliveredAt` exists)
4. **Completed** (or branching: Cancelled/Reverted)

Real carrier tracking has intermediate states not represented:
- Label Created
- Picked Up
- In Transit (with location updates)
- Out for Delivery
- Exception (held at facility, returned, etc.)

**Citations**:
- `frontend/src/pages/purchases/ShippingTimeline.tsx:34-43` -- `resolveStep` function
- `frontend/src/pages/purchases/ShippingTimeline.tsx:59-116` -- step resolution logic (4 steps)
- `frontend/src/pages/purchases/ShippingTimeline.tsx:1` -- imports: Check, Clock, Package, Truck, XCircle, RotateCcw

### 3.3 Manual Shipping Update Endpoint

`app/routers/purchase_history.py:70-78`:

```python
@router.put("/transactions/{txn_id}/shipping", response_model=PurchaseTransactionInfo)
async def ui_update_shipping(
    req: Request,
    txn_id: str,
    body: PurchaseShippingReq,
    ctx=Depends(require_ui_session),
):
    _ = req
    return update_shipping(ctx["user_sub"], txn_id, body.shipping.model_dump())
```

This is the only way to update shipping status. The `update_shipping` service function writes to DynamoDB but has no logic to auto-detect carrier, construct tracking URLs, or trigger alerts on delivery.

**Citations**:
- `app/routers/purchase_history.py:70-78` -- `ui_update_shipping` endpoint
- `app/routers/purchase_history.py:65-67` -- `ui_get_transaction` endpoint (returns full transaction)

### 3.4 UPS Integration Service

`app/services/ups.py` (101 lines) provides authenticated UPS API access:

```python
def ups_access_token() -> str:
    cached = _TOKEN_CACHE.get("access_token")
    if cached:
        return cached
    if not S.ups_client_id or not S.ups_client_secret:
        raise HTTPException(500, "UPS client credentials not configured")
    r = requests.post(
        _ups_auth_url(),
        auth=(S.ups_client_id, S.ups_client_secret),
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    # ... token caching
```

Available functions:
- `ups_access_token()` (line 30) -- OAuth token retrieval with caching
- `_ups_post(path, payload)` (line 53) -- authenticated POST helper
- `quote(shipment)` (line 66) -- shipping rate quote
- `create_label(shipment)` (line 70) -- label generation
- `validate_address(req)` (line 74) -- address validation (XAV format)
- `verify_tracking_webhook_signature(raw_body, signature)` (line 94) -- HMAC SHA-256 verification

**Notably missing**: No `track_package()` function for querying tracking status.

**Citations**:
- `app/services/ups.py:30-50` -- `ups_access_token()` with caching
- `app/services/ups.py:53-63` -- `_ups_post()` authenticated request helper
- `app/services/ups.py:66-91` -- `quote()`, `create_label()`, `validate_address()`
- `app/services/ups.py:94-101` -- `verify_tracking_webhook_signature()`

### 3.5 UPS Webhook Receiver

`app/routers/ups.py:91-108` receives UPS tracking webhooks:

```python
@router.post("/api/ups/tracking/webhook")
async def ups_tracking_webhook(req: Request) -> Dict[str, Any]:
    raw = await req.body()
    signature = req.headers.get("x-ups-signature", "")
    if not verify_tracking_webhook_signature(raw, signature):
        raise HTTPException(403, "Invalid UPS webhook signature")

    payload = await req.json() if raw else {}
    tracking_number = payload.get("tracking_number") or payload.get("trackingNumber") or "unknown"
    T.billing.put_item(
        Item={
            "user_sub": "UPS_TRACKING",
            "sk": f"{now_ts()}#{tracking_number}",
            "payload": payload,
            "created_at": now_ts(),
        }
    )
    return {"received": True}
```

Key issues:
- Only writes to audit table (`user_sub="UPS_TRACKING"`) -- never looks up the associated order.
- Never calls `update_shipping()` to update order status.
- Never sends alerts to buyer/seller.
- Never resolves tracking number to a transaction ID.

**Citations**:
- `app/routers/ups.py:91-108` -- `ups_tracking_webhook` endpoint
- `app/routers/ups.py:95` -- signature verification
- `app/routers/ups.py:100-106` -- audit log write (no order update)

### 3.6 UPS Mock Endpoints

`app/routers/ups.py:121-169` provides mock endpoints for dev/test:

```python
@router.post("/mock/ups/label")
async def mock_ups_label(req: Request) -> Dict[str, Any]:
    if not _mock_enabled():
        raise HTTPException(404, "Not found")
    body = await req.json()
    tracking = f"1ZMOCK{int(time.time()*1000)}"
    return {
        "tracking_number": tracking,
        "label_url": f"https://mock-ups.local/labels/{tracking}.pdf",
        "service": body.get("service", "ground"),
        "status": "created",
    }
```

Available mocks: OAuth token, rate quote, label creation, address validation.
**Missing**: No mock tracking status lookup endpoint.

**Citations**:
- `app/routers/ups.py:121-131` -- mock OAuth token
- `app/routers/ups.py:134-146` -- mock rate quote
- `app/routers/ups.py:149-160` -- mock label with `1ZMOCK{timestamp}` tracking number
- `app/routers/ups.py:163-169` -- mock address validation

### 3.7 UPS Settings

`app/core/settings.py:278-283`:

```python
ups_base_url: str = os.environ.get("UPS_BASE_URL", "")
ups_auth_url: str = os.environ.get("UPS_AUTH_URL", "")
ups_client_id: str = os.environ.get("UPS_CLIENT_ID", "")
ups_client_secret: str = os.environ.get("UPS_CLIENT_SECRET", "")
ups_webhook_secret: str = os.environ.get("UPS_WEBHOOK_SECRET", "")
```

All default to empty string. In dev mode, `ups_base_url` should point to `http://localhost:8000/mock/ups`.

**Citations**:
- `app/core/settings.py:278-283` -- UPS configuration variables

### 3.8 Gaps Summary

| Gap | Current State | Required |
|-----|---------------|----------|
| Tracking URL | None | Construct from carrier + tracking number |
| Carrier detection | Manual only | Auto-detect from tracking number format |
| Webhook → order update | Logs to audit table | Update order shipping status |
| Status polling | None | Background job for non-webhook carriers |
| Intermediate timeline steps | 4 steps only | 7 steps with carrier event data |
| Mock tracking endpoint | None | GET /mock/ups/track/{tracking_number} |
| Delivery alerts | None | Alert buyer/seller on delivery |
| Tracking URL in API response | None | `tracking_url` field in transaction response |

---

## 4. Implementation Plan

### 4.1 Backend: Carrier Tracking URL Construction

**New file: `app/services/carrier_tracking.py`**

```python
"""Carrier tracking URL construction and auto-detection."""
from __future__ import annotations

import re
from typing import Optional, Dict

# ── Tracking URL Templates ────────────────────────────────────────

CARRIER_TRACKING_URLS: Dict[str, str] = {
    "ups": "https://www.ups.com/track?tracknum={tracking_number}",
    "fedex": "https://www.fedex.com/fedextrack/?trknbr={tracking_number}",
    "usps": "https://tools.usps.com/go/TrackConfirmAction?tLabels={tracking_number}",
    "dhl": "https://www.dhl.com/en/express/tracking.html?AWB={tracking_number}",
    "ontrac": "https://www.ontrac.com/tracking/?number={tracking_number}",
    "lasership": "https://www.lasership.com/track/{tracking_number}",
}

# ── Carrier Detection Patterns ────────────────────────────────────

# UPS: 1Z + 16 alphanumeric characters (18 total)
_UPS_PATTERN = re.compile(r"^1Z[A-Z0-9]{16}$", re.IGNORECASE)

# FedEx: 12, 15, 20, or 22 digits
_FEDEX_LENGTHS = {12, 15, 20, 22}

# USPS: 20, 22, 30, or 34 digits (or starts with specific prefixes)
_USPS_LENGTHS = {20, 22, 30, 34}
_USPS_PREFIXES = ("94", "92", "93", "70", "23", "13")

# DHL: 10 digits or starts with JD/JJD followed by digits
_DHL_PATTERN = re.compile(r"^(JJD?\d{18,20}|\d{10})$", re.IGNORECASE)


def build_tracking_url(carrier: str, tracking_number: str) -> Optional[str]:
    """Construct a tracking URL for the given carrier and tracking number.

    Args:
        carrier: Carrier identifier (ups, fedex, usps, dhl, etc.)
        tracking_number: The tracking number string.

    Returns:
        Full tracking URL string, or None if carrier is unknown.
    """
    if not carrier or not tracking_number:
        return None
    template = CARRIER_TRACKING_URLS.get(carrier.lower().strip())
    if not template:
        return None
    return template.format(tracking_number=tracking_number.strip())


def detect_carrier(tracking_number: str) -> Optional[str]:
    """Auto-detect carrier from tracking number format.

    Args:
        tracking_number: Raw tracking number string.

    Returns:
        Carrier identifier string ("ups", "fedex", "usps", "dhl") or None.

    Detection rules (applied in order):
        1. UPS: starts with "1Z" + 16 alphanumeric = 18 chars total
        2. DHL: starts with JD/JJD + digits, or exactly 10 digits
        3. FedEx: 12, 15, 20, or 22 digits (all numeric)
        4. USPS: 20, 22, 30, or 34 digits OR starts with 94/92/93/70/23/13
        5. Unknown: None
    """
    tn = tracking_number.strip().upper()
    if not tn:
        return None

    # UPS: 1Z prefix + 16 alphanumeric
    if _UPS_PATTERN.match(tn):
        return "ups"

    # DHL: JD/JJD prefix or exactly 10 digits
    if _DHL_PATTERN.match(tn):
        return "dhl"

    # Numeric-only patterns
    if tn.isdigit():
        length = len(tn)
        # FedEx lengths
        if length in _FEDEX_LENGTHS:
            return "fedex"
        # USPS lengths
        if length in _USPS_LENGTHS:
            return "usps"
        # USPS prefixes (for lengths not in FedEx set)
        if any(tn.startswith(p) for p in _USPS_PREFIXES):
            return "usps"

    return None


def map_carrier_status(carrier: str, raw_status: str) -> str:
    """Normalize carrier-specific status codes to our internal status enum.

    Internal statuses: label_created, picked_up, in_transit,
                       out_for_delivery, delivered, exception, returned.
    """
    status_lower = (raw_status or "").lower().strip()

    # UPS status mapping
    if carrier == "ups":
        if status_lower in ("label created", "manifest pickup", "billing information received"):
            return "label_created"
        if status_lower in ("picked up", "package picked up", "origin scan"):
            return "picked_up"
        if status_lower in ("in transit", "in-transit", "departed facility", "arrived at facility"):
            return "in_transit"
        if status_lower in ("out for delivery",):
            return "out_for_delivery"
        if status_lower in ("delivered",):
            return "delivered"
        if status_lower in ("exception", "returned to sender", "undeliverable"):
            return "exception"

    # Default mapping
    if "deliver" in status_lower:
        return "delivered"
    if "transit" in status_lower:
        return "in_transit"
    if "out for" in status_lower:
        return "out_for_delivery"
    if "picked" in status_lower or "pickup" in status_lower:
        return "picked_up"

    return "in_transit"  # safe default
```

### 4.2 Backend: Tracking Status Lookup

**File: `app/services/ups.py`** (additions)

```python
def track_package(tracking_number: str) -> Dict[str, Any]:
    """Query UPS Tracking API v1 for package status.

    Returns:
        {
            "tracking_number": str,
            "status": str,         # normalized status
            "status_description": str,
            "estimated_delivery": str | None,
            "delivered_at": str | None,
            "events": [
                {"timestamp": str, "description": str, "location": str}
            ]
        }
    """
    resp = _ups_post(f"api/track/v1/details/{tracking_number}", {})

    # Normalize UPS response format
    package = (resp.get("trackResponse", {})
               .get("shipment", [{}])[0]
               .get("package", [{}])[0])

    activities = package.get("activity", [])
    events = []
    for act in activities:
        events.append({
            "timestamp": act.get("date", "") + "T" + act.get("time", ""),
            "description": act.get("status", {}).get("description", ""),
            "location": _format_ups_location(act.get("location", {})),
        })

    current_status = package.get("currentStatus", {}).get("description", "")
    return {
        "tracking_number": tracking_number,
        "status": map_carrier_status("ups", current_status),
        "status_description": current_status,
        "estimated_delivery": package.get("deliveryDate", [{}])[0].get("date"),
        "delivered_at": _extract_delivery_timestamp(activities),
        "events": events,
    }


def _format_ups_location(loc: Dict[str, Any]) -> str:
    parts = [loc.get("city", ""), loc.get("stateProvince", ""), loc.get("countryCode", "")]
    return ", ".join(p for p in parts if p)


def _extract_delivery_timestamp(activities: list) -> Optional[str]:
    for act in activities:
        if act.get("status", {}).get("type") == "D":  # Delivered
            return act.get("date", "") + "T" + act.get("time", "")
    return None
```

### 4.3 Backend: Mock Tracking Endpoint

**File: `app/routers/ups.py`** (addition after line 169)

```python
@router.get("/mock/ups/track/{tracking_number}")
def mock_ups_track(tracking_number: str) -> Dict[str, Any]:
    """Mock UPS tracking status lookup.

    Returns a synthetic tracking response with configurable status.
    The status progresses based on the tracking number suffix:
    - ends with 0-2: label_created
    - ends with 3-4: in_transit
    - ends with 5-6: out_for_delivery
    - ends with 7-9: delivered
    """
    if not _mock_enabled():
        raise HTTPException(404, "Not found")

    # Determine mock status from tracking number
    last_digit = int(tracking_number[-1]) if tracking_number[-1].isdigit() else 5
    if last_digit <= 2:
        status, desc = "label_created", "Label Created"
    elif last_digit <= 4:
        status, desc = "in_transit", "In Transit"
    elif last_digit <= 6:
        status, desc = "out_for_delivery", "Out for Delivery"
    else:
        status, desc = "delivered", "Delivered"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "tracking_number": tracking_number,
        "status": status,
        "status_description": desc,
        "estimated_delivery": "2026-06-01",
        "delivered_at": now_iso if status == "delivered" else None,
        "events": [
            {
                "timestamp": now_iso,
                "description": desc,
                "location": "New York, NY, US",
            },
            {
                "timestamp": "2026-05-27T08:00:00Z",
                "description": "Picked up",
                "location": "Los Angeles, CA, US",
            },
        ],
    }
```

### 4.4 Backend: Wire Webhook to Order Updates

**File: `app/routers/ups.py`** (modify `ups_tracking_webhook` at lines 91-108)

```python
@router.post("/api/ups/tracking/webhook")
async def ups_tracking_webhook(req: Request) -> Dict[str, Any]:
    raw = await req.body()
    signature = req.headers.get("x-ups-signature", "")
    if not verify_tracking_webhook_signature(raw, signature):
        raise HTTPException(403, "Invalid UPS webhook signature")

    payload = await req.json() if raw else {}
    tracking_number = (
        payload.get("tracking_number")
        or payload.get("trackingNumber")
        or "unknown"
    )

    # 1. Audit log (existing behavior)
    T.billing.put_item(
        Item={
            "user_sub": "UPS_TRACKING",
            "sk": f"{now_ts()}#{tracking_number}",
            "payload": payload,
            "created_at": now_ts(),
        }
    )

    # 2. NEW: Look up order by tracking number and update shipping status
    txn = find_transaction_by_tracking(tracking_number)
    if txn:
        new_status = map_carrier_status("ups", _extract_webhook_status(payload))
        old_status = txn.get("shipping", {}).get("status", "")

        if new_status != old_status:
            update_data = {"status": new_status}
            if new_status == "delivered":
                update_data["delivered_at"] = now_ts()

            update_shipping(txn["user_sub"], txn["txn_id"], update_data)

            # 3. NEW: Send delivery alert
            if new_status == "delivered":
                _send_delivery_alert(txn, tracking_number)

    return {"received": True}


def _extract_webhook_status(payload: Dict[str, Any]) -> str:
    """Extract status string from UPS webhook payload."""
    return (
        payload.get("status_description")
        or payload.get("statusDescription")
        or payload.get("status")
        or ""
    )


def _send_delivery_alert(txn: Dict[str, Any], tracking_number: str) -> None:
    """Send alert to buyer and seller on delivery."""
    from app.services.alerts import create_alert

    buyer_sub = txn.get("user_sub", "")
    seller_sub = txn.get("seller_sub", "")
    txn_id = txn.get("txn_id", "")

    if buyer_sub:
        create_alert(
            user_id=buyer_sub,
            alert_type="delivery_confirmed",
            title="Package Delivered",
            body=f"Your order {txn_id} has been delivered (tracking: {tracking_number}).",
            metadata={"txn_id": txn_id, "tracking_number": tracking_number},
        )
    if seller_sub:
        create_alert(
            user_id=seller_sub,
            alert_type="delivery_confirmed",
            title="Delivery Confirmed",
            body=f"Order {txn_id} has been delivered to the buyer.",
            metadata={"txn_id": txn_id, "tracking_number": tracking_number},
        )
```

### 4.5 Backend: Transaction Lookup by Tracking Number

**New function in `app/services/purchase_history.py`:**

```python
def find_transaction_by_tracking(tracking_number: str) -> Optional[Dict[str, Any]]:
    """Look up a transaction by its tracking number.

    Uses GSI (TrackingIndex) on the purchases table:
        GSI PK: tracking_number
        GSI SK: txn_id

    Returns the full transaction item or None.
    """
    if not tracking_number or tracking_number == "unknown":
        return None

    resp = T.purchases.query(
        IndexName="TrackingIndex",
        KeyConditionExpression=Key("tracking_number").eq(tracking_number),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return items[0]
```

### 4.6 Backend: DynamoDB GSI for Tracking Lookup

**File: `scripts/local-ddb-init.py`** (addition to purchases table)

Add a new GSI to enable lookup by tracking number:

```python
TableDef(
    name=S.purchases_table_name,
    pk="user_sub",
    sk="txn_id",
    gsis=[
        # ... existing GSIs ...
        GsiDef(
            name="TrackingIndex",
            pk="tracking_number",
            sk="txn_id",
        ),
    ],
),
```

The `tracking_number` attribute is only set on items that have shipping info, so the GSI will be sparse (DynamoDB skips items without the GSI PK attribute).

### 4.7 Backend: Background Polling

**New file: `app/services/carrier_polling.py`**

A background task that polls carrier APIs for status updates on orders that are in transit but have not yet received webhook updates.

```python
"""Background polling for carrier tracking status updates.

This runs as a periodic background task registered at FastAPI startup.
It queries for orders with active tracking and polls carrier APIs for
status changes. This serves as a complement to webhooks:
- Webhooks are real-time but may be unreliable (missed events, downtime)
- Polling is the fallback that ensures all orders eventually get updated

Configuration:
    CARRIER_POLL_INTERVAL_MINUTES: How often to poll (default 30)
    CARRIER_POLL_BATCH_SIZE: Max orders to check per cycle (default 50)
"""
import asyncio
import logging
from typing import List, Dict, Any

from app.core.settings import S
from app.core.time import now_ts
from app.services.ups import track_package
from app.services.carrier_tracking import build_tracking_url, map_carrier_status

logger = logging.getLogger(__name__)

POLL_INTERVAL_MINUTES = int(getattr(S, "carrier_poll_interval_minutes", 30))
POLL_BATCH_SIZE = int(getattr(S, "carrier_poll_batch_size", 50))

# Statuses that indicate the order is still in flight
POLLABLE_STATUSES = {"shipped", "label_created", "picked_up", "in_transit", "out_for_delivery"}


async def carrier_polling_loop():
    """Background loop that polls carrier APIs for tracking updates."""
    while True:
        try:
            await _poll_cycle()
        except Exception:
            logger.exception("Error in carrier polling cycle")
        await asyncio.sleep(POLL_INTERVAL_MINUTES * 60)


async def _poll_cycle():
    """Single poll cycle: find orders needing update, query carriers."""
    orders = _get_pollable_orders(limit=POLL_BATCH_SIZE)
    logger.info(f"Carrier poll: checking {len(orders)} orders")

    for order in orders:
        try:
            await _poll_single_order(order)
        except Exception:
            logger.exception(f"Error polling order {order.get('txn_id')}")
        # Rate limit: 1 request per second
        await asyncio.sleep(1.0)


async def _poll_single_order(order: Dict[str, Any]):
    """Poll carrier for a single order and update if status changed."""
    carrier = (order.get("shipping", {}).get("carrier") or "").lower()
    tracking_number = order.get("shipping", {}).get("tracking_number")

    if not carrier or not tracking_number:
        return

    # Only UPS tracking is implemented for now
    if carrier != "ups":
        return

    # Query carrier
    result = track_package(tracking_number)
    new_status = result.get("status", "")
    old_status = order.get("shipping", {}).get("status", "")

    if new_status and new_status != old_status:
        update_data = {
            "status": new_status,
            "last_carrier_check": now_ts(),
        }
        if new_status == "delivered" and result.get("delivered_at"):
            update_data["delivered_at"] = now_ts()
        if result.get("events"):
            update_data["carrier_events"] = result["events"][:20]  # cap at 20 events

        update_shipping(order["user_sub"], order["txn_id"], update_data)

        # Alert on delivery
        if new_status == "delivered":
            _send_delivery_alert(order, tracking_number)


def _get_pollable_orders(limit: int) -> List[Dict[str, Any]]:
    """Query orders that have tracking and are in a pollable status."""
    # Uses GSI on shipping status
    # In practice this scans with FilterExpression -- acceptable for low volume
    # For high volume, add a dedicated GSI with status as PK
    # ...implementation details...
    pass
```

**Registration in `app/main.py`:**

```python
@app.on_event("startup")
async def start_carrier_polling():
    if S.dev_mode:  # Only in production or when explicitly enabled
        return
    from app.services.carrier_polling import carrier_polling_loop
    asyncio.create_task(carrier_polling_loop())
```

### 4.8 Backend: Include tracking_url in API Response

**File: `app/services/purchase_history.py`** (modify `get_transaction_info`)

```python
def get_transaction_info(user_sub: str, txn_id: str) -> Dict[str, Any]:
    # ... existing logic ...

    # Enrich shipping with tracking URL
    if txn.get("shipping"):
        carrier = txn["shipping"].get("carrier")
        tracking_number = txn["shipping"].get("tracking_number")
        if carrier and tracking_number:
            txn["shipping"]["tracking_url"] = build_tracking_url(carrier, tracking_number)

    return txn
```

Also modify `update_shipping` to auto-detect carrier:

```python
def update_shipping(user_sub: str, txn_id: str, shipping_data: Dict[str, Any]) -> Dict[str, Any]:
    # Auto-detect carrier if tracking_number provided but carrier is not
    if shipping_data.get("tracking_number") and not shipping_data.get("carrier"):
        detected = detect_carrier(shipping_data["tracking_number"])
        if detected:
            shipping_data["carrier"] = detected

    # ... existing update logic ...
```

### 4.9 Frontend: Clickable Tracking Link

**File: `frontend/src/pages/purchases/TransactionDetail.tsx`** (modify lines 441-445)

```typescript
{txn.shipping.tracking_number && (
  <div>
    <dt className="text-muted-foreground">Tracking</dt>
    <dd>
      {txn.shipping.tracking_url ? (
        <a
          href={txn.shipping.tracking_url}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-xs text-primary underline hover:text-primary/80"
          title={`Track on ${txn.shipping.carrier?.toUpperCase() || "carrier"}`}
        >
          {txn.shipping.tracking_number}
          <ExternalLink className="ml-1 inline h-3 w-3" />
        </a>
      ) : (
        <span className="font-mono text-xs">{txn.shipping.tracking_number}</span>
      )}
    </dd>
  </div>
)}
```

### 4.10 Frontend: Enhanced Shipping Timeline

**File: `frontend/src/pages/purchases/ShippingTimeline.tsx`** (modification)

Add intermediate carrier event steps when `txn.shipping.carrier_events` is available:

```typescript
interface CarrierEvent {
  timestamp: string;
  description: string;
  location: string;
}

interface ShippingTimelineProps {
  txnStatus: string;
  createdAt: number;
  shippedAt?: number;
  deliveredAt?: number;
  completedAt?: number;
  revertedAt?: number;
  cancelledAt?: number;
  carrierEvents?: CarrierEvent[];  // NEW
}

export function ShippingTimeline({
  txnStatus,
  createdAt,
  shippedAt,
  deliveredAt,
  completedAt,
  revertedAt,
  cancelledAt,
  carrierEvents,
}: ShippingTimelineProps) {
  // ... existing 4-step logic for default view ...

  // Enhanced view when carrier events are available
  if (carrierEvents && carrierEvents.length > 0) {
    return (
      <div className="space-y-0">
        {/* Ordered step (always first) */}
        <TimelineStep status="complete" label="Ordered" date={formatTs(createdAt)} />

        {/* Carrier events as intermediate steps */}
        {carrierEvents.map((event, i) => (
          <TimelineStep
            key={i}
            status={i === 0 ? "current" : "complete"}
            label={event.description}
            date={event.timestamp}
            sublabel={event.location}
          />
        ))}

        {/* Completed/Cancelled final step */}
        {/* ... */}
      </div>
    );
  }

  // Fall back to existing 4-step timeline
  // ... existing code ...
}
```

### 4.11 Frontend: TypeScript Types

**File: `frontend/src/api/types.ts`** (additions)

```typescript
export interface CarrierEvent {
  timestamp: string;
  description: string;
  location: string;
}

export interface TransactionShipping {
  carrier?: string;
  tracking_number?: string;
  tracking_url?: string;       // NEW
  status?: string;             // NEW: label_created | in_transit | out_for_delivery | delivered
  shipped_at?: number;
  delivered_at?: number;
  carrier_events?: CarrierEvent[];  // NEW
  last_carrier_check?: number;      // NEW
}
```

---

## 5. Data Model

### 5.1 Purchase Transaction (Existing Table -- Modified)

New attributes added to shipping sub-object:

| Attribute | Type | Example | Notes |
|-----------|------|---------|-------|
| `shipping.carrier` | S | `"ups"` | Existing; now auto-detected |
| `shipping.tracking_number` | S | `"1Z12345678901234"` | Existing |
| `shipping.tracking_url` | S | `"https://www.ups.com/track?tracknum=1Z..."` | NEW: computed on read |
| `shipping.status` | S | `"in_transit"` | NEW: normalized carrier status |
| `shipping.shipped_at` | N | `1716580000` | Existing |
| `shipping.delivered_at` | N | `1716590000` | Existing; now auto-set |
| `shipping.carrier_events` | L | `[{"timestamp": "...", "description": "...", "location": "..."}]` | NEW: carrier event history |
| `shipping.last_carrier_check` | N | `1716585000` | NEW: last poll timestamp |

### 5.2 New GSI: TrackingIndex

| Component | Value |
|-----------|-------|
| Table | `purchases` (existing) |
| GSI Name | `TrackingIndex` |
| GSI PK | `tracking_number` (S) |
| GSI SK | `txn_id` (S) |
| Projection | ALL |

This GSI is sparse -- only items with `tracking_number` attribute are indexed. Used by `find_transaction_by_tracking()` and the webhook handler.

### 5.3 Example DynamoDB Item (After Enhancement)

```json
{
  "user_sub": "user_abc123",
  "txn_id": "txn_def456",
  "status": "SHIPPED",
  "items": [...],
  "shipping": {
    "carrier": "ups",
    "tracking_number": "1Z999AA10123456784",
    "status": "in_transit",
    "shipped_at": 1716580000,
    "delivered_at": null,
    "carrier_events": [
      {
        "timestamp": "2026-05-27T14:00:00Z",
        "description": "Departed facility",
        "location": "Newark, NJ, US"
      },
      {
        "timestamp": "2026-05-27T10:00:00Z",
        "description": "Picked up",
        "location": "New York, NY, US"
      }
    ],
    "last_carrier_check": 1716583600
  },
  "tracking_number": "1Z999AA10123456784",
  "created_at": 1716570000
}
```

Note: `tracking_number` appears both inside `shipping` (for display) and at the top level (for the GSI). The top-level attribute is written when shipping info is set.

---

## 6. API Design

### 6.1 GET /ui/purchase-history/transactions/{txn_id}

**Existing endpoint -- response enhanced with tracking URL and events.**

**Response** (200):
```json
{
  "txn_id": "txn_def456",
  "status": "SHIPPED",
  "shipping": {
    "carrier": "ups",
    "tracking_number": "1Z999AA10123456784",
    "tracking_url": "https://www.ups.com/track?tracknum=1Z999AA10123456784",
    "status": "in_transit",
    "shipped_at": 1716580000,
    "delivered_at": null,
    "carrier_events": [
      {"timestamp": "2026-05-27T14:00:00Z", "description": "In Transit", "location": "Newark, NJ"},
      {"timestamp": "2026-05-27T10:00:00Z", "description": "Picked Up", "location": "New York, NY"}
    ]
  }
}
```

### 6.2 PUT /ui/purchase-history/transactions/{txn_id}/shipping

**Existing endpoint -- enhanced with carrier auto-detection.**

**Request**:
```json
{
  "shipping": {
    "tracking_number": "1Z999AA10123456784"
  }
}
```

**Response** (200): Full transaction with auto-detected `carrier: "ups"` and constructed `tracking_url`.

### 6.3 GET /mock/ups/track/{tracking_number}

**New mock endpoint.**

**Response** (200):
```json
{
  "tracking_number": "1ZMOCK1716580000123",
  "status": "in_transit",
  "status_description": "In Transit",
  "estimated_delivery": "2026-06-01",
  "delivered_at": null,
  "events": [
    {"timestamp": "2026-05-27T14:00:00Z", "description": "In Transit", "location": "New York, NY, US"},
    {"timestamp": "2026-05-27T08:00:00Z", "description": "Picked up", "location": "Los Angeles, CA, US"}
  ]
}
```

### 6.4 POST /api/ups/tracking/webhook

**Existing endpoint -- now updates order status and sends alerts.**

No request/response format change. Still returns `{"received": true}`.

---

## 7. Frontend Implementation Details

### 7.1 Tracking Link Component

The tracking link is inline within the existing `TransactionDetail.tsx` shipping section. No new component file needed -- just modify the `<dd>` element for tracking number.

### 7.2 Enhanced ShippingTimeline

When `carrier_events` is available, the timeline transitions from the simple 4-step view to a detailed event list. The layout uses a vertical line with circular step indicators:

```
  ● Ordered               May 26, 2026 2:00 PM
  │
  ● Picked Up            May 27, 2026 10:00 AM
  │  Los Angeles, CA
  │
  ● Departed facility    May 27, 2026 2:00 PM
  │  Newark, NJ
  │
  ◉ In Transit           May 28, 2026 8:00 AM    ← current
  │  Memphis, TN
  │
  ○ Out for Delivery     (upcoming)
  │
  ○ Delivered            (upcoming)
```

### 7.3 React Query Keys

| Key | Purpose |
|-----|---------|
| `["transaction", txnId]` | Transaction detail (existing, now includes tracking_url + events) |
| `["transactions"]` | Transaction list (existing) |

No new query keys needed. The tracking URL and events are part of the transaction response.

### 7.4 Responsive Design

- **Desktop**: Tracking number shown inline with external link icon. Timeline is vertical with dates on the right.
- **Mobile**: Tracking number is full-width tap target (entire row is tappable). Timeline collapses to compact form with only latest event shown + expandable "Show all events" toggle.

---

## 8. Testing Plan

### 8.1 Unit Tests (pytest)

**File: `tests/test_carrier_tracking.py`**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test_build_tracking_url_ups` | carrier="ups", tn="1Z..." | URL = "https://www.ups.com/track?tracknum=1Z..." |
| 2 | `test_build_tracking_url_fedex` | carrier="fedex", tn="..." | URL = "https://www.fedex.com/fedextrack/?trknbr=..." |
| 3 | `test_build_tracking_url_usps` | carrier="usps" | Correct USPS URL |
| 4 | `test_build_tracking_url_dhl` | carrier="dhl" | Correct DHL URL |
| 5 | `test_build_tracking_url_unknown` | carrier="random" | Returns None |
| 6 | `test_build_tracking_url_empty` | carrier="" or tn="" | Returns None |
| 7 | `test_detect_carrier_ups` | "1Z12345678901234AB" | Returns "ups" |
| 8 | `test_detect_carrier_fedex_12` | "123456789012" | Returns "fedex" |
| 9 | `test_detect_carrier_fedex_22` | "1234567890123456789012" | Returns "fedex" |
| 10 | `test_detect_carrier_usps_20` | "94748500000000000000" | Returns "usps" |
| 11 | `test_detect_carrier_dhl` | "JD012345678901234567" | Returns "dhl" |
| 12 | `test_detect_carrier_unknown` | "ABC123" | Returns None |
| 13 | `test_map_carrier_status_delivered` | "ups", "Delivered" | Returns "delivered" |
| 14 | `test_map_carrier_status_transit` | "ups", "In Transit" | Returns "in_transit" |
| 15 | `test_webhook_updates_order` | Seed order with tracking; send webhook | Order status updated |
| 16 | `test_webhook_sends_delivery_alert` | Send delivered webhook | Alert created for buyer |
| 17 | `test_mock_tracking_returns_events` | GET /mock/ups/track/1Z... | 200; events array non-empty |
| 18 | `test_auto_detect_on_shipping_update` | PUT shipping with tn only | carrier field auto-populated |
| 19 | `test_tracking_url_in_response` | GET transaction with shipping | tracking_url field populated |
| 20 | `test_find_transaction_by_tracking` | Seed order with tracking_number | find_transaction_by_tracking returns order |

### 8.2 E2E Tests

**File: `frontend/e2e/carrier-tracking.spec.ts`**

**Section 1: Tracking URL API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Transaction with UPS tracking number has tracking URL | GET transaction; `shipping.tracking_url` contains "ups.com" |
| 2 | Transaction with FedEx tracking has FedEx URL | Contains "fedex.com" |
| 3 | Unknown carrier has no tracking URL | `tracking_url` is null |
| 4 | Auto-detection populates carrier field | PUT shipping with 1Z... only; GET shows carrier="ups" |

**Section 2: Mock Tracking API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | Mock tracking endpoint returns status | GET /mock/ups/track/1Z...; status field present |
| 6 | Mock tracking returns events array | events array non-empty |
| 7 | Mock tracking with suffix 9 returns "delivered" | status === "delivered" |

**Section 3: Webhook Integration (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | Webhook updates order shipping status | POST webhook; GET order; shipping.status changed |
| 9 | Delivery webhook sets delivered_at | status="delivered"; delivered_at populated |
| 10 | Webhook with invalid signature is rejected | 403 response |

**Section 4: Frontend UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Tracking number rendered as link | `<a>` element with tracking URL href |
| 12 | Link opens in new tab | `target="_blank"` attribute present |
| 13 | Enhanced timeline shows carrier events | Events list visible when carrier_events present |

---

## 9. Security Considerations

### 9.1 Webhook Authentication

- UPS webhook signature verification uses HMAC-SHA256 (`verify_tracking_webhook_signature`).
- The secret is stored in `S.ups_webhook_secret` (never exposed to frontend).
- Invalid signatures return 403 immediately.
- Empty secret (dev mode) allows all webhooks through (`return True`).

### 9.2 Tracking Number Validation

- Tracking numbers are sanitized before use in URL templates (no injection risk since templates use simple string substitution, not URL construction).
- `_sanitize_tracking_number()` strips whitespace and validates length (max 64 chars).

### 9.3 Rate Limiting

- Background polling is rate-limited (1 request/second, 50 orders per cycle).
- Webhook endpoint should be rate-limited by IP (existing middleware).
- Browse proxy for tracking status should be rate-limited per user (max 10 lookups/minute).

### 9.4 Data Exposure

- Carrier events may contain sensitive location data. Only store the last 20 events.
- Tracking URLs are safe to expose (they link to public carrier pages).
- The webhook payload is stored in full in the audit table but carrier events in the order record are sanitized (only timestamp, description, location).

---

## 10. Performance Considerations

### 10.1 DynamoDB Capacity

- **TrackingIndex GSI**: Sparse index. Only orders with shipping info are indexed. Expected < 1000 items. On-demand pricing is fine.
- **Carrier events storage**: Capped at 20 events per order (approx 2KB). No significant storage impact.
- **Webhook writes**: Two writes per webhook (audit + order update). Expected < 100 webhooks/day initially.

### 10.2 Background Polling

- **Batch size**: 50 orders per cycle (configurable).
- **Interval**: 30 minutes (configurable via `CARRIER_POLL_INTERVAL_MINUTES`).
- **Rate limiting**: 1 request/second to carrier API = 50 seconds per cycle maximum.
- **Scale limit**: At 10,000+ active shipments, polling may need to be replaced with a dedicated queue (SQS) processing system. For MVP, polling is sufficient.

### 10.3 Tracking URL Computation

- `build_tracking_url()` is a pure function (string template substitution). Zero database cost.
- Computed at read time in `get_transaction_info()`. Not stored persistently (allows URL template updates without migration).

---

## 11. Migration & Rollout

### 11.1 New Settings

| Setting | Default | Purpose |
|---------|---------|---------|
| `CARRIER_POLL_INTERVAL_MINUTES` | `30` | Background polling interval |
| `CARRIER_POLL_BATCH_SIZE` | `50` | Max orders to check per cycle |
| `CARRIER_POLL_ENABLED` | `false` | Toggle for background polling |

### 11.2 Database Migration

- **TrackingIndex GSI**: Add to `scripts/local-ddb-init.py`. For production, create GSI via CloudFormation update (zero-downtime, DDB backfills the index).
- **Existing orders**: Orders created before this change will not have `tracking_number` at the top level (only inside `shipping` nested map). A one-time backfill script should copy `shipping.tracking_number` to the top-level attribute for GSI indexing.

### 11.3 Rollout Phases

1. **Phase 1**: Tracking URL construction + clickable links. Zero-risk, computed at read time.
2. **Phase 2**: Carrier auto-detection on `update_shipping`. Low risk, additive.
3. **Phase 3**: Wire webhook to order updates. Medium risk (test with mock webhook first).
4. **Phase 4**: Background polling. Enable with `CARRIER_POLL_ENABLED=true` after webhook integration is stable.

### 11.4 Backwards Compatibility

- `tracking_url` is a new optional field in the API response. Existing clients ignore it.
- `carrier_events` is a new optional field. Existing UI renders the 4-step fallback when absent.
- Webhook behavior is purely additive (still writes audit log, now also updates order).

---

## 12. Acceptance Criteria

1. Tracking numbers are displayed as clickable links to the carrier's tracking page.
2. Tracking URLs are auto-constructed for UPS, FedEx, USPS, and DHL from the carrier name and tracking number.
3. The carrier is auto-detected from tracking number format when not explicitly provided.
4. The UPS webhook receiver updates order shipping status (not just audit log).
5. Delivery events trigger alerts to the buyer and seller.
6. A background polling job checks carrier APIs for status updates (disabled by default, enabled via config).
7. `ShippingTimeline.tsx` shows intermediate carrier events when available.
8. A mock tracking endpoint exists for dev/test (consistent with existing UPS mock pattern).
9. The `TrackingIndex` GSI enables efficient tracking-number-to-order lookup.
10. All 13 E2E tests pass.

---

## 13. Dependencies

- **Purchase History (existing)**: `purchase_history.py` endpoints and `update_shipping()` service.
- **UPS Integration (existing)**: `ups.py` service and `ups.py` router.
- **Alerts System (existing)**: `create_alert()` for delivery notifications.
- **DynamoDB Tables (existing)**: `purchases` table (new GSI), `billing` table (audit log).

---

## 14. Open Questions & Risks

### 14.1 Open Questions

1. **FedEx/USPS/DHL API integration**: This ticket only implements UPS tracking lookup and webhook. Should FedEx/USPS polling be included or deferred to a follow-up ticket?
2. **Auto-complete on delivery**: Should orders automatically transition from SHIPPED to COMPLETED 48 hours after delivery confirmation? Or require manual seller confirmation?
3. **Tracking number format overlap**: FedEx 20-digit and USPS 20-digit numbers are ambiguous. Should the auto-detection prompt the user to confirm when ambiguous?
4. **Webhook registration**: UPS webhook subscription requires calling the UPS API to register our webhook URL. Should this be automatic per-order or a one-time admin setup?

### 14.2 Risks

1. **UPS API rate limits**: UPS Tracking API has rate limits (~300 requests/hour for sandbox, higher for production). The polling batch size must respect this.
2. **Webhook delivery reliability**: UPS webhooks may be delayed or missed during their outages. The polling fallback mitigates this but introduces 30-minute maximum delay.
3. **Mock tracking determinism in tests**: The mock tracking endpoint returns status based on the last digit of the tracking number. Tests must use specific tracking numbers to get predictable results.
4. **GSI backfill for existing orders**: Orders created before the migration will not appear in TrackingIndex until backfilled. The backfill script must be run as part of deployment.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `app/services/carrier_tracking.py` | Tracking URL construction, carrier detection, status mapping |
| `app/services/carrier_polling.py` | Background polling for carrier status updates |
| `frontend/e2e/carrier-tracking.spec.ts` | E2E tests |
| `tests/test_carrier_tracking.py` | Unit tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `app/services/ups.py` | Add `track_package()` function |
| `app/routers/ups.py` | Add mock tracking endpoint; wire webhook to order update (lines 91-108) |
| `app/routers/purchase_history.py` | Include `tracking_url` in transaction response |
| `app/services/purchase_history.py` | Add `find_transaction_by_tracking()`, auto-detect carrier in `update_shipping()` |
| `app/main.py` | Register carrier polling background task at startup |
| `app/core/settings.py` | Add `CARRIER_POLL_INTERVAL_MINUTES`, `CARRIER_POLL_BATCH_SIZE`, `CARRIER_POLL_ENABLED` settings |
| `scripts/local-ddb-init.py` | Add TrackingIndex GSI to purchases table |
| `frontend/src/pages/purchases/TransactionDetail.tsx` | Make tracking number a clickable link (lines 441-445) |
| `frontend/src/pages/purchases/ShippingTimeline.tsx` | Add intermediate carrier event steps |
| `frontend/src/api/types.ts` | Add `tracking_url`, `carrier_events`, `CarrierEvent` to shipping interface |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| TransactionDetail tracking display | `frontend/src/pages/purchases/TransactionDetail.tsx` | 431-459 | VERIFIED |
| Tracking number as plain text `<dd>` | `frontend/src/pages/purchases/TransactionDetail.tsx` | 444 | VERIFIED: `<dd className="font-mono text-xs">` |
| ShippingTimeline component | `frontend/src/pages/purchases/ShippingTimeline.tsx` | 1-189 | VERIFIED: 4-step timeline |
| resolveStep function | `frontend/src/pages/purchases/ShippingTimeline.tsx` | 34-43 | VERIFIED: determines step status |
| Step 2 "Shipped" logic | `frontend/src/pages/purchases/ShippingTimeline.tsx` | 69-78 | VERIFIED |
| Step 3 "Delivered" logic | `frontend/src/pages/purchases/ShippingTimeline.tsx` | 80-89 | VERIFIED |
| Manual shipping update endpoint | `app/routers/purchase_history.py` | 70-78 | VERIFIED |
| UPS access token with caching | `app/services/ups.py` | 30-50 | VERIFIED: `_TOKEN_CACHE` |
| UPS authenticated POST helper | `app/services/ups.py` | 53-63 | VERIFIED: `_ups_post()` |
| UPS service functions | `app/services/ups.py` | 66-91 | VERIFIED: quote, label, validate |
| No tracking lookup in UPS service | `app/services/ups.py` | all (101 lines) | VERIFIED: no track function |
| UPS webhook signature verification | `app/services/ups.py` | 94-101 | VERIFIED: HMAC SHA-256 |
| UPS webhook receiver | `app/routers/ups.py` | 91-108 | VERIFIED: logs to audit only |
| Webhook writes to billing table | `app/routers/ups.py` | 100-106 | VERIFIED: `user_sub="UPS_TRACKING"` |
| UPS mock endpoints | `app/routers/ups.py` | 121-169 | VERIFIED: token, quote, label, validate |
| Mock tracking number format | `app/routers/ups.py` | 154 | VERIFIED: `f"1ZMOCK{int(time.time()*1000)}"` |
| UPS settings | `app/core/settings.py` | 294-298 | VERIFIED: 5 settings (was 278-283; line drift) |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_carrier_tracking.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_shop_004_create` | Create primary entity; 201 |
| 2 | `test_shop_004_read` | Read back entity; correct fields |
| 3 | `test_shop_004_update` | Update entity; 200; changes reflected |
| 4 | `test_shop_004_delete` | Delete entity; 200/204 |
| 5 | `test_shop_004_auth_required` | No auth; 401 |
| 6 | `test_shop_004_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/carrier-tracking.spec.ts` -- 14 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Independent** -- Extends existing UPS integration with tracking status pipeline.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/carrier-tracking.spec.ts`
