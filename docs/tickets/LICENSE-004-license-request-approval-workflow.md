# LICENSE-004: License Request & Approval Workflow

**Ticket**: LICENSE-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-004 adds a structured request-and-approval workflow for content licensing. Instead of only the content owner initiating licenses (LICENSE-002), any creator can now request a license for content they want to use. The content owner receives the request in their license inbox, reviews it, and can approve, deny, or counter-offer with different terms. Approved requests automatically create an `IssuedLicense` record (LICENSE-002), completing the licensing circle. The workflow supports multi-round negotiation -- the requester can accept or reject counter-offers, and either party can withdraw at any point.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator B | As a creator, I want to request a license for Creator A's video so that I can use it in my remix. | POST creates license request with proposed terms; Creator A receives notification. |
| Creator A | As a content owner, I want to see incoming license requests in my inbox. | GET returns list of pending requests with requester info and proposed terms. |
| Creator A | As a content owner, I want to approve a license request, accepting the proposed terms. | POST approve creates an IssuedLicense; requester is notified; request status → `approved`. |
| Creator A | As a content owner, I want to deny a request with an optional reason. | POST deny sets status to `denied`; requester notified with reason. |
| Creator A | As a content owner, I want to counter-offer with different terms (e.g., higher revenue share). | POST counter-offer sets status to `negotiating`; requester sees counter-terms. |
| Creator B | As a requester, I want to accept or reject a counter-offer. | POST accept-counter creates license with counter-terms; POST reject-counter sets status to `denied`. |
| Creator B | As a requester, I want to withdraw my pending request. | POST withdraw sets status to `withdrawn`; content owner notified. |
| System | Requests that are not acted upon within 30 days should expire automatically. | Background task sets status to `expired` for stale requests. |
| Creator | As any creator, I want to see a history of all my license requests (sent and received). | GET returns paginated list with status filters. |

### 1.3 Why This Is Needed

LICENSE-002 only supports top-down licensing (content owner issues a license). In practice, many collaborations are initiated by the party who wants to USE the content, not the owner. A request workflow enables bottom-up discovery: creators can browse content, propose terms, and negotiate. This dramatically lowers the friction for licensed collaboration and creates a marketplace dynamic where content owners can evaluate demand for their work.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Issued licenses service | `app/services/issued_licenses.py` (LICENSE-002) | `issue_license` called on approval; `check_license_for_use` for existing license checks |
| Issued licenses table | `scripts/local-ddb-init.py` (LICENSE-002) | Reuse `issued_licenses` table with `REQUEST#` SK pattern |
| Contact requests | `app/routers/contacts.py` | 1:1 request/accept/decline pattern; architectural reference for approval workflow |
| Alerts service | `app/services/alerts.py` (~899 lines) | `write_alert` (line 355) for request/approval/denial notifications |
| Profile service | `app/services/profile.py` (345 lines) | `get_profile(user_id)` (line 220) for requester/owner display names |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` (line 184) returns `{user_sub, role, admin_profile}` |

<!-- NOTE: app/services/issued_licenses.py (LICENSE-002) does NOT exist yet — LICENSE-002 is a prerequisite. -->
<!-- NOTE: app/services/contacts.py does NOT exist — contacts logic lives in app/routers/contacts.py. -->
<!-- NOTE: app/services/syndicates.py (SYND-001) does NOT exist — not yet implemented. -->
<!-- NOTE: app/services/license_requests.py does NOT exist yet — new implementation required. -->

### 2.2 Gaps

1. **No license request model** -- there is no mechanism for a creator to request permission to use another creator's content.
2. **No negotiation workflow** -- existing approval patterns (contacts, syndicate invites) are binary (accept/decline) with no counter-offer capability.
3. **No license inbox** -- content owners have no centralized view of incoming license requests.
4. **No request expiration** -- no background process for timing out unanswered requests.
5. **No request-to-license conversion** -- no automated path from an approved request to an IssuedLicense record.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Storage in IssuedLicenses Table

License requests are stored in the existing `issued_licenses` table (LICENSE-002) using distinct SK patterns.

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CONTENT#{content_id}` | `REQUEST#{request_id}` | License request for content | `request_id`, `content_id`, `content_type`, `requester_id`, `owner_id`, `status`, `proposed_terms`, `counter_terms`, `denial_reason`, `message`, `created_at`, `updated_at`, `expires_at` |
| `REQUESTER#{user_id}` | `REQ_SENT#{request_id}` | Requester's sent requests index | `request_id`, `content_id`, `owner_id`, `status`, `created_at` |
| `OWNER#{user_id}` | `REQ_RECEIVED#{request_id}` | Owner's received requests index (license inbox) | `request_id`, `content_id`, `requester_id`, `status`, `created_at` |

#### 3.1.2 GSIs (reuse existing from issued_licenses)

**GSI1** (existing): Used for library browse -- not directly used by requests.

**GSI2** (existing): `CONTENT_STATUS#{content_id}#{status}` -- reused for request status queries on a content item.

**New GSI4** (`GSI4PK` / `GSI4SK`): Pending requests expiry processing.
- `GSI4PK`: `REQ_STATUS#{status}` (e.g., `REQ_STATUS#pending`, `REQ_STATUS#negotiating`)
- `GSI4SK`: `expires_at` (N) -- for finding expired requests

Add to `issued_licenses` table definition:

```python
# Append to existing gsis list:
{"name": "GSI4", "pk": "GSI4PK", "sk": "GSI4SK"},
# Append to existing attr_types:
"GSI4SK": "N"
```

#### 3.1.3 Example DynamoDB Items

**License request (primary)**:
```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "REQUEST#req_abc123",
  "request_id": "req_abc123",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "requester_id": "bob@test.local",
  "owner_id": "alice@test.local",
  "status": "pending",
  "proposed_terms": {
    "profit_share_pct": 5,
    "fixed_cost_cents": 0,
    "revenue_share_pct": 3
  },
  "counter_terms": null,
  "denial_reason": "",
  "message": "I'd like to use your drone footage in my travel vlog",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "expires_at": 1751112000,
  "GSI2PK": "CONTENT_STATUS#vid_xyz789#pending",
  "GSI2SK": 1748520000,
  "GSI4PK": "REQ_STATUS#pending",
  "GSI4SK": 1751112000
}
```

**Requester sent index**:
```json
{
  "pk": "REQUESTER#bob@test.local",
  "sk": "REQ_SENT#req_abc123",
  "request_id": "req_abc123",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "owner_id": "alice@test.local",
  "status": "pending",
  "created_at": 1748520000
}
```

**Owner received index (inbox)**:
```json
{
  "pk": "OWNER#alice@test.local",
  "sk": "REQ_RECEIVED#req_abc123",
  "request_id": "req_abc123",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "requester_id": "bob@test.local",
  "requester_display_name": "Bob Creator",
  "status": "pending",
  "created_at": 1748520000
}
```

### 3.2 Request State Machine

```
                ┌──────────┐
        ┌──────►│ withdrawn│
        │       └──────────┘
        │
   ┌────┴───┐     approve    ┌──────────┐
   │ pending ├───────────────►│ approved │
   │        │                 └──────────┘
   │        │     deny        ┌──────┐
   │        ├────────────────►│denied│
   │        │                 └──────┘
   │        │     counter     ┌────────────┐
   │        ├────────────────►│negotiating │
   └────┬───┘                 │            │
        │                     │  accept    │    ┌──────────┐
        │         ┌──────────►├───────────►├───►│ approved │
        │         │           │            │    └──────────┘
        │         │           │  reject    │    ┌──────┐
        │         │           ├───────────►├───►│denied│
        │         │           │            │    └──────┘
        │         │           │  withdraw  │    ┌──────────┐
        │         │           ├───────────►├───►│withdrawn │
        │         │           └────┬───────┘    └──────────┘
        │         │                │
        │         │  counter       │
        │         └────────────────┘ (owner can re-counter)
        │
        │    timeout (30 days)  ┌───────┐
        └──────────────────────►│expired│
                                └───────┘
```

Valid transitions:
- `pending` → `approved`, `denied`, `negotiating`, `withdrawn`, `expired`
- `negotiating` → `approved`, `denied`, `negotiating` (re-counter), `withdrawn`, `expired`
- `approved`, `denied`, `withdrawn`, `expired` → terminal (no further transitions)

### 3.3 Backend Service

**New file**: `app/services/license_requests.py` (~400 lines)

```python
"""License request & approval workflow (LICENSE-004)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.issued_licenses import issue_license
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

REQUEST_EXPIRY_DAYS = 30
REQUEST_EXPIRY_SECONDS = REQUEST_EXPIRY_DAYS * 86400


def create_request(
    *,
    requester_sub: str,
    content_id: str,
    content_type: str,
    owner_id: str,
    proposed_terms: Dict[str, Any],
    message: str = "",
) -> Dict[str, Any]:
    """Creator requests a license for another creator's content."""
    if requester_sub == owner_id:
        raise ValueError("Cannot request a license for your own content")

    # Check for existing pending request for same content by same requester
    _check_no_duplicate_request(requester_sub, content_id)

    request_id = f"req_{uuid4().hex}"
    ts = now_ts()
    expires_at = ts + REQUEST_EXPIRY_SECONDS
    profile = get_profile(requester_sub) or {}

    # Validate proposed terms
    _validate_terms(proposed_terms)

    item = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"REQUEST#{request_id}",
        "request_id": request_id,
        "content_id": content_id,
        "content_type": content_type,
        "requester_id": requester_sub,
        "owner_id": owner_id,
        "status": "pending",
        "proposed_terms": proposed_terms,
        "counter_terms": None,
        "denial_reason": "",
        "message": message,
        "created_at": ts,
        "updated_at": ts,
        "expires_at": expires_at,
        "GSI2PK": f"CONTENT_STATUS#{content_id}#pending",
        "GSI2SK": ts,
        "GSI4PK": "REQ_STATUS#pending",
        "GSI4SK": expires_at,
    }
    T.issued_licenses.put_item(Item=item)

    # Write requester + owner index records
    _write_requester_index(request_id, requester_sub, content_id, content_type,
                           owner_id, "pending", ts)
    _write_owner_index(request_id, owner_id, content_id, content_type,
                       requester_sub, profile, "pending", ts)

    # Notify owner
    write_alert(owner_id, "license_request_received", {
        "requester_id": requester_sub,
        "requester_name": profile.get("display_name", requester_sub),
        "content_id": content_id,
        "request_id": request_id,
    })

    return item


def approve_request(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Content owner approves a license request. Creates an IssuedLicense."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, {"pending", "negotiating"})

    # Determine final terms (counter_terms if negotiation happened, else proposed_terms)
    final_terms = request.get("counter_terms") or request["proposed_terms"]

    # Create IssuedLicense via LICENSE-002
    issued = issue_license(
        licensor_sub=owner_sub,
        content_id=content_id,
        content_type=request["content_type"],
        license_mode="per_user",
        licensee_id=request["requester_id"],
        profit_share_pct=final_terms.get("profit_share_pct", 0),
        fixed_cost_cents=final_terms.get("fixed_cost_cents", 0),
        revenue_share_pct=final_terms.get("revenue_share_pct", 0),
    )

    # Update request status
    _update_request_status(request, "approved")

    # Notify requester
    write_alert(request["requester_id"], "license_request_approved", {
        "owner_id": owner_sub,
        "content_id": content_id,
        "issued_license_id": issued["issued_license_id"],
    })

    return {"request": request, "issued_license": issued}


def deny_request(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Content owner denies a license request."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, {"pending", "negotiating"})

    request["denial_reason"] = reason
    _update_request_status(request, "denied")

    write_alert(request["requester_id"], "license_request_denied", {
        "owner_id": owner_sub,
        "content_id": content_id,
        "reason": reason,
    })
    return request


def counter_offer(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
    counter_terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Content owner proposes different terms."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, {"pending", "negotiating"})

    _validate_terms(counter_terms)
    request["counter_terms"] = counter_terms
    _update_request_status(request, "negotiating")

    write_alert(request["requester_id"], "license_counter_offer", {
        "owner_id": owner_sub,
        "content_id": content_id,
        "counter_terms": counter_terms,
    })
    return request


def accept_counter(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester accepts the owner's counter-offer. Creates an IssuedLicense."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, {"negotiating"})

    if not request.get("counter_terms"):
        raise ValueError("No counter-offer to accept")

    # Create IssuedLicense with counter terms
    issued = issue_license(
        licensor_sub=request["owner_id"],
        content_id=content_id,
        content_type=request["content_type"],
        license_mode="per_user",
        licensee_id=requester_sub,
        profit_share_pct=request["counter_terms"].get("profit_share_pct", 0),
        fixed_cost_cents=request["counter_terms"].get("fixed_cost_cents", 0),
        revenue_share_pct=request["counter_terms"].get("revenue_share_pct", 0),
    )

    _update_request_status(request, "approved")

    write_alert(request["owner_id"], "license_counter_accepted", {
        "requester_id": requester_sub,
        "content_id": content_id,
        "issued_license_id": issued["issued_license_id"],
    })
    return {"request": request, "issued_license": issued}


def reject_counter(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester rejects the owner's counter-offer."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, {"negotiating"})

    _update_request_status(request, "denied")

    write_alert(request["owner_id"], "license_counter_rejected", {
        "requester_id": requester_sub,
        "content_id": content_id,
    })
    return request


def withdraw_request(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester withdraws their pending/negotiating request."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, {"pending", "negotiating"})

    _update_request_status(request, "withdrawn")

    write_alert(request["owner_id"], "license_request_withdrawn", {
        "requester_id": requester_sub,
        "content_id": content_id,
    })
    return request


def list_sent_requests(
    *,
    requester_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List license requests sent by a creator."""
    # Query REQUESTER#{user_id} sk begins_with REQ_SENT#


def list_received_requests(
    *,
    owner_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List license requests received by a content owner (license inbox)."""
    # Query OWNER#{user_id} sk begins_with REQ_RECEIVED#


def get_request(
    *,
    content_id: str,
    request_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a specific request (must be requester or owner)."""


def process_expired_requests() -> int:
    """Background task: expire stale requests past their expiry date."""
    # Query GSI4: REQ_STATUS#pending and REQ_STATUS#negotiating where GSI4SK < now_ts()
    # Update status to "expired"
    # Notify both parties


# --- Internal helpers ---

def _get_request(content_id, request_id):
    """Fetch request or raise 404."""

def _require_owner(request, user_id):
    """Raise 403 if user is not the content owner."""

def _require_requester(request, user_id):
    """Raise 403 if user is not the requester."""

def _require_status(request, valid_statuses):
    """Raise 400 if request status is not in valid_statuses."""

def _update_request_status(request, new_status):
    """Update status on primary + index records + GSI keys."""

def _write_requester_index(request_id, requester_id, content_id, content_type,
                           owner_id, status, ts):
    """Write REQUESTER#{id}/REQ_SENT#{request_id} index."""

def _write_owner_index(request_id, owner_id, content_id, content_type,
                       requester_id, profile, status, ts):
    """Write OWNER#{id}/REQ_RECEIVED#{request_id} index."""

def _check_no_duplicate_request(requester_id, content_id):
    """Raise 409 if requester already has a pending/negotiating request for this content."""

def _validate_terms(terms):
    """Validate proposed/counter terms dict."""
```

### 3.4 Backend Router

**New file**: `app/routers/license_requests.py` (~250 lines)

```python
"""License request & approval workflow router (LICENSE-004)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import license_requests as svc

router = APIRouter(prefix="/ui/licenses/requests", tags=["license-requests"])
```

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/licenses/requests` | `require_ui_session` | Create a new license request |
| `GET` | `/ui/licenses/requests/sent` | `require_ui_session` | List requests I've sent |
| `GET` | `/ui/licenses/requests/received` | `require_ui_session` | List requests I've received (license inbox) |
| `GET` | `/ui/licenses/requests/{request_id}` | `require_ui_session` | Get request detail |
| `POST` | `/ui/licenses/requests/{request_id}/approve` | `require_ui_session` | Approve request (owner only) |
| `POST` | `/ui/licenses/requests/{request_id}/deny` | `require_ui_session` | Deny request (owner only) |
| `POST` | `/ui/licenses/requests/{request_id}/counter` | `require_ui_session` | Counter-offer with different terms (owner only) |
| `POST` | `/ui/licenses/requests/{request_id}/accept-counter` | `require_ui_session` | Accept counter-offer (requester only) |
| `POST` | `/ui/licenses/requests/{request_id}/reject-counter` | `require_ui_session` | Reject counter-offer (requester only) |
| `POST` | `/ui/licenses/requests/{request_id}/withdraw` | `require_ui_session` | Withdraw request (requester only) |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- License Requests (LICENSE-004) --

class LicenseTermsIn(BaseModel):
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)

class LicenseRequestCreateIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")
    owner_id: str
    proposed_terms: LicenseTermsIn
    message: str = Field(default="", max_length=1000)

class LicenseRequestDenyIn(BaseModel):
    reason: str = Field(default="", max_length=500)

class LicenseRequestCounterIn(BaseModel):
    counter_terms: LicenseTermsIn

class LicenseRequestOut(BaseModel):
    request_id: str
    content_id: str
    content_type: str
    requester_id: str
    requester_display_name: str = ""
    owner_id: str
    owner_display_name: str = ""
    status: str  # pending, approved, denied, negotiating, withdrawn, expired
    proposed_terms: Dict[str, Any] = Field(default_factory=dict)
    counter_terms: Optional[Dict[str, Any]] = None
    denial_reason: str = ""
    message: str = ""
    created_at: int = 0
    updated_at: int = 0
    expires_at: int = 0

class LicenseRequestApprovalOut(BaseModel):
    request: LicenseRequestOut
    issued_license: Optional[IssuedLicenseOut] = None

class LicenseRequestListOut(BaseModel):
    items: List[LicenseRequestOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
```

### 3.7 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/licenses/LicenseRequestsPage.tsx` | License inbox + sent requests | ~300 |
| `frontend/src/pages/licenses/RequestLicenseDialog.tsx` | Dialog for creating a new request | ~160 |
| `frontend/src/pages/licenses/RequestDetailDialog.tsx` | View request with actions (approve/deny/counter/accept/reject/withdraw) | ~200 |
| `frontend/src/pages/licenses/CounterOfferDialog.tsx` | Counter-offer terms form | ~100 |
| `frontend/src/api/endpoints/license-requests.ts` | API client wrappers | ~120 |

**Component tree**:

```
LicenseRequestsPage
├── Tabs: "Inbox" / "Sent"
├── Inbox Tab (requests received as content owner)
│   ├── Filter: status dropdown (all, pending, negotiating, approved, denied)
│   ├── Badge count for pending + negotiating
│   └── Request list
│       └── For each request:
│           ├── Requester avatar + name
│           ├── Content title + type badge
│           ├── Proposed terms summary
│           ├── Status badge (color-coded)
│           ├── Message preview
│           ├── Time since request
│           └── "Review" → RequestDetailDialog
├── Sent Tab (requests I've sent)
│   ├── Filter: status dropdown
│   └── Request list (similar layout)
│       └── Actions based on status:
│           ├── pending: "Withdraw"
│           ├── negotiating: "Accept Counter" / "Reject Counter" / "Withdraw"
│           └── approved: "View License"

RequestDetailDialog (owner view)
├── Requester info (avatar, name, profile link)
├── Content being requested (title, thumbnail, link)
├── Proposed terms display
├── Counter terms display (if negotiating)
├── Message from requester
├── Action buttons:
│   ├── "Approve" (green) -- accepts proposed/counter terms
│   ├── "Counter-Offer" → CounterOfferDialog
│   └── "Deny" (red) -- with optional reason input

CounterOfferDialog
├── Current proposed terms display (read-only)
├── LicenseTermsForm (editable counter terms)
│   ├── Profit share % slider
│   ├── Fixed cost input
│   └── Revenue share % slider
└── "Send Counter-Offer" button
```

### 3.8 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/licenses/requests" element={<LicenseRequestsPage />} />
```

### 3.9 Notification Types

| Alert Type | Recipient | Message |
|------------|-----------|---------|
| `license_request_received` | Content owner | "Creator B wants to license your content '{title}'" |
| `license_request_approved` | Requester | "Your license request for '{title}' was approved" |
| `license_request_denied` | Requester | "Your license request for '{title}' was denied: {reason}" |
| `license_counter_offer` | Requester | "Creator A has counter-offered different terms for '{title}'" |
| `license_counter_accepted` | Content owner | "Creator B accepted your counter-offer for '{title}'" |
| `license_counter_rejected` | Content owner | "Creator B rejected your counter-offer for '{title}'" |
| `license_request_withdrawn` | Content owner | "Creator B withdrew their license request for '{title}'" |
| `license_request_expired` | Both parties | "License request for '{title}' has expired" |

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/license_requests.py` | Request/approval workflow service | ~400 |
| `app/routers/license_requests.py` | REST API endpoints | ~250 |
| `frontend/src/pages/licenses/LicenseRequestsPage.tsx` | Inbox + sent page | ~300 |
| `frontend/src/pages/licenses/RequestLicenseDialog.tsx` | Create request dialog | ~160 |
| `frontend/src/pages/licenses/RequestDetailDialog.tsx` | Request detail with actions | ~200 |
| `frontend/src/pages/licenses/CounterOfferDialog.tsx` | Counter-offer dialog | ~100 |
| `frontend/src/api/endpoints/license-requests.ts` | API wrappers | ~120 |
| `frontend/e2e/license-requests.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `license_requests_router` |
| `app/models.py` | Add License Request Pydantic models |
| `scripts/local-ddb-init.py` | Add GSI4 to `issued_licenses` table definition |
| `frontend/src/api/types.ts` | Add License Request TypeScript interfaces |
| `frontend/src/App.tsx` | Add requests route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "License Requests" sub-item |

---

## 4. Negotiation Flow Detail

### 4.1 Happy Path: Approve

1. Creator B sends request with proposed terms (5% revenue share).
2. Creator A reviews request, terms are acceptable.
3. Creator A clicks "Approve".
4. System creates IssuedLicense with proposed terms via `issue_license`.
5. Request status → `approved`.
6. Creator B notified; license appears in "Licenses I Hold".

### 4.2 Counter-Offer Path

1. Creator B sends request with proposed terms (5% revenue share).
2. Creator A thinks 5% is too low, clicks "Counter-Offer".
3. Creator A proposes 10% revenue share + $2 fixed fee.
4. Request status → `negotiating`. Creator B notified.
5. Creator B reviews counter-terms.
   - If accept: IssuedLicense created with counter-terms. Status → `approved`.
   - If reject: Status → `denied`. Creator A notified.

### 4.3 Multi-Round Negotiation

The owner can re-counter if the requester hasn't yet responded to the previous counter. This is supported by the `negotiating` → `negotiating` transition (owner updates `counter_terms`). The requester always sees the latest counter-terms.

### 4.4 Edge Cases

- **Duplicate request**: A requester cannot have two pending/negotiating requests for the same content. Enforced by `_check_no_duplicate_request`.
- **Request for own content**: Rejected with 400. Creators cannot request licenses for content they own.
- **Blanket-licensed content**: If the content already has a blanket license, the request is still valid (requester may want per-user terms).
- **Owner issues license directly (LICENSE-002) while request is pending**: The request remains pending; the requester can withdraw it. No automatic status sync.
- **Both parties counter at the same time**: Not possible -- only the owner can counter; the requester can only accept/reject.
- **Expired during negotiation**: Both `pending` and `negotiating` requests expire after 30 days from creation. The background task handles this.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/license-requests.spec.ts`

### Section 475: License Request Creation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 475.1 | Bob requests license for Alice's content | POST `/ui/licenses/requests`; 200; response has `request_id`, `status=pending`, `proposed_terms` |
| 475.2 | Request appears in Bob's sent list | GET `/ui/licenses/requests/sent`; response includes the request |
| 475.3 | Request appears in Alice's inbox | GET `/ui/licenses/requests/received` (as Alice); response includes Bob's request |
| 475.4 | Duplicate request for same content fails | Bob POST again for same content → 409 |

### Section 476: Approve & Deny API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 476.1 | Alice approves Bob's request | POST `/ui/licenses/requests/{id}/approve`; 200; status → `approved`; `issued_license` returned |
| 476.2 | Approved request creates IssuedLicense | GET `/ui/licenses/held` (as Bob); new per-user license present with proposed terms |
| 476.3 | Alice denies a different request with reason | POST deny with `reason="Not compatible"`; status → `denied`; denial_reason set |
| 476.4 | Non-owner cannot approve | Bob POST approve on his own request → 403 |

### Section 477: Counter-Offer & Negotiation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 477.1 | Alice counter-offers with different terms | POST `/ui/licenses/requests/{id}/counter`; 200; status → `negotiating`; `counter_terms` set |
| 477.2 | Bob accepts counter-offer | POST `/ui/licenses/requests/{id}/accept-counter`; 200; status → `approved`; license created with counter terms |
| 477.3 | Bob rejects counter-offer on another request | POST reject-counter; status → `denied` |
| 477.4 | Requester cannot counter (only owner can) | Bob POST counter → 403 |
| 477.5 | Cannot accept counter on non-negotiating request | POST accept-counter on pending request → 400 |

### Section 478: Withdraw & Expiry API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 478.1 | Bob withdraws a pending request | POST `/ui/licenses/requests/{id}/withdraw`; 200; status → `withdrawn` |
| 478.2 | Cannot withdraw an already approved request | POST withdraw on approved request → 400 |
| 478.3 | Request detail returns full info for both parties | GET `/ui/licenses/requests/{id}` (as Alice); returns all fields including proposed_terms and message |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Create request | `require_ui_session` | Any authenticated user (cannot request own content) |
| Approve / deny / counter | `require_ui_session` | Must be content owner |
| Accept-counter / reject-counter / withdraw | `require_ui_session` | Must be requester |
| List sent | `require_ui_session` | Only own sent requests |
| List received | `require_ui_session` | Only own received requests |
| Get detail | `require_ui_session` | Must be requester or owner |

### 6.2 State Machine Enforcement

- All status transitions are validated server-side via `_require_status`.
- Only valid transitions are allowed (see state machine diagram).
- Terminal states (`approved`, `denied`, `withdrawn`, `expired`) cannot be changed.

### 6.3 Rate Limiting

- Request creation: max 20 per user per hour (prevent spam).
- Approval/denial actions: max 50 per user per hour.
- Counter-offers: max 10 per request per day (prevent negotiation abuse).

### 6.4 Input Validation

- `content_id`, `owner_id`: non-empty strings.
- `proposed_terms` / `counter_terms`: validated for range (0-100 for percentages, >= 0 for fixed cost).
- `message`: 0-1000 characters.
- `reason`: 0-500 characters.

### 6.5 Information Disclosure

- Request detail is only visible to the requester and the content owner.
- Sent/received lists only return the authenticated user's own requests.
- Proposed and counter terms are visible to both parties (transparency by design).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| LICENSE-002 | Required | `issue_license` called on approval; IssuedLicenses table for storage |
| `app/services/profile.py` | Exists | Display names for requester/owner |
| `app/services/alerts.py` | Exists | Notifications at each state transition |
| `app/auth/deps.py` | Exists | `require_ui_session` for all endpoints |
| `scripts/local-ddb-init.py` | Exists (modify) | Add GSI4 to `issued_licenses` table |
| LICENSE-003 | Parallel | Approved requests create licenses with terms used by revenue sharing |
| LICENSE-005 | Not started | Syndicate auto-licensing bypasses request workflow |

---

## 8. Acceptance Criteria

1. Creators can request licenses for other creators' content with proposed terms.
2. Content owners see incoming requests in their license inbox.
3. Owners can approve requests (automatically creates IssuedLicense) or deny with reason.
4. Owners can counter-offer with different terms; requesters can accept or reject.
5. Requesters can withdraw pending or negotiating requests.
6. Requests expire after 30 days if not acted upon.
7. Duplicate pending requests for the same content by the same requester are blocked.
8. All state transitions follow the defined state machine.
9. Both parties receive notifications at each state change.
10. All 16 E2E tests pass.

---

## Codebase References

All file paths relative to the repository root.

### Existing Files Referenced (verified)
- `app/routers/contacts.py` — Contact request/accept/decline pattern (architectural reference)
  - Note: `app/services/contacts.py` does NOT exist; contacts logic is in the router
- `app/services/alerts.py` (899 lines) — `write_alert()` at line 355
- `app/services/profile.py` (345 lines) — `get_profile()` at line 220
- `app/auth/deps.py` — `require_ui_session` at line 184
- `scripts/local-ddb-init.py` — DynamoDB table definitions

### Dependencies Not Yet Implemented
- `app/services/issued_licenses.py` — LICENSE-002 prerequisite (does not exist)
- `issued_licenses` DDB table — LICENSE-002 prerequisite (not in `scripts/local-ddb-init.py`)
- `app/services/syndicates.py` — Referenced as pattern but does not exist

### Files to Create (none exist yet)
- `app/services/license_requests.py` — Request workflow service (~400 lines)
- `app/routers/license_requests.py` — REST API endpoints (~250 lines)
- Frontend pages in `frontend/src/pages/licenses/` (RequestLicenseDialog, LicenseInboxPage, etc.)
- `frontend/src/api/endpoints/license-requests.ts` — API wrappers
- `frontend/e2e/license-requests.spec.ts` — E2E tests

### Files to Modify (verified to exist)
- `app/main.py` — Register request routers
- `app/models.py` — Add License Request Pydantic models
- `scripts/local-ddb-init.py` — Add GSI4 to `issued_licenses` table
- `frontend/src/App.tsx` — Add request routes
