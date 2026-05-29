# LICENSE-002: Content License Issuance

**Ticket**: LICENSE-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-002 enables creators to issue licenses for their OWN original content, granting other creators explicit permission to remix, react to, or reuse that content. Two licensing modes are supported: **per-user licenses** (granted to a specific creator) and **blanket licenses** (open to all creators on the platform). Blanket-licensed content appears in a publicly browsable "Licensed Content Library" that any creator can search and use. Each issued license carries configurable terms -- profit share percentage, fixed cost, or a combination -- that feed into LICENSE-003 revenue sharing.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator A | As a content owner, I want to issue a per-user license to Creator B so that they can use my music track in their video. | POST creates issued license; Creator B sees it in "Licenses I Hold"; license terms are recorded. |
| Creator A | As a content owner, I want to issue a blanket license on my video clip so that any creator can use it. | POST creates blanket license; content appears in Licensed Content Library; "Licensed" badge displayed. |
| Creator A | As a licensor, I want to set terms (profit share %, fixed cost, or both) on the license I issue. | License record includes `profit_share_pct`, `fixed_cost_cents`, `revenue_share_pct` fields. |
| Creator A | As a licensor, I want to revoke a license I previously issued if terms are violated. | POST revoke sets status to `revoked`; licensee notified; content using the license flagged for review. |
| Creator B | As a licensee, I want to see all licenses I hold so that I know what content I can use. | GET returns list of active licenses with terms, licensor info, and content details. |
| Creator B | As a licensee, I want to browse the Licensed Content Library to find content I can use in my work. | GET returns paginated list of blanket-licensed content with search and filters. |
| Any user | As a viewer, I want to see a "Licensed" badge on content that has been licensed for reuse. | Content detail view shows badge with licensor attribution. |
| Creator A | As a licensor, I want to update the terms of a blanket license (e.g., change the profit share percentage). | PATCH updates terms; existing licensees under old terms keep their original terms until renewal. |

### 1.3 Why This Is Needed

Creator collaboration -- reaction videos, remixes, duets, compilations -- is a major content growth driver, but the platform currently has no mechanism for creators to formally grant reuse permission or define compensation terms. Without formal licensing, creators either avoid collaboration (lost engagement) or collaborate without terms (lost revenue). This ticket provides the legal and economic framework that LICENSE-003 (revenue sharing) and LICENSE-004 (request/approval workflow) build upon.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| License agreements service | `app/services/license_agreements.py` (LICENSE-001) | Agreement upload/metadata; this ticket adds issued license layer on top |
| Licenses DDB table | `scripts/local-ddb-init.py` (LICENSE-001) | Reuse `licenses` table with new PK/SK patterns for issued licenses |
| Billing shared | `app/services/billing_shared.py` (~260 lines) | `new_ledger_entry` (line 217); LICENSE-003 integrates for revenue splits |
| Subscription access | `app/services/subscription_access.py` (82 lines) | `has_active_subscription` (line 55); pattern reference for entitlement checks |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` (173 lines) | Fan-out patterns; Licensed Content Library notifications could follow similar pattern |
| Profile service | `app/services/profile.py` (345 lines) | `get_profile(user_id)` (line 220) for licensor/licensee display names |
| Alerts service | `app/services/alerts.py` (~899 lines) | `write_alert` (line 355) for license grant/revoke notifications |
| File manager | `app/services/filemanager.py` (~4955 lines) | Content metadata access for linking issued licenses to specific files/videos |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` (line 184) returns `{user_sub, role, admin_profile}` |

<!-- NOTE: app/services/license_agreements.py (LICENSE-001) and the licenses DDB table do NOT exist yet — LICENSE-001 is a prerequisite that has not been implemented. -->
<!-- NOTE: app/services/issued_licenses.py and app/routers/issued_licenses.py do NOT exist yet — new implementation required. -->
<!-- NOTE: No frontend/src/pages/licenses/ directory exists yet. -->

### 2.2 Gaps

1. **No issued license model** -- LICENSE-001 covers uploaded third-party agreements, but there is no mechanism for creators to issue their own licenses to others.
2. **No blanket/per-user licensing distinction** -- no concept of a license that is open to all vs. granted to a specific user.
3. **No Licensed Content Library** -- no browsable catalog of content available for reuse under license.
4. **No license terms model** -- no structured way to define profit share, fixed costs, or revenue share percentages.
5. **No "Licensed" badge** -- content display has no indication of licensing status for reuse.
6. **No license revocation workflow** -- no way to revoke a previously granted license with downstream effects.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 IssuedLicenses Table

**Table name**: `issued_licenses` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CONTENT#{content_id}` | `LICENSE#{issued_license_id}` | Issued license for a content item | `issued_license_id`, `content_id`, `content_type`, `licensor_id`, `licensee_id` (null for blanket), `license_mode` (per_user/blanket), `status`, `profit_share_pct`, `fixed_cost_cents`, `revenue_share_pct`, `currency`, `created_at`, `updated_at`, `expires_at` |
| `LICENSOR#{user_id}` | `ISSUED#{issued_license_id}` | Licensor's issued licenses index | `issued_license_id`, `content_id`, `licensee_id`, `license_mode`, `status`, `created_at` |
| `LICENSEE#{user_id}` | `HELD#{issued_license_id}` | Licensee's held licenses index | `issued_license_id`, `content_id`, `licensor_id`, `content_type`, `status`, `terms_snapshot` |
| `LIBRARY` | `CONTENT#{content_id}#{issued_license_id}` | Blanket-licensed content library index | `content_id`, `content_type`, `licensor_id`, `title`, `thumbnail_url`, `profit_share_pct`, `fixed_cost_cents`, `created_at` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Browse licensed content library by content type.
- `GSI1PK`: `LIBRARY_TYPE#{content_type}` (e.g., `LIBRARY_TYPE#video`, `LIBRARY_TYPE#music`)
- `GSI1SK`: `created_at` (N) -- newest first
- `attr_types={"GSI1SK": "N"}`

**GSI2** (`GSI2PK` / `GSI2SK`): Lookup all licenses (issued + held) for a specific content item by status.
- `GSI2PK`: `CONTENT_STATUS#{content_id}#{status}` (e.g., `CONTENT_STATUS#vid_xyz#active`)
- `GSI2SK`: `created_at` (N)

**GSI3** (`GSI3PK` / `GSI3SK`): Search licensed content library by licensor.
- `GSI3PK`: `LICENSOR_LIBRARY#{user_id}`
- `GSI3SK`: `created_at` (N) -- enables browsing a specific creator's licensed content

#### 3.1.3 TableDef Entry

```python
TableDef(
    "issued_licenses", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
        {"name": "GSI3", "pk": "GSI3PK", "sk": "GSI3SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Blanket license**:
```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "LICENSE#il_def456",
  "issued_license_id": "il_def456",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "licensor_id": "alice@test.local",
  "licensee_id": null,
  "license_mode": "blanket",
  "status": "active",
  "profit_share_pct": 10,
  "fixed_cost_cents": 0,
  "revenue_share_pct": 5,
  "currency": "usd",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "expires_at": null,
  "title": "City Skyline Drone Footage",
  "thumbnail_url": "/mock/s3/thumbnails/vid_xyz789.jpg",
  "GSI2PK": "CONTENT_STATUS#vid_xyz789#active",
  "GSI2SK": 1748520000
}
```

**Library index entry** (for blanket licenses):
```json
{
  "pk": "LIBRARY",
  "sk": "CONTENT#vid_xyz789#il_def456",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "licensor_id": "alice@test.local",
  "licensor_display_name": "Alice Creator",
  "title": "City Skyline Drone Footage",
  "thumbnail_url": "/mock/s3/thumbnails/vid_xyz789.jpg",
  "profit_share_pct": 10,
  "fixed_cost_cents": 0,
  "created_at": 1748520000,
  "GSI1PK": "LIBRARY_TYPE#video",
  "GSI1SK": 1748520000,
  "GSI3PK": "LICENSOR_LIBRARY#alice@test.local",
  "GSI3SK": 1748520000
}
```

**Per-user license (licensee index)**:
```json
{
  "pk": "LICENSEE#bob@test.local",
  "sk": "HELD#il_ghi789",
  "issued_license_id": "il_ghi789",
  "content_id": "track_abc",
  "content_type": "music",
  "licensor_id": "alice@test.local",
  "status": "active",
  "terms_snapshot": {
    "profit_share_pct": 15,
    "fixed_cost_cents": 500,
    "revenue_share_pct": 0
  }
}
```

### 3.2 Backend Service

**New file**: `app/services/issued_licenses.py` (~450 lines)

```python
"""Content license issuance -- per-user and blanket licenses (LICENSE-002)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

VALID_LICENSE_MODES = {"per_user", "blanket"}
VALID_CONTENT_TYPES = {"video", "music", "image", "post", "broadcast", "clip"}
MAX_PROFIT_SHARE_PCT = 100
MAX_REVENUE_SHARE_PCT = 100


def issue_license(
    *,
    licensor_sub: str,
    content_id: str,
    content_type: str,
    license_mode: str,
    licensee_id: Optional[str] = None,
    profit_share_pct: int = 0,
    fixed_cost_cents: int = 0,
    revenue_share_pct: int = 0,
    currency: str = "usd",
    title: str = "",
    thumbnail_url: str = "",
    expires_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a new license for content owned by the licensor."""
    if license_mode not in VALID_LICENSE_MODES:
        raise ValueError(f"Invalid license_mode: {license_mode}")
    if content_type not in VALID_CONTENT_TYPES:
        raise ValueError(f"Invalid content_type: {content_type}")
    if license_mode == "per_user" and not licensee_id:
        raise ValueError("licensee_id required for per_user license")
    if license_mode == "blanket" and licensee_id:
        raise ValueError("licensee_id must be null for blanket license")
    if not (0 <= profit_share_pct <= MAX_PROFIT_SHARE_PCT):
        raise ValueError("profit_share_pct must be 0-100")
    if not (0 <= revenue_share_pct <= MAX_REVENUE_SHARE_PCT):
        raise ValueError("revenue_share_pct must be 0-100")
    if fixed_cost_cents < 0:
        raise ValueError("fixed_cost_cents must be >= 0")

    # TODO: Verify licensor owns the content (content ownership check)

    issued_license_id = f"il_{uuid4().hex}"
    ts = now_ts()
    profile = get_profile(licensor_sub) or {}

    # Primary record under content PK
    item = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"LICENSE#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "content_type": content_type,
        "licensor_id": licensor_sub,
        "licensee_id": licensee_id,
        "license_mode": license_mode,
        "status": "active",
        "profit_share_pct": profit_share_pct,
        "fixed_cost_cents": fixed_cost_cents,
        "revenue_share_pct": revenue_share_pct,
        "currency": currency,
        "title": title,
        "thumbnail_url": thumbnail_url,
        "created_at": ts,
        "updated_at": ts,
        "expires_at": expires_at,
        "GSI2PK": f"CONTENT_STATUS#{content_id}#active",
        "GSI2SK": ts,
    }
    T.issued_licenses.put_item(Item=item)

    # Licensor index
    licensor_index = {
        "pk": f"LICENSOR#{licensor_sub}",
        "sk": f"ISSUED#{issued_license_id}",
        "issued_license_id": issued_license_id,
        "content_id": content_id,
        "licensee_id": licensee_id,
        "license_mode": license_mode,
        "status": "active",
        "created_at": ts,
    }
    T.issued_licenses.put_item(Item=licensor_index)

    # Per-user: write licensee index + notify
    if license_mode == "per_user" and licensee_id:
        _write_licensee_index(issued_license_id, licensee_id, content_id,
                              content_type, licensor_sub, profit_share_pct,
                              fixed_cost_cents, revenue_share_pct)
        write_alert(licensee_id, "license_granted", {
            "licensor_id": licensor_sub,
            "licensor_name": profile.get("display_name", licensor_sub),
            "content_id": content_id,
            "issued_license_id": issued_license_id,
        })

    # Blanket: write library index
    if license_mode == "blanket":
        _write_library_index(issued_license_id, content_id, content_type,
                             licensor_sub, profile, title, thumbnail_url,
                             profit_share_pct, fixed_cost_cents, ts)

    return item


def update_license_terms(
    *,
    licensor_sub: str,
    issued_license_id: str,
    content_id: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    """Update terms on an issued license. Only licensor can update."""
    # Fetch primary record, validate licensor ownership
    # Update allowed fields: profit_share_pct, fixed_cost_cents, revenue_share_pct, expires_at
    # Note: existing per-user licensees keep their original terms_snapshot until renewal


def revoke_license(
    *,
    licensor_sub: str,
    issued_license_id: str,
    content_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Revoke an issued license. Notifies licensee, flags content for review."""
    # Update status to "revoked" on primary + licensor index
    # If per_user: update licensee index, notify licensee
    # If blanket: remove from library index
    # Flag content using this license for compliance review (LICENSE-006)


def get_issued_license(
    *,
    content_id: str,
    issued_license_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a single issued license."""


def list_licenses_issued_by(
    *,
    licensor_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all licenses issued by a creator."""
    # Query LICENSOR#{user_id} sk begins_with ISSUED#


def list_licenses_held_by(
    *,
    licensee_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all licenses held by a creator (per-user licenses granted to them)."""
    # Query LICENSEE#{user_id} sk begins_with HELD#


def list_licenses_for_content(
    *,
    content_id: str,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all issued licenses for a content item."""
    # Query CONTENT#{content_id} sk begins_with LICENSE#


def browse_library(
    *,
    content_type: Optional[str] = None,
    licensor_id: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Browse the Licensed Content Library (blanket-licensed content)."""
    # If content_type: query GSI1 LIBRARY_TYPE#{content_type}
    # If licensor_id: query GSI3 LICENSOR_LIBRARY#{user_id}
    # Else: query pk=LIBRARY with sk begins_with CONTENT#


def check_license_for_use(
    *,
    content_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Check if a user has a valid license to use a piece of content.
    Returns the active license (per-user for this user, or blanket) or None."""
    # Query CONTENT#{content_id} sk begins_with LICENSE#
    # Find first active license that is either blanket or per_user for this user


# --- Internal helpers ---

def _write_licensee_index(issued_license_id, licensee_id, content_id,
                          content_type, licensor_id, psp, fcc, rsp):
    """Write LICENSEE#{id}/HELD#{license_id} index entry."""

def _write_library_index(issued_license_id, content_id, content_type,
                         licensor_id, profile, title, thumbnail_url,
                         psp, fcc, ts):
    """Write LIBRARY/CONTENT#{content_id}#{license_id} entry + GSI projections."""

def _remove_library_index(content_id, issued_license_id):
    """Remove from library when blanket license is revoked."""

def _validate_content_ownership(user_id, content_id):
    """Verify the user owns the content being licensed."""
```

### 3.3 Backend Router

**New file**: `app/routers/issued_licenses.py` (~280 lines)

```python
"""Issued license management router (LICENSE-002)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import issued_licenses as svc

router = APIRouter(prefix="/ui/licenses/issued", tags=["issued-licenses"])
library_router = APIRouter(prefix="/ui/licenses/library", tags=["licensed-library"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/licenses/issued` | `require_ui_session` | Issue a new license (per-user or blanket) |
| `GET` | `/ui/licenses/issued` | `require_ui_session` | List licenses I've issued |
| `GET` | `/ui/licenses/issued/{issued_license_id}` | `require_ui_session` | Get issued license detail |
| `PATCH` | `/ui/licenses/issued/{issued_license_id}` | `require_ui_session` | Update license terms |
| `POST` | `/ui/licenses/issued/{issued_license_id}/revoke` | `require_ui_session` | Revoke an issued license |
| `GET` | `/ui/licenses/held` | `require_ui_session` | List licenses I hold (granted to me) |
| `GET` | `/ui/licenses/content/{content_id}` | `require_ui_session` | List all issued licenses for a content item |
| `GET` | `/ui/licenses/content/{content_id}/check` | `require_ui_session` | Check if current user has a valid license for content |
| `GET` | `/ui/licenses/library` | `require_ui_session` | Browse Licensed Content Library |
| `GET` | `/ui/licenses/library/creator/{licensor_id}` | `require_ui_session` | Browse a specific creator's licensed content |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Issued Licenses (LICENSE-002) --

class IssueLicenseIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")
    license_mode: str = Field(description="One of: per_user, blanket")
    licensee_id: Optional[str] = Field(default=None, description="Required for per_user mode")
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)
    currency: str = Field(default="usd", max_length=3)
    title: str = Field(default="", max_length=200)
    thumbnail_url: str = Field(default="", max_length=500)
    expires_at: Optional[int] = None

class UpdateLicenseTermsIn(BaseModel):
    profit_share_pct: Optional[int] = Field(default=None, ge=0, le=100)
    fixed_cost_cents: Optional[int] = Field(default=None, ge=0)
    revenue_share_pct: Optional[int] = Field(default=None, ge=0, le=100)
    expires_at: Optional[int] = None

class RevokeLicenseIn(BaseModel):
    reason: str = Field(default="", max_length=500)

class IssuedLicenseOut(BaseModel):
    issued_license_id: str
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    licensee_id: Optional[str] = None
    license_mode: str
    status: str  # active, revoked, expired
    profit_share_pct: int = 0
    fixed_cost_cents: int = 0
    revenue_share_pct: int = 0
    currency: str = "usd"
    title: str = ""
    thumbnail_url: str = ""
    created_at: int = 0
    updated_at: int = 0
    expires_at: Optional[int] = None

class HeldLicenseOut(BaseModel):
    issued_license_id: str
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    status: str
    terms_snapshot: Dict[str, Any] = Field(default_factory=dict)

class LibraryItemOut(BaseModel):
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    title: str = ""
    thumbnail_url: str = ""
    profit_share_pct: int = 0
    fixed_cost_cents: int = 0
    created_at: int = 0

class LicenseCheckOut(BaseModel):
    has_license: bool
    issued_license_id: Optional[str] = None
    license_mode: Optional[str] = None
    terms: Optional[Dict[str, Any]] = None
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/licenses/IssuedLicensesPage.tsx` | Manage licenses I've issued | ~250 |
| `frontend/src/pages/licenses/HeldLicensesPage.tsx` | View licenses I hold | ~150 |
| `frontend/src/pages/licenses/IssueLicenseDialog.tsx` | Dialog for issuing a new license | ~180 |
| `frontend/src/pages/licenses/LicensedLibraryPage.tsx` | Browse Licensed Content Library | ~200 |
| `frontend/src/pages/licenses/LicenseTermsForm.tsx` | Reusable form for setting license terms | ~100 |
| `frontend/src/components/shared/LicensedBadge.tsx` | "Licensed" badge component | ~30 |
| `frontend/src/api/endpoints/issued-licenses.ts` | API client wrappers | ~130 |

**Component tree**:

```
IssuedLicensesPage
├── Card: "Licenses I've Issued"
│   ├── IssueLicenseDialog (Button: "Issue License")
│   ├── Filter tabs: All / Per-User / Blanket / Revoked
│   └── DataTable
│       └── For each license:
│           ├── Content title, type badge, licensee (or "Blanket")
│           ├── Terms summary (e.g., "10% profit share + $5 fixed")
│           ├── Status badge
│           └── Actions: "Update Terms", "Revoke"

HeldLicensesPage
├── Card: "Licenses I Hold"
│   └── DataTable
│       └── For each held license:
│           ├── Content title, type, licensor name
│           ├── Terms snapshot
│           ├── Status badge
│           └── "View Content" link

LicensedLibraryPage
├── Search bar + content type filter
├── Grid of library items
│   └── For each item:
│       ├── Thumbnail
│       ├── Title, licensor name
│       ├── Terms summary
│       ├── "Licensed" badge
│       └── "View Details" → content detail with license info
└── Pagination

IssueLicenseDialog
├── Content selector (search owned content)
├── Mode toggle: Per-User / Blanket
├── Licensee search (per-user mode only)
├── LicenseTermsForm
│   ├── Profit share % slider
│   ├── Fixed cost input
│   ├── Revenue share % slider
│   └── Expiry date picker (optional)
└── Confirm button
```

### 3.7 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/licenses/issued" element={<IssuedLicensesPage />} />
<Route path="/licenses/held" element={<HeldLicensesPage />} />
<Route path="/licenses/library" element={<LicensedLibraryPage />} />
```

### 3.8 Files to Create

<!-- NOTE: None of the files below exist yet — all are new implementation required. The issued_licenses table is not in scripts/local-ddb-init.py, app/core/settings.py, or app/core/tables.py. -->

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/issued_licenses.py` | Issued license service | ~450 |
| `app/routers/issued_licenses.py` | REST API endpoints | ~280 |
| `frontend/src/pages/licenses/IssuedLicensesPage.tsx` | Issued licenses page | ~250 |
| `frontend/src/pages/licenses/HeldLicensesPage.tsx` | Held licenses page | ~150 |
| `frontend/src/pages/licenses/IssueLicenseDialog.tsx` | Issue license dialog | ~180 |
| `frontend/src/pages/licenses/LicensedLibraryPage.tsx` | Licensed Content Library | ~200 |
| `frontend/src/pages/licenses/LicenseTermsForm.tsx` | Terms form component | ~100 |
| `frontend/src/components/shared/LicensedBadge.tsx` | Licensed badge | ~30 |
| `frontend/src/api/endpoints/issued-licenses.ts` | API wrappers | ~130 |
| `frontend/e2e/license-issuance.spec.ts` | E2E tests | ~500 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `issued_licenses_router` and `library_router` |
| `app/models.py` | Add Issued License Pydantic models |
| `app/core/settings.py` | Add `issued_licenses_table_name` setting |
| `app/core/tables.py` | Add `T.issued_licenses` table handle |
| `scripts/local-ddb-init.py` | Add `issued_licenses` TableDef with 3 GSIs |
| `frontend/src/api/types.ts` | Add Issued License TypeScript interfaces |
| `frontend/src/App.tsx` | Add issued license routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add sub-items under "Licenses" nav entry |

---

## 4. License Modes

### 4.1 Per-User License

- Granted from Creator A to a specific Creator B.
- Licensee identified by `licensee_id` field.
- Only the named licensee can use the content under this license.
- Licensor can revoke at any time (with notification to licensee).
- A `terms_snapshot` is frozen at grant time in the licensee's index record; subsequent term changes by the licensor don't affect existing per-user licenses.

### 4.2 Blanket License

- Open to ALL creators on the platform.
- `licensee_id` is `null`; any authenticated creator can use the content.
- Content appears in the Licensed Content Library for discovery.
- Terms are global: when the licensor updates terms, the new terms apply to all future uses.
- Revocation removes the content from the library and flags existing uses for review.

### 4.3 "Licensed" Badge

- Displayed on content detail views (video page, post card, broadcast info).
- Badge shows: "Licensed" + licensor attribution if the viewer is a different creator.
- Badge is informational -- it indicates the content is available for reuse, not that the viewer has already licensed it.
- Check endpoint (`/content/{id}/check`) tells the frontend whether the current user has an active license.

### 4.4 Edge Cases

- Same content can have both blanket and per-user licenses simultaneously (per-user terms take precedence for that licensee).
- Licensor cannot issue a license for content they don't own.
- Licensee cannot be the same as the licensor (you can't license content to yourself).
- Expired licenses are soft-expired: status changes to `expired`, but the record remains for audit/reference.
- Revoking a blanket license does NOT automatically revoke per-user licenses for the same content.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/license-issuance.spec.ts`

### Section 467: Per-User License Issuance API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 467.1 | Alice issues a per-user license to Bob for her video | POST `/ui/licenses/issued`; 200; response has `issued_license_id`, `license_mode=per_user`, `licensee_id=bob`, `status=active` |
| 467.2 | License appears in Alice's issued list | GET `/ui/licenses/issued`; response includes the per-user license |
| 467.3 | Bob sees the license in his held list | GET `/ui/licenses/held` (as Bob); response includes license with `terms_snapshot` |
| 467.4 | Per-user license without licensee_id fails | POST with `license_mode=per_user` and no `licensee_id` → 400 |

### Section 468: Blanket License Issuance API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 468.1 | Alice issues a blanket license on a video clip | POST with `license_mode=blanket`; 200; `licensee_id=null`, `status=active` |
| 468.2 | Blanket-licensed content appears in library | GET `/ui/licenses/library`; response includes content item with Alice's terms |
| 468.3 | Library is filterable by content type | GET `/ui/licenses/library?content_type=video`; only video items returned |
| 468.4 | Library is browsable by licensor | GET `/ui/licenses/library/creator/{alice_id}`; only Alice's items returned |

### Section 469: License Check & Terms API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 469.1 | Bob checks license for content with per-user license | GET `/ui/licenses/content/{id}/check` (as Bob); `has_license=true`, terms returned |
| 469.2 | Charlie checks license for blanket-licensed content | GET check (as Charlie); `has_license=true`, `license_mode=blanket` |
| 469.3 | Bob checks unlicensed content | GET check for content with no license; `has_license=false` |
| 469.4 | Alice updates blanket license terms | PATCH `/ui/licenses/issued/{id}`; 200; new `profit_share_pct` reflected |

### Section 470: License Revocation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 470.1 | Alice revokes Bob's per-user license | POST `/ui/licenses/issued/{id}/revoke`; 200; status → `revoked` |
| 470.2 | Bob no longer sees revoked license as active | GET `/ui/licenses/held` (as Bob); license status is `revoked` |
| 470.3 | Alice revokes blanket license | POST revoke; 200; GET library no longer includes the content |
| 470.4 | Non-licensor cannot revoke | Bob POST revoke on Alice's license → 403 |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Issue / update / revoke | `require_ui_session` | Must be content owner (licensor) |
| List issued | `require_ui_session` | Only own issued licenses |
| List held | `require_ui_session` | Only own held licenses |
| Browse library | `require_ui_session` | Any authenticated user |
| License check | `require_ui_session` | Any authenticated user for their own check |

### 6.2 Content Ownership Verification

- Before issuing a license, the service verifies the licensor owns the content by checking the content's creator field in the relevant content table (videos, posts, broadcasts).
- This prevents creators from licensing content they don't own.

### 6.3 Rate Limiting

- License issuance: max 50 per user per hour.
- Library browse: max 100 requests per user per minute.
- License check: max 200 requests per user per minute (frequently called by frontend).

### 6.4 Input Validation

- `content_id`: non-empty string, validated against content existence.
- `licensee_id`: non-empty string (per-user mode), validated against user existence.
- `profit_share_pct`: integer 0-100.
- `fixed_cost_cents`: integer >= 0.
- `revenue_share_pct`: integer 0-100.
- `title`: 0-200 characters.
- `expires_at`: if provided, must be a future Unix timestamp.

### 6.5 Data Integrity

- Per-user license `terms_snapshot` is immutable once created -- prevents retroactive term changes.
- Blanket license term changes apply only to future uses; existing revenue-sharing arrangements (LICENSE-003) use the terms at the time of content use.
- Revocation is permanent (no un-revoke); a new license must be issued if access is restored.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| LICENSE-001 | Required (same release) | Licenses DDB table pattern; agreement management foundation |
| `app/services/profile.py` | Exists | Display names for licensor/licensee |
| `app/services/alerts.py` | Exists | Notifications for license grant/revoke |
| `app/auth/deps.py` | Exists | `require_ui_session` for all endpoints |
| `app/core/tables.py` | Exists (modify) | Add `T.issued_licenses` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `issued_licenses` table definition |
| LICENSE-003 | Not started | Revenue sharing uses issued license terms |
| LICENSE-004 | Not started | License requests create issued licenses on approval |
| LICENSE-005 | Not started | Syndicate open licensing auto-creates blanket licenses |
| LICENSE-006 | Not started | Compliance checking validates issued license status |

---

## 8. Acceptance Criteria

1. Creators can issue per-user licenses granting a specific creator permission to use their content.
2. Creators can issue blanket licenses making their content available to all creators.
3. License terms (profit share %, fixed cost, revenue share %) are configurable at issuance time.
4. Per-user licenses appear in the licensee's "Licenses I Hold" list.
5. Blanket-licensed content appears in the Licensed Content Library.
6. Licensed Content Library is browsable and filterable by content type and licensor.
7. License check endpoint correctly identifies whether a user has a valid license for content.
8. Licensors can revoke issued licenses; licensees are notified.
9. Blanket license revocation removes content from the library.
10. All 16 E2E tests pass.

---

## Codebase References

All file paths relative to the repository root.

### Existing Files Referenced (verified)
- `app/services/billing_shared.py` (~260 lines) — `new_ledger_entry()` at line 217
- `app/services/subscription_access.py` (82 lines) — `has_active_subscription()` at line 55 (pattern reference)
- `app/services/newsfeed_fanout.py` (173 lines) — Fan-out pattern reference
- `app/services/profile.py` (345 lines) — `get_profile()` at line 220
- `app/services/alerts.py` (899 lines) — `write_alert()` at line 355
- `app/services/filemanager.py` (4955 lines) — Content metadata access
- `app/auth/deps.py` — `require_ui_session` at line 184
- `scripts/local-ddb-init.py` — DynamoDB table definitions

### Dependencies Not Yet Implemented
- `app/services/license_agreements.py` — LICENSE-001 prerequisite (does not exist)
- `licenses` DDB table — LICENSE-001 prerequisite (not in `scripts/local-ddb-init.py`)

### Files to Create (none exist yet)
- `app/services/issued_licenses.py` — Issued license service (~450 lines)
- `app/routers/issued_licenses.py` — REST API endpoints (~280 lines)
- `frontend/src/pages/licenses/IssuedLicensesPage.tsx` — Issued licenses page (~250 lines)
- `frontend/src/pages/licenses/HeldLicensesPage.tsx` — Held licenses page (~150 lines)
- `frontend/src/pages/licenses/IssueLicenseDialog.tsx` — Issue dialog (~180 lines)
- `frontend/src/pages/licenses/LicensedLibraryPage.tsx` — Library page (~200 lines)
- `frontend/src/pages/licenses/LicenseTermsForm.tsx` — Terms form (~100 lines)
- `frontend/src/components/shared/LicensedBadge.tsx` — Badge component (~30 lines)
- `frontend/src/api/endpoints/issued-licenses.ts` — API wrappers (~130 lines)
- `frontend/e2e/license-issuance.spec.ts` — E2E tests (~500 lines)

### Files to Modify (verified to exist)
- `app/main.py` — Register issued license routers
- `app/models.py` — Add Issued License Pydantic models
- `app/core/settings.py` — Add `issued_licenses_table_name` setting
- `app/core/tables.py` — Add `T.issued_licenses` table handle
- `scripts/local-ddb-init.py` — Add `issued_licenses` TableDef with 3 GSIs
- `frontend/src/App.tsx` — Add issued license routes
- `frontend/src/components/layout/Sidebar.tsx` — Add sub-items under Licenses nav
