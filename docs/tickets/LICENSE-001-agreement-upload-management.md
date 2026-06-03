# LICENSE-001: License Agreement Upload & Management

**Ticket**: LICENSE-001
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-001 introduces the ability for creators to upload and manage licensing agreements that prove they have rights to use third-party content (music tracks, video clips, stock images, fonts) in their own creations. Agreements are stored as documents (PDF, PNG, JPG) with structured metadata -- licensor name, license type, territory restrictions, and expiration dates. Agreements can be attached to specific content items (videos, posts, broadcasts) to demonstrate provenance. Platform admins can review and verify uploaded agreements, and the system proactively alerts creators when agreements are approaching expiration.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to upload a licensing agreement PDF so that I can prove I have rights to use a music track. | POST creates agreement record; file stored in S3; agreement appears in "My Licenses" list. |
| Creator | As a creator, I want to add metadata (licensor, type, expiry, territory) to my agreement so that the system can track its validity. | PATCH updates metadata fields; expiration date triggers future alerts. |
| Creator | As a creator, I want to attach an agreement to a specific video or post so that the content-license link is documented. | POST creates content-license mapping; content detail shows linked agreements. |
| Creator | As a creator, I want to detach an agreement from content when the content is removed or the license is replaced. | DELETE removes content-license mapping; agreement itself remains. |
| Creator | As a creator, I want to see all my license agreements in one place with their status and expiry. | GET returns paginated list with status badges (active, expiring_soon, expired, pending_review). |
| Admin | As a platform admin, I want to review uploaded agreements and mark them as verified or rejected. | POST verify/reject updates status; creator receives notification. |
| System | When an agreement is within 30 days of expiry, the creator should receive an alert. | Background check writes alert via `alerts.write_alert`; appears in alert inbox and email. |
| System | When an agreement expires, content linked to it should be flagged for compliance review. | Expiry processor updates agreement status to `expired`; linked content gets `compliance_status=license_expired`. |

### 1.3 Why This Is Needed

Creators increasingly incorporate third-party assets -- licensed music, stock footage, Creative Commons images -- into their content. Without a structured system to track these agreements, the platform has no way to verify that content is legally compliant, and creators have no centralized place to manage their licenses. This foundation enables downstream features: LICENSE-002 (issuing licenses to others), LICENSE-003 (revenue sharing), and LICENSE-006 (compliance auditing).

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| File manager service | `app/services/filemanager.py` (~4955 lines) | S3 upload/download patterns; `put_node` (line 460), `get_node` (line 450), bucket helpers; reuse for agreement file storage |
| Billing shared | `app/services/billing_shared.py` (~260 lines) | Ledger entry patterns (`new_ledger_entry` at line 217); LICENSE-003 will extend for revenue splits |
| Alerts service | `app/services/alerts.py` (~899 lines) | `write_alert` (line 355), SSE publish, email/SMS dispatch; reuse for expiry warnings |
| Content reports | `app/services/content_reports_store.py` (82 lines) | Content flagging patterns; LICENSE-006 will extend for compliance flags |
| Profile service | `app/services/profile.py` (345 lines) | `get_profile(user_id)` (line 220) for creator display names in admin review views |
| DDB table init | `scripts/local-ddb-init.py` | `TableDef` pattern with GSIs and `attr_types` for numeric sort keys |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` (line 184) returns `{user_sub, role, admin_profile}` |
| S3 mock (moto) | `app/core/dev_s3.py` | In-process S3 mock; agreement PDFs stored alongside other uploads |

<!-- NOTE: require_admin_session does NOT exist in app/auth/deps.py. The codebase pattern for admin auth is: require_ui_session + manual role check via normalize_role(user.role) not in {Role.ADMIN, Role.ROOT} (see app/routers/kyc_cases.py:1003 for the pattern). -->

### 2.2 Gaps

1. **No license/agreement model** -- there is no table, service, or UI for managing licensing agreements anywhere in the codebase.
2. **No content-to-license linking** -- content items (videos, posts, broadcasts) have no foreign key or mapping to license records.
3. **No license type taxonomy** -- no enum or configuration for license categories (royalty-free, Creative Commons, commercial, custom).
4. **No expiration tracking** -- no scheduled or background process that checks document expiry dates and generates alerts.
5. **No admin verification workflow** -- admins can moderate content (via content moderation service) but have no flow for reviewing legal documents.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Licenses Table

**Table name**: `licenses` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CREATOR#{user_id}` | `LICENSE#{license_id}` | Agreement metadata | `license_id`, `title`, `licensor_name`, `license_type`, `file_key`, `file_name`, `file_size`, `mime_type`, `status`, `territory`, `expires_at`, `notes`, `created_at`, `updated_at` |
| `CREATOR#{user_id}` | `CONTENT#{content_id}` | Content-to-license mapping | `content_id`, `content_type` (video/post/broadcast), `license_id`, `linked_at` |
| `LICENSE#{license_id}` | `META` | Reverse lookup for license by ID | `license_id`, `creator_id`, `title`, `status`, `expires_at`, `created_at` |
| `LICENSE#{license_id}` | `CONTENT#{content_id}` | Content linked to this license | `content_id`, `content_type`, `linked_at` |
| `ADMIN_REVIEW` | `PENDING#{created_at}#{license_id}` | Admin review queue | `license_id`, `creator_id`, `title`, `submitted_at` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Lookup licenses by status for admin review and expiry processing.
- `GSI1PK`: `STATUS#{status}` (e.g., `STATUS#active`, `STATUS#pending_review`, `STATUS#expired`)
- `GSI1SK`: `expires_at` (N) -- enables sorting by expiration date
- `attr_types={"GSI1SK": "N"}` required for numeric sort key

**GSI2** (`GSI2PK` / `GSI2SK`): Lookup content-license mappings by content ID.
- `GSI2PK`: `CONTENT#{content_id}` -- find all licenses for a given content item
- `GSI2SK`: `linked_at` (N) -- sorted by link timestamp

**GSI3** (`GSI3PK` / `GSI3SK`): Lookup licenses by expiry window for background processing.
- `GSI3PK`: `EXPIRY_MONTH#{YYYY-MM}` -- partition by expiry month for efficient scanning
- `GSI3SK`: `expires_at` (N) -- sorted within the month

#### 3.1.3 TableDef Entry

```python
TableDef(
    "licenses", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
        {"name": "GSI3", "pk": "GSI3PK", "sk": "GSI3SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Agreement metadata**:
```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "LICENSE#lic_abc123",
  "license_id": "lic_abc123",
  "title": "Epidemic Sound - Royalty Free Music Pack",
  "licensor_name": "Epidemic Sound AB",
  "license_type": "royalty_free",
  "file_key": "licenses/alice@test.local/lic_abc123/agreement.pdf",
  "file_name": "epidemic_license_2026.pdf",
  "file_size": 245000,
  "mime_type": "application/pdf",
  "status": "active",
  "territory": "worldwide",
  "expires_at": 1767225600,
  "notes": "Covers all tracks in the Creator Pro plan",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "GSI1PK": "STATUS#active",
  "GSI1SK": 1767225600,
  "GSI3PK": "EXPIRY_MONTH#2026-01",
  "GSI3SK": 1767225600
}
```

**Content-license mapping (under creator PK)**:
```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "CONTENT#vid_xyz789",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "license_id": "lic_abc123",
  "linked_at": 1748520100,
  "GSI2PK": "CONTENT#vid_xyz789",
  "GSI2SK": 1748520100
}
```

**Reverse lookup**:
```json
{
  "pk": "LICENSE#lic_abc123",
  "sk": "META",
  "license_id": "lic_abc123",
  "creator_id": "alice@test.local",
  "title": "Epidemic Sound - Royalty Free Music Pack",
  "status": "active",
  "expires_at": 1767225600,
  "created_at": 1748520000
}
```

### 3.2 S3 Storage

Agreement files stored in the existing S3 bucket under a dedicated prefix:

```
licenses/{user_id}/{license_id}/{original_filename}
```

- Max file size: 20 MB
- Accepted MIME types: `application/pdf`, `image/png`, `image/jpeg`, `image/webp`
- Files are private (no public URL); download via signed URL or proxied through backend

### 3.3 Backend Service

**New file**: `app/services/license_agreements.py` (~400 lines)

```python
"""License agreement upload, metadata, and content linking (LICENSE-001)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)

LICENSE_TYPES = {"royalty_free", "creative_commons", "commercial", "custom", "editorial", "public_domain"}
ALLOWED_MIME_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/webp"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
EXPIRY_WARNING_DAYS = 30


def create_agreement(
    *,
    creator_sub: str,
    title: str,
    licensor_name: str,
    license_type: str,
    file_key: str,
    file_name: str,
    file_size: int,
    mime_type: str,
    territory: str = "worldwide",
    expires_at: Optional[int] = None,
    notes: str = "",
) -> Dict[str, Any]:
    """Create a new license agreement record after file upload."""
    if license_type not in LICENSE_TYPES:
        raise ValueError(f"Invalid license_type: {license_type}")
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Invalid mime_type: {mime_type}")
    if file_size > MAX_FILE_SIZE:
        raise ValueError("File too large")

    license_id = f"lic_{uuid4().hex}"
    ts = now_ts()
    status = "pending_review"

    item = {
        "pk": f"CREATOR#{creator_sub}",
        "sk": f"LICENSE#{license_id}",
        "license_id": license_id,
        "title": title,
        "licensor_name": licensor_name,
        "license_type": license_type,
        "file_key": file_key,
        "file_name": file_name,
        "file_size": file_size,
        "mime_type": mime_type,
        "status": status,
        "territory": territory,
        "expires_at": expires_at,
        "notes": notes,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"STATUS#{status}",
        "GSI1SK": expires_at or 0,
    }
    if expires_at:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        item["GSI3PK"] = f"EXPIRY_MONTH#{dt.strftime('%Y-%m')}"
        item["GSI3SK"] = expires_at

    T.licenses.put_item(Item=item)

    # Write reverse lookup
    reverse = {
        "pk": f"LICENSE#{license_id}",
        "sk": "META",
        "license_id": license_id,
        "creator_id": creator_sub,
        "title": title,
        "status": status,
        "expires_at": expires_at,
        "created_at": ts,
    }
    T.licenses.put_item(Item=reverse)

    # Add to admin review queue
    _enqueue_review(license_id, creator_sub, title, ts)
    return item


def update_agreement(
    *,
    creator_sub: str,
    license_id: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    """Update agreement metadata (title, licensor, territory, expires_at, notes)."""
    # Fetch existing, validate ownership, apply updates, update GSI keys


def delete_agreement(
    *,
    creator_sub: str,
    license_id: str,
) -> None:
    """Soft-delete an agreement. Unlinks all content mappings."""
    # Set status to "deleted", remove from review queue, unlink content


def get_agreement(
    *,
    creator_sub: str,
    license_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a single agreement by ID for the creator."""
    # get_item pk=CREATOR#{creator_sub}, sk=LICENSE#{license_id}


def list_agreements(
    *,
    creator_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all agreements for a creator, optionally filtered by status."""
    # Query pk=CREATOR#{creator_sub}, sk begins_with LICENSE#
    # Apply status filter post-query
    # Return {items: [...], next_cursor: ...}


def link_content(
    *,
    creator_sub: str,
    license_id: str,
    content_id: str,
    content_type: str,
) -> Dict[str, Any]:
    """Link a content item to a license agreement."""
    # Validate license exists and is owned by creator
    # Write mapping under CREATOR#{creator_sub}/CONTENT#{content_id}
    # Write mapping under LICENSE#{license_id}/CONTENT#{content_id}


def unlink_content(
    *,
    creator_sub: str,
    license_id: str,
    content_id: str,
) -> None:
    """Remove content-license link."""
    # Delete both mapping records


def list_content_for_license(
    *,
    license_id: str,
) -> List[Dict[str, Any]]:
    """List all content linked to a license."""
    # Query pk=LICENSE#{license_id}, sk begins_with CONTENT#


def list_licenses_for_content(
    *,
    content_id: str,
) -> List[Dict[str, Any]]:
    """List all licenses linked to a content item (via GSI2)."""
    # GSI2 query: GSI2PK=CONTENT#{content_id}


def admin_verify_agreement(
    *,
    admin_sub: str,
    license_id: str,
    verified: bool,
    rejection_reason: str = "",
) -> Dict[str, Any]:
    """Admin marks an agreement as verified or rejected."""
    # Fetch reverse lookup to get creator_id
    # Update status to "active" or "rejected"
    # Update GSI1PK
    # Remove from review queue
    # Send notification to creator via write_alert


def admin_list_review_queue(
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List agreements pending admin review."""
    # Query pk=ADMIN_REVIEW, sk begins_with PENDING#


def process_expiry_alerts() -> int:
    """Background task: find agreements expiring within 30 days, send alerts."""
    # Query GSI3 for current month + next month
    # Filter: expires_at within 30 days AND status=active AND not already alerted
    # Write alert for each via write_alert
    # Return count of alerts sent


def process_expired_agreements() -> int:
    """Background task: mark expired agreements and flag linked content."""
    # Query GSI1 for STATUS#active where GSI1SK < now_ts()
    # Update status to "expired"
    # For each linked content: set compliance_status="license_expired"
    # Return count of expired agreements processed


# --- Internal helpers ---

def _enqueue_review(license_id, creator_id, title, ts):
    """Add agreement to admin review queue."""

def _dequeue_review(license_id, ts):
    """Remove agreement from admin review queue."""

def _get_reverse_lookup(license_id):
    """Get LICENSE#{id}/META item or raise 404."""
```

### 3.4 Backend Router

**New file**: `app/routers/license_agreements.py` (~250 lines)

```python
"""License agreement management router (LICENSE-001)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from app.auth.deps import require_ui_session
from app.auth.roles import Role, normalize_role
from app.services import license_agreements as svc

router = APIRouter(prefix="/ui/licenses", tags=["licenses"])
admin_router = APIRouter(prefix="/ui/admin/licenses", tags=["licenses-admin"])
```

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/licenses/agreements` | `require_ui_session` | Upload agreement file + metadata; multipart form |
| `GET` | `/ui/licenses/agreements` | `require_ui_session` | List creator's agreements (optional status filter) |
| `GET` | `/ui/licenses/agreements/{license_id}` | `require_ui_session` | Get single agreement detail |
| `PATCH` | `/ui/licenses/agreements/{license_id}` | `require_ui_session` | Update agreement metadata |
| `DELETE` | `/ui/licenses/agreements/{license_id}` | `require_ui_session` | Soft-delete agreement |
| `POST` | `/ui/licenses/agreements/{license_id}/link` | `require_ui_session` | Link content to agreement |
| `DELETE` | `/ui/licenses/agreements/{license_id}/link/{content_id}` | `require_ui_session` | Unlink content from agreement |
| `GET` | `/ui/licenses/agreements/{license_id}/content` | `require_ui_session` | List content linked to agreement |
| `GET` | `/ui/licenses/content/{content_id}/licenses` | `require_ui_session` | List licenses for a content item |
| `GET` | `/ui/licenses/agreements/{license_id}/download` | `require_ui_session` | Download agreement file (signed URL) |
| `GET` | `/ui/admin/licenses/review` | `require_ui_session + admin role check` | List agreements pending review |
| `POST` | `/ui/admin/licenses/review/{license_id}` | `require_ui_session + admin role check` | Verify or reject agreement |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- License Agreements (LICENSE-001) --

class LicenseAgreementCreateIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    licensor_name: str = Field(min_length=1, max_length=200)
    license_type: str = Field(description="One of: royalty_free, creative_commons, commercial, custom, editorial, public_domain")
    territory: str = Field(default="worldwide", max_length=100)
    expires_at: Optional[int] = Field(default=None, description="Unix timestamp of expiration date")
    notes: str = Field(default="", max_length=1000)

class LicenseAgreementUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=2, max_length=200)
    licensor_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    license_type: Optional[str] = None
    territory: Optional[str] = Field(default=None, max_length=100)
    expires_at: Optional[int] = None
    notes: Optional[str] = Field(default=None, max_length=1000)

class LicenseContentLinkIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, post, broadcast")

class LicenseAdminReviewIn(BaseModel):
    verified: bool
    rejection_reason: str = Field(default="", max_length=500)

class LicenseAgreementOut(BaseModel):
    license_id: str
    title: str
    licensor_name: str = ""
    license_type: str
    file_name: str = ""
    file_size: int = 0
    mime_type: str = ""
    status: str  # pending_review, active, rejected, expired, deleted
    territory: str = "worldwide"
    expires_at: Optional[int] = None
    notes: str = ""
    created_at: int = 0
    updated_at: int = 0
    content_count: int = 0

class LicenseContentLinkOut(BaseModel):
    content_id: str
    content_type: str
    license_id: str
    linked_at: int = 0

class LicenseReviewQueueItemOut(BaseModel):
    license_id: str
    creator_id: str
    creator_display_name: str = ""
    title: str
    licensor_name: str = ""
    license_type: str = ""
    submitted_at: int = 0
```

### 3.7 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/licenses/LicensesPage.tsx` | Main license management page | ~280 |
| `frontend/src/pages/licenses/UploadAgreementDialog.tsx` | Upload dialog with file picker + metadata form | ~150 |
| `frontend/src/pages/licenses/AgreementDetailDialog.tsx` | View agreement detail, linked content, download | ~120 |
| `frontend/src/pages/licenses/LinkContentDialog.tsx` | Dialog to link content to an agreement | ~80 |
| `frontend/src/pages/licenses/AdminReviewPage.tsx` | Admin agreement review queue | ~150 |
| `frontend/src/api/endpoints/licenses.ts` | API client wrappers | ~120 |

**Component tree**:

```
LicensesPage
├── Card: "My License Agreements"
│   ├── UploadAgreementDialog (Button: "Upload Agreement")
│   ├── Filter bar: status dropdown (all, active, pending_review, expiring_soon, expired)
│   └── DataTable
│       └── For each agreement:
│           ├── Title, licensor, type badge, territory
│           ├── Status badge (color-coded)
│           ├── Expiry date (red if < 30 days)
│           ├── Content count badge
│           ├── "View" → AgreementDetailDialog
│           ├── "Link Content" → LinkContentDialog
│           └── "Delete" (with confirmation)
└── Card: "Expiring Soon" (filtered view of agreements expiring within 30 days)

AgreementDetailDialog
├── Agreement metadata (title, licensor, type, territory, notes)
├── File preview (PDF embed or image) + Download button
├── Status + admin verification info
├── Linked Content list
│   └── For each: content type icon, content title, "Unlink" button
└── Edit button → inline editing of metadata fields

AdminReviewPage (admin only)
├── Header: "License Agreement Review"
└── Review queue table
    └── For each pending agreement:
        ├── Creator name, title, licensor, type
        ├── File download/preview link
        ├── "Verify" button
        └── "Reject" button (with reason input)
```

### 3.8 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/licenses" element={<LicensesPage />} />
<Route path="/admin/license-review" element={<AdminReviewPage />} />
```

### 3.9 Sidebar Navigation

Add "Licenses" entry to the Productivity group in `Sidebar.tsx` and `AppShell.tsx` (MobileSidebar) with `FileCheck` icon from lucide-react. Add to `MORE_LINKS` in `MobileNav.tsx`.

### 3.10 Files to Create

<!-- NOTE: None of the files below exist yet — all are new implementation required. The licenses table is not in scripts/local-ddb-init.py, app/core/settings.py, or app/core/tables.py. No frontend pages/licenses/ directory exists. -->

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/license_agreements.py` | Core agreement management service | ~400 |
| `app/routers/license_agreements.py` | REST API endpoints | ~250 |
| `frontend/src/pages/licenses/LicensesPage.tsx` | Agreements list page | ~280 |
| `frontend/src/pages/licenses/UploadAgreementDialog.tsx` | Upload dialog | ~150 |
| `frontend/src/pages/licenses/AgreementDetailDialog.tsx` | Detail dialog | ~120 |
| `frontend/src/pages/licenses/LinkContentDialog.tsx` | Link content dialog | ~80 |
| `frontend/src/pages/licenses/AdminReviewPage.tsx` | Admin review page | ~150 |
| `frontend/src/api/endpoints/licenses.ts` | API wrappers | ~120 |
| `frontend/e2e/license-agreements.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `license_agreements_router` and `license_agreements_admin_router` |
| `app/models.py` | Add License Agreement Pydantic models |
| `app/core/settings.py` | Add `licenses_table_name` setting |
| `app/core/tables.py` | Add `T.licenses` table handle |
| `scripts/local-ddb-init.py` | Add `licenses` TableDef with 3 GSIs |
| `frontend/src/api/types.ts` | Add License Agreement TypeScript interfaces |
| `frontend/src/App.tsx` | Add license routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Licenses" nav entry |
| `frontend/src/components/layout/AppShell.tsx` | Add to mobile sidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add to MORE_LINKS |

---

## 4. File Upload Flow

### 4.1 Upload Sequence

1. Frontend opens `UploadAgreementDialog` with file input + metadata form.
2. User selects file (PDF or image, max 20 MB) and fills in metadata fields.
3. Frontend sends multipart `POST /ui/licenses/agreements` with file + metadata as form fields.
4. Backend validates file type and size.
5. Backend uploads file to S3 at `licenses/{user_id}/{license_id}/{filename}`.
6. Backend creates DynamoDB records (agreement, reverse lookup, review queue).
7. Backend returns `LicenseAgreementOut` with `status=pending_review`.

### 4.2 Download Flow

1. Frontend requests `GET /ui/licenses/agreements/{id}/download`.
2. Backend validates ownership (creator match or admin role).
3. Backend generates S3 presigned URL (300-second expiry).
4. Backend returns `{"download_url": "<presigned_url>"}`.
5. Frontend opens URL in new tab or triggers download.

### 4.3 Content Linking

- Content types supported: `video`, `post`, `broadcast`.
- A content item can be linked to multiple licenses (e.g., video uses licensed music AND stock footage).
- A license can be linked to multiple content items.
- Linking requires the license to be in `active` or `pending_review` status (not `expired` or `rejected`).

---

## 5. Expiry Processing

### 5.1 Background Task

A periodic background task (runs daily, triggered by `BackgroundTasks` or a cron endpoint):

1. **Expiry warning**: Query GSI3 for agreements expiring within 30 days. For each, if not already alerted:
   - Write alert: `write_alert(creator_sub, "license_expiring", {license_id, title, expires_at})`.
   - Set `expiry_alert_sent=true` on the agreement record.

2. **Expiry processing**: Query GSI1 for `STATUS#active` where `expires_at < now_ts()`:
   - Update status to `expired`, GSI1PK to `STATUS#expired`.
   - For each linked content item, set `compliance_status=license_expired` (used by LICENSE-006).
   - Write alert: `write_alert(creator_sub, "license_expired", {license_id, title})`.

### 5.2 Alert Types

| Alert Type | Message | Action URL |
|------------|---------|------------|
| `license_expiring` | "Your license '{title}' expires in {days} days" | `/licenses?highlight={license_id}` |
| `license_expired` | "Your license '{title}' has expired" | `/licenses?highlight={license_id}` |
| `license_verified` | "Your license '{title}' has been verified" | `/licenses?highlight={license_id}` |
| `license_rejected` | "Your license '{title}' was rejected: {reason}" | `/licenses?highlight={license_id}` |

---

## 6. E2E Test Plan

**File**: `frontend/e2e/license-agreements.spec.ts`

### Section 463: Agreement Upload API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 463.1 | Alice uploads a PDF license agreement | POST `/ui/licenses/agreements` with multipart file + metadata; 200; response has `license_id`, `status=pending_review`, `file_name` matches |
| 463.2 | Agreement appears in creator's list | GET `/ui/licenses/agreements`; response includes uploaded agreement with correct metadata |
| 463.3 | Agreement detail returns all fields | GET `/ui/licenses/agreements/{id}`; response has `title`, `licensor_name`, `license_type`, `territory`, `expires_at`, `file_size` |
| 463.4 | Invalid file type is rejected | POST with `.exe` file → 400; error mentions file type |

### Section 464: Agreement Metadata & Download API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 464.1 | Creator updates agreement metadata | PATCH `/ui/licenses/agreements/{id}` with new title + territory; 200; response reflects updates |
| 464.2 | Agreement download returns presigned URL | GET `/ui/licenses/agreements/{id}/download`; 200; response has `download_url` containing S3 signature |
| 464.3 | Non-owner cannot access agreement | Bob GET `/ui/licenses/agreements/{alice_license_id}` → 404 |
| 464.4 | Soft-delete removes agreement from list | DELETE `/ui/licenses/agreements/{id}`; 200; GET list no longer includes it |

### Section 465: Content Linking API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 465.1 | Link content to agreement | POST `/ui/licenses/agreements/{id}/link` with `{content_id, content_type: "video"}`; 200; link record returned |
| 465.2 | List content for agreement | GET `/ui/licenses/agreements/{id}/content`; response includes linked content item |
| 465.3 | List licenses for content item | GET `/ui/licenses/content/{content_id}/licenses`; response includes the agreement |
| 465.4 | Unlink content from agreement | DELETE `/ui/licenses/agreements/{id}/link/{content_id}`; 200; GET content list no longer includes it |

### Section 466: Admin Review API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 466.1 | Admin sees pending agreement in review queue | GET `/ui/admin/licenses/review`; response includes Alice's pending agreement |
| 466.2 | Admin verifies agreement | POST `/ui/admin/licenses/review/{id}` with `{verified: true}`; 200; agreement status → `active` |
| 466.3 | Admin rejects agreement with reason | POST with `{verified: false, rejection_reason: "Illegible"}`; status → `rejected` |
| 466.4 | Non-admin cannot access review queue | Alice GET `/ui/admin/licenses/review` → 403 |

**Total E2E tests: 16**

---

## 7. Security Considerations

### 7.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| `/ui/licenses/*` | `require_ui_session` | Creator sees only own agreements |
| `/ui/admin/licenses/*` | `require_ui_session + admin role check` | Platform admin or root only |
| Download endpoint | `require_ui_session` | Owner or admin only |

### 7.2 File Upload Security

- File type validated by both MIME type header and magic bytes (first 4 bytes).
- File size capped at 20 MB server-side (checked before S3 upload).
- File names sanitized: strip path separators, limit to 200 characters.
- S3 key uses `license_id` (UUID), not user-supplied filename, to prevent path traversal.
- Presigned download URLs expire after 300 seconds.

### 7.3 Authorization Enforcement

- Agreement CRUD operations validate `creator_sub` matches the agreement owner in the PK.
- Content linking validates the creator owns both the agreement and has access to the content item.
- Admin endpoints use `require_ui_session + admin role check` (role >= ADMIN).
- Soft-delete prevents data loss; hard-delete is admin-only (future consideration).

### 7.4 Rate Limiting

- Agreement upload: max 20 per user per hour.
- Content linking: max 100 per user per hour.
- All endpoints inherit global rate limiter.

### 7.5 Input Validation

- `title`: 2-200 characters, stripped of leading/trailing whitespace.
- `licensor_name`: 1-200 characters.
- `license_type`: must be one of the defined enum values.
- `territory`: 0-100 characters.
- `expires_at`: if provided, must be a future Unix timestamp.
- `notes`: 0-1000 characters.
- `content_type`: must be one of `video`, `post`, `broadcast`.

---

## 8. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/filemanager.py` | Exists | S3 upload/download patterns and bucket access |
| `app/services/alerts.py` | Exists | Expiry notifications and admin review notifications |
| `app/services/profile.py` | Exists | Creator display names in admin review queue |
| `app/auth/deps.py` | Exists | `require_ui_session` (line 184); admin auth via manual role check pattern |
| `app/core/tables.py` | Exists (modify) | Add `T.licenses` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `licenses` table definition |
| LICENSE-002 | Not started | Extends the licenses table with issued license records |
| LICENSE-003 | Not started | Revenue sharing for licensed content uses agreement metadata |
| LICENSE-006 | Not started | Compliance checking depends on agreement status and content links |

---

## 9. Acceptance Criteria

1. Creators can upload license agreement files (PDF, images) with metadata via multipart form.
2. Agreements are stored in S3 and tracked in DynamoDB with full metadata.
3. Creators can view, update, and soft-delete their agreements.
4. Agreements can be linked to and unlinked from content items (videos, posts, broadcasts).
5. Content-license mappings are queryable in both directions (license → content, content → licenses).
6. Platform admins can review pending agreements and verify or reject them.
7. Agreement status transitions are correct: `pending_review` → `active`/`rejected`; `active` → `expired`.
8. Expiry alerts are sent when agreements are within 30 days of expiration.
9. Expired agreements are automatically flagged and linked content marked for compliance review.
10. All 16 E2E tests pass.

---

## Codebase References

All file paths relative to the repository root.

### Existing Files Referenced (verified)
- `app/services/filemanager.py` (4955 lines) — S3 upload/download patterns
  - `get_node()` at line 450
  - `put_node()` at line 460
- `app/services/alerts.py` (899 lines) — Alert system
  - `write_alert()` at line 355 — reuse for license expiry/verification notifications
- `app/services/billing_shared.py` (~260 lines) — Billing helpers
  - `new_ledger_entry()` at line 217 — pattern for LICENSE-003 revenue splits
- `app/services/content_reports_store.py` (82 lines) — Content flagging patterns
- `app/services/profile.py` (345 lines) — Profile lookups
  - `get_profile()` at line 220 — for admin review queue display names
- `app/auth/deps.py` — Auth dependencies
  - `require_ui_session` at line 184 (returns `{user_sub, role, admin_profile}`)
  - `require_root_session` at line 273
  - **`require_admin_session` does NOT exist** — use `require_ui_session` + `normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}` pattern (see `app/routers/kyc_cases.py:1003`)
- `app/auth/roles.py` — `Role` enum and `normalize_role()` helper
- `app/core/dev_s3.py` — In-process S3 mock (moto)
- `scripts/local-ddb-init.py` — DynamoDB table definitions (`TableDef` pattern)

### Files to Create (none exist yet)
- `app/services/license_agreements.py` — Core service (~400 lines)
- `app/routers/license_agreements.py` — REST API endpoints (~250 lines)
- `frontend/src/pages/licenses/LicensesPage.tsx` — Main page (~280 lines)
- `frontend/src/pages/licenses/UploadAgreementDialog.tsx` — Upload dialog (~150 lines)
- `frontend/src/pages/licenses/AgreementDetailDialog.tsx` — Detail dialog (~120 lines)
- `frontend/src/pages/licenses/LinkContentDialog.tsx` — Link content dialog (~80 lines)
- `frontend/src/pages/licenses/AdminReviewPage.tsx` — Admin review page (~150 lines)
- `frontend/src/api/endpoints/licenses.ts` — API wrappers (~120 lines)
- `frontend/e2e/license-agreements.spec.ts` — E2E tests (~500 lines)

### Files to Modify (verified to exist)
- `app/main.py` — Register license routers
- `app/models.py` — Add License Agreement Pydantic models
- `app/core/settings.py` — Add `licenses_table_name` setting
- `app/core/tables.py` — Add `T.licenses` table handle
- `scripts/local-ddb-init.py` — Add `licenses` TableDef with 3 GSIs
- `frontend/src/App.tsx` — Add license routes
- `frontend/src/components/layout/Sidebar.tsx` — Add "Licenses" nav entry
- `frontend/src/components/layout/AppShell.tsx` — Add to mobile sidebar
- `frontend/src/components/layout/MobileNav.tsx` — Add to MORE_LINKS

---

## Testing Strategy

### Unit Tests (`tests/test_license_agreements.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_agreement_stores_metadata` | Create agreement stores metadata |
| 2 | `test_upload_file_to_s3` | Upload file to s3 |
| 3 | `test_update_metadata_fields` | Update metadata fields |
| 4 | `test_attach_to_content` | Attach to content |
| 5 | `test_detach_from_content` | Detach from content |
| 6 | `test_list_agreements_paginated` | List agreements paginated |
| 7 | `test_admin_verify_agreement` | Admin verify agreement |
| 8 | `test_admin_reject_agreement` | Admin reject agreement |
| 9 | `test_expiry_alert_within_30_days` | Expiry alert within 30 days |
| 10 | `test_expired_flags_linked_content` | Expired flags linked content |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/license-agreements.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~15 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `LICENSE_MANAGEMENT_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

No dependencies -- this ticket can be implemented independently.

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| LICENSE-002 | Content License Issuance references agreement records |
| LICENSE-006 | Compliance Verification checks agreement validity |

### Merge Strategy
**Independent -- first ticket in the LICENSE chain. New DDB table, S3 storage, and endpoints are all additive.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: LICENSE_MANAGEMENT_ENABLED=true
- [ ] Service file created/modified: `app/services/license_agreements.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/license-agreements.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_license_agreements.py`
