# LICENSE-006: License Compliance & Verification

**Ticket**: LICENSE-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-006 builds the compliance layer that ensures licensed content usage is valid, current, and properly documented across the platform. The system tracks which content uses licensed material, verifies that referenced licenses are active and unexpired, surfaces warnings when compliance issues arise, and provides admin and creator dashboards for managing licensing health. A community flag system allows viewers and creators to report potentially unlicensed content, which feeds into the admin compliance review queue.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| System | When content is published that references licensed material, the system should verify the license is still valid. | Publish flow checks license status; warning displayed if license is expired or revoked. |
| System | When a license expires, all content linked to it should be flagged for compliance review. | Background process sets `compliance_status=license_expired` on affected content; admin dashboard shows flagged items. |
| Creator | As a creator, I want to see a compliance overview of my content that uses licensed material. | "My Compliance" page shows all content with license references, color-coded by compliance status. |
| Creator | As a creator, I want to be notified when a license I'm using is about to expire so I can renew. | Alert sent 30 days before expiry; appears in notifications and email. |
| Admin | As an admin, I want a compliance dashboard showing all content with expired or missing licenses. | Admin page shows filterable list of compliance issues across all creators. |
| Admin | As an admin, I want to resolve compliance issues by marking content as compliant, requiring action, or removing. | POST updates compliance status; creator notified of required action. |
| Viewer | As a viewer, I want to flag content that I believe uses unlicensed material. | "Report licensing issue" option on content; creates compliance flag for admin review. |
| Creator | As a creator, I want to flag another creator's content that I believe uses my material without a license. | "Report unlicensed use" with content ownership evidence; creates priority compliance flag. |
| Admin | As an admin, I want to see and manage all compliance flags. | Flag queue with status, reporter, content, and resolution actions. |

### 1.3 Why This Is Needed

The licensing system (LICENSE-001 through LICENSE-005) establishes agreement tracking, license issuance, revenue sharing, and workflows, but without compliance enforcement, licenses can silently expire while content continues to be monetized. Viewers and creators need a way to report suspected violations, and admins need tools to investigate and resolve issues. This ticket closes the loop: every piece of licensed content is continuously monitored, and violations are surfaced before they become legal liabilities.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| License agreements | `app/services/license_agreements.py` (LICENSE-001) | Agreement status tracking; `process_expired_agreements` sets `compliance_status` on linked content |
<!-- NOTE: app/services/license_agreements.py does not exist yet — new implementation required as part of LICENSE-001 -->
| Issued licenses | `app/services/issued_licenses.py` (LICENSE-002) | `list_licenses_for_content`, `check_license_for_use`; validation against active licenses |
<!-- NOTE: app/services/issued_licenses.py does not exist yet — new implementation required as part of LICENSE-002 -->
| Content reports | `app/services/content_reports_store.py` | Existing content reporting/flagging patterns; architectural reference for compliance flags |
<!-- VERIFIED: app/services/content_reports_store.py exists -->
| Content moderation | `app/services/content_moderation.py` | Content removal and moderation queue patterns |
<!-- NOTE: app/services/content_moderation.py does not exist yet — new implementation required. Moderation logic is currently in app/routers/moderation.py and related service files (moderation_audit_log.py, moderation_policy_engine.py) -->
| DMCA operations | `app/services/dmca_content_operations.py` | DMCA takedown patterns; related legal compliance workflow |
<!-- VERIFIED: app/services/dmca_content_operations.py exists -->
| Alerts service | `app/services/alerts.py` | `write_alert` for compliance notifications (see app/services/alerts.py:355) |
| Profile service | `app/services/profile.py` | Display names in compliance views |
<!-- VERIFIED: app/services/profile.py exists -->
| Billing shared | `app/services/billing_shared.py` | Ledger entries; compliance issues may freeze revenue splits |
<!-- VERIFIED: app/services/billing_shared.py exists -->
| Auth dependencies | `app/auth/deps.py` | `require_ui_session`; `app/auth/policy.py` | `require_admin_scope(AdminScope.CONTENT_MODERATION)` |
<!-- NOTE: require_admin_session does not exist in app/auth/deps.py. The correct admin auth pattern is require_admin_scope(AdminScope.CONTENT_MODERATION) from app/auth/policy.py:84 -->

### 2.2 Gaps

1. **No compliance status on content** -- content items have no `compliance_status` field or concept of licensing health.
2. **No publish-time license validation** -- content can be published claiming to use licensed material even if the license is expired.
3. **No compliance dashboard** -- neither admins nor creators have a view of licensing compliance across content.
4. **No community flag system** -- viewers cannot report suspected unlicensed use of content.
5. **No compliance resolution workflow** -- admins have no tool to investigate and resolve licensing disputes.
6. **No continuous monitoring** -- license expiry in LICENSE-001 sets a flag, but there is no broader compliance scanning.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 License Compliance Table

**Table name**: `license_compliance` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CONTENT#{content_id}` | `STATUS` | Compliance status for a content item | `content_id`, `content_type`, `creator_id`, `compliance_status`, `last_checked_at`, `issues`, `resolved_at`, `resolved_by` |
| `CONTENT#{content_id}` | `LICENSE_REF#{license_id}` | License reference on content | `license_id`, `license_type` (agreement/issued), `license_status`, `expires_at`, `verified_at` |
| `CONTENT#{content_id}` | `FLAG#{flag_id}` | Compliance flag on content | `flag_id`, `reporter_id`, `reporter_type` (viewer/creator), `reason`, `evidence`, `status` (open/investigating/resolved/dismissed), `created_at`, `resolved_at`, `resolved_by`, `resolution_notes` |
| `CREATOR#{user_id}` | `COMPLIANCE#{content_id}` | Creator's content compliance index | `content_id`, `content_type`, `compliance_status`, `issue_count`, `last_checked_at` |
| `ADMIN_COMPLIANCE` | `ISSUE#{severity}#{created_at}#{content_id}` | Admin compliance queue | `content_id`, `creator_id`, `compliance_status`, `issue_type`, `severity`, `created_at` |
| `ADMIN_COMPLIANCE` | `FLAG#{created_at}#{flag_id}` | Admin flag queue | `flag_id`, `content_id`, `reporter_id`, `reason`, `status`, `created_at` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Compliance issues by status for admin dashboard.
- `GSI1PK`: `COMPLIANCE_STATUS#{status}` (e.g., `COMPLIANCE_STATUS#license_expired`, `COMPLIANCE_STATUS#flagged`)
- `GSI1SK`: `created_at` (N)
- `attr_types={"GSI1SK": "N"}`

**GSI2** (`GSI2PK` / `GSI2SK`): Flags by status for admin review.
- `GSI2PK`: `FLAG_STATUS#{status}` (e.g., `FLAG_STATUS#open`, `FLAG_STATUS#investigating`)
- `GSI2SK`: `created_at` (N)

**GSI3** (`GSI3PK` / `GSI3SK`): Creator compliance summary for per-creator filtering.
- `GSI3PK`: `CREATOR_COMPLIANCE#{user_id}`
- `GSI3SK`: `last_checked_at` (N)

#### 3.1.3 TableDef Entry

```python
TableDef(
    "license_compliance", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
        {"name": "GSI3", "pk": "GSI3PK", "sk": "GSI3SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
),
```

#### 3.1.4 Compliance Statuses

| Status | Description | Severity |
|--------|-------------|----------|
| `compliant` | All referenced licenses are active and valid | low |
| `expiring_soon` | One or more referenced licenses expire within 30 days | medium |
| `license_expired` | One or more referenced licenses have expired | high |
| `license_revoked` | A referenced license has been revoked by the licensor | high |
| `flagged` | Content has been flagged by a viewer or creator for potential unlicensed use | medium |
| `under_review` | Admin is actively investigating compliance | high |
| `action_required` | Admin has determined that creator action is needed | critical |
| `removed` | Content removed due to compliance violation | critical |
| `resolved` | Compliance issue was investigated and resolved | low |

#### 3.1.5 Example DynamoDB Items

**Content compliance status**:
```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "STATUS",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "creator_id": "bob@test.local",
  "compliance_status": "license_expired",
  "last_checked_at": 1748520100,
  "issues": [
    {"type": "license_expired", "license_id": "lic_abc123", "expired_at": 1748000000}
  ],
  "resolved_at": null,
  "resolved_by": null,
  "GSI1PK": "COMPLIANCE_STATUS#license_expired",
  "GSI1SK": 1748520100,
  "GSI3PK": "CREATOR_COMPLIANCE#bob@test.local",
  "GSI3SK": 1748520100
}
```

**License reference**:
```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "LICENSE_REF#lic_abc123",
  "license_id": "lic_abc123",
  "license_type": "agreement",
  "license_status": "expired",
  "expires_at": 1748000000,
  "verified_at": 1747900000
}
```

**Compliance flag**:
```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "FLAG#flg_def456",
  "flag_id": "flg_def456",
  "reporter_id": "charlie@test.local",
  "reporter_type": "creator",
  "reason": "Uses my copyrighted background music without license",
  "evidence": "Compare audio at 1:30 mark with my track 'Sunset Drive'",
  "status": "open",
  "created_at": 1748520200,
  "resolved_at": null,
  "resolved_by": null,
  "resolution_notes": "",
  "GSI2PK": "FLAG_STATUS#open",
  "GSI2SK": 1748520200
}
```

### 3.2 Backend Service

**New file**: `app/services/license_compliance.py` (~500 lines)

```python
"""License compliance tracking, flagging, and verification (LICENSE-006)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.license_agreements import list_licenses_for_content as list_agreements_for_content
from app.services.issued_licenses import list_licenses_for_content as list_issued_for_content

logger = logging.getLogger(__name__)

FLAG_REASONS = {
    "unlicensed_music", "unlicensed_video", "unlicensed_image",
    "expired_license", "copyright_claim", "other"
}
EXPIRY_WARNING_DAYS = 30


def check_content_compliance(
    *,
    content_id: str,
    content_type: str,
    creator_id: str,
) -> Dict[str, Any]:
    """Check compliance status for a content item by validating all license references.
    Called at publish time and by background compliance scanner.
    """
    ts = now_ts()
    issues = []

    # Check agreement-based licenses (LICENSE-001 links)
    agreements = list_agreements_for_content(content_id=content_id)
    for agr in agreements:
        ref_status = _evaluate_license_ref(agr, ts)
        _upsert_license_ref(content_id, agr.get("license_id", ""), "agreement", ref_status, ts)
        if ref_status["status"] != "active":
            issues.append({
                "type": ref_status["issue_type"],
                "license_id": agr.get("license_id"),
                "detail": ref_status.get("detail", ""),
            })

    # Check issued licenses (LICENSE-002)
    issued = list_issued_for_content(content_id=content_id)
    for lic in issued:
        ref_status = _evaluate_license_ref(lic, ts)
        _upsert_license_ref(content_id, lic.get("issued_license_id", ""), "issued", ref_status, ts)
        if ref_status["status"] != "active":
            issues.append({
                "type": ref_status["issue_type"],
                "license_id": lic.get("issued_license_id"),
                "detail": ref_status.get("detail", ""),
            })

    # Determine overall compliance status
    compliance_status = _determine_compliance_status(issues, ts)

    # Write/update compliance status record
    _upsert_compliance_status(content_id, content_type, creator_id,
                              compliance_status, issues, ts)

    # Write to creator index
    _upsert_creator_index(creator_id, content_id, content_type,
                          compliance_status, len(issues), ts)

    # Enqueue for admin if issues found
    if compliance_status not in ("compliant", "resolved"):
        _enqueue_admin_issue(content_id, creator_id, compliance_status,
                             _issue_type_from_status(compliance_status),
                             _severity_from_status(compliance_status), ts)

    return {
        "content_id": content_id,
        "compliance_status": compliance_status,
        "issues": issues,
        "checked_at": ts,
    }


def flag_content(
    *,
    reporter_id: str,
    content_id: str,
    reason: str,
    evidence: str = "",
    reporter_type: str = "viewer",
) -> Dict[str, Any]:
    """Flag content for potential licensing compliance issue."""
    if reason not in FLAG_REASONS:
        raise ValueError(f"Invalid reason: {reason}. Valid: {', '.join(FLAG_REASONS)}")

    flag_id = f"flg_{uuid4().hex}"
    ts = now_ts()

    flag_item = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"FLAG#{flag_id}",
        "flag_id": flag_id,
        "reporter_id": reporter_id,
        "reporter_type": reporter_type,
        "reason": reason,
        "evidence": evidence,
        "status": "open",
        "created_at": ts,
        "resolved_at": None,
        "resolved_by": None,
        "resolution_notes": "",
        "GSI2PK": "FLAG_STATUS#open",
        "GSI2SK": ts,
    }
    T.license_compliance.put_item(Item=flag_item)

    # Add to admin flag queue
    admin_flag = {
        "pk": "ADMIN_COMPLIANCE",
        "sk": f"FLAG#{ts}#{flag_id}",
        "flag_id": flag_id,
        "content_id": content_id,
        "reporter_id": reporter_id,
        "reporter_type": reporter_type,
        "reason": reason,
        "status": "open",
        "created_at": ts,
    }
    T.license_compliance.put_item(Item=admin_flag)

    # Update compliance status to "flagged" if not already worse
    _escalate_compliance_status(content_id, "flagged", ts)

    return flag_item


def admin_resolve_flag(
    *,
    admin_sub: str,
    content_id: str,
    flag_id: str,
    resolution: str,
    notes: str = "",
) -> Dict[str, Any]:
    """Admin resolves a compliance flag."""
    if resolution not in ("resolved", "dismissed", "action_required"):
        raise ValueError("resolution must be 'resolved', 'dismissed', or 'action_required'")

    ts = now_ts()

    # Update flag record
    T.license_compliance.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"FLAG#{flag_id}"},
        UpdateExpression="SET #s = :s, resolved_at = :t, resolved_by = :a, "
                         "resolution_notes = :n, GSI2PK = :gsi2",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": resolution,
            ":t": ts,
            ":a": admin_sub,
            ":n": notes,
            ":gsi2": f"FLAG_STATUS#{resolution}",
        },
    )

    # Notify content creator
    status_record = _get_compliance_status(content_id)
    if status_record:
        creator_id = status_record.get("creator_id")
        if creator_id:
            write_alert(creator_id, f"compliance_flag_{resolution}", {
                "content_id": content_id,
                "flag_id": flag_id,
                "notes": notes,
            })

    return {"flag_id": flag_id, "status": resolution}


def admin_update_compliance(
    *,
    admin_sub: str,
    content_id: str,
    new_status: str,
    notes: str = "",
) -> Dict[str, Any]:
    """Admin updates the compliance status of content."""
    valid = {"compliant", "under_review", "action_required", "removed", "resolved"}
    if new_status not in valid:
        raise ValueError(f"new_status must be one of: {', '.join(valid)}")

    ts = now_ts()
    T.license_compliance.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": "STATUS"},
        UpdateExpression="SET compliance_status = :s, resolved_at = :t, "
                         "resolved_by = :a, GSI1PK = :gsi1, GSI1SK = :ts",
        ExpressionAttributeValues={
            ":s": new_status,
            ":t": ts if new_status in ("compliant", "resolved", "removed") else None,
            ":a": admin_sub if new_status in ("compliant", "resolved", "removed") else None,
            ":gsi1": f"COMPLIANCE_STATUS#{new_status}",
            ":ts": ts,
        },
    )

    # Notify creator
    status_record = _get_compliance_status(content_id)
    if status_record:
        creator_id = status_record.get("creator_id")
        if creator_id:
            write_alert(creator_id, f"compliance_status_{new_status}", {
                "content_id": content_id,
                "notes": notes,
            })

    return {"content_id": content_id, "compliance_status": new_status}


def get_compliance_status(
    *,
    content_id: str,
) -> Optional[Dict[str, Any]]:
    """Get compliance status for a content item."""
    # get_item pk=CONTENT#{content_id}, sk=STATUS


def list_license_refs(
    *,
    content_id: str,
) -> List[Dict[str, Any]]:
    """List all license references on a content item."""
    # Query pk=CONTENT#{content_id}, sk begins_with LICENSE_REF#


def list_content_flags(
    *,
    content_id: str,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List compliance flags on a content item."""
    # Query pk=CONTENT#{content_id}, sk begins_with FLAG#


def list_creator_compliance(
    *,
    creator_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List compliance status for all of a creator's content."""
    # Query GSI3: CREATOR_COMPLIANCE#{user_id}


def admin_list_issues(
    *,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list compliance issues across the platform."""
    # If status_filter: GSI1 query COMPLIANCE_STATUS#{status}
    # Else: query ADMIN_COMPLIANCE sk begins_with ISSUE#


def admin_list_flags(
    *,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list compliance flags."""
    # If status_filter: GSI2 query FLAG_STATUS#{status}
    # Else: query ADMIN_COMPLIANCE sk begins_with FLAG#


def run_compliance_scan() -> Dict[str, Any]:
    """Background task: scan all content with license references and update compliance status.
    Checks for expired licenses, revoked licenses, and expiring-soon warnings.
    Returns summary of issues found/updated.
    """
    # 1. Query GSI1 for COMPLIANCE_STATUS#compliant and COMPLIANCE_STATUS#expiring_soon
    # 2. For each, re-check license references
    # 3. Update status if changed
    # 4. Send alerts for new issues
    # Return {checked: N, issues_found: N, alerts_sent: N}


# --- Internal helpers ---

def _evaluate_license_ref(license_item, ts):
    """Evaluate a license reference and return status + issue type."""

def _upsert_license_ref(content_id, license_id, license_type, ref_status, ts):
    """Write/update LICENSE_REF# record."""

def _upsert_compliance_status(content_id, content_type, creator_id, status, issues, ts):
    """Write/update STATUS record."""

def _upsert_creator_index(creator_id, content_id, content_type, status, issue_count, ts):
    """Write/update CREATOR#{user_id}/COMPLIANCE#{content_id} index."""

def _enqueue_admin_issue(content_id, creator_id, status, issue_type, severity, ts):
    """Add to admin compliance queue."""

def _escalate_compliance_status(content_id, new_status, ts):
    """Update compliance status only if new status is more severe."""

def _get_compliance_status(content_id):
    """Get STATUS record for content."""

def _determine_compliance_status(issues, ts):
    """Determine overall compliance status from list of issues."""

def _issue_type_from_status(status):
    """Map compliance status to issue type string."""

def _severity_from_status(status):
    """Map compliance status to severity level."""
```

### 3.3 Backend Router

**New file**: `app/routers/license_compliance.py` (~280 lines)

```python
"""License compliance and verification router (LICENSE-006)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session, require_admin_session
from app.services import license_compliance as svc

router = APIRouter(prefix="/ui/licenses/compliance", tags=["license-compliance"])
admin_router = APIRouter(prefix="/ui/admin/licenses/compliance", tags=["license-compliance-admin"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/licenses/compliance/my-content` | `require_ui_session` | List creator's content compliance status |
| `GET` | `/ui/licenses/compliance/content/{content_id}` | `require_ui_session` | Get compliance detail for a content item |
| `GET` | `/ui/licenses/compliance/content/{content_id}/refs` | `require_ui_session` | List license references on content |
| `GET` | `/ui/licenses/compliance/content/{content_id}/flags` | `require_ui_session` | List flags on content |
| `POST` | `/ui/licenses/compliance/content/{content_id}/check` | `require_ui_session` | Trigger compliance check on content |
| `POST` | `/ui/licenses/compliance/flag` | `require_ui_session` | Flag content for potential licensing issue |
| `GET` | `/ui/admin/licenses/compliance/issues` | `require_admin_session` | Admin compliance issue queue |
| `GET` | `/ui/admin/licenses/compliance/flags` | `require_admin_session` | Admin flag queue |
| `POST` | `/ui/admin/licenses/compliance/flags/{flag_id}/resolve` | `require_admin_session` | Resolve a compliance flag |
| `POST` | `/ui/admin/licenses/compliance/content/{content_id}/status` | `require_admin_session` | Admin update compliance status |
| `POST` | `/ui/admin/licenses/compliance/scan` | `require_admin_session` | Trigger platform-wide compliance scan |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- License Compliance (LICENSE-006) --

class ComplianceFlagIn(BaseModel):
    content_id: str
    reason: str = Field(description="One of: unlicensed_music, unlicensed_video, unlicensed_image, expired_license, copyright_claim, other")
    evidence: str = Field(default="", max_length=2000)

class ComplianceFlagResolveIn(BaseModel):
    content_id: str
    resolution: str = Field(description="One of: resolved, dismissed, action_required")
    notes: str = Field(default="", max_length=1000)

class ComplianceStatusUpdateIn(BaseModel):
    new_status: str = Field(description="One of: compliant, under_review, action_required, removed, resolved")
    notes: str = Field(default="", max_length=1000)

class ComplianceStatusOut(BaseModel):
    content_id: str
    content_type: str = ""
    creator_id: str = ""
    compliance_status: str  # compliant, expiring_soon, license_expired, license_revoked, flagged, under_review, action_required, removed, resolved
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    last_checked_at: Optional[int] = None
    resolved_at: Optional[int] = None
    resolved_by: Optional[str] = None

class LicenseRefOut(BaseModel):
    license_id: str
    license_type: str  # agreement, issued
    license_status: str
    expires_at: Optional[int] = None
    verified_at: Optional[int] = None

class ComplianceFlagOut(BaseModel):
    flag_id: str
    content_id: str = ""
    reporter_id: str
    reporter_type: str = "viewer"
    reason: str
    evidence: str = ""
    status: str  # open, investigating, resolved, dismissed, action_required
    created_at: int = 0
    resolved_at: Optional[int] = None
    resolved_by: Optional[str] = None
    resolution_notes: str = ""

class ComplianceCheckResultOut(BaseModel):
    content_id: str
    compliance_status: str
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    checked_at: int = 0

class CreatorComplianceItemOut(BaseModel):
    content_id: str
    content_type: str = ""
    compliance_status: str
    issue_count: int = 0
    last_checked_at: Optional[int] = None

class ComplianceScanResultOut(BaseModel):
    checked: int = 0
    issues_found: int = 0
    alerts_sent: int = 0

class AdminComplianceIssueOut(BaseModel):
    content_id: str
    creator_id: str
    creator_display_name: str = ""
    compliance_status: str
    issue_type: str = ""
    severity: str = ""
    created_at: int = 0
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/licenses/CompliancePage.tsx` | Creator compliance overview | ~280 |
| `frontend/src/pages/licenses/ComplianceDetailDialog.tsx` | Content compliance detail with license refs and flags | ~180 |
| `frontend/src/pages/licenses/FlagContentDialog.tsx` | Dialog for flagging content | ~100 |
| `frontend/src/pages/licenses/AdminCompliancePage.tsx` | Admin compliance dashboard | ~300 |
| `frontend/src/pages/licenses/AdminFlagResolveDialog.tsx` | Admin flag resolution dialog | ~100 |
| `frontend/src/components/shared/ComplianceBadge.tsx` | Compliance status badge component | ~40 |
| `frontend/src/api/endpoints/license-compliance.ts` | API client wrappers | ~130 |

**Component tree**:

```
CompliancePage (Creator view)
├── Summary cards
│   ├── Total content items tracked
│   ├── Compliant count (green)
│   ├── Expiring soon count (yellow)
│   ├── Issues count (red)
│   └── Flags count (orange)
├── Filter: compliance status dropdown
├── DataTable: "My Content Compliance"
│   └── For each content item:
│       ├── Content title, type badge
│       ├── ComplianceBadge (color-coded status)
│       ├── Issue count
│       ├── Last checked date
│       ├── "Check Now" button (re-run compliance check)
│       └── "View Details" → ComplianceDetailDialog

ComplianceDetailDialog
├── Content info (title, type, creator)
├── Compliance status with ComplianceBadge
├── License References list
│   └── For each ref:
│       ├── License title/ID
│       ├── Type (agreement/issued)
│       ├── Status badge
│       └── Expiry date (red if expired, yellow if soon)
├── Compliance Flags list
│   └── For each flag:
│       ├── Reporter type + reason
│       ├── Evidence text
│       ├── Status badge
│       └── Resolution notes (if resolved)
└── Issues list with recommended actions

AdminCompliancePage
├── Tabs: "Issues" / "Flags"
├── Issues Tab
│   ├── Filter: status, severity, creator
│   └── DataTable
│       └── For each issue:
│           ├── Content title, creator name
│           ├── Compliance status badge
│           ├── Severity badge
│           ├── Date
│           └── Actions: "Review" → detail, "Resolve" → status update
├── Flags Tab
│   ├── Filter: status (open, investigating, resolved, dismissed)
│   └── DataTable
│       └── For each flag:
│           ├── Content title, reporter name
│           ├── Reason, evidence preview
│           ├── Status badge
│           └── Actions: "Resolve" → AdminFlagResolveDialog
└── "Run Compliance Scan" button (triggers background scan)

FlagContentDialog
├── Content ID (pre-filled if opened from content page)
├── Reason dropdown (unlicensed_music, unlicensed_video, etc.)
├── Evidence textarea (optional, up to 2000 chars)
└── "Submit Flag" button
```

### 3.7 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/licenses/compliance" element={<CompliancePage />} />
<Route path="/admin/license-compliance" element={<AdminCompliancePage />} />
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/license_compliance.py` | Compliance tracking service | ~500 |
| `app/routers/license_compliance.py` | REST API endpoints | ~280 |
| `frontend/src/pages/licenses/CompliancePage.tsx` | Creator compliance page | ~280 |
| `frontend/src/pages/licenses/ComplianceDetailDialog.tsx` | Detail dialog | ~180 |
| `frontend/src/pages/licenses/FlagContentDialog.tsx` | Flag dialog | ~100 |
| `frontend/src/pages/licenses/AdminCompliancePage.tsx` | Admin dashboard | ~300 |
| `frontend/src/pages/licenses/AdminFlagResolveDialog.tsx` | Flag resolution dialog | ~100 |
| `frontend/src/components/shared/ComplianceBadge.tsx` | Status badge | ~40 |
| `frontend/src/api/endpoints/license-compliance.ts` | API wrappers | ~130 |
| `frontend/e2e/license-compliance.spec.ts` | E2E tests | ~550 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `license_compliance_router` and `license_compliance_admin_router` |
| `app/models.py` | Add License Compliance Pydantic models |
| `app/core/settings.py` | Add `license_compliance_table_name` setting |
| `app/core/tables.py` | Add `T.license_compliance` table handle |
| `scripts/local-ddb-init.py` | Add `license_compliance` TableDef with 3 GSIs |
| `frontend/src/api/types.ts` | Add License Compliance TypeScript interfaces |
| `frontend/src/App.tsx` | Add compliance routes |

---

## 4. Compliance Checking Flow

### 4.1 Publish-Time Check

When content is published that declares use of licensed material:

1. Content creation endpoint calls `check_content_compliance(content_id, content_type, creator_id)`.
2. Service queries all license references (agreements from LICENSE-001, issued licenses from LICENSE-002).
3. Each reference is evaluated: active, expired, revoked, or expiring soon.
4. Overall compliance status is computed.
5. Status record is written/updated.
6. If issues found: warnings returned to frontend (but publish is NOT blocked -- see Compliance Philosophy below).

### 4.2 Background Scan

A periodic background task (triggered by admin or cron):

1. Queries GSI1 for content with `compliant` or `expiring_soon` status.
2. Re-evaluates each by checking current license statuses.
3. Updates compliance records that have changed.
4. Sends alerts for newly discovered issues.
5. Returns summary of scan results.

### 4.3 Flag-Triggered Check

When a compliance flag is created:

1. Flag record is written.
2. Content compliance status is escalated to `flagged` (if not already more severe).
3. Admin queue entry is created.
4. Content creator is notified.

### 4.4 Compliance Philosophy

- **Non-blocking**: Compliance issues generate warnings and queue admin review, but do NOT prevent content from being published or accessed. This avoids false-positive censorship.
- **Graduated severity**: Status progresses from `compliant` → `expiring_soon` → `license_expired` → `flagged` → `under_review` → `action_required` → `removed`. Each step requires explicit admin action.
- **Creator-first notifications**: Creators are notified at every step, giving them opportunity to renew licenses or address issues before admin action.
- **Flag accountability**: All flags include reporter identity and evidence, preventing anonymous abuse.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/license-compliance.spec.ts`

### Section 483: Compliance Check API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 483.1 | Compliance check on content with active license returns compliant | POST `/ui/licenses/compliance/content/{id}/check`; 200; `compliance_status=compliant`, empty issues |
| 483.2 | Compliance check on content with expired license returns license_expired | Set up content with expired agreement (LICENSE-001); check returns `compliance_status=license_expired`, issues array has entry |
| 483.3 | Creator compliance list shows content items | GET `/ui/licenses/compliance/my-content`; response includes content with compliance status |
| 483.4 | Content compliance detail returns license refs | GET `/ui/licenses/compliance/content/{id}/refs`; response includes license reference records |

### Section 484: Content Flagging API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 484.1 | Viewer flags content for unlicensed music | POST `/ui/licenses/compliance/flag`; 200; flag has `status=open`, `reason=unlicensed_music` |
| 484.2 | Creator flags content with evidence | POST with `reporter_type=creator`, evidence text; 200; evidence stored |
| 484.3 | Flagging updates content compliance status | GET compliance status for flagged content; `compliance_status` includes `flagged` |
| 484.4 | Invalid flag reason is rejected | POST with `reason=invalid_reason` → 400 |

### Section 485: Admin Compliance Management API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 485.1 | Admin sees compliance issues in queue | GET `/ui/admin/licenses/compliance/issues` (as root); response includes issues from previous tests |
| 485.2 | Admin sees open flags in flag queue | GET `/ui/admin/licenses/compliance/flags`; includes open flags |
| 485.3 | Admin resolves flag as dismissed | POST `/ui/admin/licenses/compliance/flags/{id}/resolve` with `resolution=dismissed`; flag status → `dismissed` |
| 485.4 | Admin updates content to action_required | POST `/ui/admin/licenses/compliance/content/{id}/status` with `new_status=action_required`; 200; creator notified |
| 485.5 | Non-admin cannot access admin compliance endpoints | Alice GET admin issues → 403 |

### Section 486: Compliance Scan & Notification API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 486.1 | Admin triggers compliance scan | POST `/ui/admin/licenses/compliance/scan` (as root); 200; returns `checked`, `issues_found`, `alerts_sent` counts |
| 486.2 | Compliance scan detects newly expired license | Create agreement with past expiry; run scan; content now shows `license_expired` |
| 486.3 | Flagging content twice creates two flag records | POST flag twice with different reasons; GET flags returns 2 entries |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| My compliance list | `require_ui_session` | Only own content |
| Content compliance detail | `require_ui_session` | Content owner or admin |
| Flag content | `require_ui_session` | Any authenticated user |
| Admin endpoints | `require_admin_session` | Platform admin or root only |
| Compliance scan | `require_admin_session` | Admin/root only (resource-intensive) |

### 6.2 Flag Abuse Prevention

- Flag reporters are identified (no anonymous flags).
- Rate limit: max 10 flags per user per hour.
- Repeated flags on the same content by the same reporter are rejected (1 flag per user per content item).
- Flag evidence is capped at 2000 characters.
- Admin can dismiss flags; patterns of dismissed flags from the same reporter may result in flag rate-limit reduction.

### 6.3 Compliance Status Protection

- Only admins can set content to `removed` status (prevents self-service censorship bypass).
- Compliance status updates are logged with admin identity and timestamp.
- Creators can trigger compliance re-checks on their own content but cannot change the status directly.

### 6.4 Rate Limiting

- Compliance check: max 20 per user per hour (re-checks are computationally non-trivial).
- Flag creation: max 10 per user per hour.
- Admin scan: max 1 per hour (platform-wide).

### 6.5 Data Privacy

- Flag reporters are not visible to the content creator (only to admins).
- Compliance status is visible to the content creator and admins only.
- Flag evidence may contain sensitive information; stored encrypted at rest (S3-level encryption).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| LICENSE-001 | Required | Agreement status for license reference validation |
| LICENSE-002 | Required | Issued license status for reference validation |
| LICENSE-003 | Optional | Revenue split freezing on compliance violations (future enhancement) |
| `app/services/content_reports_store.py` | Exists | Architectural reference for flag system |
| `app/services/alerts.py` | Exists | Notifications for compliance events |
| `app/services/profile.py` | Exists | Display names in admin views |
| `app/auth/deps.py` | Exists | `require_ui_session` for user auth |
| `app/auth/policy.py` | Exists | `require_admin_scope(AdminScope.CONTENT_MODERATION)` for admin auth (see policy.py:84) |
<!-- NOTE: require_admin_session does not exist. Use require_admin_scope from app/auth/policy.py instead -->
| `app/core/tables.py` | Exists (modify) | Add `T.license_compliance` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `license_compliance` table definition |

---

## 8. Acceptance Criteria

1. Compliance checks validate all license references on content and produce accurate status.
2. Content with expired licenses is flagged with `compliance_status=license_expired`.
3. Content with soon-to-expire licenses is flagged with `compliance_status=expiring_soon`.
4. Creators see their content compliance status in a dedicated compliance page.
5. Viewers and creators can flag content for potential licensing issues.
6. Flags create admin queue entries with reporter identity, reason, and evidence.
7. Admins can view compliance issues and flag queues with filtering and pagination.
8. Admins can resolve flags (dismiss/resolve/action_required) and update content compliance status.
9. Background compliance scan re-checks content and surfaces new issues.
10. All 16 E2E tests pass.

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/services/content_reports_store.py` | — | EXISTS: architectural reference for flag system |
| `app/services/dmca_content_operations.py` | — | EXISTS: DMCA takedown patterns |
| `app/services/alerts.py` | 355 | EXISTS: `write_alert()` function for notifications |
| `app/services/profile.py` | — | EXISTS: display name resolution |
| `app/services/billing_shared.py` | — | EXISTS: ledger entry patterns |
| `app/auth/deps.py` | — | EXISTS: `require_ui_session` for cookie/bearer auth |
| `app/auth/policy.py` | 84 | EXISTS: `require_admin_scope()` — correct admin auth pattern |
| `app/core/tables.py` | — | EXISTS: table handle registry (needs `T.license_compliance` added) |
| `scripts/local-ddb-init.py` | — | EXISTS: DDB table definitions (no `license_compliance` table yet) |
| `app/core/settings.py` | — | EXISTS: no `license_compliance_table_name` setting yet — must be added |
| `app/services/license_agreements.py` | — | DOES NOT EXIST: dependency from LICENSE-001, not yet implemented |
| `app/services/issued_licenses.py` | — | DOES NOT EXIST: dependency from LICENSE-002, not yet implemented |
| `app/services/content_moderation.py` | — | DOES NOT EXIST: moderation logic lives in `app/routers/moderation.py` and service files like `moderation_audit_log.py`, `moderation_policy_engine.py` |

---

## Testing Strategy

### Unit Tests (`tests/test_license_compliance.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_verify_license_active_on_publish` | Verify license active on publish |
| 2 | `test_flag_expired_license_content` | Flag expired license content |
| 3 | `test_creator_compliance_overview` | Creator compliance overview |
| 4 | `test_admin_compliance_dashboard` | Admin compliance dashboard |
| 5 | `test_resolve_compliance_issue` | Resolve compliance issue |
| 6 | `test_community_flag_creates_review` | Community flag creates review |
| 7 | `test_owner_flag_priority` | Owner flag priority |
| 8 | `test_expiry_notification_30_days` | Expiry notification 30 days |
| 9 | `test_revoked_license_flags_content` | Revoked license flags content |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/license-compliance.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~16 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `LICENSE_COMPLIANCE_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| LICENSE-001 | Agreement management for validity checks | Hard |
| LICENSE-002 | License Issuance for license status tracking | Hard |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Sequential -- requires LICENSE-001 and LICENSE-002 merged first. Compliance checks query agreement and license records.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: LICENSE_COMPLIANCE_ENABLED=true
- [ ] Service file created/modified: `app/services/license_compliance.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/license-compliance.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_license_compliance.py`
