# LICENSE-005: Syndicate Open Licensing

**Ticket**: LICENSE-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-005 adds an optional "open licensing" rule to syndicates, enabling automatic blanket license grants between all syndicate members. When a syndicate admin enables open licensing, every member automatically grants every other member a blanket license for content created during their membership. License terms (profit share, revenue share, fixed cost) are configured at the syndicate level and apply uniformly. When a member leaves the syndicate, licenses granted during their membership remain valid, but no new auto-licenses are created. This feature transforms syndicates from loose creator groups into fully collaborative content-sharing collectives.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Syndicate Admin | As a syndicate admin, I want to enable open licensing so that all members can freely use each other's content. | POST toggles `open_licensing_enabled=true` on syndicate; all members notified. |
| Syndicate Admin | As a syndicate admin, I want to set syndicate-level license terms so that all auto-licenses have consistent terms. | POST sets `open_licensing_terms` with profit_share_pct, fixed_cost_cents, revenue_share_pct. |
| Member | As a syndicate member, I want new content I create to be automatically licensed to other members. | On content creation (when syndicate open licensing is active), auto-license records are created for all current members. |
| Member | As a member, I want to see which of my content is auto-licensed to the syndicate. | GET returns list of auto-licensed content items with syndicate terms. |
| Member | As a member leaving a syndicate, I want my existing auto-licenses to remain valid. | After leaving, previously granted licenses retain `status=active`; no new auto-licenses for future content. |
| Syndicate Admin | As an admin, I want to disable open licensing so that no further auto-licenses are created. | POST sets `open_licensing_enabled=false`; existing auto-licenses remain; no new ones created. |
| Member | As a member, I want to opt out of auto-licensing for specific content items while staying in the syndicate. | POST exempts a content item from syndicate auto-licensing; the exempt content is not auto-licensed to other members. |
| System | When a new member joins a syndicate with open licensing, existing content by other members should be auto-licensed to the new member. | Auto-license records created for existing content when a new member is added. |

### 1.3 Why This Is Needed

Syndicate members (SYND-001) can pool audiences and share advertising (SYND-006), but content itself remains siloed. Open licensing removes friction: members don't need to individually request and approve licenses for every piece of content. Instead, the syndicate admin sets uniform terms, and the system handles license creation automatically. This is especially powerful for creator collectives producing complementary content -- a music producer, a videographer, and an editor can each freely use each other's work with fair, pre-agreed compensation.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `create_syndicate`, `list_members`, `leave_syndicate`, `_add_member`; membership lifecycle hooks for auto-licensing |
| Syndicates table | `scripts/local-ddb-init.py` (SYND-001) | `SYND#{id}/META` holds syndicate config; add `open_licensing_enabled` + `open_licensing_terms` fields |
| Issued licenses service | `app/services/issued_licenses.py` (LICENSE-002) | `issue_license` for creating auto-license records |
| Issued licenses table | `scripts/local-ddb-init.py` (LICENSE-002) | Storage for auto-license records with `license_mode=syndicate_auto` |
| License revenue | `app/services/license_revenue.py` (LICENSE-003) | Revenue splits apply to syndicate-auto-licensed content like any other license |
| Alerts service | `app/services/alerts.py` (~899 lines) | `write_alert` (line 355) for notifications |
| Profile service | `app/services/profile.py` (345 lines) | `get_profile` (line 220) for display names |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` (line 184) for all endpoints |

<!-- NOTE: app/services/syndicates.py (SYND-001) does NOT exist yet — SYND-001 is an unimplemented prerequisite. The syndicates table is not in scripts/local-ddb-init.py. -->
<!-- NOTE: app/services/issued_licenses.py (LICENSE-002) does NOT exist yet — LICENSE-002 prerequisite. -->
<!-- NOTE: app/services/license_revenue.py (LICENSE-003) does NOT exist yet — LICENSE-003 prerequisite. -->
<!-- NOTE: app/services/syndicate_licensing.py does NOT exist yet — new implementation required. -->

### 2.2 Gaps

1. **No open licensing concept** -- syndicates have no setting for enabling automatic content licensing between members.
2. **No syndicate-level license terms** -- no way to configure uniform license terms that apply to all auto-granted licenses.
3. **No `syndicate_auto` license mode** -- LICENSE-002 supports `per_user` and `blanket` but not syndicate-level auto-grants.
4. **No membership lifecycle hooks** -- syndicate join/leave events don't trigger any licensing actions.
5. **No content creation hook** -- publishing new content doesn't check for syndicate open licensing obligations.
6. **No exemption mechanism** -- no way for a member to opt out of auto-licensing for specific content.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 Syndicates Table -- New Fields on META Record

Add to existing `SYND#{syndicate_id}/META` record:

| Field | Type | Description |
|-------|------|-------------|
| `open_licensing_enabled` | `BOOL` | Whether auto-licensing is active |
| `open_licensing_terms` | `MAP` | `{profit_share_pct, fixed_cost_cents, revenue_share_pct, currency}` |
| `open_licensing_enabled_at` | `N` | Timestamp when open licensing was enabled |
| `open_licensing_disabled_at` | `N` | Timestamp when open licensing was disabled (null if active) |

#### 3.1.2 Syndicate Content Registry Table

**Table name**: `syndicate_content` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

Tracks which content is covered by syndicate open licensing.

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `SYND#{syndicate_id}` | `CONTENT#{content_id}` | Content registered under syndicate open licensing | `content_id`, `content_type`, `creator_id`, `registered_at`, `exempt` |
| `CREATOR_SYND#{user_id}` | `CONTENT#{content_id}` | Creator's content under syndicate licensing | `content_id`, `syndicate_id`, `content_type`, `registered_at` |
| `SYND#{syndicate_id}` | `EXEMPT#{content_id}` | Content exempted from auto-licensing | `content_id`, `creator_id`, `exempted_at` |

#### 3.1.3 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Lookup content by creator within a syndicate.
- `GSI1PK`: `SYND_CREATOR#{syndicate_id}#{user_id}`
- `GSI1SK`: `registered_at` (N)
- `attr_types={"GSI1SK": "N"}`

#### 3.1.4 TableDef Entry

```python
TableDef(
    "syndicate_content", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

#### 3.1.5 Auto-License Records in IssuedLicenses Table

Auto-licenses created by syndicate open licensing use the existing `issued_licenses` table with `license_mode=syndicate_auto`:

```json
{
  "pk": "CONTENT#vid_xyz789",
  "sk": "LICENSE#il_synd_abc123",
  "issued_license_id": "il_synd_abc123",
  "content_id": "vid_xyz789",
  "content_type": "video",
  "licensor_id": "alice@test.local",
  "licensee_id": "bob@test.local",
  "license_mode": "syndicate_auto",
  "status": "active",
  "syndicate_id": "synd_xyz",
  "profit_share_pct": 5,
  "fixed_cost_cents": 0,
  "revenue_share_pct": 3,
  "currency": "usd",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "expires_at": null
}
```

Key differences from regular licenses:
- `license_mode` is `syndicate_auto` (not `per_user` or `blanket`).
- `syndicate_id` field links back to the originating syndicate.
- Auto-licenses are NOT revoked when the member leaves (they persist).
- Auto-licenses ARE revoked if the content is exempted from syndicate licensing.

### 3.2 Backend Service

**New file**: `app/services/syndicate_licensing.py` (~450 lines)

```python
"""Syndicate open licensing -- auto-license management (LICENSE-005)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.syndicates import (
    get_syndicate, list_members, _require_admin, _require_is_member
)
from app.services.issued_licenses import issue_license
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)


def enable_open_licensing(
    *,
    syndicate_id: str,
    admin_sub: str,
    terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Enable open licensing on a syndicate. Admin only."""
    _require_admin(syndicate_id, admin_sub)
    _validate_terms(terms)

    ts = now_ts()
    meta = get_syndicate(syndicate_id)
    if not meta:
        raise ValueError("Syndicate not found")

    # Update META record with open licensing config
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET open_licensing_enabled = :e, open_licensing_terms = :t, "
                         "open_licensing_enabled_at = :ts, updated_at = :ts "
                         "REMOVE open_licensing_disabled_at",
        ExpressionAttributeValues={
            ":e": True,
            ":t": terms,
            ":ts": ts,
        },
    )

    # Notify all members
    members = list_members(syndicate_id)
    for m in members:
        if m["user_id"] != admin_sub:
            write_alert(m["user_id"], "syndicate_open_licensing_enabled", {
                "syndicate_id": syndicate_id,
                "syndicate_name": meta.get("name", ""),
                "terms": terms,
            })

    return {
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": True,
        "open_licensing_terms": terms,
        "enabled_at": ts,
    }


def disable_open_licensing(
    *,
    syndicate_id: str,
    admin_sub: str,
) -> Dict[str, Any]:
    """Disable open licensing. Existing auto-licenses remain active."""
    _require_admin(syndicate_id, admin_sub)

    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET open_licensing_enabled = :e, "
                         "open_licensing_disabled_at = :ts, updated_at = :ts",
        ExpressionAttributeValues={":e": False, ":ts": ts},
    )

    # Notify members
    members = list_members(syndicate_id)
    for m in members:
        if m["user_id"] != admin_sub:
            write_alert(m["user_id"], "syndicate_open_licensing_disabled", {
                "syndicate_id": syndicate_id,
            })

    return {"syndicate_id": syndicate_id, "open_licensing_enabled": False}


def update_open_licensing_terms(
    *,
    syndicate_id: str,
    admin_sub: str,
    terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Update syndicate-level license terms. Applies to future auto-licenses only."""
    _require_admin(syndicate_id, admin_sub)
    _validate_terms(terms)

    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
        UpdateExpression="SET open_licensing_terms = :t, updated_at = :ts",
        ExpressionAttributeValues={":t": terms, ":ts": ts},
    )
    return {"syndicate_id": syndicate_id, "open_licensing_terms": terms}


def register_content(
    *,
    syndicate_id: str,
    creator_sub: str,
    content_id: str,
    content_type: str,
) -> Dict[str, Any]:
    """Register content under syndicate open licensing.
    Called when a member publishes new content while open licensing is active.
    Creates auto-license records for all other current members.
    """
    _require_is_member(syndicate_id, creator_sub)
    meta = get_syndicate(syndicate_id)
    if not meta or not meta.get("open_licensing_enabled"):
        raise ValueError("Open licensing is not enabled for this syndicate")

    ts = now_ts()
    terms = meta.get("open_licensing_terms", {})

    # Register content
    content_item = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"CONTENT#{content_id}",
        "content_id": content_id,
        "content_type": content_type,
        "creator_id": creator_sub,
        "registered_at": ts,
        "exempt": False,
        "GSI1PK": f"SYND_CREATOR#{syndicate_id}#{creator_sub}",
        "GSI1SK": ts,
    }
    T.syndicate_content.put_item(Item=content_item)

    # Creator index
    creator_index = {
        "pk": f"CREATOR_SYND#{creator_sub}",
        "sk": f"CONTENT#{content_id}",
        "content_id": content_id,
        "syndicate_id": syndicate_id,
        "content_type": content_type,
        "registered_at": ts,
    }
    T.syndicate_content.put_item(Item=creator_index)

    # Create auto-licenses for all other members
    members = list_members(syndicate_id)
    licenses_created = []
    for m in members:
        if m["user_id"] == creator_sub:
            continue
        lic = _create_auto_license(
            content_id=content_id,
            content_type=content_type,
            licensor_id=creator_sub,
            licensee_id=m["user_id"],
            syndicate_id=syndicate_id,
            terms=terms,
            ts=ts,
        )
        licenses_created.append(lic)

    return {
        "content_id": content_id,
        "syndicate_id": syndicate_id,
        "licenses_created": len(licenses_created),
    }


def on_member_joined(
    *,
    syndicate_id: str,
    new_member_id: str,
) -> int:
    """Hook called when a new member joins a syndicate with open licensing.
    Creates auto-licenses for existing syndicate content to the new member.
    Returns count of auto-licenses created.
    """
    meta = get_syndicate(syndicate_id)
    if not meta or not meta.get("open_licensing_enabled"):
        return 0

    terms = meta.get("open_licensing_terms", {})
    ts = now_ts()

    # Query all content registered under this syndicate
    content_items = _list_syndicate_content(syndicate_id)
    count = 0
    for item in content_items:
        if item.get("exempt"):
            continue
        if item["creator_id"] == new_member_id:
            continue  # Don't license own content to self
        _create_auto_license(
            content_id=item["content_id"],
            content_type=item["content_type"],
            licensor_id=item["creator_id"],
            licensee_id=new_member_id,
            syndicate_id=syndicate_id,
            terms=terms,
            ts=ts,
        )
        count += 1
    return count


def on_member_left(
    *,
    syndicate_id: str,
    member_id: str,
) -> Dict[str, Any]:
    """Hook called when a member leaves a syndicate.
    Existing auto-licenses REMAIN active. No new auto-licenses will be created.
    Returns summary of licensing impact.
    """
    # No license revocation -- existing licenses persist
    # Just log the event for audit
    return {
        "syndicate_id": syndicate_id,
        "member_id": member_id,
        "action": "licenses_preserved",
    }


def exempt_content(
    *,
    syndicate_id: str,
    creator_sub: str,
    content_id: str,
) -> Dict[str, Any]:
    """Exempt a specific content item from syndicate auto-licensing.
    The creator must own the content. Existing auto-licenses for this content are revoked.
    """
    _require_is_member(syndicate_id, creator_sub)
    # Verify content is registered and owned by creator
    # Set exempt=True on content record
    # Write EXEMPT# record
    # Revoke existing syndicate_auto licenses for this content
    ts = now_ts()

    T.syndicate_content.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"},
        UpdateExpression="SET exempt = :e",
        ExpressionAttributeValues={":e": True},
        ConditionExpression="creator_id = :c",
        ExpressionAttributeValues={":e": True, ":c": creator_sub},
    )

    exempt_item = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"EXEMPT#{content_id}",
        "content_id": content_id,
        "creator_id": creator_sub,
        "exempted_at": ts,
    }
    T.syndicate_content.put_item(Item=exempt_item)

    # Revoke auto-licenses
    revoked_count = _revoke_auto_licenses_for_content(content_id, syndicate_id)
    return {"content_id": content_id, "revoked_count": revoked_count}


def remove_content_exemption(
    *,
    syndicate_id: str,
    creator_sub: str,
    content_id: str,
) -> Dict[str, Any]:
    """Remove exemption, re-enabling auto-licensing for this content."""
    # Verify ownership
    # Set exempt=False
    # Delete EXEMPT# record
    # Re-create auto-licenses for current members


def list_syndicate_content(
    *,
    syndicate_id: str,
    creator_id: Optional[str] = None,
    include_exempt: bool = False,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List content under syndicate open licensing."""


def get_open_licensing_config(
    *,
    syndicate_id: str,
) -> Dict[str, Any]:
    """Get open licensing configuration for a syndicate."""


# --- Internal helpers ---

def _create_auto_license(*, content_id, content_type, licensor_id, licensee_id,
                         syndicate_id, terms, ts):
    """Create a syndicate_auto license record."""

def _list_syndicate_content(syndicate_id):
    """Query all content registered under a syndicate."""

def _revoke_auto_licenses_for_content(content_id, syndicate_id):
    """Revoke all syndicate_auto licenses for a specific content item."""

def _validate_terms(terms):
    """Validate license terms dict."""
```

### 3.3 Backend Router

**New file**: `app/routers/syndicate_licensing.py` (~200 lines)

```python
"""Syndicate open licensing router (LICENSE-005)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import syndicate_licensing as svc

router = APIRouter(prefix="/ui/syndicates/{syndicate_id}/licensing", tags=["syndicate-licensing"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/syndicates/{syndicate_id}/licensing` | `require_ui_session` | Get open licensing configuration |
| `POST` | `/ui/syndicates/{syndicate_id}/licensing/enable` | `require_ui_session` | Enable open licensing (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/licensing/disable` | `require_ui_session` | Disable open licensing (admin only) |
| `PATCH` | `/ui/syndicates/{syndicate_id}/licensing/terms` | `require_ui_session` | Update syndicate-level terms (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/licensing/register` | `require_ui_session` | Register content under syndicate licensing |
| `GET` | `/ui/syndicates/{syndicate_id}/licensing/content` | `require_ui_session` | List syndicate-licensed content |
| `POST` | `/ui/syndicates/{syndicate_id}/licensing/exempt/{content_id}` | `require_ui_session` | Exempt content from auto-licensing |
| `DELETE` | `/ui/syndicates/{syndicate_id}/licensing/exempt/{content_id}` | `require_ui_session` | Remove content exemption |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Open Licensing (LICENSE-005) --

class SyndicateLicensingTermsIn(BaseModel):
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)
    currency: str = Field(default="usd", max_length=3)

class SyndicateLicensingEnableIn(BaseModel):
    terms: SyndicateLicensingTermsIn

class SyndicateContentRegisterIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")

class SyndicateLicensingConfigOut(BaseModel):
    syndicate_id: str
    open_licensing_enabled: bool = False
    open_licensing_terms: Optional[Dict[str, Any]] = None
    enabled_at: Optional[int] = None
    disabled_at: Optional[int] = None

class SyndicateContentOut(BaseModel):
    content_id: str
    content_type: str
    creator_id: str
    creator_display_name: str = ""
    registered_at: int = 0
    exempt: bool = False

class SyndicateContentRegistrationOut(BaseModel):
    content_id: str
    syndicate_id: str
    licenses_created: int = 0
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/OpenLicensingCard.tsx` | Open licensing config card on syndicate detail page | ~200 |
| `frontend/src/pages/syndicates/SyndicateContentList.tsx` | List of content under syndicate licensing | ~150 |
| `frontend/src/pages/syndicates/RegisterContentDialog.tsx` | Dialog to register content for syndicate licensing | ~100 |
| `frontend/src/api/endpoints/syndicate-licensing.ts` | API client wrappers | ~100 |

**Component tree** (embedded in existing `SyndicateDetailPage`):

```
SyndicateDetailPage (existing, from SYND-001)
├── ... existing tabs ...
└── New Tab: "Open Licensing"
    └── OpenLicensingCard
        ├── Toggle: "Enable Open Licensing" (admin only)
        ├── Terms configuration form (admin only, when enabled)
        │   ├── Profit share % slider
        │   ├── Fixed cost input
        │   └── Revenue share % slider
        ├── Status: "Active since {date}" or "Disabled"
        ├── RegisterContentDialog (Button: "Register Content")
        └── SyndicateContentList
            └── For each content item:
                ├── Content title, type badge, creator name
                ├── Registration date
                ├── Exempt badge (if exempted)
                ├── Auto-license count
                └── Actions: "Exempt" / "Remove Exemption" (content owner only)
```

### 3.7 Integration with Syndicate Lifecycle

#### 3.7.1 Membership Hooks

Add calls to `syndicate_licensing` hooks in `app/services/syndicates.py`:

| Event | Hook | Effect |
|-------|------|--------|
| Member joins (accept invite or approve request) | `on_member_joined(syndicate_id, new_member_id)` | Auto-licenses created for existing content to new member |
| Member leaves | `on_member_left(syndicate_id, member_id)` | Existing licenses preserved; logged for audit |
| Member removed by admin | `on_member_left(syndicate_id, member_id)` | Same as voluntary leave |

#### 3.7.2 Content Creation Hook

When content is published by a user who is a member of a syndicate with open licensing, the publish flow should call `register_content` automatically. This hook is added in the content creation endpoints:

| Endpoint | Change |
|----------|--------|
| `POST /ui/newsfeed/posts` | After creating post, check if creator is in a syndicate with open licensing; if so, call `register_content` |
| Video upload completion | Same check + register |
| Broadcast creation | Same check + register |

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_licensing.py` | Syndicate open licensing service | ~450 |
| `app/routers/syndicate_licensing.py` | REST API endpoints | ~200 |
| `frontend/src/pages/syndicates/OpenLicensingCard.tsx` | Licensing config card | ~200 |
| `frontend/src/pages/syndicates/SyndicateContentList.tsx` | Content list | ~150 |
| `frontend/src/pages/syndicates/RegisterContentDialog.tsx` | Register content dialog | ~100 |
| `frontend/src/api/endpoints/syndicate-licensing.ts` | API wrappers | ~100 |
| `frontend/e2e/syndicate-licensing.spec.ts` | E2E tests | ~500 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `syndicate_licensing_router` |
| `app/models.py` | Add Syndicate Licensing Pydantic models |
| `app/core/settings.py` | Add `syndicate_content_table_name` setting |
| `app/core/tables.py` | Add `T.syndicate_content` table handle |
| `scripts/local-ddb-init.py` | Add `syndicate_content` TableDef with GSI1 |
| `app/services/syndicates.py` | Add `on_member_joined` and `on_member_left` hooks |
| `frontend/src/api/types.ts` | Add Syndicate Licensing TypeScript interfaces |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Add "Open Licensing" tab |

---

## 4. Auto-License Lifecycle

### 4.1 License Creation Triggers

| Trigger | Who Gets Licensed | Terms Source |
|---------|-------------------|-------------|
| Content registered while open licensing is active | All current members (except content creator) | Syndicate's `open_licensing_terms` at registration time |
| New member joins syndicate with open licensing | New member gets licenses for all existing registered content | Syndicate's current `open_licensing_terms` |
| Open licensing enabled on existing syndicate | No automatic retroactive licensing; members must manually register existing content | N/A |

### 4.2 License Persistence After Leave

When a member leaves a syndicate:
1. All `syndicate_auto` licenses WHERE `licensor_id = leaving_member` remain `status=active`.
2. All `syndicate_auto` licenses WHERE `licensee_id = leaving_member` remain `status=active`.
3. No new auto-licenses will be created for content by the departed member.
4. Revenue sharing (LICENSE-003) continues to apply for existing active licenses.

### 4.3 License Revocation Triggers

Auto-licenses are only revoked in these cases:
1. Content is exempted from syndicate licensing (`exempt_content`).
2. Syndicate is dissolved (all auto-licenses for that syndicate are revoked).
3. Admin action (future consideration -- not in this ticket).

Open licensing being disabled does NOT revoke existing auto-licenses.

### 4.4 Edge Cases

- **Member joins then immediately leaves**: Auto-licenses created on join remain active.
- **Content registered then exempted then un-exempted**: Exemption revokes licenses; removing exemption re-creates them for current members.
- **Multiple syndicates with open licensing**: A creator in multiple syndicates registers content under each syndicate independently. Each produces separate auto-license records.
- **Syndicate terms updated after content registered**: Existing auto-licenses use the old terms (frozen at creation time). Only new registrations use updated terms.
- **Creator creates content while in two syndicates**: Content should be registered to each syndicate separately. The `register_content` endpoint is per-syndicate.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicate-licensing.spec.ts`

### Section 479: Enable/Disable Open Licensing API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 479.1 | Admin enables open licensing with terms | POST `/ui/syndicates/{id}/licensing/enable`; 200; `open_licensing_enabled=true`, terms match input |
| 479.2 | Non-admin cannot enable open licensing | Bob POST enable → 403 |
| 479.3 | Admin updates terms | PATCH `/ui/syndicates/{id}/licensing/terms`; 200; new terms reflected in GET config |
| 479.4 | Admin disables open licensing | POST disable; 200; `open_licensing_enabled=false`; existing licenses not revoked |

### Section 480: Content Registration & Auto-License API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 480.1 | Alice registers content under syndicate | POST `/ui/syndicates/{id}/licensing/register`; 200; `licenses_created` equals member_count - 1 |
| 480.2 | Bob sees auto-license in held licenses | GET `/ui/licenses/held` (as Bob); includes `license_mode=syndicate_auto` license for Alice's content |
| 480.3 | Syndicate content list includes registered content | GET `/ui/syndicates/{id}/licensing/content`; includes Alice's content |
| 480.4 | Registration fails when open licensing is disabled | Disable, then POST register → 400 |

### Section 481: Membership Lifecycle & Auto-Licensing API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 481.1 | New member receives auto-licenses for existing content | Charlie joins syndicate; GET held licenses (as Charlie); includes auto-licenses for existing content |
| 481.2 | Leaving member retains existing licenses | Bob leaves syndicate; GET held licenses (as Bob); auto-licenses still `status=active` |
| 481.3 | Content by departed member remains licensed to others | Bob left; Alice still has auto-license for Bob's content; check returns `has_license=true` |
| 481.4 | No new auto-licenses for departed member's future content | Alice registers new content after Bob left; Bob does NOT receive new auto-license |

### Section 482: Content Exemption API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 482.1 | Creator exempts content from auto-licensing | POST `/ui/syndicates/{id}/licensing/exempt/{content_id}`; 200; content marked exempt |
| 482.2 | Exempted content's auto-licenses are revoked | GET held licenses (as Bob); auto-license for exempt content has `status=revoked` or is absent |
| 482.3 | Non-owner cannot exempt content | Bob POST exempt on Alice's content → 403 |
| 482.4 | Remove exemption re-creates auto-licenses | DELETE exempt; 200; Bob's held licenses include re-created auto-license |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Enable / disable / update terms | `require_ui_session` | Syndicate admin only |
| Register content | `require_ui_session` | Syndicate member; must own the content |
| Exempt / un-exempt content | `require_ui_session` | Syndicate member; must own the content |
| List content, get config | `require_ui_session` | Syndicate member |

### 6.2 Authorization Enforcement

- Admin-only operations (enable/disable/terms) use `_require_admin` from syndicates service.
- Content registration validates membership via `_require_is_member`.
- Content exemption validates both membership AND content ownership.
- Auto-license creation validates that licensor != licensee (no self-licensing).

### 6.3 Rate Limiting

- Enable/disable: max 10 per syndicate per hour (prevent toggle spam).
- Content registration: max 100 per user per hour.
- Exemption: max 50 per user per hour.

### 6.4 Data Consistency

- Auto-license records include `syndicate_id` for traceability.
- Terms are frozen at creation time (stored on each auto-license record).
- Membership hooks are called synchronously within the join/leave transaction.
- Content exemption revokes licenses atomically (revoke all, then mark exempt).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate membership lifecycle; `_require_admin`, `_require_is_member`, `list_members` |
| LICENSE-002 | Required | `issue_license` for creating auto-license records; `issued_licenses` table |
| LICENSE-003 | Required (parallel) | Revenue sharing applies to syndicate auto-licenses |
| `app/services/syndicates.py` | Exists (modify) | Add `on_member_joined` and `on_member_left` hook calls |
| `app/services/alerts.py` | Exists | Notifications for enable/disable/join |
| `app/core/tables.py` | Exists (modify) | Add `T.syndicate_content` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `syndicate_content` table definition |
| LICENSE-006 | Not started | Compliance checks for syndicate auto-licensed content |

---

## 8. Acceptance Criteria

1. Syndicate admin can enable open licensing with configurable terms.
2. When content is registered under an open-licensing syndicate, auto-licenses are created for all current members.
3. When a new member joins, they receive auto-licenses for all existing registered content.
4. When a member leaves, their existing auto-licenses remain active.
5. Open licensing can be disabled; existing auto-licenses remain active.
6. Syndicate-level terms can be updated; updates apply only to future auto-licenses.
7. Creators can exempt specific content from auto-licensing; exemption revokes existing auto-licenses.
8. Auto-licenses integrate with LICENSE-003 revenue sharing.
9. All admin-only operations are properly access-controlled.
10. All 16 E2E tests pass.

---

## Codebase References

All file paths relative to the repository root.

### Existing Files Referenced (verified)
- `app/services/alerts.py` (899 lines) — `write_alert()` at line 355
- `app/services/profile.py` (345 lines) — `get_profile()` at line 220
- `app/auth/deps.py` — `require_ui_session` at line 184
- `scripts/local-ddb-init.py` — DynamoDB table definitions

### Dependencies Not Yet Implemented (all are prerequisites)
- `app/services/syndicates.py` — SYND-001 prerequisite (does not exist; syndicates table not in DDB init)
- `app/services/issued_licenses.py` — LICENSE-002 prerequisite (does not exist)
- `issued_licenses` DDB table — LICENSE-002 prerequisite (not in `scripts/local-ddb-init.py`)
- `app/services/license_revenue.py` — LICENSE-003 prerequisite (does not exist)

### Files to Create (none exist yet)
- `app/services/syndicate_licensing.py` — Syndicate open licensing service (~450 lines)
- `app/routers/syndicate_licensing.py` — REST API endpoints (~200 lines)
- Frontend pages for syndicate licensing settings and content registry
- `frontend/src/api/endpoints/syndicate-licensing.ts` — API wrappers
- `frontend/e2e/syndicate-licensing.spec.ts` — E2E tests

### Files to Modify (dependencies must be created first)
- `app/main.py` — Register syndicate licensing routers
- `app/models.py` — Add Syndicate Licensing Pydantic models
- `app/core/settings.py` — Add `syndicate_content_table_name` setting
- `app/core/tables.py` — Add `T.syndicate_content` table handle
- `scripts/local-ddb-init.py` — Add `syndicate_content` TableDef with 1 GSI
- `app/services/syndicates.py` (SYND-001, when created) — Add membership lifecycle hooks for auto-licensing
- `frontend/src/App.tsx` — Add syndicate licensing routes

---

## Testing Strategy

### Unit Tests (`tests/test_syndicate_licensing.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_enable_open_licensing` | Enable open licensing |
| 2 | `test_disable_open_licensing` | Disable open licensing |
| 3 | `test_set_syndicate_terms` | Set syndicate terms |
| 4 | `test_auto_license_on_content_create` | Auto license on content create |
| 5 | `test_new_member_gets_existing_licenses` | New member gets existing licenses |
| 6 | `test_leaving_member_keeps_licenses` | Leaving member keeps licenses |
| 7 | `test_exempt_content_from_auto_license` | Exempt content from auto license |
| 8 | `test_no_new_licenses_after_disable` | No new licenses after disable |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/syndicate-licensing.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~14 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `SYNDICATE_OPEN_LICENSING_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| LICENSE-002 | Content License Issuance for auto-license creation | Hard |
| LICENSE-003 | Revenue Sharing for syndicate-level terms | Soft |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Sequential -- requires LICENSE-002 merged first. Auto-licensing creates IssuedLicense records using LICENSE-002 infrastructure.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: SYNDICATE_OPEN_LICENSING_ENABLED=true
- [ ] Service file created/modified: `app/services/syndicate_licensing.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/syndicate-licensing.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_syndicate_licensing.py`
