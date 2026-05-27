# MOD-003: User Appeals System for Enforcement Actions

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Blocked by**: None (all required infrastructure exists)  
**Blocks**: MOD-007 (appeal analytics dashboard), TRUST-001 (trust & safety quality review)

---

## 1. Overview & Motivation

### The Gap

The moderation system has a complete enforcement pipeline: reports flow into moderation tickets (`app/services/moderation_tickets_store.py`), admins review and decide via the moderation board (`app/routers/admin_moderation.py`), and enforcement actions (warnings, bans) are recorded in the `UserEnforcementHistory` table and applied via the policy engine (`app/services/moderation_policy_engine.py`). Users receive alert notifications when actions are taken against them (`write_alert` with events like `moderation_warning`, `moderation_ban`, `moderation_content_removed`).

However, **there is no mechanism for users to challenge or appeal these enforcement decisions**. Once an admin issues a warning or ban, the user's only recourse is to contact support through the general helpdesk -- which has no structured appeal workflow, no link to the original enforcement action, and no SLA for review. The admin who receives the helpdesk ticket has no easy way to look up the original moderation context.

### Why This Is Needed

1. **Due process**: Users deserve a structured mechanism to contest enforcement actions they believe were applied in error. This is an industry standard practice for platforms with community guidelines.

2. **Error correction**: Moderation at scale inevitably produces false positives. A formal appeals channel with admin review reduces the lasting impact of incorrect decisions and builds user trust.

3. **Audit and accountability**: Every appeal and its outcome must be logged. This creates a complete record of moderation decisions from initial report through enforcement to appeal resolution -- essential for legal discovery and internal quality reviews.

4. **Rate-limited, anti-abuse**: Without a structured system, banned users flood the helpdesk with repeated support tickets. A formal appeals system enforces: one appeal per enforcement action, one pending appeal at a time, and automatic rejection of frivolous appeals.

5. **Workflow integration**: The appeal review should present the admin with the original moderation ticket, the enforcement action, the user's appeal text, and the user's overall enforcement history -- all in one view. This context is fragmented today.

### Architecture After This Change

```
User (Enforcement Recipient)        Backend                          DynamoDB
     |                                 |                                |
     |  [Receives moderation alert     |                                |
     |   with "Appeal" link]           |                                |
     |                                 |                                |
     |-- POST /appeals -------------->|                                |
     |   {enforcement_id,             |-- validate one-appeal-per-enf->|
     |    appeal_text}                |-- validate no pending appeal -->|
     |                                |-- put_item(appeal) ----------->|
     |                                |-- write_audit("appeal_filed")->|
     |                                |-- write_alert(admin) --------->|
     |<-- 201 {appeal_id, status} ----|                                |
     |                                |                                |
     |-- GET /appeals --------------->|                                |
     |<-- {items: [AppealOut]} -------|                                |
     |                                |                                |

Admin (Moderation)                  Backend                          DynamoDB
     |                                |                                |
     |-- GET /admin/appeals --------->|-- Query ByStatusCreatedAt ---->|
     |   ?status=submitted            |<-- Items[] -------------------|
     |<-- {items[], cursor} ----------|                                |
     |                                |                                |
     |-- GET /admin/appeals/{id} ---->|                                |
     |<-- {appeal, enforcement,       |                                |
     |     moderation_ticket,         |                                |
     |     user_history} -------------|                                |
     |                                |                                |
     |-- POST /admin/appeals/{id}/    |                                |
     |   decide --------------------->|                                |
     |   {decision: "upheld"}         |-- update_item(appeal) ------->|
     |                                |   status -> upheld             |
     |                                |-- write_audit("upheld") ------>|
     |                                |-- write_alert(user) ---------->|
     |<-- 200 {updated appeal} -------|                                |
     |                                |                                |
     |-- POST /admin/appeals/{id}/    |                                |
     |   decide --------------------->|                                |
     |   {decision: "reversed",       |-- update_item(appeal) ------->|
     |    reversal_note}              |   status -> reversed           |
     |                                |-- reverse_enforcement() ------>|
     |                                |   (lift ban / clear warning)   |
     |                                |-- write_audit("reversed") ---->|
     |                                |-- write_alert(user) ---------->|
     |<-- 200 {updated appeal} -------|                                |
```

---

## 2. Current State Analysis

### 2.1 Enforcement History Table (`scripts/local-ddb-init.py`, lines 424-440)

```
Table: UserEnforcementHistory
  PK: user_id (String)
  SK: enforcement_id (String) -- "enf_{uuid4().hex[:20]}"

  GSI ByStatusCreatedAt:
    PK: status    SK: created_at
  GSI BySourceTicketCreatedAt:
    PK: source_ticket_id    SK: created_at
```

Note: This table has no `attr_types` declaration, so both GSI sort keys (`created_at`) default to **String** type. The `created_at` value is stored as a string (passed as `now_ts: str` to `_persist_enforcement_if_needed`).

Enforcement records (from `app/routers/admin_moderation.py`, `_persist_enforcement_if_needed()` at lines 475-495; enforcement_id generated at line 482):
```python
{
    "user_id": offender_user_id,
    "enforcement_id": "enf_...",
    "entity_type": "user_enforcement",
    "status": "active" | "recorded",    # "active" for bans, "recorded" for warnings
    "enforcement_type": "warn" | "ban",
    "source_ticket_id": ticket_id,
    "created_at": now_ts,               # stored as string
    "created_by_admin_user_id": admin_sub,
    "note": note,
}
```

Note: `duration_days` is NOT currently stored in the enforcement record. Ban duration is only recorded in the `T.account_state` record (via `apply_ban()` in `moderation_policy_engine.py` at line 59). The appeals system will need to look up `T.account_state` for ban duration details.

The enforcement record links to the moderation ticket via `source_ticket_id`, but there is no field linking to an appeal. This ticket adds `appeal_id` and `appeal_status` fields.

### 2.2 Enforcement History Query (`app/routers/admin_moderation.py`, lines 388-413)

`_query_enforcement_history(user_id, *, limit)` (default `limit=25`) queries by `user_id` PK with `ScanIndexForward=False`, then sorts by `(created_at, enforcement_id)` descending in Python (line 412). Returns up to `limit` items. This function is used by the moderation ticket detail view (via `_prior_enforcement_history()` at line 416) to show prior enforcement history.

### 2.3 Ban Application (`app/services/moderation_policy_engine.py`, lines 59-110)

`apply_ban()` (keyword args: `offender_user_id`, `ticket_id`, `admin_user_id`, `note`, `duration_days`, `policy_category`) writes a ban record to `T.account_state` (PK=`user_sub`) via `put_item` (line 75) with:
- `user_sub`: offender's user ID
- `status`: `"banned"` (constant `BAN_STATUS` at line 10)
- `ban_duration_days`: days (0 = permanent; coerced via `_coerce_int` at line 72)
- `ban_started_at`: timestamp (`now_ts()`)
- `ban_until`: expiry timestamp (`ts + duration * 86400` if duration > 0, else `0`)

Also sends alert: `write_alert(event="moderation_ban")` (line 90).

`is_user_currently_banned()` (lines 113-126) checks `T.account_state` for active bans. Returns `False` if status is not `"banned"` or if `ban_until > 0 and now_ts() >= ban_until` (ban expired). An appeal reversal must clear this ban record.

### 2.4 Warning Notifications (`app/services/moderation_policy_engine.py`, lines 20-34)

`issue_warning_notification(*, offender_user_id, ticket_id, note, policy_category)` sends an alert to the user with event `moderation_warning` via `write_alert()` (line 23). The alert `details` dict (lines 28-33) includes `ticket_id`, `action`, `policy_category`, and `note`. Currently there is no `enforcement_id` in the alert details -- this must be added so the frontend can link the notification to the appeal form. Similarly, `apply_ban()` (line 59) sends an alert with event `moderation_ban` whose `details` dict (lines 95-103) also lacks `enforcement_id`.

### 2.5 Alert System (`app/services/alerts.py`, line 261; file is 680 lines)

`write_alert(user_sub, *, event, outcome, title, details)` writes to `T.alerts`. The details dict is arbitrary JSON. Alerts are displayed in the frontend alerts page (`frontend/src/pages/alerts/`). The appeal link in enforcement alerts will reference the `enforcement_id` so the frontend can deep-link to `/appeals/new?enforcement_id=enf_xxx`.

### 2.6 Admin Moderation Router Pattern (`app/routers/admin_moderation.py`, 970 lines)

All admin moderation endpoints:
- Use `require_admin_scope(AdminScope.CONTENT_MODERATION)` dependency (line 36), with the router prefix `/v1/admin/moderation` (line 34)
- Follow RESTful patterns: GET for listing/detail, POST for actions
- Use cursor-based pagination with base64-encoded DynamoDB `LastEvaluatedKey`
- Return Pydantic response models
- Write audit log entries via `write_moderation_audit_event()`

The appeals admin router will follow this exact same pattern.

### 2.7 Moderation Ticket Detail (`app/routers/admin_moderation.py`, lines 606-633)

`get_moderation_ticket_detail()` (decorator at line 606, function def at line 607) returns a `ModerationTicketDetailOut` with:
- `ticket`: ticket metadata
- `content_snapshot`: the reported content
- `linked_reports`: all content reports linked to the ticket
- `offender_history_summary`: aggregate stats
- `prior_enforcement_history`: list of past enforcements

The appeal detail view will reference this same data, pulling the original moderation ticket and enforcement history to give the reviewing admin full context.

### 2.8 Account State Table

`T.account_state` stores ban records with PK=`user_sub` (see `app/core/tables.py` line 28 for field, line 101 for instantiation). Each user has at most one record (written via `put_item` in `apply_ban()`, which overwrites any existing record). An appeal reversal of a ban must update `status` to a non-banned value (e.g., `"unbanned_via_appeal"`). Checking `is_user_currently_banned()` (lines 113-126) already handles non-`"banned"` status values correctly (returns `False` at line 120-121), so updating the status is sufficient.

---

## 3. Technical Design

### 3.1 New DynamoDB Table: `Appeals`

```
Table: Appeals
  PK: appeal_id (String) -- "appeal_{uuid4().hex[:20]}"

Attributes:
  appeal_id                   String    PK
  entity_type                 String    "enforcement_appeal"
  user_id                     String    The user who filed the appeal
  enforcement_id              String    Reference to UserEnforcementHistory SK
  enforcement_type            String    "warn" | "ban" (copied for convenience)
  source_ticket_id            String    Original moderation ticket ID
  appeal_text                 String    User's explanation (5-5000 chars)
  status                      String    submitted | under_review | upheld |
                                        modified | reversed | withdrawn
  created_at                  Number    Unix timestamp
  updated_at                  Number    Unix timestamp
  assigned_admin_user_id      String    Admin reviewing the appeal (or "UNASSIGNED")
  decided_at                  Number    Timestamp of admin decision
  decided_by_admin_user_id    String    Admin who made the decision
  decision_note               String    Admin's explanation for the decision
  modified_enforcement_type   String    New enforcement type if modified (e.g., "warn" -> reduced)
  modified_duration_days      Number    New duration if modified

GSI ByStatusCreatedAt:
  PK: status        SK: created_at (N)
  -- Admin queue: list appeals by status (submitted = needs review)

GSI ByUserCreatedAt:
  PK: user_id       SK: created_at (N)
  -- User's own appeals list; also used for pending-appeal-at-a-time check

GSI ByEnforcementId:
  PK: enforcement_id    SK: created_at (N)
  -- One-appeal-per-enforcement check; also links appeal to enforcement

GSI ByAssignedAdminCreatedAt:
  PK: assigned_admin_user_id    SK: created_at (N)
  -- Admin workload: list appeals assigned to a specific admin
```

DDB init entry for `scripts/local-ddb-init.py`:
```python
TableDef(
    _resolve_table_name(S.appeals_table_name, "Appeals"),
    "appeal_id",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByUserCreatedAt", "partition_key": "user_id", "sort_key": "created_at"},
        {"index_name": "ByEnforcementId", "partition_key": "enforcement_id", "sort_key": "created_at"},
        {"index_name": "ByAssignedAdminCreatedAt", "partition_key": "assigned_admin_user_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

### 3.2 Appeal Status State Machine

```
  submitted ---------> withdrawn (user retracts)
      |
      v
  under_review
      |
      +---------> upheld    (enforcement stands, no change)
      |
      +---------> modified  (enforcement reduced, e.g., ban -> warning)
      |
      +---------> reversed  (enforcement fully reversed, ban lifted)
```

Valid transitions:
```python
_APPEAL_STATUS_TRANSITIONS = {
    "submitted": {"under_review", "withdrawn"},
    "under_review": {"upheld", "modified", "reversed"},
    "upheld": set(),      # terminal
    "modified": set(),    # terminal
    "reversed": set(),    # terminal
    "withdrawn": set(),   # terminal
}
```

### 3.3 Pydantic Models

```python
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# --- User-Facing Models ---

class AppealCreateIn(BaseModel):
    """User submits an appeal against an enforcement action.

    The enforcement_id must reference a real enforcement in the user's
    UserEnforcementHistory. The appeal_text is the user's explanation
    for why they believe the enforcement was applied in error.
    """

    enforcement_id: str = Field(
        min_length=1, max_length=128,
        description="The enforcement_id from the enforcement action being appealed",
    )
    appeal_text: str = Field(
        min_length=5, max_length=5000,
        description="User's explanation for why the enforcement should be reconsidered",
    )

    @field_validator("appeal_text")
    @classmethod
    def _sanitize_appeal_text(cls, v: str) -> str:
        """Strip HTML tags to prevent stored XSS in admin dashboard."""
        return re.sub(r"<[^>]+>", "", v)

    @field_validator("enforcement_id")
    @classmethod
    def _validate_enforcement_id(cls, v: str) -> str:
        """Ensure enforcement_id has the expected prefix."""
        if not v.startswith("enf_"):
            raise ValueError("enforcement_id must start with 'enf_'")
        return v


class AppealOut(BaseModel):
    """Public representation of an appeal, visible to the user who filed it."""

    appeal_id: str
    user_id: str
    enforcement_id: str
    enforcement_type: str
    source_ticket_id: str
    appeal_text: str
    status: str
    created_at: int
    updated_at: int
    decided_at: Optional[int] = None
    decision_note: Optional[str] = None
    modified_enforcement_type: Optional[str] = None
    modified_duration_days: Optional[int] = None


class AppealCreateOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str
    created_at: int


class AppealListOut(BaseModel):
    items: list[AppealOut]
    next_cursor: Optional[str] = None


class AppealWithdrawOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str


# --- Admin-Facing Models ---

class AppealDetailOut(BaseModel):
    """Full appeal context for admin review. Assembles data from multiple
    tables to give the reviewing admin a complete picture."""

    appeal: AppealOut
    enforcement_record: dict[str, Any] = Field(
        default_factory=dict,
        description="The original enforcement from UserEnforcementHistory",
    )
    moderation_ticket: dict[str, Any] = Field(
        default_factory=dict,
        description="The original moderation ticket that led to enforcement",
    )
    content_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of the content that was reported/removed",
    )
    user_enforcement_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="All enforcement actions against this user",
    )
    user_appeal_history: list[AppealOut] = Field(
        default_factory=list,
        description="All appeals filed by this user",
    )
    user_profile: dict[str, Any] = Field(
        default_factory=dict,
        description="User profile data (display_name, email, created_at)",
    )


class AppealDecisionIn(BaseModel):
    """Admin records a decision on an appeal."""

    decision: Literal["upheld", "modified", "reversed"] = Field(
        description="The appeal outcome",
    )
    decision_note: str = Field(
        default="", max_length=2000,
        description="Admin's explanation for the decision (shown to user)",
    )
    modified_enforcement_type: Optional[Literal["warn"]] = Field(
        default=None,
        description="Only applicable when decision='modified'. "
                    "Downgrade enforcement (e.g., ban -> warning).",
    )
    modified_duration_days: Optional[int] = Field(
        default=None, ge=1, le=3650,
        description="Only applicable when decision='modified' and modifying a ban. "
                    "New ban duration in days.",
    )

    @field_validator("decision_note")
    @classmethod
    def _sanitize_note(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)

    @model_validator(mode="after")
    def _validate_modification_fields(self) -> AppealDecisionIn:
        """Ensure modification fields are only set when decision is 'modified'."""
        if self.decision != "modified":
            if self.modified_enforcement_type is not None:
                raise ValueError("modified_enforcement_type only valid when decision='modified'")
            if self.modified_duration_days is not None:
                raise ValueError("modified_duration_days only valid when decision='modified'")
        return self


class AppealDecisionOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str
    decision: str
    decided_at: int
    enforcement_reversed: bool
    enforcement_modified: bool


class AppealClaimOut(BaseModel):
    ok: bool
    appeal_id: str
    assigned_admin_user_id: str


class AppealQueueStatsOut(BaseModel):
    total_submitted: int = Field(description="Appeals waiting for initial review")
    total_under_review: int = Field(description="Appeals claimed by an admin")
    oldest_submitted_age_minutes: int = Field(
        description="Age of the oldest submitted appeal in minutes"
    )
```

### 3.4 User-Facing Endpoint Specifications

#### `POST /v1/appeals`

Submit an appeal against an enforcement action.

**Auth**: `require_ui_session`  
**Request**: `AppealCreateIn`  
**Response**: `AppealCreateOut` (201)

**Validation**:
1. Look up enforcement record by `enforcement_id` from `UserEnforcementHistory` table. Verify it belongs to the authenticated user (`user_id` matches). Return 404 if not found or not the user's.
2. Check `ByEnforcementId` GSI: if any appeal exists for this `enforcement_id` that is not `withdrawn`, reject with 409 ("an appeal already exists for this enforcement action").
3. Check `ByUserCreatedAt` GSI: if the user has any appeal with `status in {"submitted", "under_review"}`, reject with 429 ("you already have a pending appeal -- please wait for it to be resolved before filing another").
4. Create appeal record with `status="submitted"`.
5. Write audit event: `action="appeal_filed"`.
6. Notify on-call moderation admins via `write_alert()`.

#### `GET /v1/appeals`

List the authenticated user's own appeals.

**Auth**: `require_ui_session`  
**Query params**: `status` (optional filter), `limit` (default=25, max=100), `cursor` (optional)  
**Response**: `AppealListOut`

Uses `ByUserCreatedAt` GSI with the authenticated user's ID.

#### `GET /v1/appeals/{appeal_id}`

Get a specific appeal (must belong to the authenticated user).

**Auth**: `require_ui_session`  
**Response**: `AppealOut`

#### `POST /v1/appeals/{appeal_id}/withdraw`

Withdraw a pending appeal. Only allowed when `status` is `submitted` or `under_review`.

**Auth**: `require_ui_session` (must be the appeal's user)  
**Response**: `AppealWithdrawOut`

### 3.5 Admin-Facing Endpoint Specifications

#### `GET /v1/admin/appeals`

List appeals with filters for admin review queue.

**Auth**: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
**Query params**:
- `status` (optional): filter by appeal status
- `assigned_admin` (optional): filter by assigned admin
- `limit` (default=25, max=100)
- `cursor` (optional)
**Response**: `AppealListOut`

Uses `ByStatusCreatedAt` GSI (default: `status="submitted"` for unreviewed appeals), or `ByAssignedAdminCreatedAt` if filtering by assignee.

#### `GET /v1/admin/appeals/{appeal_id}`

Full appeal detail with all related context.

**Auth**: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
**Response**: `AppealDetailOut`

Assembles:
1. The appeal record itself
2. The enforcement record from `UserEnforcementHistory` (by `enforcement_id`)
3. The original moderation ticket from `ModerationTickets` (by `source_ticket_id`)
4. Content snapshot of the originally reported content (reuses `_content_snapshot()` from `admin_moderation.py`)
5. The user's full enforcement history (reuses `_query_enforcement_history()`)
6. The user's appeal history (query `ByUserCreatedAt`)
7. The user's profile data

#### `POST /v1/admin/appeals/{appeal_id}/claim`

Admin claims an appeal for review (sets `assigned_admin_user_id` and transitions to `under_review`).

**Auth**: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
**Response**: `AppealClaimOut`

#### `POST /v1/admin/appeals/{appeal_id}/decide`

Admin records a decision on the appeal.

**Auth**: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
**Request**: `AppealDecisionIn`  
**Response**: `AppealDecisionOut`

**Decision logic**:

- **`upheld`**: Enforcement stands. Update appeal status to `upheld`. Notify user: "Your appeal has been reviewed and the original action has been upheld."

- **`modified`**: Enforcement is reduced. For example, a permanent ban downgraded to a 30-day ban, or a ban downgraded to a warning.
  - If `modified_enforcement_type="warn"` and original was `"ban"`: lift the ban from `T.account_state`, record a warning in `UserEnforcementHistory` with the modified parameters.
  - If `modified_duration_days` is set and original was a permanent ban: update `ban_until` to `ban_started_at + modified_duration_days * 86400`.
  - Update appeal status to `modified`. Notify user with new enforcement details.

- **`reversed`**: Enforcement fully reversed.
  - If enforcement was `"ban"`: delete or update `T.account_state` to lift the ban.
  - Update the enforcement record's `status` to `"reversed"`.
  - Update appeal status to `reversed`. Notify user: "Your appeal has been reviewed and the enforcement action has been reversed."

#### `GET /v1/admin/appeals/stats`

Queue statistics for the admin dashboard header.

**Auth**: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
**Response**: `AppealQueueStatsOut`

### 3.6 Enforcement Reversal Logic

New service function in `app/services/appeals_enforcement.py`:

```python
from __future__ import annotations

import logging
from typing import Any, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.moderation_audit_log import write_moderation_audit_event

logger = logging.getLogger(__name__)


def reverse_enforcement(
    *,
    enforcement_record: dict[str, Any],
    appeal_id: str,
    admin_user_id: str,
) -> None:
    """Fully reverse an enforcement action.

    This function:
    1. Updates the enforcement record status to 'reversed' with metadata
    2. If the enforcement was a ban, lifts the ban from account_state
    3. Writes an audit trail entry for the reversal

    Args:
        enforcement_record: The enforcement dict from UserEnforcementHistory.
        appeal_id: The appeal that triggered this reversal.
        admin_user_id: The admin who decided to reverse.
    """
    user_id = str(enforcement_record.get("user_id") or "")
    enforcement_type = str(enforcement_record.get("enforcement_type") or "")
    enforcement_id = str(enforcement_record.get("enforcement_id") or "")

    # 1. Update enforcement record status
    T.user_enforcement_history.update_item(
        Key={"user_id": user_id, "enforcement_id": enforcement_id},
        UpdateExpression="SET #status = :reversed, appeal_id = :appeal_id, "
                         "reversed_at = :ts, reversed_by = :admin",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":reversed": "reversed",
            ":appeal_id": appeal_id,
            ":ts": str(now_ts()),
            ":admin": admin_user_id,
        },
    )

    # 2. If ban: lift it from account_state
    if enforcement_type == "ban":
        _lift_ban(user_id, appeal_id, admin_user_id)

    # 3. Audit trail
    write_moderation_audit_event(
        action="enforcement_reversed_via_appeal",
        actor_user_id=admin_user_id,
        ticket_id=str(enforcement_record.get("source_ticket_id") or ""),
        target_user_id=user_id,
        metadata={
            "enforcement_id": enforcement_id,
            "appeal_id": appeal_id,
            "enforcement_type": enforcement_type,
        },
    )


def _lift_ban(user_id: str, appeal_id: str, admin_user_id: str) -> None:
    """Remove ban from account_state table.

    Updates the account_state record from 'banned' to 'unbanned_via_appeal'
    rather than deleting it, to preserve the history of the ban.

    This is a best-effort operation. If the ban has already expired
    naturally, the update still succeeds (idempotent).
    """
    try:
        item = T.account_state.get_item(Key={"user_sub": user_id}).get("Item") or {}
        if str(item.get("status") or "") == "banned":
            T.account_state.update_item(
                Key={"user_sub": user_id},
                UpdateExpression="SET #status = :unbanned, unban_reason = :reason, "
                                 "unban_appeal_id = :appeal, unban_by = :admin, "
                                 "unban_at = :ts",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":unbanned": "unbanned_via_appeal",
                    ":reason": f"Appeal {appeal_id} reversed",
                    ":appeal": appeal_id,
                    ":admin": admin_user_id,
                    ":ts": now_ts(),
                },
            )
    except Exception:
        logger.exception("Failed to lift ban for user %s via appeal %s", user_id, appeal_id)


def modify_enforcement(
    *,
    enforcement_record: dict[str, Any],
    appeal_id: str,
    admin_user_id: str,
    new_enforcement_type: str | None = None,
    new_duration_days: int | None = None,
) -> None:
    """Modify an enforcement action (reduce severity).

    Supports two modification modes:
    1. Downgrade type: ban -> warning (lifts ban, records modification)
    2. Reduce duration: permanent ban -> N-day ban (updates ban_until)

    Args:
        enforcement_record: The enforcement dict from UserEnforcementHistory.
        appeal_id: The appeal that triggered this modification.
        admin_user_id: The admin who decided to modify.
        new_enforcement_type: New type ('warn') if downgrading.
        new_duration_days: New ban duration if reducing a permanent ban.
    """
    user_id = str(enforcement_record.get("user_id") or "")
    enforcement_id = str(enforcement_record.get("enforcement_id") or "")
    original_type = str(enforcement_record.get("enforcement_type") or "")

    # Update enforcement record
    update_expr = "SET #status = :modified, appeal_id = :appeal_id, modified_at = :ts, modified_by = :admin"
    expr_values: dict[str, Any] = {
        ":modified": "modified",
        ":appeal_id": appeal_id,
        ":ts": str(now_ts()),
        ":admin": admin_user_id,
    }

    if new_enforcement_type:
        update_expr += ", enforcement_type = :new_type"
        expr_values[":new_type"] = new_enforcement_type

    if new_duration_days is not None:
        update_expr += ", duration_days = :new_duration"
        expr_values[":new_duration"] = new_duration_days

    T.user_enforcement_history.update_item(
        Key={"user_id": user_id, "enforcement_id": enforcement_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues=expr_values,
    )

    # If downgrading ban -> warning: lift the ban
    if original_type == "ban" and new_enforcement_type == "warn":
        _lift_ban(user_id, appeal_id, admin_user_id)
    # If modifying ban duration: update ban_until
    elif original_type == "ban" and new_duration_days is not None:
        _modify_ban_duration(user_id, new_duration_days)

    write_moderation_audit_event(
        action="enforcement_modified_via_appeal",
        actor_user_id=admin_user_id,
        ticket_id=str(enforcement_record.get("source_ticket_id") or ""),
        target_user_id=user_id,
        metadata={
            "enforcement_id": enforcement_id,
            "appeal_id": appeal_id,
            "original_type": original_type,
            "new_type": new_enforcement_type,
            "new_duration_days": new_duration_days,
        },
    )


def _modify_ban_duration(user_id: str, new_duration_days: int) -> None:
    """Update ban_until on existing ban record.

    Recalculates ban_until based on ban_started_at + new_duration_days.
    If ban_started_at is not set (shouldn't happen), defaults to now.
    """
    item = T.account_state.get_item(Key={"user_sub": user_id}).get("Item") or {}
    ban_started_at = int(str(item.get("ban_started_at") or 0))
    if ban_started_at <= 0:
        ban_started_at = now_ts()  # fallback
    new_until = ban_started_at + new_duration_days * 86400
    T.account_state.update_item(
        Key={"user_sub": user_id},
        UpdateExpression="SET ban_until = :until, ban_duration_days = :days, updated_at = :ts",
        ExpressionAttributeValues={
            ":until": new_until,
            ":days": new_duration_days,
            ":ts": now_ts(),
        },
    )
```

### 3.7 Rate Limiting

Two constraints to prevent abuse:

1. **One appeal per enforcement action**: Before creating an appeal, query `ByEnforcementId` GSI. If any non-withdrawn appeal exists, return 409.

2. **One pending appeal at a time**: Query `ByUserCreatedAt` GSI for the user. If any appeal has `status in {"submitted", "under_review"}`, return 429 with `Retry-After` header.

These are enforced at the service layer, not via DDB conditional writes, because the checks require GSI queries.

```python
def _check_one_appeal_per_enforcement(enforcement_id: str) -> None:
    """Verify no non-withdrawn appeal exists for this enforcement action."""
    resp = T.appeals.query(
        IndexName="ByEnforcementId",
        KeyConditionExpression=Key("enforcement_id").eq(enforcement_id),
        Limit=10,
    )
    for item in resp.get("Items", []):
        if str(item.get("status", "")) != "withdrawn":
            raise HTTPException(
                status_code=409,
                detail="an appeal already exists for this enforcement action",
            )


def _check_no_pending_appeal(user_id: str) -> None:
    """Verify user has no pending (submitted or under_review) appeal."""
    resp = T.appeals.query(
        IndexName="ByUserCreatedAt",
        KeyConditionExpression=Key("user_id").eq(user_id),
        ScanIndexForward=False,
        Limit=50,
    )
    for item in resp.get("Items", []):
        status = str(item.get("status", ""))
        if status in {"submitted", "under_review"}:
            raise HTTPException(
                status_code=429,
                detail="you already have a pending appeal -- please wait for it to be resolved before filing another",
                headers={"Retry-After": "3600"},
            )
```

### 3.8 Notification Design

| Event | Recipient | Alert Event | Outcome |
|-------|-----------|-------------|---------|
| Appeal filed | On-call admins | `moderation_appeal_filed` | `info` |
| Appeal upheld | User | `moderation_appeal_upheld` | `warning` |
| Appeal modified | User | `moderation_appeal_modified` | `info` |
| Appeal reversed | User | `moderation_appeal_reversed` | `success` |
| Appeal withdrawn | (none) | -- | -- |

The enforcement notification alerts (`moderation_warning`, `moderation_ban`) must be updated to include `enforcement_id` in their `details` dict, so the frontend can render an "Appeal this decision" link.

### 3.9 Error Handling

| Condition | HTTP Status | Detail |
|-----------|-------------|--------|
| Enforcement not found | 404 | `"enforcement action not found"` |
| Enforcement belongs to another user | 404 | `"enforcement action not found"` (do not leak existence) |
| Appeal already exists for this enforcement | 409 | `"an appeal already exists for this enforcement action"` |
| User has a pending appeal | 429 | `"you already have a pending appeal"` |
| Appeal not found | 404 | `"appeal not found"` |
| Appeal not in valid state for decision | 409 | `"appeal is not under review"` |
| Invalid modified_enforcement_type for non-ban | 400 | `"modified_enforcement_type only applicable when modifying a ban"` |
| Admin lacks content_moderation scope | 403 | `"admin scope not authorized"` |
| Withdraw non-pending appeal | 409 | `"appeal cannot be withdrawn in current state"` |
| Appeal text too short | 422 | Pydantic validation |

---

## 4. Implementation Plan

### Step 1: Add Table Definition and Settings

**File**: `scripts/local-ddb-init.py`  
Add `Appeals` table definition with 4 GSIs (after the `UserEnforcementHistory` table definition, closing paren at line 440; the next table `MessageArchiveChainHeads` starts at line 441).

**Line-by-line change description**:
- Insert after line 440 (end of `UserEnforcementHistory` TableDef)
- Add 12 lines: `TableDef(...)` with 4 GSIs
- Set `attr_types={"created_at": "N"}` to ensure numeric sort key type on all GSIs
- Note: `ByAssignedAdminCreatedAt` GSI has `assigned_admin_user_id` as PK; items without this field won't appear in the GSI (sparse index behavior is desired -- only claimed appeals appear)

**File**: `app/core/settings.py` (1117 lines total)  
Add setting (after line 543, in the moderation table names block which runs from lines 528-543; note: line 76 is `alerts_table_name`, not the moderation block):
```python
appeals_table_name: str = os.environ.get("DDB_APPEALS", "Appeals")
```

**File**: `app/core/tables.py` (155 lines total)  
Add to `Tables` dataclass (after `user_enforcement_history`, line 56):
```python
appeals: Any
```
Add to `T` instantiation (after `user_enforcement_history` at line 129):
```python
appeals=ddb.Table(S.appeals_table_name),
```

### Step 2: Create Service Layer

**New file**: `app/services/appeals.py` (~250 lines)

**Line-by-line change description**:
- Lines 1-15: Imports from `boto3.dynamodb.conditions`, `fastapi`, `app.core.tables`, `app.core.time`, `app.services.alerts`, `app.services.moderation_audit_log`
- Lines 17-25: `_check_one_appeal_per_enforcement()` -- GSI query + iterate items, raise 409 if non-withdrawn appeal exists
- Lines 27-40: `_check_no_pending_appeal()` -- GSI query + iterate items, raise 429 if submitted/under_review appeal exists
- Lines 42-95: `file_appeal()` -- look up enforcement record, verify ownership, run both checks, put_item, write audit, notify admins
- Lines 97-115: `list_user_appeals()` -- query ByUserCreatedAt GSI with optional status filter
- Lines 117-130: `get_appeal()` -- get_item + 404 check + ownership verification
- Lines 132-152: `withdraw_appeal()` -- validate ownership + status, update_item to withdrawn
- Lines 154-180: `list_appeals_admin()` -- query ByStatusCreatedAt or ByAssignedAdminCreatedAt GSI
- Lines 182-210: `claim_appeal()` -- conditional update_item with ConditionExpression for submitted status, set assigned_admin + under_review
- Lines 212-260: `decide_appeal()` -- validate under_review status, dispatch to enforcement reversal/modification, update appeal, write audit, notify user
- Lines 262-290: `get_appeal_detail()` -- assemble data from Appeals, UserEnforcementHistory, ModerationTickets, profile tables
- Lines 292-315: `get_appeal_queue_stats()` -- COUNT queries on ByStatusCreatedAt for submitted and under_review

Functions:
- `file_appeal(user_id: str, enforcement_id: str, appeal_text: str) -> dict` -- validates constraints, creates record, notifies admins
- `list_user_appeals(user_id: str, *, status: str | None, limit: int, cursor: dict | None) -> dict` -- user's own appeals
- `get_appeal(appeal_id: str) -> dict` -- get_item + 404
- `withdraw_appeal(appeal_id: str, user_id: str) -> dict` -- validates ownership + state, transitions to withdrawn
- `list_appeals_admin(*, status: str | None, assigned_admin: str | None, limit: int, cursor: dict | None) -> dict` -- admin queue
- `claim_appeal(appeal_id: str, admin_user_id: str) -> dict` -- sets assigned_admin + under_review
- `decide_appeal(appeal_id: str, inp: AppealDecisionIn, admin_user_id: str) -> dict` -- validates state, records decision, dispatches enforcement changes
- `get_appeal_detail(appeal_id: str) -> dict` -- assembles full context
- `get_appeal_queue_stats() -> dict` -- counts submitted + under_review

**New file**: `app/services/appeals_enforcement.py` (~150 lines)

Functions:
- `reverse_enforcement(enforcement_record, appeal_id, admin_user_id)` -- lifts ban, updates enforcement record
- `modify_enforcement(enforcement_record, appeal_id, admin_user_id, new_type, new_duration)` -- reduces enforcement
- `_lift_ban(user_id, appeal_id, admin_user_id)` -- updates account_state
- `_modify_ban_duration(user_id, new_duration_days)` -- updates ban_until

### Step 3: Update Enforcement Notifications

**File**: `app/services/moderation_policy_engine.py`

Update `issue_warning_notification()` (line 20) to accept a new `enforcement_id` parameter and include it in the alert `details` dict:
```python
# Line 28-33: add enforcement_id to details dict
details={
    "ticket_id": ticket_id,
    "enforcement_id": enforcement_id,  # NEW -- enables "Appeal" link in alert UI
    "action": "warn",
    "policy_category": str(policy_category or "unspecified"),
    "note": (note or "")[:500],
},
```

Update `apply_ban()` (line 59) to accept a new `enforcement_id` parameter and include it similarly:
```python
# Line 95-103: add enforcement_id to details dict  
details={
    "ticket_id": ticket_id,
    "enforcement_id": enforcement_id,  # NEW
    "action": "ban",
    ...
},
```

This requires passing `enforcement_id` through the call chain from `_persist_enforcement_if_needed()` in `admin_moderation.py` (function at line 475). The enforcement_id is generated at line 482 (`f"enf_{uuid.uuid4().hex[:20]}"`) and must be threaded to the notification calls. Currently, the function does not return the enforcement_id -- it must be modified to return it so the caller can pass it to `issue_warning_notification()` and `apply_ban()`.

### Step 4: Create Routers

**New file**: `app/routers/appeals.py` (~120 lines)  
User-facing endpoints: POST /appeals, GET /appeals, GET /appeals/{id}, POST /appeals/{id}/withdraw.

**Line-by-line change description**:
- Lines 1-10: Imports
- Lines 12-15: `router = APIRouter(prefix="/v1/appeals", tags=["appeals"])`
- Lines 17-40: `POST /` handler -- parse AppealCreateIn, extract user_id from session, call file_appeal(), return 201
- Lines 42-55: `GET /` handler -- parse query params, call list_user_appeals(), return AppealListOut
- Lines 57-70: `GET /{appeal_id}` handler -- call get_appeal(), verify ownership, return AppealOut
- Lines 72-90: `POST /{appeal_id}/withdraw` handler -- call withdraw_appeal(), return AppealWithdrawOut

**New file**: `app/routers/admin_appeals.py` (~180 lines)  
Admin endpoints: GET /admin/appeals, GET /admin/appeals/{id}, POST /admin/appeals/{id}/claim, POST /admin/appeals/{id}/decide, GET /admin/appeals/stats.

**Line-by-line change description**:
- Lines 1-15: Imports, router creation with prefix `/v1/admin/appeals`
- Lines 17-20: `require_appeal_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- Lines 22-45: `GET /` handler -- parse query params, call list_appeals_admin(), return AppealListOut
- Lines 47-65: `GET /stats` handler -- call get_appeal_queue_stats(), return AppealQueueStatsOut
- Lines 67-85: `GET /{appeal_id}` handler -- call get_appeal_detail(), return AppealDetailOut
- Lines 87-110: `POST /{appeal_id}/claim` handler -- call claim_appeal(), return AppealClaimOut
- Lines 112-150: `POST /{appeal_id}/decide` handler -- parse AppealDecisionIn, call decide_appeal(), return AppealDecisionOut

### Step 5: Register Routers in `app/main.py`

**File**: `app/main.py`

Add imports (after line 85, alongside the `admin_moderation_router` import; `app/main.py` is 620 lines total):
```python
from app.routers.appeals import router as appeals_router
from app.routers.admin_appeals import router as admin_appeals_router
```

Add registrations (after the `admin_moderation_router` registration at line 279):
```python
app.include_router(appeals_router)
app.include_router(admin_appeals_router)
```

### Step 6: Add Frontend API Endpoints

**New file**: `frontend/src/api/endpoints/appeals.ts` (~80 lines)

```typescript
import client from "../client";

export interface Appeal {
  appeal_id: string;
  user_id: string;
  enforcement_id: string;
  enforcement_type: string;
  source_ticket_id: string;
  appeal_text: string;
  status: string;
  created_at: number;
  updated_at: number;
  decided_at?: number;
  decision_note?: string;
  modified_enforcement_type?: string;
  modified_duration_days?: number;
}

export interface AppealDetail {
  appeal: Appeal;
  enforcement_record: Record<string, unknown>;
  moderation_ticket: Record<string, unknown>;
  content_snapshot: Record<string, unknown>;
  user_enforcement_history: Array<Record<string, unknown>>;
  user_appeal_history: Appeal[];
  user_profile: Record<string, unknown>;
}

export interface AppealDecisionResult {
  ok: boolean;
  appeal_id: string;
  status: string;
  decision: string;
  decided_at: number;
  enforcement_reversed: boolean;
  enforcement_modified: boolean;
}

export interface AppealQueueStats {
  total_submitted: number;
  total_under_review: number;
  oldest_submitted_age_minutes: number;
}

export async function submitAppeal(data: {
  enforcement_id: string;
  appeal_text: string;
}): Promise<{ ok: boolean; appeal_id: string; status: string }> {
  const resp = await client.post("/v1/appeals", data);
  return resp.data;
}

export async function listMyAppeals(params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}): Promise<{ items: Appeal[]; next_cursor?: string }> {
  const { data } = await client.get("/v1/appeals", { params });
  return data;
}

export async function getAppeal(appealId: string): Promise<Appeal> {
  const { data } = await client.get(`/v1/appeals/${appealId}`);
  return data;
}

export async function withdrawAppeal(
  appealId: string
): Promise<{ ok: boolean; appeal_id: string; status: string }> {
  const resp = await client.post(`/v1/appeals/${appealId}/withdraw`);
  return resp.data;
}

// Admin endpoints
export async function listAppealQueue(params?: {
  status?: string;
  assigned_admin?: string;
  limit?: number;
  cursor?: string;
}): Promise<{ items: Appeal[]; next_cursor?: string }> {
  const { data } = await client.get("/v1/admin/appeals", { params });
  return data;
}

export async function getAppealDetail(
  appealId: string
): Promise<AppealDetail> {
  const { data } = await client.get(`/v1/admin/appeals/${appealId}`);
  return data;
}

export async function claimAppeal(
  appealId: string
): Promise<{ ok: boolean; appeal_id: string; assigned_admin_user_id: string }> {
  const resp = await client.post(`/v1/admin/appeals/${appealId}/claim`);
  return resp.data;
}

export async function decideAppeal(appealId: string, data: {
  decision: "upheld" | "modified" | "reversed";
  decision_note?: string;
  modified_enforcement_type?: string;
  modified_duration_days?: number;
}): Promise<AppealDecisionResult> {
  const resp = await client.post(`/v1/admin/appeals/${appealId}/decide`, data);
  return resp.data;
}

export async function getAppealQueueStats(): Promise<AppealQueueStats> {
  const { data } = await client.get("/v1/admin/appeals/stats");
  return data;
}
```

### Step 7: Add Frontend Pages

**New file**: `frontend/src/pages/appeals/AppealFormPage.tsx` (~180 lines)  
Form for users to submit an appeal. Pre-populated with enforcement details from query param `?enforcement_id=enf_xxx`. Shows: enforcement type, date, admin note, textarea for appeal text.

**New file**: `frontend/src/pages/appeals/MyAppealsPage.tsx` (~150 lines)  
List of the user's appeals with status badges. Shows decision outcome for resolved appeals.

**New file**: `frontend/src/pages/admin/AppealReviewQueuePage.tsx` (~350 lines)  
Admin queue with:
- Stats header (total submitted, under review, oldest age)
- Paginated list of appeals with user info and enforcement summary
- Detail panel with full context (enforcement record, moderation ticket, content snapshot, user history)
- Decision buttons: Uphold, Modify, Reverse
- Modification dialog for entering new enforcement type/duration

### Step 8: Add Routes and Navigation

**File**: `frontend/src/App.tsx`  
Add routes:
```typescript
<Route path="/appeals/new" element={<AppealFormPage />} />
<Route path="/appeals" element={<MyAppealsPage />} />
<Route path="/admin/appeals" element={<AppealReviewQueuePage />} />
```

**File**: `frontend/src/components/layout/Sidebar.tsx`  
Add "My Appeals" link in the user section (visible when user has enforcement history).  
Add "Appeal Queue" link in the admin section with badge count.

### Step 9: Update Enforcement Alert Rendering

**File**: `frontend/src/pages/alerts/AlertsPage.tsx` (or equivalent alert rendering component)

For alerts with `event in {"moderation_warning", "moderation_ban"}`, render an "Appeal this decision" button that links to `/appeals/new?enforcement_id={details.enforcement_id}`.

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `scripts/local-ddb-init.py` | Modified (~15 lines) | ~15 |
| `app/core/settings.py` | Modified (1 line) | ~1 |
| `app/core/tables.py` | Modified (3 lines) | ~3 |
| `app/services/appeals.py` | **New** | ~250 |
| `app/services/appeals_enforcement.py` | **New** | ~150 |
| `app/services/moderation_policy_engine.py` | Modified (~10 lines) | ~10 |
| `app/routers/appeals.py` | **New** | ~120 |
| `app/routers/admin_appeals.py` | **New** | ~180 |
| `app/main.py` | Modified (4 lines) | ~4 |
| `frontend/src/api/endpoints/appeals.ts` | **New** | ~80 |
| `frontend/src/pages/appeals/AppealFormPage.tsx` | **New** | ~180 |
| `frontend/src/pages/appeals/MyAppealsPage.tsx` | **New** | ~150 |
| `frontend/src/pages/admin/AppealReviewQueuePage.tsx` | **New** | ~350 |
| `frontend/src/App.tsx` | Modified (~4 lines) | ~4 |
| `frontend/src/components/layout/Sidebar.tsx` | Modified (~10 lines) | ~10 |
| `frontend/e2e/user-appeals.spec.ts` | **New** | ~450 |
| **Total** | | **~1960** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_appeals.py`)

**New file**, ~300 lines. Tests the service layer using moto-mocked DynamoDB.

**Fixtures**:

```python
import pytest
from moto import mock_dynamodb
from app.core.tables import T
from app.core.time import now_ts
from app.services.appeals import (
    claim_appeal,
    decide_appeal,
    file_appeal,
    get_appeal,
    get_appeal_detail,
    get_appeal_queue_stats,
    list_appeals_admin,
    list_user_appeals,
    withdraw_appeal,
)
from app.services.moderation_policy_engine import apply_ban, is_user_currently_banned


@pytest.fixture
def appeals_tables(moto_ddb):
    """Create Appeals, UserEnforcementHistory, and account_state tables."""
    # Create Appeals table
    T.appeals.meta.client.create_table(
        TableName=T.appeals.name,
        KeySchema=[{"AttributeName": "appeal_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "appeal_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "enforcement_id", "AttributeType": "S"},
            {"AttributeName": "assigned_admin_user_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByEnforcementId",
                "KeySchema": [
                    {"AttributeName": "enforcement_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByAssignedAdminCreatedAt",
                "KeySchema": [
                    {"AttributeName": "assigned_admin_user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    yield


def _seed_enforcement(user_id: str, enforcement_type: str = "warn",
                      ticket_id: str = "ticket_001", duration_days: int = 0) -> str:
    """Helper to create an enforcement record in UserEnforcementHistory."""
    from uuid import uuid4
    enforcement_id = f"enf_{uuid4().hex[:20]}"
    T.user_enforcement_history.put_item(Item={
        "user_id": user_id,
        "enforcement_id": enforcement_id,
        "entity_type": "user_enforcement",
        "status": "active" if enforcement_type == "ban" else "recorded",
        "enforcement_type": enforcement_type,
        "source_ticket_id": ticket_id,
        "created_at": now_ts(),
        "created_by_admin_user_id": "admin_001",
        "note": "Test enforcement",
        "duration_days": duration_days,
    })
    return enforcement_id
```

**Test cases**:

1. **`test_file_appeal_success`** -- Create enforcement record for Alice, file appeal. Verify appeal record created with `status="submitted"`, correct `enforcement_id`, `user_id`, `appeal_text`.
   ```python
   def test_file_appeal_success(appeals_tables):
       """Verify basic appeal filing creates record with correct fields."""
       enf_id = _seed_enforcement("alice", "warn")
       result = file_appeal("alice", enf_id, "I believe this was a mistake")
       assert result["status"] == "submitted"
       assert result["enforcement_id"] == enf_id
       assert result["user_id"] == "alice"
       assert result["appeal_id"].startswith("appeal_")
   ```

2. **`test_file_appeal_enforcement_not_found`** -- File appeal with non-existent enforcement_id. Expect 404.

3. **`test_file_appeal_wrong_user`** -- Create enforcement for Alice, try to appeal as Bob. Expect 404.

4. **`test_file_appeal_duplicate_409`** -- File appeal, then file again for same enforcement. Expect 409 ("already exists").

5. **`test_file_appeal_pending_appeal_429`** -- File appeal for enforcement A. Before it's resolved, file appeal for enforcement B. Expect 429 ("pending appeal").

6. **`test_file_appeal_after_withdrawal_allowed`** -- File appeal, withdraw it, file again for same enforcement. Should succeed (withdrawn appeals don't block re-filing).

7. **`test_list_user_appeals`** -- Create 3 appeals for Alice. List them. Verify count and order (newest first).

8. **`test_list_user_appeals_with_status_filter`** -- Create appeals in different statuses. Filter by `status="submitted"`. Verify only matching appeals returned.

9. **`test_get_appeal_by_id`** -- Create appeal, get by ID. Verify all fields match.

10. **`test_get_appeal_wrong_user_404`** -- Create appeal as Alice, try to get as Bob. Expect 404.

11. **`test_withdraw_appeal_success`** -- File appeal, withdraw. Verify status="withdrawn".

12. **`test_withdraw_already_decided_409`** -- File appeal, admin upholds it, try to withdraw. Expect 409.

13. **`test_claim_appeal`** -- Admin claims a submitted appeal. Verify `status="under_review"`, `assigned_admin_user_id` set.
    ```python
    def test_claim_appeal(appeals_tables):
        """Verify admin claim transitions to under_review with assignment."""
        enf_id = _seed_enforcement("alice", "warn")
        appeal = file_appeal("alice", enf_id, "Test appeal text here")
        result = claim_appeal(appeal["appeal_id"], "admin_001")
        assert result["ok"] is True
        assert result["assigned_admin_user_id"] == "admin_001"
        # Verify the appeal record was updated
        record = get_appeal(appeal["appeal_id"])
        assert record["status"] == "under_review"
    ```

14. **`test_decide_appeal_upheld`** -- Admin upholds appeal. Verify `status="upheld"`, `decided_at` set, `decided_by_admin_user_id` set.

15. **`test_decide_appeal_reversed_ban`** -- Create ban enforcement, file appeal, admin reverses. Verify: appeal `status="reversed"`, enforcement record `status="reversed"`, ban lifted from `account_state` (`is_user_currently_banned()` returns False).

16. **`test_decide_appeal_reversed_warning`** -- Create warning enforcement, file appeal, admin reverses. Verify: appeal `status="reversed"`, enforcement record `status="reversed"`.

17. **`test_decide_appeal_modified_ban_to_warning`** -- Create ban, file appeal, admin modifies to warning. Verify: enforcement type changed to "warn", ban lifted.

18. **`test_decide_appeal_modified_ban_duration`** -- Create permanent ban, file appeal, admin modifies to 30-day ban. Verify: `ban_until` updated, `duration_days=30`.
    ```python
    def test_decide_appeal_modified_ban_duration(appeals_tables):
        """Verify modifying permanent ban to 30-day updates ban_until."""
        enf_id = _seed_enforcement("alice", "ban", duration_days=0)
        apply_ban(offender_user_id="alice", ticket_id="ticket_001",
                  admin_user_id="admin_001", note="Test", duration_days=0)
        assert is_user_currently_banned("alice") is True
        
        appeal = file_appeal("alice", enf_id, "Please reduce my ban")
        claim_appeal(appeal["appeal_id"], "admin_002")
        result = decide_appeal(
            appeal["appeal_id"],
            {"decision": "modified", "decision_note": "Reducing to 30 days",
             "modified_duration_days": 30},
            "admin_002",
        )
        assert result["enforcement_modified"] is True
        # Ban still active but with 30-day expiry
        assert is_user_currently_banned("alice") is True
        # Verify ban_until was updated
        item = T.account_state.get_item(Key={"user_sub": "alice"}).get("Item", {})
        assert int(str(item.get("ban_duration_days", 0))) == 30
    ```

19. **`test_decide_appeal_wrong_state_409`** -- Try to decide a submitted appeal (not yet under_review). Expect 409.

20. **`test_decide_appeal_already_decided_409`** -- Decide an appeal, try to decide again. Expect 409.

21. **`test_decide_appeal_writes_audit`** -- Decide appeal. Verify moderation audit log entry with `action="appeal_upheld"` (or `reversed`, `modified`).

22. **`test_decide_appeal_notifies_user`** -- Decide appeal. Verify user receives alert.

23. **`test_appeal_queue_stats`** -- Create 3 submitted and 2 under_review appeals. Verify stats: total_submitted=3, total_under_review=2.

24. **`test_appeal_detail_includes_context`** -- Create enforcement from a moderation ticket, file appeal. Get appeal detail. Verify: enforcement_record, moderation_ticket, user_enforcement_history all populated.

### 5.2 E2E Tests (`frontend/e2e/user-appeals.spec.ts`)

**New file**, ~450 lines.

**Setup (`beforeAll`)**:
- Seed sessions for Alice (user), Bob (user), Root (admin), Charlie (admin with content_moderation scope)
- Create a moderation ticket against Alice (report -> ticket -> resolve with warning enforcement)
- Record the `enforcement_id` for use in appeal tests

**Section 100: User Appeal Submission API (7 tests)**:

1. `Alice files appeal against warning` -- POST with enforcement_id and appeal_text. Verify 201.
2. `Appeal has status=submitted` -- GET the appeal, verify status.
3. `Duplicate appeal returns 409` -- file again for same enforcement.
4. `Appeal with wrong enforcement_id returns 404` -- non-existent ID.
5. `Bob cannot appeal Alice's enforcement` -- Bob tries to file appeal against Alice's enforcement. Expect 404.
6. `Alice lists her appeals` -- GET /appeals returns the filed appeal.
7. `Alice withdraws her appeal` -- POST /withdraw, verify status=withdrawn.

**Section 101: Admin Appeal Review API (8 tests)**:

1. `Root lists submitted appeals` -- GET /admin/appeals?status=submitted. Verify Alice's appeal appears.
2. `Root views appeal detail` -- GET /admin/appeals/{id}. Verify enforcement_record and moderation_ticket present.
3. `Root claims appeal` -- POST /claim. Verify status=under_review.
4. `Root upholds appeal` -- POST /decide with decision=upheld. Verify status=upheld.
5. `Alice receives upheld notification` -- Check Alice's alerts.
6. `Re-file appeal after upheld for new enforcement` -- Create new enforcement, file new appeal. Should work (different enforcement_id).
7. `Root reverses appeal on ban` -- Create ban enforcement, file appeal, root reverses. Verify ban lifted.
8. `Root modifies ban duration` -- Create permanent ban, file appeal, modify to 30 days. Verify ban_until updated.

**Section 102: Rate Limiting (4 tests)**:

1. `One appeal per enforcement` -- file appeal, try duplicate, verify 409.
2. `One pending appeal at a time` -- file appeal A, try filing appeal B for different enforcement. Verify 429.
3. `Can file new appeal after previous resolved` -- file, admin upholds, file new for different enforcement. Should work.
4. `Can re-file after withdrawal` -- file, withdraw, re-file for same enforcement. Should work.

**Section 103: Appeal Form UI (5 tests)**:

1. `Appeal form page renders` -- navigate to `/appeals/new?enforcement_id=enf_xxx`, verify form.
2. `Form shows enforcement details` -- verify enforcement type and date displayed.
3. `Submit appeal shows success` -- fill text, submit, verify success toast.
4. `My Appeals page lists appeals` -- navigate to `/appeals`, verify appeal card.
5. `Appeal status badge shows correctly` -- verify "Submitted" badge on the appeal card.

**Section 104: Admin Appeal Queue UI (5 tests)**:

1. `Queue page renders with stats header` -- navigate to `/admin/appeals`, verify stats badges.
2. `Appeal list shows user info and enforcement summary` -- verify card content.
3. `Claim button assigns appeal to admin` -- click Claim, verify assigned.
4. `Uphold button records decision` -- click Uphold, verify toast + status change.
5. `Reverse button with confirmation` -- click Reverse, confirm dialog, verify decision.

### 5.3 Edge Cases to Cover

1. **Appeal filed after ban expires**: User files appeal on a 7-day ban after 8 days have passed. The ban has already expired naturally. The appeal should still be processable (for the user's record), but reversal is a no-op since `is_user_currently_banned()` already returns False. The enforcement record's `status` should still be updated to `reversed` for historical accuracy.

2. **Concurrent claim by two admins**: Two admins try to claim the same appeal simultaneously. The DDB `update_item` with `ConditionExpression="#status = :submitted"` ensures only one succeeds. The second gets 409.

3. **Admin reverses, then new enforcement applied**: If an appeal reversal lifts a ban, and then the user commits another violation, a new enforcement action and new moderation ticket should be created independently. The reversed appeal should have no bearing on new enforcements.

4. **Appeal on a warning (no account_state impact)**: Warnings do not write to `account_state` -- they only exist in `UserEnforcementHistory` with `status="recorded"`. Reversing a warning simply updates the enforcement record to `status="reversed"`. No ban lifting is needed.

5. **Modified enforcement: ban downgraded to warning**: The ban record in `account_state` must be removed or updated. A new warning entry in `UserEnforcementHistory` is NOT created -- instead the existing enforcement record is updated with `enforcement_type="warn"` and `status="modified"`.

6. **User deletes account while appeal is pending**: The appeal record remains in DynamoDB (no cascade delete). Admin can still decide the appeal. Notifications to the deleted user silently fail (write_alert to non-existent user is a no-op in the current system).

7. **Multiple enforcements from same moderation ticket**: A ticket resolution can apply both content removal AND a ban (via the `ResolveModerationTicketIn` model). Each enforcement generates a separate `UserEnforcementHistory` entry. The user can appeal each independently.

8. **Appeal text moderation**: Users might include abusive language in their appeal text. The appeal text is not displayed to the original reporter -- only to admins. No content filtering is needed on the appeal text itself, but it should be length-limited (5-5000 chars).

### 5.4 Performance Notes

- **Appeal filing**: 3 DDB operations (enforcement lookup, pending check via GSI query, put_item). Expected p50: ~25ms.
- **Appeal listing (user)**: Single GSI query. Expected p50: ~10ms for 25 items.
- **Appeal detail (admin)**: 5-6 DDB operations (appeal + enforcement + ticket + content snapshot + enforcement history + user profile). Expected p50: ~60ms.
- **Appeal queue listing**: Single GSI query. Expected p50: ~10ms for 25 items.
- **Appeal decision (reversal)**: 4-5 DDB operations (appeal update + enforcement update + account_state update + audit write + alert). Expected p50: ~50ms.
- **Queue stats**: 2 GSI count queries (submitted + under_review). Expected p50: ~15ms.

---

## 6. Security Considerations

### 6.1 Admin Authentication and Authorization

All admin appeal endpoints require `require_admin_scope(AdminScope.CONTENT_MODERATION)` (from `app/auth/policy.py`, line 84), the same scope used by the moderation board (`app/routers/admin_moderation.py`, line 36). This ensures that only admins specifically authorized for content moderation can review appeals. ROOT users bypass scope checks entirely (policy.py line 94).

**Self-review prevention**: An admin should not decide an appeal if they were the admin who issued the original enforcement. This is enforced by comparing `appeal.decided_by_admin_user_id` with the enforcement record's `created_by_admin_user_id`. If they match, the endpoint returns 409 with "the original enforcement admin cannot decide this appeal." This prevents rubber-stamping of original decisions.

**Concurrent claim race condition**: The `claim_appeal()` function uses a DDB `ConditionExpression` to atomically check that the appeal is still in `submitted` status before transitioning to `under_review`:

```python
T.appeals.update_item(
    Key={"appeal_id": appeal_id},
    UpdateExpression="SET #status = :under_review, assigned_admin_user_id = :admin, updated_at = :ts",
    ConditionExpression="#status = :submitted",
    ExpressionAttributeNames={"#status": "status"},
    ExpressionAttributeValues={
        ":under_review": "under_review",
        ":submitted": "submitted",
        ":admin": admin_user_id,
        ":ts": now_ts(),
    },
)
```

If two admins call `claim_appeal()` simultaneously, only one succeeds -- the other receives a `ConditionalCheckFailedException` which the service layer converts to HTTP 409.

### 6.2 User Identity Verification

The `POST /v1/appeals` endpoint extracts the user identity from the `ui_access_token` JWT cookie (via `require_ui_session`). The enforcement record lookup verifies that `enforcement_record["user_id"]` matches the authenticated user's `user_sub`. This prevents users from appealing other users' enforcements.

The identity check uses equality on `user_id` field, not on the `user_sub` PK -- because the enforcement record's PK is `user_id` and the JWT's subject is `sub`. These should always match for the same user, but the code explicitly checks both to prevent subtle identity mismatches.

### 6.3 Input Sanitization

- **`appeal_text`**: Stripped of HTML tags via `@field_validator` to prevent stored XSS when rendered in the admin appeal detail view
- **`decision_note`**: Similarly sanitized -- this is shown to the user in the appeal outcome notification
- **`enforcement_id`**: Validated to start with `enf_` prefix to prevent injection of arbitrary DDB key values
- All text fields have `max_length` constraints to bound storage and prevent payload-based attacks

### 6.4 Audit Trail Integrity

Every appeal action writes an immutable audit record:
- `appeal_filed`: User submits appeal
- `appeal_claimed`: Admin claims appeal for review
- `appeal_upheld`: Admin upholds enforcement
- `appeal_modified`: Admin modifies enforcement
- `appeal_reversed`: Admin reverses enforcement (includes enforcement_id in metadata)
- `enforcement_reversed_via_appeal`: Separate audit entry for the enforcement record change
- `enforcement_modified_via_appeal`: Separate audit entry for enforcement modification

This dual-audit approach (one entry for the appeal decision, one for the enforcement change) ensures that both the appeal workflow and enforcement history have complete, independent audit trails.

### 6.5 Rate Limiting Abuse Vectors

| Vector | Mitigation |
|--------|------------|
| User submits appeal, withdraws, re-submits repeatedly to game the queue | Withdrawal is allowed, but re-filing queries the ByEnforcementId GSI for ANY prior appeal (including withdrawn). If 3+ withdrawn appeals exist for the same enforcement, the endpoint could reject with 429 (future enhancement). |
| User creates many enforcement actions (via moderation reports) to file many appeals | Appeals are tied to enforcements, which are admin-initiated. Users cannot create enforcement actions against themselves. |
| Banned user floods appeal endpoint | Rate limit POST /appeals to 5 per hour per user. Banned users can still authenticate (ban check is on specific actions, not auth). |

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

Add to `scripts/local-ddb-init.py` after the `UserEnforcementHistory` table definition (closing paren at line 440):

```python
TableDef(
    _resolve_table_name(S.appeals_table_name, "Appeals"),
    "appeal_id",
    gsi=[
        {
            "index_name": "ByStatusCreatedAt",
            "partition_key": "status",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByUserCreatedAt",
            "partition_key": "user_id",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByEnforcementId",
            "partition_key": "enforcement_id",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByAssignedAdminCreatedAt",
            "partition_key": "assigned_admin_user_id",
            "sort_key": "created_at",
        },
    ],
    attr_types={"created_at": "N"},
),
```

### 7.2 Feature Flag Rollout

```python
# app/core/settings.py
appeals_enabled: bool = os.environ.get("APPEALS_ENABLED", "0") not in ("0", "false", "False")
```

**Phase 1: Backend dark launch**
- Create Appeals table in production
- Deploy service layer and routers with `APPEALS_ENABLED=0`
- All endpoints return 404 when disabled

**Phase 2: Admin testing**
- Enable in staging: `APPEALS_ENABLED=1`
- QA creates test enforcements and appeals
- Verify enforcement reversal and ban lifting work correctly
- Verify audit trail completeness

**Phase 3: User-facing launch**
- Enable in production
- Update enforcement notification alerts to include "Appeal" link
- Add sidebar navigation links
- Monitor appeal submission rate and queue depth

### 7.3 Rollback Steps

1. Set `APPEALS_ENABLED=0` -- all endpoints return 404
2. Pending appeals remain in DDB (no data loss)
3. Users lose access to the appeal form but existing enforcement actions are unaffected
4. Appeals that were in-progress (under_review) can be resolved manually via DDB updates
5. The enforcement notification alert "Appeal" link leads to a 404 -- acceptable for temporary rollback

### 7.4 Enforcement Record Schema Update

The enforcement records in `UserEnforcementHistory` need two new optional fields:
- `appeal_id`: Set when an appeal is filed against this enforcement
- `appeal_status`: Mirrors the appeal's status (for quick enforcement-level queries)

These fields are added by the appeals service layer when it updates the enforcement record. No migration is needed -- DDB items without these fields simply have them as `undefined`.

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `appeals_submitted_per_day` | New appeals filed per day | > 50 (unusual volume) |
| `appeals_queue_depth_submitted` | Appeals in submitted status | > 20 (warning), > 50 (critical) |
| `appeals_queue_depth_under_review` | Appeals claimed but not decided | > 10 (stale reviews) |
| `appeals_oldest_submitted_age_hours` | Age of oldest unreviewed appeal | > 24h (SLA breach) |
| `appeals_reversal_rate` | Percentage of appeals resulting in reversal | > 20% (moderation quality issue) |
| `appeals_avg_review_time_hours` | Average time from filed to decided | > 48h (review backlog) |
| `appeals_withdrawal_rate` | Percentage of appeals withdrawn before review | > 30% (possible user confusion) |

### 8.2 SLA Tracking

| SLA | Target | Measurement |
|-----|--------|-------------|
| Appeal acknowledged (submitted) | Immediate | Appeal creation is synchronous |
| Appeal claimed for review | < 4 hours | `now - created_at` for submitted appeals |
| Appeal decided | < 24 hours | `decided_at - created_at` |
| User notified of outcome | < 1 minute after decision | Alert timestamp - decided_at |
| Ban lifted after reversal | < 1 second after decision | Synchronous in decide_appeal() |

### 8.3 Common Debugging Scenarios

**Scenario: User says "Appeal" link is missing from enforcement notification**
1. Check the enforcement alert in DDB (`T.alerts` with user's `user_sub`)
2. Look for `enforcement_id` in the alert's `details` dict
3. If missing: the enforcement was created before the Step 3 code change (adding `enforcement_id` to notification details). The user can still appeal by navigating directly to `/appeals/new` and entering the enforcement ID manually.

**Scenario: Appeal decision made but ban not lifted**
1. Check the appeal record: `status` should be `reversed`
2. Check the enforcement record: `status` should be `reversed`
3. Check `T.account_state` for the user: `status` should be `unbanned_via_appeal`
4. If account_state still shows `banned`: the `_lift_ban()` function failed silently. Check logs for exceptions. Manually update the record.

**Scenario: Two admins claiming the same appeal**
1. This is handled automatically by the `ConditionExpression` on the DDB update
2. The first claim succeeds; the second receives 409
3. If both admins see "Claim" succeed in the UI: this is a frontend race condition. The second admin's subsequent actions will fail with "appeal not assigned to you."

**Scenario: High reversal rate (>20%)**
1. Query the `ModerationAuditLog` for recent `enforcement_reversed_via_appeal` actions
2. Cross-reference with the original enforcement admins (`created_by_admin_user_id`)
3. Identify if specific admins are having their decisions reversed disproportionately
4. Schedule a quality review meeting with the moderation team

### 8.4 Escalation Procedures

| Situation | Action |
|-----------|--------|
| Appeal queue depth > 50 | Page on-call moderation lead. Consider auto-assigning appeals to available admins. |
| Appeal SLA breach (> 24h without decision) | Escalate to moderation manager. Appeal should be auto-assigned to senior moderator. |
| Appeal reversed a DMCA repeat infringer ban | Requires additional review by legal team (DMCA ban reversal has legal implications). |
| User files appeal on a system-generated enforcement (e.g., DMCA auto-ban) | Admin should review the underlying DMCA claims, not just the ban. Link to MOD-002 claim records via `source_ticket_id`. |

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Scenario | Requests/sec | DDB Operations/sec |
|----------|-------------|-------------------|
| Normal operations (5-10 appeals/day) | < 0.01 | < 0.1 |
| Appeal surge after mass moderation action | ~0.1 | ~0.5 |
| Admin review session (1 admin) | ~0.05 | ~0.3 |
| Stats endpoint (dashboard auto-refresh) | ~0.02 | ~0.04 |

### 9.2 DDB Capacity

On-demand mode is recommended for the `Appeals` table due to low and unpredictable traffic.

GSI capacity considerations:
- `ByStatusCreatedAt`: Low cardinality PK (6 status values). Most items will be in terminal states (upheld, reversed, withdrawn). Active partitions (submitted, under_review) will have few items.
- `ByUserCreatedAt`: Partition per user. Most users will have 0-2 appeals total.
- `ByEnforcementId`: Partition per enforcement. Almost always 1 appeal per enforcement.
- `ByAssignedAdminCreatedAt`: Partition per admin. Sparse index -- only populated for claimed appeals.

### 9.3 Appeal Detail Query Performance

The `get_appeal_detail()` function performs 5-6 DDB operations:

1. `T.appeals.get_item(Key={"appeal_id": appeal_id})` -- ~5ms
2. `T.user_enforcement_history.get_item(Key={"user_id": ..., "enforcement_id": ...})` -- ~5ms
3. `T.moderation_tickets.get_item(Key={"ticket_id": ...})` -- ~5ms
4. `_content_snapshot(content_type, content_id)` -- ~10ms (varies by content type)
5. `_query_enforcement_history(user_id, limit=10)` -- ~10ms
6. `T.profile.get_item(Key={"user_sub": user_id})` -- ~5ms

Total expected p50: ~40ms. Caching the enforcement and ticket records could reduce this to ~20ms for repeat views, but the low request rate makes caching unnecessary.

---

## 10. Dependency Analysis

### 10.1 Dependencies (This Ticket Requires)

| Dependency | Status | Impact |
|------------|--------|--------|
| UserEnforcementHistory table | Complete | Provides enforcement records to appeal against |
| Moderation policy engine | Complete | Provides `apply_ban()`, `is_user_currently_banned()` for reversal logic |
| Moderation audit log | Complete | Provides `write_moderation_audit_event()` for audit trail |
| Alert notification system | Complete | Provides `write_alert()` for user and admin notifications |
| Admin scope system | Complete | Provides `require_admin_scope(AdminScope.CONTENT_MODERATION)` |
| Account state table | Complete | Stores ban records that may need to be updated on reversal |

### 10.2 Dependents (Blocked by This Ticket)

| Dependent | Description |
|-----------|-------------|
| MOD-007: Appeal analytics dashboard | Needs appeal resolution data for quality metrics |
| TRUST-001: Trust & safety quality review | Needs appeal reversal rate data to identify moderation quality issues |
| MOD-002: DMCA takedown (partial) | DMCA repeat infringer bans may be appealed; the appeal admin needs context about DMCA claims |

### 10.3 Notification System Integration

The appeals system produces 4 notification types and modifies 2 existing notifications:

**New notifications**:
- `moderation_appeal_filed` -> on-call admins
- `moderation_appeal_upheld` -> user
- `moderation_appeal_modified` -> user
- `moderation_appeal_reversed` -> user

**Modified notifications** (add `enforcement_id` to details):
- `moderation_warning` (existing)
- `moderation_ban` (existing)

---

## 11. Acceptance Criteria

### 11.1 Functional Requirements

- [ ] User can file an appeal against any enforcement action in their history
- [ ] Appeal requires text explanation (5-5000 characters)
- [ ] Only one appeal per enforcement action (duplicate returns 409)
- [ ] Only one pending appeal at a time per user (second returns 429)
- [ ] User can withdraw a pending appeal
- [ ] User can list their own appeals with status filter
- [ ] Admin can list appeal queue with status and assignee filters
- [ ] Admin can claim an appeal for review (sets under_review + assigned admin)
- [ ] Admin can uphold, modify, or reverse an appeal
- [ ] Reversal of a ban lifts the ban from account_state
- [ ] Modification of a ban updates ban duration or downgrades to warning
- [ ] Every action writes an audit log entry
- [ ] User receives notification of appeal outcome
- [ ] Enforcement notification alerts include `enforcement_id` for appeal linking
- [ ] Appeal queue stats endpoint returns submitted count, under_review count, oldest age

### 11.2 Non-Functional Requirements

- [ ] Appeal filing responds in < 100ms p99
- [ ] Appeal detail responds in < 200ms p99
- [ ] Queue listing responds in < 100ms p99
- [ ] No XSS vectors in appeal text or decision notes
- [ ] Concurrent admin claims handled atomically (only one succeeds)

### 11.3 Testing Requirements

- [ ] 24 unit tests pass (service layer with moto-mocked DDB)
- [ ] 29 E2E tests pass (sections 100-104)
- [ ] Edge cases covered: expired ban appeal, concurrent claim, warning reversal, modification

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | Admin Message | User Message | Recovery |
|-------|-------------|------------|---------------|-------------|----------|
| Enforcement not found | 404 | `enforcement_not_found` | N/A | "The enforcement action was not found" | Verify enforcement ID |
| Enforcement belongs to another user | 404 | `enforcement_not_found` | N/A | "The enforcement action was not found" | N/A (prevents info leak) |
| Appeal already exists | 409 | `appeal_exists` | N/A | "An appeal has already been filed for this enforcement" | View existing appeal |
| Pending appeal limit | 429 | `pending_appeal` | N/A | "You already have a pending appeal" | Wait for current appeal |
| Appeal not found | 404 | `appeal_not_found` | "Appeal not found" | "Appeal not found" | Verify appeal ID |
| Appeal not under_review | 409 | `invalid_state` | "Appeal must be under review to decide" | N/A | Admin claims first |
| Modified fields on non-modified decision | 400 | `invalid_modification` | "Modification fields only valid when decision is 'modified'" | N/A | Remove extra fields |
| Admin lacks scope | 403 | `role_required_scope` | "Content moderation scope required" | N/A | Contact root admin |
| Withdraw non-pending appeal | 409 | `invalid_state` | N/A | "Appeal cannot be withdrawn" | N/A |
| Appeal text too short | 422 | `validation_error` | N/A | "Appeal text must be at least 5 characters" | Enter longer text |
| Appeal text too long | 422 | `validation_error` | N/A | "Appeal text must be at most 5000 characters" | Shorten text |
| Concurrent claim race | 409 | `already_claimed` | "This appeal was claimed by another admin" | N/A | Refresh queue |
| Self-review (same admin) | 409 | `self_review_prohibited` | "You cannot decide an appeal for your own enforcement action" | N/A | Assign to different admin |
| DDB conditional check failed | 409 | `conflict` | "The appeal state changed since you loaded it" | N/A | Refresh and retry |

---

## 13. Frontend Component Specifications

### 13.1 AppealFormPage Layout

```
+---------------------------------------------------------------+
| Appeal Enforcement Action                                      |
+---------------------------------------------------------------+
| --- Original Enforcement ---                                   |
| Type: Warning                                                  |
| Date: 2026-05-20 14:23 UTC                                    |
| Admin note: "Inappropriate language in post #1234"             |
| Related ticket: MOD-TKT-789                                   |
|                                                                |
| --- Your Appeal ---                                            |
| Please explain why you believe this enforcement was applied    |
| in error. Be specific and provide any relevant context.        |
|                                                                |
| +------------------------------------------------------------+ |
| | [textarea, 5-5000 chars]                                   | |
| |                                                            | |
| | "I believe this was taken out of context. The comment      | |
| |  was part of a larger discussion about..."                 | |
| |                                                            | |
| +------------------------------------------------------------+ |
| 127 / 5000 characters                                         |
|                                                                |
| Note: You may only have one pending appeal at a time.         |
| Your appeal will be reviewed by a moderation team member.      |
|                                                                |
|                     [Cancel]  [Submit Appeal]                  |
+---------------------------------------------------------------+
```

### 13.2 MyAppealsPage Layout

```
+---------------------------------------------------------------+
| My Appeals                                                     |
+---------------------------------------------------------------+
| Filter: [All v]                                                |
+---------------------------------------------------------------+
| Appeal #1                                    [Submitted]       |
| Against: Warning (2026-05-20)                                  |
| Filed: 2026-05-21                                              |
| "I believe this was taken out of context..."                   |
|                                              [Withdraw]        |
+---------------------------------------------------------------+
| Appeal #2                                    [Upheld]          |
| Against: 7-day Ban (2026-04-15)                                |
| Filed: 2026-04-16 | Decided: 2026-04-17                       |
| Decision: "The enforcement was appropriate given the severity  |
|  of the violation."                                            |
+---------------------------------------------------------------+
| Appeal #3                                    [Reversed]        |
| Against: Warning (2026-03-10)                                  |
| Filed: 2026-03-11 | Decided: 2026-03-12                       |
| Decision: "Upon review, the reported content did not violate   |
|  community guidelines."                                        |
+---------------------------------------------------------------+
```

### 13.3 Admin AppealReviewQueuePage Layout

```
+---------------------------------------------------------------+
| Appeal Review Queue                                            |
| [5 submitted] [2 under review] [Oldest: 3h ago]  [Refresh]   |
+---------------------------------------------------------------+
| Filter: [Status: submitted v] [Admin: All v] [Apply]          |
+---------------------------------------------------------------+
| appeal_a1b2  | @alice | Warning | Filed 3h ago   | [Claim]   |
| appeal_c3d4  | @bob   | Ban(7d) | Filed 1h ago   | [Claim]   |
| appeal_e5f6  | @carol | Ban(30d)| Filed 30m ago  | [Claim]   |
+---------------------------------------------------------------+
|                     [Load More]                                |
+---------------------------------------------------------------+

Appeal Detail Panel (when appeal is selected):
+----------------------------------------------+
| Appeal: appeal_a1b2c3                        |
| User: @alice (alice@test.local)              |
| Status: under_review (assigned to @admin1)   |
+----------------------------------------------+
| --- User's Appeal Text ---                   |
| "I believe this warning was issued in error. |
|  The comment was part of a discussion..."    |
+----------------------------------------------+
| --- Original Enforcement ---                 |
| Type: Warning                                |
| Date: 2026-05-20 14:23 UTC                  |
| Admin: @moderator1                           |
| Note: "Inappropriate language"               |
| Ticket: MOD-TKT-789                         |
+----------------------------------------------+
| --- User Enforcement History ---             |
| 1 warning, 0 bans (all time)                |
| 0 prior appeals                              |
+----------------------------------------------+
|                                              |
| [Uphold]  [Modify]  [Reverse]               |
+----------------------------------------------+
```

### 13.4 TypeScript Component Interfaces

```typescript
interface AppealFormPageProps {}

interface MyAppealsPageProps {}

interface AppealReviewQueuePageProps {}

interface AppealCardProps {
  appeal: Appeal;
  showActions?: boolean;
  onWithdraw?: (appealId: string) => void;
}

interface AppealDetailPanelProps {
  appealId: string;
  onClaim: (appealId: string) => void;
  onDecide: (appealId: string, decision: AppealDecisionIn) => void;
  onClose: () => void;
}

interface AppealDecisionDialogProps {
  open: boolean;
  appealId: string;
  enforcementType: string;
  onConfirm: (decision: AppealDecisionIn) => void;
  onCancel: () => void;
}

interface ModifyEnforcementDialogProps {
  open: boolean;
  originalType: "warn" | "ban";
  originalDurationDays: number;
  onConfirm: (newType: string | null, newDuration: number | null, note: string) => void;
  onCancel: () => void;
}

interface AppealStatusBadgeProps {
  status: string;
}

interface AppealQueueStatsHeaderProps {
  stats: AppealQueueStats;
}
```

### 13.5 Keyboard Shortcuts for Admin Review

| Shortcut | Action |
|----------|--------|
| `c` | Claim current appeal |
| `u` | Uphold (opens confirmation) |
| `m` | Modify (opens modification dialog) |
| `r` | Reverse (opens confirmation) |
| `j` / `Arrow Down` | Next appeal in queue |
| `k` / `Arrow Up` | Previous appeal in queue |
| `Enter` | Open detail panel |
| `Escape` | Close detail panel or dialog |

### 13.6 Accessibility

- Status badges use both color and text ("Submitted" in blue, "Upheld" in red, "Reversed" in green)
- Appeal detail panel is a focus trap when open (Tab cycles within panel)
- Decision confirmation dialogs use `role="alertdialog"` with `aria-describedby` for the decision text
- Queue stats header uses `aria-live="polite"` to announce count changes on refresh
- All action buttons have descriptive `aria-label` (e.g., "Claim appeal from alice for warning enforcement")

---

## 14. Workflow Diagrams

### 14.1 Complete Appeal State Machine with Guard Conditions

```
         +----------+
         | submitted|-------------------+
         +----+-----+                   |
              |                         |
    [admin: claim_appeal()]        [user: withdraw_appeal()]
    [guard: status == submitted]   [guard: status in {submitted,
    [action: set assigned_admin]          under_review}]
    [action: write_audit                  |
     ("appeal_claimed")]                  v
              |                    +----------+
              v                    | withdrawn|
       +--------------+           +----------+
       | under_review |
       +------+-------+
              |
    +---------+---------+
    |         |         |
    v         v         v
+--------+ +--------+ +--------+
| upheld | |modified| |reversed|
+--------+ +--------+ +--------+
    |         |         |
    v         v         v
[notify     [update    [update
 user:       enf.       enf.
 "upheld"]   record     record
             + modify   + lift ban
             ban/warn]  (if ban)]
             [notify    [notify
              user:      user:
              "modified"] "reversed"]
```

Guard conditions:
- `submitted -> under_review`: Admin has `CONTENT_MODERATION` scope; appeal is not already claimed
- `under_review -> upheld/modified/reversed`: Admin is the assigned admin (or ROOT); appeal is `under_review`; admin is NOT the original enforcement admin (self-review prevention)
- `submitted/under_review -> withdrawn`: Authenticated user is the appeal's `user_id`; status is not terminal

### 14.2 Enforcement Reversal Sequence Diagram

```
Admin           Backend                UserEnforcement     AccountState      AuditLog
  |                |                       |                    |                |
  |-- POST decide  |                       |                    |                |
  |   (reversed) ->|                       |                    |                |
  |                |-- get appeal -------->|                    |                |
  |                |<-- appeal record -----|                    |                |
  |                |                       |                    |                |
  |                |-- verify under_review |                    |                |
  |                |   (ConditionExpr)     |                    |                |
  |                |                       |                    |                |
  |                |-- update appeal ----->|                    |                |
  |                |   status=reversed     |                    |                |
  |                |                       |                    |                |
  |                |-- get enforcement --->|                    |                |
  |                |<-- enf record --------|                    |                |
  |                |                       |                    |                |
  |                |-- update enf -------->|                    |                |
  |                |   status=reversed     |                    |                |
  |                |   appeal_id=xxx       |                    |                |
  |                |                       |                    |                |
  |                |-- [if ban] get ban -->|                    |                |
  |                |                       |                    |                |
  |                |-- [if ban] update ----|-------------------->|                |
  |                |   status=unbanned     |                    |                |
  |                |                       |                    |                |
  |                |-- write_audit --------|--------------------|--> put_item    |
  |                |   "reversed"          |                    |                |
  |                |                       |                    |                |
  |                |-- write_alert(user)   |                    |                |
  |                |                       |                    |                |
  |<-- 200 {ok} ---|                       |                    |                |
```

---

## 15. Abuse Prevention

### 15.1 Gaming the Appeals System

| Vector | Mitigation |
|--------|------------|
| Filing frivolous appeals to waste admin time | One pending appeal at a time (429 on second). Appeal text has 5-char minimum requiring some effort. |
| Repeatedly filing and withdrawing to trigger admin notifications | Each `appeal_filed` notification costs 1 DDB write. Track withdrawal count; after 3 withdrawals, suppress admin notifications. |
| Using appeals to harass the enforcement admin | The appeal does not identify the reviewing admin to the user. The user only sees the decision and note. Self-review prevention ensures a different admin reviews. |
| Coordinated appeal flooding (many users) | Monitor `appeals_submitted_per_day` metric. If >50/day, alert on-call team. Consider auto-upholding appeals that are substantively identical (future enhancement). |
| Appeal delay tactic (file appeal to delay new enforcement) | Pending appeal does NOT prevent new enforcement actions. If a user violates policy again while an appeal is pending, a new enforcement can be applied independently. |

### 15.2 Admin Abuse Vectors

| Vector | Mitigation |
|--------|------------|
| Admin rubber-stamps all appeals as "upheld" | Monitor `appeals_reversal_rate` per admin. If an admin upholds 100% of >20 appeals, flag for quality review. |
| Admin reverses enforcement for a friend | Audit trail records `decided_by_admin_user_id`. Self-review prevention blocks the original enforcement admin. Cross-reference reversal decisions with admin-user social connections (future). |
| Admin claims many appeals without deciding them | Monitor `appeals_queue_depth_under_review`. Alert if an admin has >5 claimed appeals without decisions after 24h. |
