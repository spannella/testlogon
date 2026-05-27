# MOD-002: DMCA Takedown Workflow

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 8-12 days  
**Blocked by**: None (all required infrastructure exists)  
**Blocks**: MOD-006 (automated copyright scanning), LEGAL-001 (designated agent registration)

---

## 1. Overview & Motivation

### The Gap

The platform has a mature content moderation system (`app/routers/admin_moderation.py`, 970 lines) that handles user-generated reports, ticket triage, content removal, and enforcement actions. However, this system is designed for **community-reported policy violations** (spam, harassment, etc.) and does not support the legally distinct **DMCA takedown process** required under 17 U.S.C. Section 512.

DMCA compliance requires a structured workflow with specific legal requirements: a rights holder must submit a sworn statement, the platform must promptly remove allegedly infringing content, the content creator must be notified and given the opportunity to file a counter-notice, and there is a mandatory 10-14 business day waiting period before content can be restored after a counter-notice. None of these steps exist in the current moderation pipeline.

### Why This Is Needed

1. **Legal compliance**: Section 512 safe harbor requires a designated DMCA agent, a process for receiving claims, expeditious removal of infringing material, a counter-notice procedure, and a repeat infringer policy. Without these, the platform risks losing safe harbor protection.

2. **Distinct from moderation**: DMCA claims are not moderation tickets. They have different lifecycles, different stakeholders (rights holder vs. community reporter), different timelines (mandatory waiting periods), and different outcomes (restoration vs. enforcement). Mixing them into the existing moderation ticket system would create confusion and legal risk.

3. **Repeat infringer tracking**: Section 512(i) requires a policy for terminating "repeat infringers." The platform must track which users have had content removed due to DMCA claims and enforce a strikes-based policy (commonly 3 strikes).

4. **Transparency and audit**: DMCA claims and counter-notices are legal instruments. Every state transition must be logged with timestamps for potential litigation. The existing `moderation_audit_log` provides the right pattern but needs DMCA-specific action types.

### Architecture After This Change

```
Rights Holder                  Backend                          DynamoDB
     |                            |                                |
     |-- POST /dmca/claims ------>|                                |
     |   {content_url, ...}       |-- put_item(claim) ----------->|
     |                            |-- hide_content() ------------>|
     |                            |-- notify_creator() ---------->|
     |                            |-- write_audit("claim_filed")->|
     |<-- 201 {claim_id} ---------|                                |
     |                            |                                |
                                                                   |
Creator                        Backend                          DynamoDB
     |                            |                                |
     |-- POST /dmca/claims/       |                                |
     |   {id}/counter-notice ---->|                                |
     |   {statement, ...}         |-- update_item(claim) -------->|
     |                            |   status -> counter_notice_filed
     |                            |-- notify_rights_holder() ---->|
     |                            |-- schedule_waiting_period() ->|
     |                            |-- write_audit("counter_filed")>|
     |<-- 200 {updated} ----------|                                |
     |                            |                                |
                                                                   |
Admin                          Backend                          DynamoDB
     |                            |                                |
     |-- GET /admin/dmca/claims ->|-- Query ByStatusCreatedAt --->|
     |<-- { items[], cursor } ----|<-- Items[] -------------------|
     |                            |                                |
     |-- POST /admin/dmca/claims/ |                                |
     |   {id}/resolve ----------->|                                |
     |   {resolution: "restored"} |-- update_item(claim) -------->|
     |                            |   status -> resolved           |
     |                            |-- restore_content() --------->|
     |                            |-- write_audit("resolved") --->|
     |<-- 200 {updated} ----------|                                |

         Waiting Period Timer (background loop)
     +-------------------------------------------------+
     | Every 1h: scan claims with                      |
     | status=waiting_period AND                       |
     | waiting_period_expires_at <= now                 |
     | -> auto-resolve: restore content                |
     +-------------------------------------------------+

         Repeat Infringer Check
     +-------------------------------------------------+
     | On each claim filed:                            |
     | Query ByTargetUserCreatedAt for creator         |
     | Count claims with status in                     |
     |   {content_removed, resolved, escalated}        |
     | If count >= STRIKE_THRESHOLD (3):               |
     |   -> apply_ban(permanent)                       |
     |   -> write_audit("repeat_infringer_ban")        |
     +-------------------------------------------------+
```

---

## 2. Current State Analysis

### 2.1 Content Removal Infrastructure (`app/services/moderation_content_removal.py`)

The existing removal system (222 lines) supports removing feed posts, comments, media, messages, and profile photos. Each content type has a dedicated `_mark_*_removed()` function that sets `moderation_removed=True` and related fields on the DynamoDB item. The `apply_content_removal()` dispatcher (lines 172-222) routes by `content_type`.

DMCA takedowns need to reuse this infrastructure but also support:
- **Videos**: The `_mark_*` functions do not cover `video_metadata` items. A new `_mark_video_removed()` function is needed that transitions the video to a `dmca_removed` status (or sets a `dmca_hidden=True` flag while preserving the current status for potential restoration).
- **Restoration**: Current removal is one-way. DMCA counter-notices require content restoration after the waiting period. The removal functions set `moderation_removed=True` but there is no `_unmark_*_removed()` counterpart.

### 2.2 Moderation Audit Log (`app/services/moderation_audit_log.py`)

`write_moderation_audit_event()` (lines 10-38) is a generic audit writer that accepts any `action` string. Note: `created_at` is stored as a **string** (`str(int(time.time()))`) -- the `ModerationAuditLog` table has no `attr_types` declaration, so the `ByActionCreatedAt` GSI sort key defaults to String type. The `ModerationAuditLog` table definition is at `scripts/local-ddb-init.py`, lines 403-422, with `ByActionCreatedAt` at lines 417-421. DMCA-specific actions (e.g., `dmca_claim_filed`, `dmca_content_removed`, `dmca_counter_notice_filed`, `dmca_resolved`) will use this same mechanism.

### 2.3 Enforcement System (`app/services/moderation_policy_engine.py`)

`apply_ban()` (lines 59-110) writes a ban record to `T.account_state` (PK=`user_sub`) with `status="banned"`, `ban_duration_days`, `ban_started_at`, `ban_until`, and sends an alert to the user via `write_alert(event="moderation_ban")`. `is_user_currently_banned()` (lines 113-126) checks ban status by reading `T.account_state` and comparing `ban_until` against `now_ts()`. The repeat infringer ban will use `apply_ban()` with `duration_days=None` (permanent) and `reason="dmca_repeat_infringer"`. Note: `apply_ban` takes keyword arguments `offender_user_id`, `ticket_id`, `admin_user_id`, `note`, `duration_days`, and `policy_category`.

### 2.4 Alert Notifications (`app/services/alerts.py`, line 261; file is 680 lines)

`write_alert()` sends notifications to users. DMCA requires multiple notification touchpoints:
- Creator notified when claim is filed against their content
- Creator notified of claim details (identifying information of claimant, description of allegedly infringed work)
- Rights holder notified when counter-notice is filed
- Creator notified when content is restored after waiting period
- Creator notified of repeat infringer warning/ban

### 2.5 Admin Moderation Board (`app/routers/admin_moderation.py`)

The existing admin moderation router (970 lines) provides ticket listing, detail view, claim, decision, and resolution endpoints. All protected by `require_admin_scope(AdminScope.CONTENT_MODERATION)`. The DMCA admin dashboard will follow the same auth pattern and endpoint structure but with DMCA-specific models and workflow.

### 2.6 DynamoDB Table Patterns

Moderation tables follow a consistent pattern: single PK (`ticket_id`, `action_id`, `audit_id`), GSIs for status-based and time-based queries, `entity_type` discriminator field. The DMCA claims table will follow this same pattern.

Current moderation table definitions in `scripts/local-ddb-init.py`:
- `ModerationTickets` (line 352): PK=`ticket_id`, GSIs: `ByStatusLatestReportAt`, `ByQueueLatestReportAt`, `ByAssignedAdminLatestReportAt`, `ByLatestReportAt`, `ByContentStatusLatestReportAt`
- `ModerationActions` (line 383): PK=`action_id`, GSIs: `ByTicketCreatedAt`, `ByActionTypeCreatedAt`, `ByTargetUserCreatedAt`
- `ModerationAuditLog` (line 404): PK=`audit_id`, GSIs: `ByTicketCreatedAt`, `ByActorCreatedAt`, `ByActionCreatedAt`
- `UserEnforcementHistory` (line 425): PK=`user_id`, SK=`enforcement_id`, GSIs: `ByStatusCreatedAt`, `BySourceTicketCreatedAt`

**Important**: None of these four tables have `attr_types` declarations, so all GSI sort keys (e.g., `created_at`, `latest_report_at`) default to **String** type. The corresponding service code stores timestamps as strings (e.g., `str(int(time.time()))`).

### 2.7 Content Types and Existing Content References

The content reporting system (`app/routers/moderation.py`, line 39) supports `content_type` values: `feed_post`, `feed_comment`, `feed_media`, `message`, `message_media`, `profile_photo` (defined as a `Literal` type on `CreateModerationReportIn.content_type`). DMCA claims need to extend this with `video` for VOD content, and also support arbitrary URLs (e.g., a rights holder may reference a specific post by URL rather than internal ID).

---

## 3. Technical Design

### 3.1 New DynamoDB Table: `DmcaClaims`

```
Table: DmcaClaims
  PK: claim_id (String) -- "dmca_{uuid4().hex}"

Attributes:
  claim_id                    String    PK
  entity_type                 String    "dmca_claim"
  status                      String    filed | content_removed | counter_notice_filed |
                                        waiting_period | resolved | escalated | withdrawn
  claimant_name               String    Full legal name of rights holder
  claimant_email              String    Contact email
  claimant_address            String    Physical address
  claimant_phone              String    Phone number (optional)
  content_url                 String    URL or identifier of infringing content
  content_type                String    feed_post | feed_media | message_media | video | other
  content_id                  String    Internal content ID (if resolvable)
  target_user_id              String    Content creator's user ID
  original_work_description   String    Description of the copyrighted work
  sworn_statement             Boolean   True = claimant affirms under penalty of perjury
  good_faith_belief           Boolean   True = claimant has good faith belief
  signature                   String    Electronic signature of claimant
  created_at                  Number    Unix timestamp
  updated_at                  Number    Unix timestamp
  content_removed_at          Number    Timestamp when content was hidden/removed
  counter_notice_text         String    Creator's counter-notice text (if filed)
  counter_notice_filed_at     Number    Timestamp of counter-notice
  counter_notice_signature    String    Creator's electronic signature on counter-notice
  waiting_period_expires_at   Number    Timestamp when 10-14 day period ends
  resolved_at                 Number    Timestamp when claim was resolved
  resolution                  String    restored | upheld | court_order | withdrawn
  resolved_by_admin_user_id   String    Admin who resolved (if manual)
  resolution_notes            String    Admin notes on resolution
  strike_number               Number    Which strike this is for the target user (1, 2, 3+)
  content_snapshot            Map       Pre-removal snapshot of content state for restoration
  claimant_user_id            String    User ID of the rights holder (if registered)

GSI ByStatusCreatedAt:
  PK: status        SK: created_at (N)
  -- Admin dashboard: list claims by status, newest first

GSI ByTargetUserCreatedAt:
  PK: target_user_id    SK: created_at (N)
  -- Repeat infringer tracking: list all claims against a user

GSI ByClaimantCreatedAt:
  PK: claimant_email    SK: created_at (N)
  -- Track claims from same rights holder (abuse detection)

GSI ByWaitingPeriodExpiry:
  PK: status            SK: waiting_period_expires_at (N)
  -- Background timer: find claims in waiting_period that have expired
```

DDB init entry for `scripts/local-ddb-init.py`:
```python
TableDef(
    _resolve_table_name(S.dmca_claims_table_name, "DmcaClaims"),
    "claim_id",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByTargetUserCreatedAt", "partition_key": "target_user_id", "sort_key": "created_at"},
        {"index_name": "ByClaimantCreatedAt", "partition_key": "claimant_email", "sort_key": "created_at"},
        {"index_name": "ByWaitingPeriodExpiry", "partition_key": "status", "sort_key": "waiting_period_expires_at"},
    ],
    attr_types={"created_at": "N", "waiting_period_expires_at": "N"},
)
```

### 3.2 Pydantic Models

```python
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# --- Public Claim Submission ---

class DmcaClaimIn(BaseModel):
    """DMCA takedown notice submission by rights holder.

    All fields mirror the requirements of 17 U.S.C. Section 512(c)(3):
    - Identification of the copyrighted work (original_work_description)
    - Identification of the infringing material (content_url, content_type, content_id)
    - Contact information (claimant_name, claimant_email, claimant_address, claimant_phone)
    - Good faith belief statement (good_faith_belief)
    - Statement of accuracy under penalty of perjury (sworn_statement)
    - Signature (signature)
    """

    claimant_name: str = Field(
        min_length=2, max_length=256,
        description="Full legal name of the copyright owner or authorized agent",
    )
    claimant_email: EmailStr = Field(
        description="Contact email for the claimant",
    )
    claimant_address: str = Field(
        min_length=10, max_length=1000,
        description="Physical mailing address of the claimant (required by DMCA)",
    )
    claimant_phone: str = Field(
        default="", max_length=30,
        description="Phone number of the claimant (optional but recommended)",
    )
    content_url: str = Field(
        min_length=5, max_length=2000,
        description="URL or identifier of the allegedly infringing content on this platform",
    )
    content_type: Literal["feed_post", "feed_media", "message_media", "video", "other"] = Field(
        default="other",
        description="Type of content being claimed",
    )
    content_id: str = Field(
        default="", max_length=256,
        description="Internal content ID if known (otherwise resolved from content_url)",
    )
    original_work_description: str = Field(
        min_length=20, max_length=5000,
        description="Description of the copyrighted work allegedly being infringed. "
                    "Must be specific enough to identify the work.",
    )
    sworn_statement: bool = Field(
        ...,
        description="I swear, under penalty of perjury, that the information "
                    "in this notification is accurate and that I am the copyright "
                    "owner or am authorized to act on behalf of the owner.",
    )
    good_faith_belief: bool = Field(
        ...,
        description="I have a good faith belief that use of the material in the "
                    "manner complained of is not authorized by the copyright owner, "
                    "its agent, or the law.",
    )
    signature: str = Field(
        min_length=2, max_length=256,
        description="Electronic signature (typed full legal name)",
    )

    @field_validator("claimant_name", "claimant_address", "original_work_description", "signature")
    @classmethod
    def _sanitize_text_fields(cls, v: str) -> str:
        """Strip HTML tags from text fields to prevent stored XSS."""
        return re.sub(r"<[^>]+>", "", v)

    @field_validator("content_url")
    @classmethod
    def _validate_content_url(cls, v: str) -> str:
        """Ensure content URL is not obviously malicious."""
        v = v.strip()
        if v.startswith("javascript:") or v.startswith("data:"):
            raise ValueError("Invalid content URL scheme")
        return v

    @model_validator(mode="after")
    def _validate_sworn_fields(self) -> DmcaClaimIn:
        """Ensure both sworn_statement and good_faith_belief are True."""
        if not self.sworn_statement:
            raise ValueError("sworn_statement must be True to file a DMCA claim")
        if not self.good_faith_belief:
            raise ValueError("good_faith_belief must be True to file a DMCA claim")
        return self


class DmcaClaimOut(BaseModel):
    """Public-facing representation of a DMCA claim.

    Omits sensitive fields (claimant_address, claimant_phone) when viewed
    by the target user. Full details visible to claimant and admins.
    """

    claim_id: str
    status: str
    claimant_name: str
    claimant_email: str
    content_url: str
    content_type: str
    content_id: str
    target_user_id: str
    original_work_description: str
    created_at: int
    updated_at: int
    content_removed_at: Optional[int] = None
    counter_notice_filed_at: Optional[int] = None
    waiting_period_expires_at: Optional[int] = None
    resolved_at: Optional[int] = None
    resolution: Optional[str] = None
    strike_number: int = 0


class DmcaClaimCreateOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    content_removed: bool
    strike_number: int
    created_at: int


# --- Counter-Notice ---

class DmcaCounterNoticeIn(BaseModel):
    """Counter-notice filed by content creator under 17 U.S.C. Section 512(g).

    Required elements:
    - Identification of removed material and its location (implicit from claim)
    - Statement under penalty of perjury that removal was a mistake
    - Consent to jurisdiction of Federal District Court
    - Physical signature (electronic accepted)
    """

    counter_notice_text: str = Field(
        min_length=50, max_length=5000,
        description="The creator's statement explaining why the content is not infringing. "
                    "Must include a statement under penalty of perjury that the content was "
                    "removed by mistake or misidentification.",
    )
    consent_to_jurisdiction: bool = Field(
        ...,
        description="I consent to the jurisdiction of the Federal District Court "
                    "for the judicial district in which my address is located.",
    )
    counter_notice_signature: str = Field(
        min_length=2, max_length=256,
        description="Electronic signature (typed full legal name)",
    )

    @field_validator("counter_notice_text", "counter_notice_signature")
    @classmethod
    def _sanitize_text(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)

    @model_validator(mode="after")
    def _validate_consent(self) -> DmcaCounterNoticeIn:
        if not self.consent_to_jurisdiction:
            raise ValueError("consent_to_jurisdiction must be True to file a counter-notice")
        return self


class DmcaCounterNoticeOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    waiting_period_expires_at: int
    counter_notice_filed_at: int


# --- Admin Models ---

class DmcaClaimListOut(BaseModel):
    items: list[DmcaClaimOut]
    next_cursor: Optional[str] = None


class DmcaClaimDetailOut(BaseModel):
    """Full claim detail for admin review. Includes content snapshot and
    user context for informed decision-making."""

    claim: DmcaClaimOut
    content_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of the content state at time of removal",
    )
    target_user_profile: dict[str, Any] = Field(
        default_factory=dict,
        description="Profile data for the content creator",
    )
    claimant_full_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Full claimant contact info (address, phone) for admin eyes only",
    )
    prior_claims_against_user: int = Field(
        default=0,
        description="Number of prior DMCA claims against this user",
    )
    prior_claims_by_claimant: int = Field(
        default=0,
        description="Number of prior claims by this claimant (abuse detection)",
    )
    repeat_infringer_status: str = Field(
        default="clear",
        description="clear | warning | banned",
    )


class DmcaResolveIn(BaseModel):
    resolution: Literal["restored", "upheld", "court_order", "withdrawn"]
    resolution_notes: str = Field(default="", max_length=2000)

    @field_validator("resolution_notes")
    @classmethod
    def _sanitize_notes(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class DmcaResolveOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    resolution: str
    resolved_at: int


# --- DMCA Agent Config ---

class DmcaAgentConfigIn(BaseModel):
    """DMCA designated agent contact information.

    Section 512(c)(2) requires the service provider to designate an agent
    to receive notifications of claimed infringement. This agent info must
    be available on the service's website and registered with the Copyright Office.
    """

    agent_name: str = Field(min_length=2, max_length=256)
    agent_email: EmailStr
    agent_address: str = Field(min_length=10, max_length=1000)
    agent_phone: str = Field(default="", max_length=30)


class DmcaAgentConfigOut(BaseModel):
    agent_name: str
    agent_email: str
    agent_address: str
    agent_phone: str


# --- Repeat Infringer ---

class RepeatInfringerStatusOut(BaseModel):
    user_id: str
    total_claims: int
    upheld_claims: int
    strike_count: int
    threshold: int
    status: str  # clear | warning | banned
    claim_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Summary of past DMCA claims against this user",
    )
```

### 3.3 Endpoint Specifications

#### Public Endpoints (no admin auth required, but user auth required)

**`POST /v1/dmca/claims`** -- Submit a DMCA takedown claim  
Auth: `require_ui_session` (rights holder must be a registered user)  
Request: `DmcaClaimIn`  
Response: `DmcaClaimCreateOut` (201)  
Side effects: content immediately hidden, creator notified, audit log entry, strike count incremented

**`GET /v1/dmca/claims/{claim_id}`** -- View a specific claim (by claimant or target user)  
Auth: `require_ui_session` -- only the claimant or the target user can view  
Response: `DmcaClaimOut`

**`POST /v1/dmca/claims/{claim_id}/counter-notice`** -- File a counter-notice  
Auth: `require_ui_session` -- only the target user (content creator) can file  
Request: `DmcaCounterNoticeIn`  
Response: `DmcaCounterNoticeOut`  
Side effects: status -> `counter_notice_filed` -> `waiting_period`, rights holder notified, waiting period timer set

**`GET /v1/dmca/agent-info`** -- Public DMCA agent contact information  
Auth: none (public)  
Response: `DmcaAgentConfigOut`

#### Admin Endpoints

**`GET /v1/admin/dmca/claims`** -- List DMCA claims with filters  
Auth: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
Query params: `status`, `target_user_id`, `limit`, `cursor`  
Response: `DmcaClaimListOut`

**`GET /v1/admin/dmca/claims/{claim_id}`** -- Claim detail with content snapshot  
Auth: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
Response: `DmcaClaimDetailOut`

**`POST /v1/admin/dmca/claims/{claim_id}/resolve`** -- Manually resolve a claim  
Auth: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
Request: `DmcaResolveIn`  
Response: `DmcaResolveOut`

**`GET /v1/admin/dmca/users/{user_id}/infringer-status`** -- Repeat infringer check  
Auth: `require_admin_scope(AdminScope.CONTENT_MODERATION)`  
Response: `RepeatInfringerStatusOut`

**`PUT /v1/admin/dmca/agent-config`** -- Update DMCA agent contact info  
Auth: `require_root` (ROOT only, from `app/auth/policy.py` line 63; note: the function is `require_root`, not `require_root_session` which does not exist)  
Request: `DmcaAgentConfigIn`  
Response: `DmcaAgentConfigOut`

### 3.4 Claim Status State Machine

```
    filed
      |
      v
  content_removed -----> withdrawn (claimant retracts)
      |
      v
  counter_notice_filed
      |
      v
  waiting_period -------> escalated (court order received)
      |
      v (10-14 business days expire)
  resolved (content restored)
```

Valid transitions:
```python
_DMCA_STATUS_TRANSITIONS = {
    "filed": {"content_removed"},
    "content_removed": {"counter_notice_filed", "withdrawn", "resolved"},
    "counter_notice_filed": {"waiting_period"},
    "waiting_period": {"resolved", "escalated"},
    "escalated": {"resolved"},
    "withdrawn": set(),  # terminal
    "resolved": set(),   # terminal
}
```

### 3.5 Repeat Infringer Policy (3 Strikes)

```python
import os

DMCA_STRIKE_THRESHOLD = int(os.environ.get("DMCA_STRIKE_THRESHOLD", "3"))
DMCA_STRIKE_LOOKBACK_DAYS = int(os.environ.get("DMCA_STRIKE_LOOKBACK_DAYS", "365"))
```

When a new claim is filed:
1. Query `ByTargetUserCreatedAt` GSI for all claims against this user in the last `DMCA_STRIKE_LOOKBACK_DAYS`
2. Count claims where `status` is in `{"content_removed", "resolved", "escalated"}` AND `resolution != "restored"` (upheld claims only)
3. Set `strike_number` on the new claim
4. If `strike_number >= DMCA_STRIKE_THRESHOLD`:
   - Call `apply_ban(offender_user_id=target_user_id, ticket_id="", admin_user_id="system", note="DMCA repeat infringer", duration_days=None, policy_category="dmca_repeat_infringer")` (note: `apply_ban` requires `ticket_id`, `admin_user_id`, `note` kwargs per its signature at line 59-67 of `moderation_policy_engine.py`)
   - Write audit event: `action="dmca_repeat_infringer_ban"`
   - Notify user via `write_alert(event="dmca_repeat_infringer_ban")`

### 3.6 Content Hiding/Restoration

On claim filed (immediate removal):
```python
def hide_content_for_dmca(*, claim: dict, content_type: str, content_id: str) -> dict:
    """Hide content immediately upon DMCA claim. Preserves original state for restoration.

    Args:
        claim: The DMCA claim record dict.
        content_type: Type of content (feed_post, video, etc.).
        content_id: Internal ID of the content.

    Returns:
        Pre-removal state snapshot for future restoration.
    """
    snapshot: dict = {}

    if content_type == "video":
        snapshot = _hide_video(content_id, claim["claim_id"])
    elif content_type in {"feed_post", "feed_media"}:
        snapshot = _mark_feed_content_dmca_hidden(content_type, content_id, claim["claim_id"])
    elif content_type in {"message_media"}:
        snapshot = _mark_message_dmca_hidden(content_id, claim["claim_id"])
    else:
        logger.warning("Unsupported content_type for DMCA hiding: %s", content_type)

    return snapshot


def _hide_video(video_id: str, claim_id: str) -> dict:
    """Set dmca_hidden=True on video_metadata record. Preserve original status."""
    item = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item")
    if not item:
        return {}
    original_status = str(item.get("status", ""))
    snapshot = {"original_status": original_status, "video_id": video_id}

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET dmca_hidden = :t, dmca_claim_id = :claim, "
                         "dmca_hidden_at = :ts, dmca_original_status = :orig, "
                         "#status = :hidden, updated_at = :ts",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":t": True,
            ":claim": claim_id,
            ":ts": now_ts(),
            ":orig": original_status,
            ":hidden": "deleted",  # Use deleted to remove from public queries
        },
    )
    return snapshot


def _mark_feed_content_dmca_hidden(content_type: str, content_id: str, claim_id: str) -> dict:
    """Hide feed post or feed media via DMCA claim."""
    APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
    pk = f"POST#{content_id}" if content_type == "feed_post" else f"MEDIA#{content_id}"
    sk = "META"
    item = ddb.Table(APP_TABLE).get_item(Key={"pk": pk, "sk": sk}).get("Item", {})
    snapshot = {k: v for k, v in item.items() if k in ("pk", "sk", "status", "visibility")}

    ddb.Table(APP_TABLE).update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET dmca_hidden = :t, dmca_claim_id = :claim, "
                         "dmca_hidden_at = :ts, updated_at = :ts",
        ExpressionAttributeValues={
            ":t": True,
            ":claim": claim_id,
            ":ts": now_ts(),
        },
    )
    return snapshot
```

On resolution (restore):
```python
def restore_content_after_dmca(*, claim: dict) -> None:
    """Restore content when claim is resolved in creator's favor.

    Reads the content_snapshot from the claim record and reverses
    the hiding operation that was applied when the claim was filed.
    """
    content_type = claim.get("content_type", "")
    content_id = claim.get("content_id", "")
    snapshot = claim.get("content_snapshot", {})

    if content_type == "video":
        _restore_video(content_id, snapshot)
    elif content_type in {"feed_post", "feed_media"}:
        _restore_feed_content(content_type, content_id)
    elif content_type in {"message_media"}:
        _restore_message(content_id)


def _restore_video(video_id: str, snapshot: dict = None) -> None:
    """Clear dmca_hidden flag and restore original video status."""
    original_status = (snapshot or {}).get("original_status", "approved")
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET dmca_hidden = :f, #status = :orig, updated_at = :ts "
                         "REMOVE dmca_claim_id, dmca_hidden_at, dmca_original_status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":f": False,
            ":orig": original_status,
            ":ts": now_ts(),
        },
    )


def _restore_feed_content(content_type: str, content_id: str) -> None:
    """Clear dmca_hidden flag on feed content."""
    APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
    pk = f"POST#{content_id}" if content_type == "feed_post" else f"MEDIA#{content_id}"
    ddb.Table(APP_TABLE).update_item(
        Key={"pk": pk, "sk": "META"},
        UpdateExpression="SET dmca_hidden = :f, updated_at = :ts "
                         "REMOVE dmca_claim_id, dmca_hidden_at",
        ExpressionAttributeValues={
            ":f": False,
            ":ts": now_ts(),
        },
    )
```

### 3.7 Waiting Period Timer

A background loop runs every hour (piggybacks on the existing scheduled task infrastructure):

```python
async def process_expired_dmca_waiting_periods():
    """Auto-resolve DMCA claims whose waiting period has expired.

    Section 512(g)(2)(C) requires the service provider to restore content
    not less than 10 nor more than 14 business days after receiving a
    counter-notice, unless the designated agent first receives notice that
    the copyright owner has filed a court action.

    This implementation uses 14 calendar days for simplicity.
    """
    now = now_ts()
    resp = T.dmca_claims.query(
        IndexName="ByWaitingPeriodExpiry",
        KeyConditionExpression=(
            Key("status").eq("waiting_period")
            & Key("waiting_period_expires_at").lte(now)
        ),
    )
    for claim in resp.get("Items", []):
        try:
            resolve_dmca_claim(
                claim_id=claim["claim_id"],
                resolution="restored",
                resolution_notes="Waiting period expired without court order filed",
                admin_user_id="system",
            )
            logger.info("Auto-resolved DMCA claim %s: waiting period expired", claim["claim_id"])
        except Exception as exc:
            logger.error("Failed to auto-resolve DMCA claim %s: %s", claim["claim_id"], exc)
```

The waiting period is 14 calendar days from counter-notice filing:
```python
DMCA_WAITING_PERIOD_DAYS = int(os.environ.get("DMCA_WAITING_PERIOD_DAYS", "14"))
waiting_period_expires_at = counter_notice_filed_at + (DMCA_WAITING_PERIOD_DAYS * 86400)
```

### 3.8 Error Handling

| Condition | HTTP Status | Detail |
|-----------|-------------|--------|
| `sworn_statement=False` | 400 | `"sworn statement is required for DMCA claims"` |
| `good_faith_belief=False` | 400 | `"good faith belief statement is required"` |
| Content not found / not resolvable | 404 | `"referenced content not found"` |
| Counter-notice on wrong claim | 403 | `"only the content creator can file a counter-notice"` |
| Counter-notice already filed | 409 | `"counter-notice already filed for this claim"` |
| Claim not in valid state for counter-notice | 409 | `"claim status does not allow counter-notice"` |
| Resolve claim in terminal state | 409 | `"claim is already resolved"` |
| Admin lacks scope | 403 | `"admin scope not authorized"` |
| Non-ROOT updates agent config | 403 | `"only root can update DMCA agent configuration"` |

---

## 4. Implementation Plan

### Step 1: Add Table Definition and Settings

**File**: `scripts/local-ddb-init.py`  
Add `DmcaClaims` table definition (after line 440, alongside existing moderation tables).

**Line-by-line change description**:
- Insert after the `UserEnforcementHistory` TableDef (line 440)
- Add 15 lines: `TableDef(...)` with 4 GSIs and `attr_types` for numeric sort keys
- Must include `attr_types={"created_at": "N", "waiting_period_expires_at": "N"}` to avoid the numeric GSI sort key gotcha documented in CLAUDE.md

**File**: `app/core/settings.py`  
Add setting: `dmca_claims_table_name: str = os.environ.get("DDB_DMCA_CLAIMS", "DmcaClaims")`

**Insertion point**: After line 543 (end of the moderation table settings block, after `user_enforcement_history_table_name`), add 1 line. Note: table name settings are NOT near line 76 (which is `alerts_table_name`); the moderation-related table names are at lines 528-543.

**File**: `app/core/tables.py` (155 lines total)  
Add to `Tables` dataclass (after `user_enforcement_history` field, line 56):
```python
dmca_claims: Any
```

Add to `T` instantiation (after `user_enforcement_history` at line 129):
```python
dmca_claims=ddb.Table(S.dmca_claims_table_name),
```

### Step 2: Create Service Layer

**New file**: `app/services/dmca_claims.py` (~350 lines)

Functions:
- `file_dmca_claim(inp: DmcaClaimIn, claimant_user_id: str) -> dict` -- creates claim record, resolves content ID from URL, hides content, calculates strike number, checks repeat infringer threshold
- `file_counter_notice(claim_id: str, inp: DmcaCounterNoticeIn, user_id: str) -> dict` -- validates creator identity, transitions status, sets waiting period, notifies rights holder
- `resolve_dmca_claim(claim_id: str, resolution: str, resolution_notes: str, admin_user_id: str) -> dict` -- transitions to resolved, restores content if resolution is "restored"
- `list_claims_by_status(status: str, *, limit: int, cursor: dict) -> dict` -- queries ByStatusCreatedAt GSI
- `list_claims_by_user(target_user_id: str, *, limit: int, cursor: dict) -> dict` -- queries ByTargetUserCreatedAt GSI
- `get_claim(claim_id: str) -> dict` -- get_item + 404 check
- `count_strikes(target_user_id: str) -> int` -- count upheld claims in lookback window
- `get_repeat_infringer_status(target_user_id: str) -> dict` -- strike count + status assessment
- `get_dmca_agent_config() -> dict` -- read from alert_prefs table (shared config store)
- `set_dmca_agent_config(config: dict) -> dict` -- write to alert_prefs table

**New file**: `app/services/dmca_content_operations.py` (~200 lines)

Functions:
- `resolve_content_from_url(content_url: str) -> tuple[str, str]` -- parse URL to extract content_type and content_id
- `hide_content_for_dmca(claim_id: str, content_type: str, content_id: str) -> dict` -- hides content, returns pre-removal snapshot
- `restore_content_after_dmca(claim: dict) -> None` -- restores content from snapshot
- `_hide_video(video_id: str, claim_id: str) -> dict` -- sets `dmca_hidden=True` on video_metadata
- `_restore_video(video_id: str, snapshot: dict) -> None` -- clears `dmca_hidden` flag
- `_hide_feed_content(content_type: str, content_id: str, claim_id: str) -> dict`
- `_restore_feed_content(content_type: str, content_id: str) -> None`

### Step 3: Create Routers

**New file**: `app/routers/dmca.py` (~150 lines)  
Public-facing endpoints for claim submission, counter-notice, and agent info.

**New file**: `app/routers/admin_dmca.py` (~200 lines)  
Admin dashboard endpoints for listing, viewing, and resolving claims.

### Step 4: Register Routers in `app/main.py`

**File**: `app/main.py`

Add imports (after line 85, alongside the `admin_moderation_router` import; `app/main.py` is 620 lines total):
```python
from app.routers.dmca import router as dmca_router
from app.routers.admin_dmca import router as admin_dmca_router
```

Add registrations (after the `admin_moderation_router` registration at line 279):
```python
app.include_router(dmca_router)
app.include_router(admin_dmca_router)
```

### Step 5: Add Background Timer

**File**: `app/main.py` (or dedicated `app/tasks/dmca_timer.py`)

Register a background task that runs `process_expired_dmca_waiting_periods()` every hour. This piggybacks on the existing startup task pattern in `main.py` (similar to `start_scheduled_messages_task` imported at line 97 and registered at line 309 via `app.add_event_handler("startup", ...)`).

```python
async def _dmca_timer_loop():
    """Background loop to process expired DMCA waiting periods every hour."""
    while True:
        try:
            await process_expired_dmca_waiting_periods()
        except Exception as exc:
            logger.error("DMCA timer loop error: %s", exc)
        await asyncio.sleep(3600)  # 1 hour
```

### Step 6: Add Frontend API Endpoints

**New file**: `frontend/src/api/endpoints/dmca.ts` (~100 lines)

API wrappers for claim submission, counter-notice filing, and admin dashboard calls.

### Step 7: Add Frontend Pages

**New file**: `frontend/src/pages/dmca/DmcaClaimForm.tsx` (~200 lines)  
Public-facing form for rights holders to submit takedown claims. Fields: contact info, content URL, description of original work, sworn statements (checkboxes), electronic signature.

**New file**: `frontend/src/pages/dmca/DmcaCounterNoticeForm.tsx` (~150 lines)  
Form for content creators to file counter-notices. Linked from the notification alert.

**New file**: `frontend/src/pages/admin/DmcaDashboardPage.tsx` (~300 lines)  
Admin dashboard with claim list, detail panel, resolve actions.

### Step 8: Add Routes and Navigation

**File**: `frontend/src/App.tsx`  
Add routes: `/dmca/submit`, `/dmca/counter-notice/:claimId`, `/admin/dmca`

**File**: `frontend/src/components/layout/Sidebar.tsx`  
Add "DMCA Claims" link in admin section.

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `scripts/local-ddb-init.py` | Modified (~15 lines) | ~15 |
| `app/core/settings.py` | Modified (1 line) | ~1 |
| `app/core/tables.py` | Modified (3 lines) | ~3 |
| `app/services/dmca_claims.py` | **New** | ~350 |
| `app/services/dmca_content_operations.py` | **New** | ~200 |
| `app/routers/dmca.py` | **New** | ~150 |
| `app/routers/admin_dmca.py` | **New** | ~200 |
| `app/main.py` | Modified (6 lines) | ~6 |
| `frontend/src/api/endpoints/dmca.ts` | **New** | ~100 |
| `frontend/src/pages/dmca/DmcaClaimForm.tsx` | **New** | ~200 |
| `frontend/src/pages/dmca/DmcaCounterNoticeForm.tsx` | **New** | ~150 |
| `frontend/src/pages/admin/DmcaDashboardPage.tsx` | **New** | ~300 |
| `frontend/src/App.tsx` | Modified (~6 lines) | ~6 |
| `frontend/src/components/layout/Sidebar.tsx` | Modified (~5 lines) | ~5 |
| `frontend/e2e/dmca-takedown.spec.ts` | **New** | ~500 |
| **Total** | | **~2190** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_dmca_claims.py`)

**New file**, ~350 lines. Tests the service layer using moto-mocked DynamoDB.

**Fixtures**:

```python
import pytest
import os
from moto import mock_dynamodb
from app.core.tables import T
from app.services.dmca_claims import (
    count_strikes,
    file_counter_notice,
    file_dmca_claim,
    get_claim,
    get_repeat_infringer_status,
    list_claims_by_status,
    resolve_dmca_claim,
)
from app.services.dmca_content_operations import (
    hide_content_for_dmca,
    resolve_content_from_url,
    restore_content_after_dmca,
)


@pytest.fixture
def dmca_tables(moto_ddb):
    """Create DmcaClaims table and supporting tables in moto."""
    T.dmca_claims.meta.client.create_table(
        TableName=T.dmca_claims.name,
        KeySchema=[{"AttributeName": "claim_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "claim_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "target_user_id", "AttributeType": "S"},
            {"AttributeName": "claimant_email", "AttributeType": "S"},
            {"AttributeName": "waiting_period_expires_at", "AttributeType": "N"},
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
                "IndexName": "ByTargetUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "target_user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByClaimantCreatedAt",
                "KeySchema": [
                    {"AttributeName": "claimant_email", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByWaitingPeriodExpiry",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "waiting_period_expires_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    yield


def _valid_claim_input() -> dict:
    """Return a valid DmcaClaimIn dict for testing."""
    return {
        "claimant_name": "Test Claimant",
        "claimant_email": "claimant@test.local",
        "claimant_address": "123 Test Street, Test City, TS 12345",
        "content_url": "/feed/post/post_abc123",
        "content_type": "feed_post",
        "content_id": "post_abc123",
        "original_work_description": "This is my original photograph taken on 2025-01-15 and registered with the US Copyright Office.",
        "sworn_statement": True,
        "good_faith_belief": True,
        "signature": "Test Claimant",
    }
```

**Test cases**:

1. **`test_file_claim_success`** -- Submit valid claim. Verify claim record created with status="filed", `created_at` set.

2. **`test_file_claim_requires_sworn_statement`** -- Submit with `sworn_statement=False`. Expect 400.

3. **`test_file_claim_requires_good_faith_belief`** -- Submit with `good_faith_belief=False`. Expect 400.

4. **`test_file_claim_hides_content`** -- Create a feed post, file claim against it. Verify post has `dmca_hidden=True`.

5. **`test_file_claim_notifies_creator`** -- File claim. Verify creator received alert with `event="dmca_claim_filed"`.

6. **`test_file_claim_increments_strike`** -- File 3 claims against same user. Verify `strike_number` is 1, 2, 3 respectively.

7. **`test_file_claim_third_strike_bans_user`** -- File 3 upheld claims. Verify user is banned after the third.

8. **`test_file_counter_notice_success`** -- File claim, then file counter-notice as creator. Verify status transitions to `waiting_period`, `waiting_period_expires_at` set.

9. **`test_counter_notice_wrong_user_403`** -- File claim, try to counter-notice as a different user. Expect 403.

10. **`test_counter_notice_already_filed_409`** -- File counter-notice twice on same claim. Second returns 409.

11. **`test_counter_notice_wrong_status_409`** -- File counter-notice on a resolved claim. Expect 409.

12. **`test_counter_notice_sets_waiting_period`** -- File counter-notice. Verify `waiting_period_expires_at` = `counter_notice_filed_at` + 14 days.
    ```python
    def test_counter_notice_sets_waiting_period(dmca_tables):
        """Verify waiting period is exactly 14 calendar days (1_209_600 seconds)."""
        claim = file_dmca_claim(_valid_claim_input(), "claimant_user")
        result = file_counter_notice(
            claim["claim_id"],
            {"counter_notice_text": "This content is my original work" * 5,
             "consent_to_jurisdiction": True,
             "counter_notice_signature": "Creator Name"},
            "target_user",
        )
        assert result["waiting_period_expires_at"] == result["counter_notice_filed_at"] + 14 * 86400
    ```

13. **`test_counter_notice_notifies_rights_holder`** -- File counter-notice. Verify claimant receives alert with `event="dmca_counter_notice_filed"`.

14. **`test_resolve_claim_restored`** -- Resolve claim with `resolution="restored"`. Verify content is unhidden, status is `resolved`.

15. **`test_resolve_claim_upheld`** -- Resolve with `resolution="upheld"`. Verify content stays hidden, status is `resolved`.

16. **`test_resolve_claim_writes_audit`** -- Resolve claim. Verify audit log entry with `action="dmca_resolved"`.

17. **`test_auto_resolve_expired_waiting_period`** -- Create claim in `waiting_period` with expired timestamp. Call `process_expired_dmca_waiting_periods()`. Verify auto-resolved with content restored.

18. **`test_list_claims_by_status`** -- Create claims in different statuses. List by `status="content_removed"`. Verify only matching claims returned.

19. **`test_get_repeat_infringer_status_clear`** -- User with 0 strikes. Verify status="clear".

20. **`test_get_repeat_infringer_status_warning`** -- User with 2 strikes. Verify status="warning", strike_count=2.

21. **`test_get_repeat_infringer_status_banned`** -- User with 3+ strikes. Verify status="banned".

22. **`test_resolve_content_from_url_feed_post`** -- Pass `/feed/post/abc123`. Verify returns `("feed_post", "abc123")`.

23. **`test_resolve_content_from_url_video`** -- Pass `/videos/v_abcdef`. Verify returns `("video", "v_abcdef")`.

24. **`test_dmca_agent_config_crud`** -- Set config, read it back. Verify all fields match.

25. **`test_hide_video_for_dmca`** -- Create video, hide it. Verify `dmca_hidden=True` on the record.

26. **`test_restore_video_after_dmca`** -- Hide video, then restore. Verify `dmca_hidden=False` and original status preserved.

### 5.2 E2E Tests (`frontend/e2e/dmca-takedown.spec.ts`)

**New file**, ~500 lines.

**Setup (`beforeAll`)**:
- Seed sessions for Alice (rights holder), Bob (content creator), and Root (admin)
- Bob creates a feed post with an image (the "infringing content")

**Section 95: Claim Submission API (6 tests)**:

1. `Alice submits valid DMCA claim` -- POST with all required fields. Verify 201, claim_id returned.
2. `Claim without sworn statement returns 400` -- sworn_statement=False.
3. `Claim with invalid content URL returns 404` -- reference non-existent content.
4. `Bob's content is hidden after claim` -- verify the post is no longer visible in feed.
5. `Bob receives notification about claim` -- check Bob's alerts.
6. `GET claim by ID returns claim details` -- verify all fields.

**Section 96: Counter-Notice API (5 tests)**:

1. `Bob files counter-notice` -- POST with statement and signature. Verify status transitions.
2. `Alice (non-creator) cannot file counter-notice` -- verify 403.
3. `Counter-notice on resolved claim returns 409` -- verify error.
4. `Waiting period is set to 14 days` -- verify `waiting_period_expires_at` value.
5. `Alice receives notification about counter-notice` -- check Alice's alerts.

**Section 97: Admin DMCA Dashboard API (6 tests)**:

1. `Root lists claims by status` -- verify paginated list.
2. `Root views claim detail` -- verify content snapshot and user profile.
3. `Root resolves claim as restored` -- verify content restored, status updated.
4. `Root resolves claim as upheld` -- verify content stays hidden.
5. `Root views repeat infringer status` -- verify strike count.
6. `Root updates DMCA agent config` -- verify config persisted.

**Section 98: Repeat Infringer Policy (4 tests)**:

1. `First DMCA strike recorded` -- file one claim, verify strike_number=1.
2. `Second DMCA strike recorded` -- file another claim against same user, verify strike_number=2.
3. `Third strike triggers ban` -- file third claim, verify user is banned.
4. `Banned user cannot post new content` -- verify 403 on new post creation (if ban enforcement exists on post endpoint).

**Section 99: DMCA Claim Form UI (5 tests)**:

1. `Claim form renders with required fields` -- navigate to `/dmca/submit`, verify all input fields.
2. `Form validates required checkboxes` -- submit without sworn statement checked, verify validation error.
3. `Successful submission shows confirmation` -- fill form, submit, verify success message.
4. `Counter-notice form accessible from notification` -- navigate to counter-notice form, verify fields.
5. `Admin DMCA dashboard renders claim list` -- navigate to `/admin/dmca`, verify table of claims.

### 5.3 Edge Cases to Cover

1. **Race condition: two claims on same content** -- Two rights holders claim the same content simultaneously. Both claims should be created (they may be different copyright holders). Content should be hidden after the first claim; the second claim's `hide_content()` is idempotent.

2. **Content already removed by moderation** -- If content was already removed via the moderation pipeline (moderation_removed=True), the DMCA claim should still be created (for legal tracking) but the content state is already hidden. Restoration should check if there is a separate moderation removal that should prevent restoration.

3. **Counter-notice on withdrawn claim** -- If the claimant withdraws their claim before the creator files a counter-notice, the content is restored immediately. The counter-notice endpoint should return 409 (status is not `content_removed`).

4. **Court order during waiting period** -- An admin can escalate a claim from `waiting_period` to `escalated` if they receive notice of a court filing. The waiting period timer should NOT auto-resolve `escalated` claims.

5. **DMCA claim on DRM-encrypted video** -- The video may have encrypted content that cannot be easily previewed in the admin dashboard. The admin detail view should show the video metadata (title, thumbnail) even if the actual content requires DRM decryption.

6. **Claimant abuse** -- A rights holder who files multiple fraudulent claims could be tracked via the `ByClaimantCreatedAt` GSI. Consider adding an admin endpoint to flag/block abusive claimants (out of scope for this ticket but noted for future work).

7. **Creator account already banned** -- If the content creator is already banned (from moderation or prior DMCA strikes), the counter-notice endpoint should still accept the filing (legal right to respond), but the content may not need restoration since the account is suspended.

8. **Waiting period calculation across weekends** -- The DMCA specifies "10-14 business days." For simplicity, this implementation uses 14 calendar days. A future enhancement could implement business day calculation.

### 5.4 Compliance Checklist

| Section 512 Requirement | Implementation |
|--------------------------|----------------|
| Designated DMCA agent | `GET /v1/dmca/agent-info` + `PUT /v1/admin/dmca/agent-config` |
| Accept takedown notices | `POST /v1/dmca/claims` with required fields |
| Expeditious removal | Content hidden immediately in `file_dmca_claim()` |
| Notify alleged infringer | `write_alert(event="dmca_claim_filed")` |
| Accept counter-notices | `POST /v1/dmca/claims/{id}/counter-notice` |
| 10-14 day waiting period | `waiting_period_expires_at` + background timer |
| Restore if no court order | `process_expired_dmca_waiting_periods()` auto-resolves |
| Repeat infringer policy | 3-strike tracking via `ByTargetUserCreatedAt` GSI |
| Good faith reliance | `sworn_statement` + `good_faith_belief` boolean fields |

---

## 6. Legal & Compliance Considerations

### 6.1 DMCA Section 512 Safe Harbor Requirements

For the platform to qualify for safe harbor protection under Section 512(c), it must satisfy all of the following conditions. This ticket implements each one:

| Requirement | Statute Reference | Implementation |
|-------------|-------------------|----------------|
| Designate an agent to receive DMCA notices | 512(c)(2) | `GET /v1/dmca/agent-info` returns publicly accessible agent contact. `PUT /v1/admin/dmca/agent-config` allows root to update. Agent must also be registered with the U.S. Copyright Office. |
| Not have actual knowledge of infringement | 512(c)(1)(A)(i) | Content is hidden immediately upon receipt of a valid notice -- "expeditious removal" demonstrates good faith. |
| Not be aware of facts making infringement apparent | 512(c)(1)(A)(ii) | The automated hiding process ensures content is removed as soon as the platform receives a qualifying notice. |
| Act expeditiously to remove or disable access | 512(c)(1)(A)(iii) | `hide_content_for_dmca()` is called synchronously within the `file_dmca_claim()` function, ensuring content is hidden before the 201 response. |
| Not receive financial benefit directly attributable to infringement, where it has the right and ability to control | 512(c)(1)(B) | Out of scope for this ticket -- requires platform-level business model analysis. |
| Upon notification, respond expeditiously | 512(c)(1)(C) | Immediate content hiding + audit trail. |
| Implement a repeat infringer policy | 512(i) | 3-strike policy with configurable threshold and lookback window. |

### 6.2 Counter-Notice Timeline Requirements

Section 512(g)(2) specifies the counter-notice procedure:

1. **Upon receipt of counter-notice**: The service provider must "promptly" provide the complaining party (claimant) with a copy of the counter-notice and inform them that the removed content will be restored in 10-14 business days.
   - **Implementation**: `write_alert(claimant_user_id, event="dmca_counter_notice_filed")` is called immediately upon counter-notice filing.

2. **10-14 business day waiting period**: Content must be restored not less than 10 and not more than 14 business days after receipt of the counter-notice, unless the designated agent receives notice that the complaining party has filed a court action.
   - **Implementation**: 14 calendar days (conservative). The `ByWaitingPeriodExpiry` GSI enables the background timer to find expired claims efficiently. The `escalated` status prevents auto-restoration when a court action is filed.

3. **Court order received**: If the copyright owner files a court action seeking to restrain the content creator, the service provider is not required to restore the content.
   - **Implementation**: Admin can transition claim from `waiting_period` to `escalated` via `POST /admin/dmca/claims/{id}/resolve` with `resolution="court_order"`.

### 6.3 Designated Agent Requirements

The DMCA requires the service provider to:
1. Designate an agent to receive DMCA notifications
2. Register the agent with the U.S. Copyright Office (via the online directory at https://www.copyright.gov/dmca-directory/)
3. Make the agent's contact information available on the service's website

**Implementation notes**:
- The `GET /v1/dmca/agent-info` endpoint returns agent contact info publicly (no auth required)
- The agent info is stored in the `alert_prefs` table as a config entry (shared config pattern used throughout the platform)
- The agent registration with the Copyright Office is a manual administrative task outside the scope of this software -- but the `/dmca/submit` page should display the agent's contact information prominently

### 6.4 Record Retention Obligations

DMCA claims and counter-notices are legal documents that may be relevant in future litigation. Retention requirements:

| Record Type | Retention Period | Implementation |
|-------------|-----------------|----------------|
| DMCA claim (full record) | 6 years minimum (statute of limitations) | DDB item with no TTL |
| Counter-notice (full text) | 6 years minimum | Stored on the claim record |
| Content removal timestamp | 6 years minimum | `content_removed_at` field |
| Waiting period timestamps | 6 years minimum | `waiting_period_expires_at`, `resolved_at` fields |
| Audit trail entries | 6 years minimum | `ModerationAuditLog` entries with no TTL |
| Content snapshots | 3 years (for potential restoration) | `content_snapshot` map on claim record |
| Repeat infringer history | Indefinite | Derived from claim records; no separate storage needed |

**Important**: Unlike regular alerts (which have a 90-day TTL via `alerts_ttl_days`), DMCA claim records must NOT have a DDB TTL applied. The `DmcaClaims` table is created without a TTL attribute.

### 6.5 International Copyright Law Variations

While this ticket implements the U.S. DMCA process, the platform should be aware of similar regimes in other jurisdictions:

| Jurisdiction | Relevant Law | Key Differences |
|-------------|-------------|-----------------|
| **EU** | Digital Services Act (DSA), Article 16 | Requires a "notice and action" mechanism. No sworn statement requirement. 14-day resolution period. Must provide information about available remedies. |
| **UK** | Copyright, Designs and Patents Act 1988, s.97A | Court order required for ISP blocking. No safe harbor equivalent to DMCA 512. |
| **Australia** | Copyright Act 1968, Division 2AA | Similar safe harbor to DMCA. Requires "expeditious" action. Counter-notice provisions exist. |
| **Canada** | Copyright Modernization Act, "Notice and Notice" | Unique system: ISP must forward notice to subscriber but is NOT required to remove content. No takedown obligation. |

**Future work**: A separate ticket should address EU DSA compliance (different notice format, different timeline, different transparency requirements). The DmcaClaims table can be extended with a `jurisdiction` field to support multi-regime workflows.

---

## 7. Security Considerations

### 7.1 Admin Authentication Edge Cases

- **Claim submission by non-authenticated user**: The `POST /v1/dmca/claims` endpoint requires `require_ui_session`, meaning the rights holder must be a registered and logged-in user. This prevents anonymous claims and provides accountability. However, Section 512 does not require the platform to authenticate claimants -- a future enhancement could accept claims via email to the designated agent.

- **Counter-notice identity verification**: The `POST /v1/dmca/claims/{id}/counter-notice` endpoint verifies that the authenticated user's `user_id` matches the claim's `target_user_id`. This is enforced via a simple string comparison after the session auth dependency extracts the user identity from the JWT cookie.

- **Admin scope enforcement**: All admin endpoints use `require_admin_scope(AdminScope.CONTENT_MODERATION)`. The `require_root` dependency from `app/auth/policy.py` (line 63; not `require_admin_scope`) is used for the agent config endpoint because changing the designated agent is a platform-level decision, not a content moderation task.

### 7.2 Privilege Escalation Prevention

- **Claimant viewing target user's data**: The `DmcaClaimOut` model omits sensitive fields (`claimant_address`, `claimant_phone`) when viewed by the target user. Full details are only in `DmcaClaimDetailOut` (admin-only).
- **Target user filing claim against themselves**: While technically valid (a user could DMCA their own content to trigger removal), this is handled by the normal flow. The strike counter only counts claims from other users.
- **Admin resolving without authority**: All resolution actions require `CONTENT_MODERATION` scope (from `AdminScope` enum in `app/auth/roles.py`, line 14), which is assigned via the role management system (`app/routers/admin_roles.py`).

### 7.3 Audit Trail Integrity

Every DMCA action writes to the `ModerationAuditLog` table:
- `dmca_claim_filed`: Claim submission (actor = claimant)
- `dmca_content_removed`: Content hiding (actor = system)
- `dmca_counter_notice_filed`: Counter-notice (actor = target user)
- `dmca_waiting_period_started`: Waiting period initiated (actor = system)
- `dmca_resolved`: Claim resolution (actor = admin or system)
- `dmca_repeat_infringer_ban`: Repeat infringer ban (actor = system)

Audit records are append-only -- there is no API to modify or delete them. The `ByActionCreatedAt` GSI enables efficient queries for all DMCA-related audit events.

### 7.4 Input Sanitization

All text fields in `DmcaClaimIn` and `DmcaCounterNoticeIn` have `@field_validator` decorators that strip HTML tags via `re.sub(r"<[^>]+>", "", v)`. This prevents:
- **Stored XSS**: Claim text and counter-notice text are rendered in the admin dashboard and alert notifications
- **URL injection**: The `content_url` field is validated to reject `javascript:` and `data:` schemes
- **Length-based DoS**: All fields have `max_length` constraints to prevent oversized payloads

### 7.5 Rate Limiting

- **Claim submission**: Rate-limited to 10 claims per hour per user (prevents DMCA abuse/harassment by a single claimant)
- **Counter-notice**: One counter-notice per claim (enforced by status transition)
- **Admin resolution**: No rate limit (admin actions are trusted)
- **Agent info**: Public endpoint, rate-limited to 100 requests per minute per IP (prevents scraping)

---

## 8. Migration & Rollback Plan

### 8.1 DDB Table Creation Script

Add to `scripts/local-ddb-init.py` after the `UserEnforcementHistory` table definition (closing paren at line 440; the next table `MessageArchiveChainHeads` starts at line 441):

```python
TableDef(
    _resolve_table_name(S.dmca_claims_table_name, "DmcaClaims"),
    "claim_id",
    gsi=[
        {
            "index_name": "ByStatusCreatedAt",
            "partition_key": "status",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByTargetUserCreatedAt",
            "partition_key": "target_user_id",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByClaimantCreatedAt",
            "partition_key": "claimant_email",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByWaitingPeriodExpiry",
            "partition_key": "status",
            "sort_key": "waiting_period_expires_at",
        },
    ],
    attr_types={"created_at": "N", "waiting_period_expires_at": "N"},
),
```

### 8.2 Feature Flag Rollout

```python
# app/core/settings.py
dmca_enabled: bool = os.environ.get("DMCA_ENABLED", "0") not in ("0", "false", "False")
```

**Phase 1: Table creation + backend dark launch**
- Create DDB table in production
- Deploy service layer and routers with `DMCA_ENABLED=0`
- Routers return 404 when disabled

**Phase 2: Admin-only testing**
- Enable `DMCA_ENABLED=1` in staging
- QA exercises all endpoints
- Verify audit trail completeness

**Phase 3: Public launch**
- Enable in production
- Add public DMCA submission page link
- Configure designated agent info

### 8.3 Rollback Steps

1. Set `DMCA_ENABLED=0` -- all endpoints return 404
2. Claims already in the system remain in DDB (no data loss)
3. Background timer stops processing (feature check at top of function)
4. Content that was hidden remains hidden until manually restored
5. **Manual recovery**: If content must be restored, use the admin endpoint (re-enable temporarily) or direct DDB updates

### 8.4 Data Backfill

Not applicable for initial launch. No existing data needs migration. The `DmcaClaims` table starts empty.

---

## 9. Operational Runbook

### 9.1 Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `dmca_claims_filed_per_day` | New claims submitted per day | > 50 (unusual volume, possible abuse) |
| `dmca_avg_removal_time_ms` | Time from claim submission to content hiding | > 5000ms (should be < 1000ms) |
| `dmca_counter_notices_per_day` | Counter-notices filed per day | Informational |
| `dmca_waiting_period_queue_depth` | Claims currently in waiting_period status | > 20 (backlog accumulating) |
| `dmca_auto_resolve_failures` | Failed auto-resolutions per timer run | > 0 (investigate immediately) |
| `dmca_repeat_infringer_bans` | Users banned via repeat infringer policy | > 5/week (possible abuse pattern) |
| `dmca_strike_rate_by_claimant` | Claims per unique claimant email | > 10/month from one claimant (possible abuse) |

### 9.2 SLA Tracking

| SLA | Target | Measurement |
|-----|--------|-------------|
| Content removal on valid claim | < 60 seconds | `content_removed_at - created_at` |
| Creator notification on claim | < 60 seconds | Alert timestamp - claim timestamp |
| Counter-notice acknowledgment | < 60 seconds | Response time of counter-notice endpoint |
| Waiting period auto-resolution | Within 1 hour of expiry | Timer runs hourly; worst case is 59 minutes late |
| Admin claim review | < 24 hours | `resolved_at - created_at` for admin-resolved claims |

### 9.3 Common Debugging Scenarios

**Scenario: Content not hidden after claim**
1. Check claim status -- should be `content_removed` after filing
2. If status is `filed`, the `hide_content_for_dmca()` call failed silently
3. Check the `content_type` and `content_id` -- if the URL couldn't be resolved, `content_id` is empty
4. Check DDB for the content item -- verify `dmca_hidden` attribute exists

**Scenario: Waiting period timer not resolving claims**
1. Check the background task is running: `ps aux | grep dmca_timer`
2. Check the `ByWaitingPeriodExpiry` GSI: query with `status=waiting_period` and `waiting_period_expires_at <= now()`
3. If claims exist but aren't being resolved: check logs for `"Failed to auto-resolve DMCA claim"` errors
4. Common cause: the claim record was manually modified and is in an inconsistent state

**Scenario: False DMCA claim detected**
1. Admin resolves claim with `resolution="withdrawn"` and `resolution_notes` explaining the finding
2. Content is restored automatically for "restored" resolution; for "withdrawn", check if content needs manual restoration
3. Consider flagging the claimant via the `ByClaimantCreatedAt` GSI for future reference

### 9.4 Escalation Procedures

| Situation | Action |
|-----------|--------|
| Court order received during waiting period | Admin resolves claim with `resolution="court_order"`. Content remains hidden indefinitely. Notify legal team. |
| Claimant filing >10 claims/week | Investigate via `ByClaimantCreatedAt` GSI. May be DMCA abuse (Section 512(f) provides remedies for bad-faith claims). |
| Repeat infringer ban contested | User files appeal via MOD-003 appeals system. Appeal admin reviews DMCA claim history. |
| Platform-wide DMCA claim surge | Check if claims are from a single claimant (automated abuse). If legitimate, scale admin review capacity. |

---

## 10. Performance & Capacity Planning

### 10.1 Expected Throughput

| Scenario | Requests/sec | DDB Operations/sec |
|----------|-------------|-------------------|
| Normal operations (1-5 claims/day) | < 0.01 | < 0.1 |
| DMCA abuse (50 claims/hour) | ~0.015 | ~0.15 |
| Admin dashboard browsing | ~0.1 | ~0.3 |
| Waiting period timer (hourly) | Burst: 1-10 | Burst: 5-50 |

### 10.2 DDB Capacity

On-demand mode is recommended for the `DmcaClaims` table due to low and unpredictable traffic. The table will likely contain < 10,000 items total.

GSI capacity considerations:
- `ByStatusCreatedAt`: Low cardinality partition key (7 status values). In practice, most items will be in `resolved` status. Active statuses (`content_removed`, `waiting_period`) will have few items.
- `ByTargetUserCreatedAt`: Partition per user. Well-distributed unless one user accumulates many claims.
- `ByClaimantCreatedAt`: Partition per claimant email. Similar distribution.
- `ByWaitingPeriodExpiry`: Only used by the timer. Queries `status=waiting_period` partition -- typically < 50 items.

### 10.3 Background Timer Performance

The timer runs every hour and queries the `ByWaitingPeriodExpiry` GSI for claims with `status=waiting_period` and `waiting_period_expires_at <= now`. In steady state:
- Expected items per run: 0-5
- DDB operations per item: 3 (get claim + update claim + restore content)
- Total runtime per execution: < 1 second

---

## 11. Dependency Analysis

### 11.1 Dependencies (This Ticket Requires)

| Dependency | Status | Impact |
|------------|--------|--------|
| Content moderation infrastructure | Complete | Provides `ModerationAuditLog` table, `write_moderation_audit_event()`, admin scope system |
| Alert notification system | Complete | Provides `write_alert()` for all notification touchpoints |
| Enforcement system | Complete | Provides `apply_ban()` for repeat infringer policy |
| Content removal infrastructure | Complete | Provides `_mark_feed_post_removed()` and similar functions |
| Video metadata system (VOD-001) | Complete | Provides `video_metadata` table for video content hiding/restoration |

### 11.2 Dependents (Blocked by This Ticket)

| Dependent | Description |
|-----------|-------------|
| MOD-006: Automated copyright scanning | Needs DMCA claim creation API to auto-file claims when content fingerprinting detects matches |
| LEGAL-001: Designated agent registration | Needs agent config storage to register with Copyright Office |
| MOD-003: User appeals system | Appeals may reference DMCA claims when a repeat infringer ban is appealed |

### 11.3 Notification System Integration

The DMCA workflow produces 6 distinct notification types, all using the existing `write_alert()` function:

| Event | Recipient | Alert Event | Outcome |
|-------|-----------|-------------|---------|
| Claim filed | Creator | `dmca_claim_filed` | `warning` |
| Content removed | Creator | `dmca_content_removed` | `warning` |
| Counter-notice filed | Claimant | `dmca_counter_notice_filed` | `info` |
| Content restored | Creator | `dmca_content_restored` | `success` |
| Repeat infringer warning | Creator | `dmca_repeat_infringer_warning` | `warning` |
| Repeat infringer ban | Creator | `dmca_repeat_infringer_ban` | `warning` |

---

## 12. Acceptance Criteria

- [ ] Rights holder can submit a DMCA claim via `POST /v1/dmca/claims` with all required Section 512 fields
- [ ] Content is hidden immediately (within the same HTTP request) upon claim submission
- [ ] Creator is notified of the claim via the alert system
- [ ] Creator can file a counter-notice via `POST /v1/dmca/claims/{id}/counter-notice`
- [ ] Counter-notice triggers a 14-day waiting period
- [ ] Claimant is notified when a counter-notice is filed
- [ ] Background timer auto-resolves claims after waiting period expires
- [ ] Content is restored automatically on resolution with `restored` outcome
- [ ] Admin can list, view, and resolve claims via the admin dashboard
- [ ] Repeat infringer policy triggers ban after 3 upheld strikes
- [ ] DMCA agent info is publicly accessible via `GET /v1/dmca/agent-info`
- [ ] All state transitions are recorded in the moderation audit log
- [ ] 26 unit tests pass
- [ ] 26 E2E tests pass
- [ ] No XSS vectors in stored claim/counter-notice text

---

## 13. Error Handling Matrix

| Error | HTTP Status | Error Code | Admin Message | User Message | Recovery |
|-------|-------------|------------|---------------|-------------|----------|
| `sworn_statement=False` | 400 | `sworn_statement_required` | N/A | "You must affirm under penalty of perjury" | User checks the checkbox |
| `good_faith_belief=False` | 400 | `good_faith_required` | N/A | "You must affirm good faith belief" | User checks the checkbox |
| Content URL not resolvable | 404 | `content_not_found` | N/A | "The referenced content could not be found on this platform" | User verifies the URL |
| Counter-notice by wrong user | 403 | `not_content_creator` | N/A | "Only the content creator can file a counter-notice" | N/A |
| Counter-notice already filed | 409 | `counter_notice_exists` | N/A | "A counter-notice has already been filed for this claim" | N/A |
| Invalid claim state for counter-notice | 409 | `invalid_claim_state` | N/A | "This claim is not in a state that allows counter-notices" | N/A |
| Resolve claim in terminal state | 409 | `claim_already_resolved` | "This claim has already been resolved" | N/A | Admin refreshes dashboard |
| Admin lacks scope | 403 | `role_required_scope` | "You do not have content moderation permissions" | N/A | Contact root |
| Non-ROOT updates agent config | 403 | `root_required` | "Only root administrators can update the DMCA agent" | N/A | Contact root |
| Claim ID not found | 404 | `claim_not_found` | "Claim not found" | "Claim not found" | Verify claim ID |
| `consent_to_jurisdiction=False` | 400 | `consent_required` | N/A | "You must consent to federal court jurisdiction" | User checks the checkbox |
| DDB throttling | 500 | `internal_error` | "Service temporarily unavailable" | "Please try again" | Retry after backoff |

---

## 14. Frontend Component Specifications

### 14.1 DmcaClaimForm Page Layout

```
+---------------------------------------------------------------+
| Submit DMCA Takedown Notice                                    |
+---------------------------------------------------------------+
| This form is for copyright owners to report allegedly          |
| infringing content. Filing a false claim may expose you to     |
| liability under Section 512(f).                                |
|                                                                |
| --- Your Information ---                                       |
| Full Legal Name:  [____________________]                       |
| Email:            [____________________]                       |
| Physical Address: [____________________]                       |
|                   [____________________]                       |
| Phone (optional): [____________________]                       |
|                                                                |
| --- Infringing Content ---                                     |
| Content URL:      [____________________]                       |
| Content Type:     [feed_post v]                                |
|                                                                |
| --- Original Work ---                                          |
| Description of your copyrighted work:                          |
| +------------------------------------------------------------+ |
| | [textarea, 20-5000 chars]                                  | |
| +------------------------------------------------------------+ |
|                                                                |
| --- Legal Statements ---                                       |
| [x] I swear, under penalty of perjury, that the information   |
|     in this notification is accurate and that I am the         |
|     copyright owner or authorized to act on behalf of the      |
|     owner. (Section 512(c)(3)(A)(vi))                         |
|                                                                |
| [x] I have a good faith belief that use of the material is    |
|     not authorized by the copyright owner, its agent, or the  |
|     law. (Section 512(c)(3)(A)(v))                            |
|                                                                |
| Electronic Signature: [____________________]                   |
| (Type your full legal name)                                    |
|                                                                |
|                        [Cancel]  [Submit Claim]                |
+---------------------------------------------------------------+
```

### 14.2 Admin DMCA Dashboard Layout

```
+---------------------------------------------------------------+
| DMCA Claims Dashboard                              [Refresh]   |
+---------------------------------------------------------------+
| Status: [All v]  User: [________]  [Filter]                   |
+---------------------------------------------------------------+
| ID           | Status          | Content    | Creator | Filed  |
+--------------+-----------------+------------+---------+--------+
| dmca_a1b2c3  | content_removed | feed_post  | @bob    | 2h ago |
| dmca_d4e5f6  | waiting_period  | video      | @carol  | 5d ago |
| dmca_g7h8i9  | resolved        | feed_media | @dave   | 12d ago|
+--------------+-----------------+------------+---------+--------+
| [< Prev]                                         [Next >]     |
+---------------------------------------------------------------+

Claim Detail Panel (right side or modal):
+----------------------------------------------+
| DMCA Claim: dmca_a1b2c3                      |
+----------------------------------------------+
| Status: content_removed                      |
| Filed: 2026-05-24 14:23 UTC                 |
| Claimant: John Smith (john@example.com)      |
| Content: /feed/post/post_abc123              |
| Creator: @bob (bob@test.local)               |
|                                              |
| Original Work:                               |
| "This is my photograph of the Golden Gate    |
|  Bridge taken on 2025-03-15..."              |
|                                              |
| --- Repeat Infringer Status ---              |
| Strikes: 1 of 3 | Status: clear             |
|                                              |
| [Restore Content]  [Uphold]  [Escalate]     |
+----------------------------------------------+
```

### 14.3 TypeScript Component Interfaces

```typescript
interface DmcaClaimFormProps {}

interface DmcaCounterNoticeFormProps {
  claimId: string;
  claimDetails: DmcaClaimOut;
}

interface DmcaDashboardPageProps {}

interface DmcaClaimRowProps {
  claim: DmcaClaimOut;
  onSelect: (claimId: string) => void;
  isSelected: boolean;
}

interface DmcaClaimDetailPanelProps {
  claimId: string;
  onResolve: (resolution: string, notes: string) => void;
  onClose: () => void;
}

interface RepeatInfringerBadgeProps {
  status: "clear" | "warning" | "banned";
  strikeCount: number;
  threshold: number;
}
```

---

## 15. Workflow Diagrams

### 15.1 Complete DMCA Claim State Machine with Guard Conditions

```
                 +--------+
                 | filed  |
                 +---+----+
                     |
          [auto: hide_content_for_dmca()]
          [auto: write_audit("dmca_claim_filed")]
          [auto: write_alert(creator)]
          [auto: check_repeat_infringer()]
                     |
                     v
            +-----------------+
            | content_removed |---------> +----------+
            +--------+--------+           | withdrawn|
                     |                    +----------+
          [user: target_user files            ^
           counter-notice]                    |
          [guard: user_id == target_user_id]  |
          [guard: consent_to_jurisdiction]    [admin: claimant retracts
          [auto: write_alert(claimant)]       OR admin determines invalid]
                     |
                     v
        +------------------------+
        | counter_notice_filed   |
        +----------+-------------+
                   |
        [auto: set waiting_period_expires_at
         = now + 14 days]
                   |
                   v
          +----------------+
          | waiting_period |-----------> +-----------+
          +-------+--------+            | escalated  |
                  |                     +-----+------+
       [timer: waiting_period_expires_at      |
        <= now_ts()]                   [admin: court_order
       [guard: status != escalated]     received]
                  |                           |
                  v                           v
            +----------+              +----------+
            | resolved |              | resolved |
            +----------+              +----------+
            (restored)                (court_order)
```

### 15.2 Repeat Infringer Decision Tree

```
On new claim filed for target_user_id:
    |
    v
Query ByTargetUserCreatedAt for target_user_id
    |
    v
Filter: created_at >= (now - LOOKBACK_DAYS * 86400)
Filter: status in {content_removed, resolved, escalated}
Filter: resolution != "restored"
    |
    v
Count upheld claims = N
    |
    +-- N == 0: strike_number = 1, status = "clear"
    |
    +-- N == 1: strike_number = 2, status = "warning"
    |           write_alert(event="dmca_repeat_infringer_warning")
    |
    +-- N >= 2: strike_number = N + 1, status = "banned"
                apply_ban(permanent, reason="dmca_repeat_infringer")
                write_audit("dmca_repeat_infringer_ban")
                write_alert(event="dmca_repeat_infringer_ban")
```

---

## 16. Abuse Prevention

### 16.1 False DMCA Claims (Section 512(f))

Section 512(f) provides remedies against anyone who "knowingly materially misrepresents" that content is infringing. The platform's abuse detection mechanisms:

| Indicator | Detection | Response |
|-----------|-----------|----------|
| Same claimant filing >10 claims/month | `ByClaimantCreatedAt` GSI query | Admin alert; manual review |
| Claims targeting multiple unrelated users | Admin dashboard filter by claimant | Investigation; potential claimant block |
| Claims against fair use content | Admin review during resolution | Resolve as "withdrawn"; flag claimant |
| Automated claim submission patterns | Rate limiting (10 claims/hour/user) | 429 response; IP-level rate limit |

### 16.2 Counter-Notice Abuse

| Vector | Mitigation |
|--------|------------|
| Filing counter-notice without valid legal basis | Counter-notice requires perjury statement under Section 512(g)(3)(C) |
| Filing multiple counter-notices for same claim | Status transition prevents duplicate filing (409 response) |
| Using counter-notice to delay enforcement | Waiting period is mandatory by law; platform cannot shorten it |

### 16.3 Creator Evasion

| Vector | Mitigation |
|--------|------------|
| Re-uploading removed content under different title | Repeat infringer tracking applies to the user, not the content |
| Creating new account after ban | Out of scope for this ticket; requires device fingerprinting |
| Modifying content slightly to avoid detection | Future: content fingerprinting (MOD-006) |
