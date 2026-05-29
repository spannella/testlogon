# PLATFORM-018: Privacy Account Deletion

**Ticket**: PLATFORM-018
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### 1.1 Purpose

PLATFORM-018 closes the gaps in the account deletion pipeline to achieve GDPR-compliant account removal. The codebase already has substantial infrastructure: `app/services/gdpr_service.py` handles export requests, deletion requests with grace periods, billing anonymization, and cascading deletes across 10+ tables. `app/routers/privacy.py` exposes endpoints for requesting deletion, cancellation, and admin approval. The frontend `PrivacyPage.tsx` and `Account.tsx` provide UI for these operations. However, the password re-verification step is a placeholder (`pass` in production), the scheduled deletion job (which runs after the 30-day grace period) does not exist, content handling for posts/messages is incomplete (messages and newsfeed posts are not anonymized), the data export does not include all user data categories, wallet balance is not addressed, and active subscriptions are not cancelled before deletion. This ticket closes all those gaps.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to delete my account so that all my personal data is removed from the platform. | POST creates deletion request; grace period starts; data is scrubbed after grace period expires. |
| User | As a user, I want to re-verify my password before deletion so that unauthorized access cannot delete my account. | Deletion endpoint validates password against Cognito (or session re-auth in dev); rejects wrong password with 401. |
| User | As a user, I want a 30-day grace period to cancel deletion so that I can change my mind. | Deletion request stays in "pending" for 30 days; user can cancel via POST; cancellation resets everything. |
| User | As a user, I want to export my data before deletion so that I keep a copy. | Export request generates ZIP with profile, messages, posts, billing, files; download link valid for 7 days. |
| User | As a user, I want my messages to be anonymized (not deleted) so that conversation partners keep their thread context. | Messages from deleted user show "Deleted User" as sender; message text is scrubbed to "[This message was deleted]". |
| User | As a user, I want my active subscriptions cancelled before deletion so that I am not charged after leaving. | All active subscriber and creator subscriptions are cancelled with refund eligibility check. |
| User | As a user, I want my wallet balance returned before deletion so that I do not lose money. | Wallet balance is zeroed with a "deletion_refund" ledger entry; refund initiated if balance > 0. |
| Admin | As an admin, I want to place a retention hold on an account to prevent deletion during an investigation. | Admin POST sets `retention_hold=true`; user's deletion request is blocked until hold is released. |
| Admin | As an admin, I want to see a complete audit trail of deletion actions. | GET returns timestamped events: request created, grace period started, export completed, deletion executed. |

### 1.3 Why This Is Needed

GDPR Article 17 ("Right to Erasure") and CCPA require platforms to delete personal data upon user request within a reasonable timeframe. The current implementation has critical gaps: password verification is a no-op in production (any authenticated user can trigger deletion without re-authentication), the scheduled deletion job that should fire after the grace period does not exist, and several data categories (messages, newsfeed posts, file manager files, push devices, analytics rollups) are not covered by the deletion cascade. These gaps create legal liability and data leakage risk.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| GDPR service | `app/services/gdpr_service.py` (~810 lines) | `create_deletion_request()` with grace period; `process_deletion()` cascading across 10 tables; `create_export_request()`; `process_export()` ZIP generation; admin hold/approve/reject |
| Privacy router | `app/routers/privacy.py` (~310 lines) | `POST /delete-account`; `POST /requests/{id}/cancel`; admin endpoints for list/approve/reject/hold |
| Privacy frontend | `frontend/src/pages/settings/PrivacyPage.tsx` | Data export request, deletion request, request list, cancel button |
| Account page | `frontend/src/pages/settings/Account.tsx:216` | "Delete Account" section with warning text |
| Data requests table | `T.data_requests` (DDB) | PK: `USER#{user_sub}`, SK: `REQUEST#{request_id}`; GSIs: ByStatus, ByType |
| Audit table | `T.data_request_audit` (DDB) | PK: `REQUEST#{request_id}`, SK: `AUDIT#{ts}#{event_id}` |
| Account service | `app/services/account.py` `delete_user_data()` | Deletes sessions, MFA devices, API keys |
| Settings | `app/core/settings.py` | `privacy_deletion_grace_period_days` (default 30), `privacy_export_rate_limit_hours`, `privacy_export_ttl_days`, `privacy_billing_retention_years`, `privacy_deletion_enabled` |

### 2.2 Gaps

1. **Password verification is a stub** -- `app/routers/privacy.py:148-151`: in production mode the password verification block is `pass` (no-op). Any authenticated session can trigger deletion without re-auth.
2. **No scheduled deletion job** -- `create_deletion_request()` sets `grace_period_ends_at` but no background task checks for expired grace periods and calls `process_deletion()`. Deletion never actually executes unless manually triggered.
3. **Messages not anonymized** -- `process_deletion()` deletes sessions, profile, addresses, contacts, calendar, subscriptions, account state, tickets, video metadata, and billing. It does NOT touch the messages table, newsfeed posts, broadcast chat messages, or file manager files.
4. **Push devices not cleaned up** -- `T.push_devices` rows are not deleted during account deletion.
5. **Analytics rollups not deleted** -- `T.analytics_rollups` rows for the creator are not deleted.
6. **Active subscriptions not cancelled** -- if the user has active subscriptions (as subscriber or creator), they are deleted from DDB but not cancelled with the payment provider; recurring billing continues.
7. **Wallet balance not handled** -- `process_deletion()` deletes non-ledger billing items (including wallet state) but does not issue a refund or zero-balance ledger entry.
8. **Export incomplete** -- `process_export()` collects profile, addresses, contacts, calendar, billing, tickets, and sessions, but omits messages, newsfeed posts, file manager metadata, push devices, and subscription data.
9. **No deletion confirmation email** -- after deletion completes, a notification alert is written but the user's email is already deleted. Pre-deletion confirmation email is not sent.
10. **Frontend lacks password re-entry dialog** -- `PrivacyPage` sends `password` field but the UI does not show a password input in the deletion confirmation dialog.

---

## 3. Technical Design

### 3.1 Password Re-verification

**Modify `app/routers/privacy.py`**:

Replace the placeholder `pass` block with actual verification:

```python
# Production: verify password via Cognito AdminInitiateAuth
if not S.dev_mode:
    if _cognito_available():
        from app.services.cognito_auth import verify_user_password
        if not verify_user_password(user_sub, body.password):
            raise HTTPException(status_code=401, detail="Invalid password")
    else:
        # Non-Cognito production: verify against stored password hash
        from app.services.account import verify_password_hash
        if not verify_password_hash(user_sub, body.password):
            raise HTTPException(status_code=401, detail="Invalid password")
```

**New function in `app/services/cognito_auth.py`** (~30 lines):

```python
def verify_user_password(user_sub: str, password: str) -> bool:
    """Verify password via Cognito AdminInitiateAuth with USER_PASSWORD_AUTH flow."""
    try:
        client = boto3.client("cognito-idp", region_name=S.aws_region)
        resp = client.admin_initiate_auth(
            UserPoolId=S.cognito_user_pool_id,
            ClientId=S.cognito_app_client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user_sub, "PASSWORD": password},
        )
        return "AuthenticationResult" in resp
    except client.exceptions.NotAuthorizedException:
        return False
    except Exception:
        logger.exception("Password verification failed")
        return False
```

### 3.2 Scheduled Deletion Job

**New file: `app/services/deletion_scheduler.py`** (~120 lines)

Background task that runs periodically (every 6 hours) to process expired grace periods:

```python
"""Scheduled deletion processor (PLATFORM-018).

Scans data_requests table for deletion requests where:
- status = "pending"
- grace_period_ends_at <= now_ts()
- retention_hold = False (or absent)

For each qualifying request, calls process_deletion() to execute the full cascade.
"""

import asyncio
import logging
from app.core.time import now_ts
from app.services.gdpr_service import (
    list_requests_by_status, process_deletion, _user_pk, _req_sk
)
from app.core.tables import T

logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = 6 * 3600  # Every 6 hours

async def run_deletion_scanner():
    """Background loop that processes expired deletion requests."""
    while True:
        try:
            _process_expired_deletions()
        except Exception:
            logger.exception("Deletion scanner error")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)

def _process_expired_deletions():
    now = now_ts()
    pending, _ = list_requests_by_status("pending", limit=200)
    for item in pending:
        if item.get("request_type") != "deletion":
            continue
        if item.get("retention_hold"):
            continue
        grace_ends = int(item.get("grace_period_ends_at", 0))
        if grace_ends == 0 or grace_ends > now:
            continue
        user_sub = item.get("user_sub")
        request_id = item.get("request_id")
        if not (user_sub and request_id):
            continue
        logger.info("Processing expired deletion: user=%s request=%s", user_sub, request_id)
        try:
            _send_pre_deletion_email(user_sub)
            process_deletion(user_sub, request_id)
            logger.info("Deletion completed: user=%s request=%s", user_sub, request_id)
        except Exception:
            logger.exception("Deletion failed: user=%s request=%s", user_sub, request_id)
```

Register in `app/main.py` startup:

```python
@app.on_event("startup")
async def start_deletion_scanner():
    if S.privacy_deletion_enabled:
        asyncio.create_task(run_deletion_scanner())
```

### 3.3 Extended Deletion Cascade

**Modify `app/services/gdpr_service.py` `process_deletion()`**:

Add steps after existing Step 10 (video metadata):

```python
# Step 11: Anonymize messages
def _anonymize_user_messages(user_sub: str) -> Dict[str, int]:
    """Find all conversations where user is a participant; anonymize their messages."""
    # Query conversations by participant
    # For each message where sender == user_sub:
    #   Update text = "[This message was deleted]"
    #   Update sender_display_name = "Deleted User"
    #   Remove encryption_envelope if present
    # Return {"conversations_processed": N, "messages_anonymized": M}

# Step 12: Anonymize newsfeed posts
def _anonymize_user_posts(user_sub: str) -> Dict[str, int]:
    """Anonymize or delete newsfeed posts authored by user."""
    # For each post by user_sub:
    #   Set author_display_name = "Deleted User"
    #   Set body = "[This post was deleted]"
    #   Remove image/video references
    #   Keep post shell for comment thread context
    # Return {"posts_anonymized": N}

# Step 13: Delete file manager files
def _delete_user_files(user_sub: str) -> Dict[str, int]:
    """Delete all file manager entries and S3 objects for user."""
    # Query files table by owner
    # Delete S3 objects (if S3 integration active)
    # Delete DDB entries
    # Return {"files_deleted": N}

# Step 14: Delete push devices
def _delete_push_devices(user_sub: str) -> int:
    devices = list_push_devices(user_sub)
    for d in devices:
        revoke_push_device(user_sub, d["device_id"])
    return len(devices)

# Step 15: Delete analytics rollups
def _delete_analytics_rollups(user_sub: str) -> int:
    items = _query_all(T.analytics_rollups, Key("pk").eq(f"CREATOR#{user_sub}"))
    for item in items:
        T.analytics_rollups.delete_item(Key={"pk": f"CREATOR#{user_sub}", "sk": item["sk"]})
    return len(items)

# Step 16: Cancel active subscriptions
def _cancel_subscriptions(user_sub: str) -> Dict[str, int]:
    """Cancel all active subscriptions (as subscriber and as creator)."""
    # As subscriber: query subscriptions where subscriber == user_sub
    # As creator: query plans where creator == user_sub, cancel all active subscribers
    # Return {"subscriber_cancelled": N, "creator_plans_cancelled": M}

# Step 17: Handle wallet balance
def _handle_wallet_balance(user_sub: str) -> Dict[str, Any]:
    """Zero wallet balance with deletion_refund ledger entry."""
    # Get current wallet balance from billing table
    # If balance > 0: write LEDGER entry with reason="deletion_refund"
    # Set wallet balance to 0
    # Return {"refunded_cents": N}
```

### 3.4 Extended Data Export

**Modify `app/services/gdpr_service.py` `process_export()`**:

Add export sections for missing data categories:

```python
# Add to _collect_export_data():

if categories.get("messages", True):
    # Export all conversations and messages
    # Include: conversation_id, participants, messages (text, sender, timestamp)
    # Exclude: encryption keys, internal metadata

if categories.get("posts", True):
    # Export all newsfeed posts authored by user
    # Include: post_id, body, created_at, media URLs, comment count

if categories.get("files", True):
    # Export file manager metadata (not file contents -- too large)
    # Include: file_id, name, size, created_at, path

if categories.get("push_devices", True):
    # Export push device registrations
    # Include: device_id, platform, created_at (NOT token)

if categories.get("subscriptions", True):
    # Export subscription history
    # Include: plan_name, status, start_date, end_date, amount
```

### 3.5 Request/Response Model Updates

**Modify in `app/models.py`**:

```python
# -- Privacy Account Deletion (PLATFORM-018) --

class DeleteAccountRequestIn(BaseModel):
    password: str = Field(min_length=1, max_length=200)
    reason: Optional[str] = Field(None, max_length=500)
    confirm_text: str = Field(..., description="Must be 'DELETE MY ACCOUNT'")

    @validator("confirm_text")
    def validate_confirm(cls, v):
        if v != "DELETE MY ACCOUNT":
            raise ValueError("Confirmation text must be exactly 'DELETE MY ACCOUNT'")
        return v

class ExportRequestIn(BaseModel):
    categories: Dict[str, bool] = Field(
        default_factory=lambda: {
            "profile": True, "messages": True, "posts": True, "billing": True,
            "files": True, "contacts": True, "calendar": True, "subscriptions": True,
            "push_devices": True, "tickets": True, "sessions": True,
        }
    )

class DeletionStatusOut(BaseModel):
    request_id: str
    status: str  # pending | processing | completed | cancelled | failed
    created_at: int
    grace_period_ends_at: Optional[int] = None
    grace_days_remaining: Optional[int] = None
    deletion_summary: Optional[Dict[str, Any]] = None
    retention_hold: bool = False
    retention_hold_reason: Optional[str] = None
    can_cancel: bool = False

class DeletionSummaryOut(BaseModel):
    billing_anonymized: int = 0
    billing_deleted: int = 0
    core_tables_deleted: bool = False
    profile_deleted: bool = False
    addresses_deleted: int = 0
    contacts_deleted: int = 0
    calendar_events_deleted: int = 0
    subscriptions_deleted: int = 0
    account_state_deleted: bool = False
    tickets_deleted: int = 0
    videos_deleted: int = 0
    messages_anonymized: int = 0
    posts_anonymized: int = 0
    files_deleted: int = 0
    push_devices_deleted: int = 0
    analytics_deleted: int = 0
    subscriptions_cancelled: int = 0
    wallet_refunded_cents: int = 0
```

### 3.6 Frontend Changes

**Modify `frontend/src/pages/settings/PrivacyPage.tsx`** (~80 lines added):

Add password re-entry dialog to the deletion flow:

```
Deletion Flow:
1. User clicks "Delete My Account"
2. Confirmation dialog opens:
   ├── Warning text listing consequences
   ├── Password input field
   ├── Confirmation text input ("Type DELETE MY ACCOUNT")
   ├── Grace period notice (30 days to cancel)
   └── "Delete My Account" button (red, disabled until password + confirm text)
3. On submit: POST /ui/privacy/delete-account with password, reason, confirm_text
4. On success: show "Deletion scheduled" banner with cancel button + countdown
```

**Modify `frontend/src/pages/settings/Account.tsx`** (~20 lines):

Update the delete account section to link to PrivacyPage instead of inline dialog.

### 3.7 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/deletion_scheduler.py` | Background deletion processor | ~120 |
| `app/services/cognito_auth.py` | Cognito password verification (if not existing) | ~30 |
| `frontend/e2e/privacy-deletion.spec.ts` | E2E tests | ~500 |

### 3.8 Files to Modify

| File | Change |
|------|--------|
| `app/services/gdpr_service.py` | Add Steps 11-17 to `process_deletion()`; extend `process_export()` with messages, posts, files, subscriptions |
| `app/routers/privacy.py` | Replace password stub with real verification; add `confirm_text` validation |
| `app/models.py` | Update `DeleteAccountRequestIn` with `confirm_text`; add `DeletionStatusOut`, `DeletionSummaryOut`, update `ExportRequestIn` categories |
| `app/main.py` | Register deletion scanner background task at startup |
| `app/core/settings.py` | Add `privacy_pre_deletion_email_enabled` setting |
| `frontend/src/pages/settings/PrivacyPage.tsx` | Add password input + confirm text to deletion dialog; show grace period countdown |
| `frontend/src/pages/settings/Account.tsx` | Link to privacy page for deletion |
| `frontend/src/api/endpoints/privacy.ts` | Update request type with confirm_text |
| `frontend/src/api/types.ts` | Update deletion-related TypeScript types |

---

## 4. Deletion Lifecycle

### 4.1 State Machine

```
                        User Request
                             │
                             ▼
                    ┌─────────────────┐
                    │     pending     │ ◄── grace_period_ends_at set
                    │  (30 day grace) │     user can cancel
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │  cancelled   │ │  processing  │ │    held      │
    │ (user cancel)│ │ (grace ended)│ │(admin hold)  │
    └──────────────┘ └──────┬───────┘ └──────┬───────┘
                            │                │
                            ▼                │ (admin release)
                    ┌──────────────┐         │
                    │  completed   │ ◄───────┘
                    │ (data wiped) │
                    └──────────────┘
```

### 4.2 Grace Period Mechanics

- Default: 30 days (`privacy_deletion_grace_period_days`).
- `grace_period_ends_at` is set at request creation time.
- During grace period: user can log in, use the platform, and cancel.
- After grace period: deletion scanner picks up the request and executes.
- On cancellation: status set to `cancelled`; no further action taken.

### 4.3 Pre-Deletion Email

Before executing deletion, the system sends a final email to the user's registered email:

- Subject: "Your account deletion is being processed"
- Body: summary of what will be deleted; link to contact support if this is an error.
- Sent BEFORE profile deletion so the email address is still available.

### 4.4 Post-Deletion State

After deletion completes:
- User cannot log in (session records deleted; Cognito user disabled).
- Profile resolves to "Deleted User" for other users' conversation views.
- Messages show "[This message was deleted]" with "Deleted User" sender.
- Posts show "[This post was deleted]" with "Deleted User" author.
- Billing ledger entries are anonymized (PII removed, amounts kept for accounting).
- All other data (contacts, calendar, tickets, files, devices, analytics) is hard-deleted.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/privacy-deletion.spec.ts`

### Section 531: Password Verification API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 531.1 | Deletion with empty password returns 401 | POST `/ui/privacy/delete-account` with `password=""`; 401 |
| 531.2 | Deletion with wrong password returns 401 | POST with `password="wrong_password"`, `confirm_text="DELETE MY ACCOUNT"`; 401 |
| 531.3 | Deletion without confirm_text returns 422 | POST with password but no `confirm_text`; 422 |
| 531.4 | Deletion with wrong confirm_text returns 422 | POST with `confirm_text="delete"`; 422 |

### Section 532: Deletion Request Lifecycle API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 532.1 | Create deletion request sets pending status with grace period | POST with valid password + confirm; 201; response has `status=pending`, `grace_period_ends_at` > now |
| 532.2 | Cannot create second deletion while one is pending | POST again; 409 response |
| 532.3 | Cancel deletion request during grace period | POST `/requests/{id}/cancel`; 200; status becomes `cancelled` |
| 532.4 | Cannot cancel after grace period expires | (Use DDB direct write to set `grace_period_ends_at` in past); POST cancel; 409 |
| 532.5 | List requests shows deletion with correct status | GET `/ui/privacy/requests`; response includes the request with all fields |

### Section 533: Data Export API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 533.1 | Create export request with all categories | POST `/ui/privacy/export` with all categories true; 201; status is `pending` |
| 533.2 | Export rate limiting prevents rapid requests | POST export; immediately POST again; 429 |
| 533.3 | Export request status transitions to completed | (Process synchronously in dev); GET request; status is `completed` or `pending` |

### Section 534: Admin Deletion Management API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 534.1 | Admin can list pending deletion requests | Root GET `/ui/admin/privacy/requests?status=pending`; response includes test deletion request |
| 534.2 | Admin can place retention hold | Root POST `/ui/admin/privacy/requests/{id}/hold` with reason; 200; request has `retention_hold=true` |
| 534.3 | Admin can release retention hold | Root POST `/ui/admin/privacy/requests/{id}/release-hold`; 200; `retention_hold=false` |
| 534.4 | Admin can view deletion audit trail | Root GET `/ui/admin/privacy/requests/{id}/audit`; response has entries for created, hold, release |

### Section 534: Admin Deletion Management + Privacy Page UI (combined, 6 tests)

Sections 534.1-534.4 are the admin tests listed above. Two additional UI tests:

| # | Test Title | Assertion |
|---|-----------|-----------|
| 534.5 | Delete Account dialog shows password and confirmation inputs | Navigate to `/settings/privacy`; click "Delete Account"; dialog has password input, confirm text input, and red delete button |
| 534.6 | Delete button is disabled until password and confirm text are entered | Dialog opens; delete button is disabled; type password + "DELETE MY ACCOUNT"; button becomes enabled |

**Total E2E tests: 18**

---

## 6. Security Considerations

### 6.1 Password Re-verification

- Password is verified against Cognito in production (AdminInitiateAuth with USER_PASSWORD_AUTH flow).
- In dev mode, any non-empty password is accepted (consistent with dev auth pattern).
- Failed password attempts are rate-limited by the existing `enforce_lockout()` mechanism.
- Password is never logged or stored; used only for the Cognito verification call.

### 6.2 Confirmation Text

- User must type exactly "DELETE MY ACCOUNT" to confirm. This prevents accidental deletion and ensures informed consent.
- Validated server-side; 422 if incorrect.

### 6.3 Grace Period Protection

- 30-day grace period gives users time to reconsider.
- During grace period, user retains full account access.
- Cancellation is allowed any time before the grace period ends.
- Admin retention hold blocks deletion even after grace period expires.

### 6.4 Data Anonymization vs Deletion

- **Anonymize** (keep structure, scrub PII): messages, billing ledger entries (within retention window), newsfeed posts.
- **Hard delete** (remove entirely): profile, sessions, MFA, API keys, contacts, calendar, addresses, files, push devices, analytics, tickets.
- This split ensures conversation context is preserved for other users while PII is fully removed.

### 6.5 Audit Trail

- All deletion lifecycle events are recorded in `T.data_request_audit` with actor, action, and timestamp.
- Audit trail is retained for 90 days after deletion (for compliance review).
- Admin actions (hold, release, approve) are logged with admin_sub.

### 6.6 Rate Limiting

- Deletion request: max 3 per user per 24 hours (prevents abuse after cancellation).
- Export request: max 1 per user per `privacy_export_rate_limit_hours` (default 24).
- Admin endpoints: inherit admin rate limiter.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/gdpr_service.py` | Exists (modify) | Core deletion/export logic; extend cascade |
| `app/routers/privacy.py` | Exists (modify) | Password verification; confirm_text validation |
| `T.data_requests` table | Exists | Deletion/export request storage |
| `T.data_request_audit` table | Exists | Audit trail |
| `app/services/account.py` | Exists | `delete_user_data()` for sessions/MFA/API keys |
| `app/services/push.py` | Exists | `list_push_devices()`, `revoke_push_device()` for cleanup |
| `app/core/settings.py` | Exists (modify) | Deletion scheduler settings |
| `frontend/src/pages/settings/PrivacyPage.tsx` | Exists (modify) | Password dialog, confirm text |
| Cognito (moto mock in dev) | Exists | Password verification via AdminInitiateAuth |

---

## 8. Acceptance Criteria

1. Password re-verification blocks deletion without valid credentials (not a stub).
2. Confirmation text "DELETE MY ACCOUNT" is required and validated server-side.
3. Deletion request enters 30-day grace period; user can cancel during grace.
4. Scheduled deletion job processes expired grace periods automatically.
5. Messages from deleted users are anonymized to "[This message was deleted]" with "Deleted User" sender.
6. Newsfeed posts from deleted users are anonymized with "Deleted User" author.
7. Push devices, analytics rollups, and file manager entries are deleted.
8. Active subscriptions are cancelled before deletion.
9. Wallet balance > 0 triggers a "deletion_refund" ledger entry.
10. Data export includes messages, posts, files, subscriptions, and push devices.
11. Admin retention hold prevents deletion even after grace period.
12. Pre-deletion email is sent before profile is deleted.
13. All 18 E2E tests pass.
