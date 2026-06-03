# PLATFORM-018: Privacy Account Deletion

**Ticket**: PLATFORM-018
**Author**: Engineering
**Status**: Implemented
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

## 2. Architecture Diagram

```
 User (Browser)                    Backend (FastAPI)                     DynamoDB / S3
 ──────────────                    ────────────────                     ──────────────
      │                                  │                                   │
      │  1. POST /delete-account         │                                   │
      │  {password, confirm_text}        │                                   │
      │─────────────────────────────────►│                                   │
      │                                  │  2. Verify password (Cognito)     │
      │                                  │─────────────────►Cognito Mock     │
      │                                  │◄─────────────────(pass/fail)      │
      │                                  │                                   │
      │                                  │  3. Validate confirm_text         │
      │                                  │     == "DELETE MY ACCOUNT"        │
      │                                  │                                   │
      │                                  │  4. Create deletion request       │
      │                                  │─────────────────────────────────►│
      │                                  │   T.data_requests:               │
      │                                  │   PK=USER#{sub}                  │
      │                                  │   SK=REQUEST#{id}                │
      │                                  │   status=pending                 │
      │                                  │   grace_period_ends_at=+30d      │
      │                                  │                                   │
      │                                  │  5. Write audit entry             │
      │                                  │─────────────────────────────────►│
      │                                  │   T.data_request_audit:          │
      │                                  │   PK=REQUEST#{id}                │
      │                                  │   SK=AUDIT#{ts}#{evt_id}         │
      │◄─────────────────────────────────│  6. Return 201 + request info    │
      │                                  │                                   │
      │                                  │                                   │
 ═══════════════════ After 30-day grace period ═══════════════════════════════
      │                                  │                                   │
      │    Deletion Scheduler (bg task)  │                                   │
      │                                  │  7. Scan pending requests         │
      │                                  │     where grace_period_ends_at    │
      │                                  │     <= now AND !retention_hold    │
      │                                  │─────────────────────────────────►│
      │                                  │  ◄── qualifying requests          │
      │                                  │                                   │
      │                                  │  8. Send pre-deletion email       │
      │                                  │                                   │
      │                                  │  9. Execute deletion cascade      │
      │                                  │     Step 1-10: existing tables    │
      │                                  │     Step 11: anonymize messages   │
      │                                  │     Step 12: anonymize posts      │
      │                                  │     Step 13: delete files + S3    │
      │                                  │     Step 14: delete push devices  │
      │                                  │     Step 15: delete analytics     │
      │                                  │     Step 16: cancel subscriptions │
      │                                  │     Step 17: refund wallet        │
      │                                  │─────────────────────────────────►│
      │                                  │                                   │
      │                                  │  10. Mark request completed       │
      │                                  │─────────────────────────────────►│
      │                                  │                                   │

 ═══════════════════ Admin Hold Flow ═════════════════════════════════════════
      │                                  │                                   │
 Admin│  POST /requests/{id}/hold        │                                   │
      │─────────────────────────────────►│                                   │
      │                                  │  Update retention_hold=true       │
      │                                  │─────────────────────────────────►│
      │                                  │  Write audit: "hold_placed"       │
      │                                  │─────────────────────────────────►│
      │◄─────────────────────────────────│  200 OK                           │

 ═══════════════════ Data Export Flow ════════════════════════════════════════
      │                                  │                                   │
 User │  POST /export                    │                                   │
      │─────────────────────────────────►│                                   │
      │                                  │  Collect: profile, messages,      │
      │                                  │  posts, billing, files metadata,  │
      │                                  │  contacts, calendar, subs,        │
      │                                  │  push devices, tickets, sessions  │
      │                                  │─────────────────────────────────►│
      │                                  │                                   │
      │                                  │  Generate ZIP → upload to S3      │
      │                                  │─────────────────────────────────►│ S3: exports/
      │                                  │                                   │
      │◄─────────────────────────────────│  201 + download URL (7-day TTL)   │
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

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

### 3.2 Gaps

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

## 4. DynamoDB Access Patterns

### 4.1 Data Requests Table

| # | Operation | Table | Key / Index | Condition | Frequency |
|---|-----------|-------|-------------|-----------|-----------|
| 1 | Create deletion request | `data_requests` | PK=`USER#{sub}`, SK=`REQUEST#{id}` | `attribute_not_exists(pk)` | Per delete |
| 2 | Get request by user + id | `data_requests` | PK=`USER#{sub}`, SK=`REQUEST#{id}` | None | Per status check |
| 3 | List user's requests | `data_requests` | PK=`USER#{sub}`, SK begins_with `REQUEST#` | None | Per list |
| 4 | List by status (admin) | `data_requests` | GSI: ByStatus, PK=`pending` | None | Scanner every 6h |
| 5 | Cancel request | `data_requests` | PK=`USER#{sub}`, SK=`REQUEST#{id}` | `status = :pending` | Per cancel |
| 6 | Set retention hold | `data_requests` | PK=`USER#{sub}`, SK=`REQUEST#{id}` | `status = :pending` | Admin action |
| 7 | Mark completed | `data_requests` | PK=`USER#{sub}`, SK=`REQUEST#{id}` | `status IN (:pending, :processing)` | Post-deletion |

### 4.2 Audit Trail Table

| # | Operation | Table | Key / Index | Condition | Frequency |
|---|-----------|-------|-------------|-----------|-----------|
| 1 | Write audit event | `data_request_audit` | PK=`REQUEST#{id}`, SK=`AUDIT#{ts}#{evt_id}` | None | Per lifecycle event |
| 2 | List audit for request | `data_request_audit` | PK=`REQUEST#{id}`, SK begins_with `AUDIT#` | ScanIndexForward=True | Admin view |

### 4.3 Example DynamoDB Items

**Deletion Request Item:**

```json
{
  "pk": "USER#e2e_alice@test.local",
  "sk": "REQUEST#req_a1b2c3d4e5f6",
  "request_id": "req_a1b2c3d4e5f6",
  "user_sub": "e2e_alice@test.local",
  "request_type": "deletion",
  "status": "pending",
  "reason": "Leaving the platform",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "grace_period_ends_at": 1751112000,
  "retention_hold": false,
  "retention_hold_reason": null,
  "GSI1PK": "STATUS#pending",
  "GSI1SK": 1748520000,
  "GSI2PK": "TYPE#deletion",
  "GSI2SK": 1748520000
}
```

**Audit Trail Item:**

```json
{
  "pk": "REQUEST#req_a1b2c3d4e5f6",
  "sk": "AUDIT#1748520000#evt_0001",
  "event_id": "evt_0001",
  "event_type": "deletion_requested",
  "actor": "e2e_alice@test.local",
  "actor_role": "user",
  "timestamp": 1748520000,
  "details": {
    "grace_period_days": 30,
    "grace_period_ends_at": 1751112000,
    "reason": "Leaving the platform"
  }
}
```

**Deletion Summary Item (after completion):**

```json
{
  "pk": "USER#e2e_alice@test.local",
  "sk": "REQUEST#req_a1b2c3d4e5f6",
  "request_id": "req_a1b2c3d4e5f6",
  "status": "completed",
  "completed_at": 1751112600,
  "deletion_summary": {
    "billing_anonymized": 47,
    "billing_deleted": 3,
    "core_tables_deleted": true,
    "profile_deleted": true,
    "addresses_deleted": 2,
    "contacts_deleted": 15,
    "calendar_events_deleted": 8,
    "subscriptions_deleted": 3,
    "tickets_deleted": 5,
    "videos_deleted": 12,
    "messages_anonymized": 342,
    "posts_anonymized": 28,
    "files_deleted": 67,
    "push_devices_deleted": 3,
    "analytics_deleted": 90,
    "subscriptions_cancelled": 2,
    "wallet_refunded_cents": 4500
  }
}
```

---

## 5. Technical Design

### 5.1 Password Re-verification

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

### 5.2 Scheduled Deletion Job

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

### 5.3 Extended Deletion Cascade

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

### 5.4 Extended Data Export

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

---

## 6. API Request/Response Examples

### 6.1 Request Account Deletion

```bash
curl -X POST http://localhost:8000/ui/privacy/delete-account \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value" \
  -H "x-csrf-token: csrf_token_value" \
  -d '{
    "password": "MyStr0ngP@ss!",
    "confirm_text": "DELETE MY ACCOUNT",
    "reason": "No longer using the platform"
  }'
```

**Response (201):**
```json
{
  "request_id": "req_a1b2c3d4e5f67890",
  "status": "pending",
  "created_at": 1748520000,
  "grace_period_ends_at": 1751112000,
  "grace_days_remaining": 30,
  "can_cancel": true,
  "retention_hold": false
}
```

### 6.2 Cancel Deletion Request

```bash
curl -X POST http://localhost:8000/ui/privacy/requests/req_a1b2c3d4e5f67890/cancel \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value" \
  -H "x-csrf-token: csrf_token_value"
```

**Response (200):**
```json
{
  "ok": true,
  "request_id": "req_a1b2c3d4e5f67890",
  "status": "cancelled",
  "cancelled_at": 1748606400
}
```

### 6.3 Request Data Export

```bash
curl -X POST http://localhost:8000/ui/privacy/export \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_csrf=csrf_token_value" \
  -H "x-csrf-token: csrf_token_value" \
  -d '{
    "categories": {
      "profile": true,
      "messages": true,
      "posts": true,
      "billing": true,
      "files": true,
      "contacts": true,
      "calendar": true,
      "subscriptions": true,
      "push_devices": true,
      "tickets": true,
      "sessions": true
    }
  }'
```

**Response (201):**
```json
{
  "request_id": "req_exp_9f8e7d6c5b4a",
  "status": "pending",
  "created_at": 1748520000,
  "estimated_completion_seconds": 120,
  "categories_requested": 11
}
```

### 6.4 Admin List Pending Deletions

```bash
curl http://localhost:8000/ui/admin/privacy/requests?status=pending \
  -H "Cookie: ui_session=root_session_id; ui_csrf=root_csrf" \
  -H "x-csrf-token: root_csrf"
```

**Response (200):**
```json
{
  "requests": [
    {
      "request_id": "req_a1b2c3d4e5f67890",
      "user_sub": "e2e_alice@test.local",
      "request_type": "deletion",
      "status": "pending",
      "created_at": 1748520000,
      "grace_period_ends_at": 1751112000,
      "retention_hold": false
    }
  ],
  "total": 1,
  "next_cursor": null
}
```

### 6.5 Admin Place Retention Hold

```bash
curl -X POST http://localhost:8000/ui/admin/privacy/requests/req_a1b2c3d4e5f67890/hold \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=root_session_id; ui_csrf=root_csrf" \
  -H "x-csrf-token: root_csrf" \
  -d '{
    "reason": "Active fraud investigation - case #FR-2026-0421"
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "request_id": "req_a1b2c3d4e5f67890",
  "retention_hold": true,
  "retention_hold_reason": "Active fraud investigation - case #FR-2026-0421",
  "held_by": "root.admin@testdev.local",
  "held_at": 1748606400
}
```

### 6.6 Admin View Deletion Audit Trail

```bash
curl http://localhost:8000/ui/admin/privacy/requests/req_a1b2c3d4e5f67890/audit \
  -H "Cookie: ui_session=root_session_id; ui_csrf=root_csrf"
```

**Response (200):**
```json
{
  "request_id": "req_a1b2c3d4e5f67890",
  "events": [
    {
      "event_id": "evt_0001",
      "event_type": "deletion_requested",
      "actor": "e2e_alice@test.local",
      "timestamp": 1748520000,
      "details": {"grace_period_days": 30}
    },
    {
      "event_id": "evt_0002",
      "event_type": "hold_placed",
      "actor": "root.admin@testdev.local",
      "timestamp": 1748606400,
      "details": {"reason": "Active fraud investigation - case #FR-2026-0421"}
    },
    {
      "event_id": "evt_0003",
      "event_type": "hold_released",
      "actor": "root.admin@testdev.local",
      "timestamp": 1748692800,
      "details": {}
    }
  ]
}
```

### 6.7 Get Deletion Request Status

```bash
curl http://localhost:8000/ui/privacy/requests/req_a1b2c3d4e5f67890 \
  -H "Cookie: ui_session=sess_abc123"
```

**Response (200):**
```json
{
  "request_id": "req_a1b2c3d4e5f67890",
  "status": "pending",
  "created_at": 1748520000,
  "grace_period_ends_at": 1751112000,
  "grace_days_remaining": 22,
  "retention_hold": false,
  "can_cancel": true,
  "deletion_summary": null
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Detail | Recovery |
|---|----------|-------------|------------|--------|----------|
| 1 | Empty password | 422 | `validation_error` | "ensure this value has at least 1 characters" | Provide non-empty password |
| 2 | Wrong password | 401 | `invalid_password` | "Invalid password" | Re-enter correct password |
| 3 | Missing confirm_text | 422 | `validation_error` | "field required" | Add confirm_text to request |
| 4 | Wrong confirm_text | 422 | `validation_error` | "Confirmation text must be exactly 'DELETE MY ACCOUNT'" | Type exact text |
| 5 | Existing pending deletion | 409 | `duplicate_request` | "A deletion request is already pending" | Cancel existing first |
| 6 | Cancel after grace expired | 409 | `grace_expired` | "Grace period has expired; deletion is being processed" | Contact support |
| 7 | Cancel non-pending request | 409 | `invalid_status` | "Request is not in pending status" | No action available |
| 8 | Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Log in first |
| 9 | CSRF token missing | 403 | `csrf_error` | "CSRF token missing" | Include x-csrf-token header |
| 10 | Rate limit (3 requests/24h) | 429 | `rate_limited` | "Too many deletion requests. Try again later." | Wait 24 hours |
| 11 | Export rate limit | 429 | `rate_limited` | "Export already requested within the last 24 hours" | Wait 24 hours |
| 12 | Admin hold on non-pending | 409 | `invalid_status` | "Can only hold pending requests" | Check request status |
| 13 | Non-admin access admin endpoint | 403 | `forbidden` | "Admin access required" | Use admin account |
| 14 | Deletion disabled by feature flag | 503 | `service_unavailable` | "Account deletion is temporarily unavailable" | Wait for re-enable |
| 15 | Cognito password verification failure | 500 | `internal_error` | "Password verification service unavailable" | Retry later |
| 16 | Request not found | 404 | `not_found` | "Deletion request not found" | Check request ID |
| 17 | Wallet refund failure | 500 (partial) | `refund_failed` | "Wallet refund failed; deletion paused" | Admin intervention |

---

## 8. Pydantic Model Definitions

```python
# -- Privacy Account Deletion (PLATFORM-018) --

from pydantic import BaseModel, Field, validator
from typing import Any, Dict, List, Optional

class DeleteAccountRequestIn(BaseModel):
    """Request body for POST /ui/privacy/delete-account."""
    password: str = Field(min_length=1, max_length=200, description="User's current password for re-verification")
    reason: Optional[str] = Field(None, max_length=500, description="Optional reason for leaving")
    confirm_text: str = Field(..., description="Must be 'DELETE MY ACCOUNT'")

    @validator("confirm_text")
    def validate_confirm(cls, v):
        if v != "DELETE MY ACCOUNT":
            raise ValueError("Confirmation text must be exactly 'DELETE MY ACCOUNT'")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "password": "MyStr0ngP@ss!",
                "confirm_text": "DELETE MY ACCOUNT",
                "reason": "No longer using the platform"
            }
        }


class ExportRequestIn(BaseModel):
    """Request body for POST /ui/privacy/export."""
    categories: Dict[str, bool] = Field(
        default_factory=lambda: {
            "profile": True, "messages": True, "posts": True, "billing": True,
            "files": True, "contacts": True, "calendar": True, "subscriptions": True,
            "push_devices": True, "tickets": True, "sessions": True,
        },
        description="Map of data category to include/exclude"
    )

    @validator("categories")
    def validate_categories(cls, v):
        valid_keys = {"profile", "messages", "posts", "billing", "files",
                      "contacts", "calendar", "subscriptions", "push_devices",
                      "tickets", "sessions"}
        invalid = set(v.keys()) - valid_keys
        if invalid:
            raise ValueError(f"Unknown categories: {', '.join(invalid)}")
        return v


class DeletionStatusOut(BaseModel):
    """Response for GET /ui/privacy/requests/{request_id} and POST /delete-account."""
    request_id: str
    status: str  # pending | processing | completed | cancelled | failed
    created_at: int
    grace_period_ends_at: Optional[int] = None
    grace_days_remaining: Optional[int] = None
    deletion_summary: Optional[Dict[str, Any]] = None
    retention_hold: bool = False
    retention_hold_reason: Optional[str] = None
    can_cancel: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "req_a1b2c3d4e5f67890",
                "status": "pending",
                "created_at": 1748520000,
                "grace_period_ends_at": 1751112000,
                "grace_days_remaining": 30,
                "can_cancel": True,
                "retention_hold": False
            }
        }


class DeletionSummaryOut(BaseModel):
    """Breakdown of what was deleted/anonymized during deletion cascade."""
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


class RetentionHoldIn(BaseModel):
    """Request body for admin hold placement."""
    reason: str = Field(min_length=5, max_length=500, description="Reason for placing hold")


class RetentionHoldOut(BaseModel):
    """Response for admin hold actions."""
    ok: bool = True
    request_id: str
    retention_hold: bool
    retention_hold_reason: Optional[str] = None
    held_by: Optional[str] = None
    held_at: Optional[int] = None


class AuditEventOut(BaseModel):
    """A single audit trail event."""
    event_id: str
    event_type: str
    actor: str
    timestamp: int
    details: Dict[str, Any] = Field(default_factory=dict)


class AuditTrailOut(BaseModel):
    """Full audit trail for a request."""
    request_id: str
    events: List[AuditEventOut] = Field(default_factory=list)


class ExportStatusOut(BaseModel):
    """Response for export request status."""
    request_id: str
    status: str  # pending | processing | completed | failed
    created_at: int
    completed_at: Optional[int] = None
    download_url: Optional[str] = None
    download_expires_at: Optional[int] = None
    categories_requested: int = 0
    file_size_bytes: Optional[int] = None
```

---

## 9. Frontend Component Tree

```
PrivacyPage
├── PageHeader
│   ├── Title: "Privacy & Data"
│   └── Description: "Manage your data, export, and account deletion"
├── Card: "Data Export"
│   ├── Text: explanation of what data is included
│   ├── CategoryCheckboxes (11 categories)
│   │   ├── Checkbox: "Profile" (default: checked)
│   │   ├── Checkbox: "Messages" (default: checked)
│   │   ├── Checkbox: "Posts" (default: checked)
│   │   ├── Checkbox: "Billing" (default: checked)
│   │   ├── Checkbox: "Files" (default: checked)
│   │   ├── Checkbox: "Contacts" (default: checked)
│   │   ├── Checkbox: "Calendar" (default: checked)
│   │   ├── Checkbox: "Subscriptions" (default: checked)
│   │   ├── Checkbox: "Push Devices" (default: checked)
│   │   ├── Checkbox: "Tickets" (default: checked)
│   │   └── Checkbox: "Sessions" (default: checked)
│   ├── Button: "Request Export" (primary)
│   └── ExportRequestList (previous exports)
│       └── For each export:
│           ├── Status badge (pending/completed/failed)
│           ├── Created date
│           └── Download link (if completed, 7-day TTL)
├── Card: "Deletion Requests"
│   ├── ActiveDeletionBanner (if pending request exists)
│   │   ├── AlertTriangle icon
│   │   ├── Text: "Your account is scheduled for deletion on {date}"
│   │   ├── GracePeriodCountdown (days/hours remaining)
│   │   └── Button: "Cancel Deletion" (destructive variant)
│   └── RequestHistoryTable
│       └── For each request:
│           ├── Type (deletion/export)
│           ├── Status badge
│           ├── Created date
│           └── Actions (cancel if pending)
├── Card: "Delete Account"
│   ├── AlertTriangle icon (red)
│   ├── Warning text: "This action is irreversible after 30 days..."
│   ├── Bullet list of consequences:
│   │   ├── "Your profile will be permanently deleted"
│   │   ├── "Your messages will be anonymized"
│   │   ├── "Your posts will be anonymized"
│   │   ├── "Your files will be permanently deleted"
│   │   ├── "Active subscriptions will be cancelled"
│   │   └── "Wallet balance will be refunded"
│   └── Button: "Delete My Account" (red, opens dialog)
└── DeleteAccountDialog (modal)
    ├── DialogHeader: "Delete Your Account"
    ├── DialogDescription: warning text
    ├── Form
    │   ├── PasswordInput
    │   │   ├── Label: "Enter your password"
    │   │   ├── Input type="password" (required)
    │   │   └── FormMessage (error state)
    │   ├── ConfirmTextInput
    │   │   ├── Label: 'Type "DELETE MY ACCOUNT" to confirm'
    │   │   ├── Input type="text" (required)
    │   │   └── FormMessage (error state)
    │   ├── ReasonInput (optional)
    │   │   ├── Label: "Why are you leaving? (optional)"
    │   │   └── Textarea maxLength={500}
    │   └── GracePeriodNotice
    │       ├── Info icon
    │       └── Text: "You will have 30 days to cancel"
    ├── DialogFooter
    │   ├── Button: "Cancel" (ghost, closes dialog)
    │   └── Button: "Delete My Account" (destructive, disabled until valid)
    └── State:
        ├── password (string)
        ├── confirmText (string)
        ├── reason (string)
        ├── isSubmitting (boolean)
        └── isValid = password.length > 0 && confirmText === "DELETE MY ACCOUNT"
```

### 9.1 Props Interfaces

```typescript
interface DeleteAccountDialogProps {
  open: boolean;
  onClose: () => void;
  onDeleted: (request: DeletionStatusOut) => void;
}

interface GracePeriodCountdownProps {
  endsAt: number; // Unix timestamp
  onExpired?: () => void;
}

interface ExportCategorySelectorProps {
  categories: Record<string, boolean>;
  onChange: (categories: Record<string, boolean>) => void;
}

interface DeletionBannerProps {
  request: DeletionStatusOut;
  onCancel: () => void;
}
```

### 9.2 State Management

```typescript
// React Query keys
const PRIVACY_KEYS = {
  requests: ["privacy", "requests"] as const,
  request: (id: string) => ["privacy", "requests", id] as const,
  exports: ["privacy", "exports"] as const,
};

// Mutations
const useDeleteAccount = () => useMutation({
  mutationFn: (data: DeleteAccountRequestIn) =>
    api.post("/ui/privacy/delete-account", data),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: PRIVACY_KEYS.requests });
    toast.success("Deletion request created. You have 30 days to cancel.");
  },
});

const useCancelDeletion = () => useMutation({
  mutationFn: (requestId: string) =>
    api.post(`/ui/privacy/requests/${requestId}/cancel`),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: PRIVACY_KEYS.requests });
    toast.success("Deletion cancelled.");
  },
});
```

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `privacy_deletion_requests_total` | Counter | `action` (created/cancelled/completed/failed) | Total deletion lifecycle events |
| `privacy_deletion_grace_period_remaining_seconds` | Gauge | `request_id` | Remaining grace period for active requests |
| `privacy_deletion_cascade_duration_seconds` | Histogram | None | Time to complete full deletion cascade |
| `privacy_deletion_cascade_items_total` | Counter | `step` (messages/posts/files/etc.) | Items processed per cascade step |
| `privacy_export_requests_total` | Counter | `status` (created/completed/failed) | Export request lifecycle |
| `privacy_export_size_bytes` | Histogram | None | Export ZIP file sizes |
| `privacy_password_verification_total` | Counter | `result` (success/failure) | Password re-verification outcomes |
| `privacy_wallet_refund_cents` | Counter | None | Total cents refunded via deletion |

### 10.2 Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `privacy.deletion_requested` | INFO | `user_sub`, `request_id`, `grace_ends` | User requests deletion |
| `privacy.deletion_cancelled` | INFO | `user_sub`, `request_id` | User cancels deletion |
| `privacy.deletion_started` | INFO | `user_sub`, `request_id` | Scheduler starts cascade |
| `privacy.deletion_completed` | INFO | `user_sub`, `request_id`, `summary` | Full cascade complete |
| `privacy.deletion_failed` | ERROR | `user_sub`, `request_id`, `error` | Cascade failed mid-execution |
| `privacy.hold_placed` | WARN | `user_sub`, `request_id`, `admin_sub`, `reason` | Admin places hold |
| `privacy.hold_released` | INFO | `user_sub`, `request_id`, `admin_sub` | Admin releases hold |
| `privacy.password_verification_failed` | WARN | `user_sub`, `ip` | Wrong password on deletion attempt |
| `privacy.export_completed` | INFO | `user_sub`, `request_id`, `size_bytes`, `categories` | Export ZIP generated |
| `privacy.wallet_refund` | INFO | `user_sub`, `amount_cents` | Wallet balance refunded |

### 10.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Deletion cascade failure | Any `privacy.deletion_failed` event | P2 Critical | Investigate immediately; data partially deleted |
| High deletion request rate | >50 deletion requests in 1 hour | P3 Warning | Check for abuse or platform issues |
| Stale pending deletions | Requests with `grace_period_ends_at` > 48h past and still pending | P2 Critical | Scheduler may be down |
| Export generation timeout | Export request pending > 1 hour | P3 Warning | Check S3 access, DDB query performance |
| Password brute-force | >10 failed password verifications for same user in 10 minutes | P2 Critical | Rate limiter should catch this; check lockout |

### 10.4 Dashboard Queries

```
-- Active deletion requests by status
SELECT status, COUNT(*) FROM data_requests
WHERE request_type = 'deletion'
GROUP BY status;

-- Average grace period remaining (pending requests)
SELECT AVG(grace_period_ends_at - UNIX_TIMESTAMP())
FROM data_requests
WHERE request_type = 'deletion' AND status = 'pending';

-- Deletion cascade duration P50/P95/P99
HISTOGRAM(privacy_deletion_cascade_duration_seconds, [1, 5, 10, 30, 60, 120, 300]);

-- Wallet refunds in last 30 days
SUM(privacy_wallet_refund_cents) WHERE timestamp > NOW() - 30d;
```

---

## 11. Deletion Lifecycle

### 11.1 State Machine

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

### 11.2 Grace Period Mechanics

- Default: 30 days (`privacy_deletion_grace_period_days`).
- `grace_period_ends_at` is set at request creation time.
- During grace period: user can log in, use the platform, and cancel.
- After grace period: deletion scanner picks up the request and executes.
- On cancellation: status set to `cancelled`; no further action taken.

### 11.3 Pre-Deletion Email

Before executing deletion, the system sends a final email to the user's registered email:

- Subject: "Your account deletion is being processed"
- Body: summary of what will be deleted; link to contact support if this is an error.
- Sent BEFORE profile deletion so the email address is still available.

### 11.4 Post-Deletion State

After deletion completes:
- User cannot log in (session records deleted; Cognito user disabled).
- Profile resolves to "Deleted User" for other users' conversation views.
- Messages show "[This message was deleted]" with "Deleted User" sender.
- Posts show "[This post was deleted]" with "Deleted User" author.
- Billing ledger entries are anonymized (PII removed, amounts kept for accounting).
- All other data (contacts, calendar, tickets, files, devices, analytics) is hard-deleted.

---

## 12. Rollout Plan

### Phase 1: Backend Core (Days 1-3)

- **Feature flag**: `PRIVACY_DELETION_V2_ENABLED=false` (shadow mode)
- Implement password re-verification in `privacy.py`
- Create `deletion_scheduler.py` background task
- Add Steps 11-17 to `process_deletion()` cascade
- Unit tests for all new service functions
- **Migration**: None (no schema changes; new fields are optional)

### Phase 2: Extended Export + Frontend (Days 4-6)

- Extend `process_export()` with messages, posts, files, subscriptions categories
- Add `DeleteAccountDialog` with password and confirm_text inputs
- Update `PrivacyPage` with grace period countdown and export category selector
- **Feature flag**: `PRIVACY_DELETION_V2_ENABLED=true` in staging

### Phase 3: Canary Deployment (Days 7-9)

- Deploy to 10% of production traffic
- Monitor: deletion cascade failure rate, cascade duration, wallet refund totals
- Verify: scheduler processes expired grace periods within 6-hour window
- Verify: pre-deletion email is sent and received
- **Rollback trigger**: >1% cascade failure rate OR >5 wallet refund errors

### Phase 4: Full Rollout (Days 10-14)

- Ramp to 100% of production traffic
- Remove shadow mode flag
- Monitor for 5 days post-full-rollout
- **Rollback procedure**:
  1. Set `PRIVACY_DELETION_V2_ENABLED=false` (stops scheduler, reverts to stub password check)
  2. Any in-flight deletions will be left in current state (no partial undo)
  3. Admin can manually process or cancel pending requests via admin endpoints
  4. Re-deploy previous version if code changes needed

### Data Migration Steps

No data migration is required. The existing `data_requests` and `data_request_audit` tables already support the new fields (DynamoDB is schemaless). New fields (`retention_hold_reason`, `held_by`, `deletion_summary`) are simply added to items. Old items without these fields are handled gracefully by the `.get()` fallback pattern.

---

## 13. Performance Considerations

### 13.1 Query Costs

| Operation | DDB Reads | DDB Writes | Latency Target |
|-----------|-----------|------------|----------------|
| Create deletion request | 1 (check existing) | 2 (request + audit) | <300ms |
| Cancel deletion | 1 (read) | 2 (update + audit) | <200ms |
| List user requests | 1 (query) | 0 | <150ms |
| Admin list by status | 1 (GSI query) | 0 | <200ms |
| Full deletion cascade | 10-50 (per table scan) | 50-500+ (per item update/delete) | <5 minutes |
| Data export | 20-100 (across all tables) | 2 (request update + S3 upload) | <2 minutes |
| Scheduler scan | 1-5 (GSI query, paginated) | 0 (read-only scan) | <2 seconds |

### 13.2 Caching Strategy

- **No caching for deletion requests**: Deletion state must always be fresh (no stale cancellation status).
- **Export download URLs**: Cached for 7 days (S3 presigned URL TTL).
- **Password verification**: No caching (must always verify against Cognito).
- **Scheduler results**: No caching (scan runs every 6 hours; results are acted upon immediately).

### 13.3 Pagination and Batch Limits

| Operation | Limit | Pagination |
|-----------|-------|------------|
| Scheduler scan for pending requests | 200 per page | Loop on `LastEvaluatedKey` |
| Message anonymization per conversation | 1000 messages per batch | Paginated query per conversation |
| File deletion | 100 files per batch | Paginated query + batch delete |
| Analytics rollup deletion | 500 items per batch | Paginated query |
| Export data collection | 1000 items per category | Paginated queries across all tables |

### 13.4 Rate Limiting

| Operation | Limit | Window | Implementation |
|-----------|-------|--------|----------------|
| Deletion request | 3 | 24 hours | Counter in DDB per user |
| Deletion cancel | 10 | 24 hours | Inherits session rate limiter |
| Export request | 1 | `privacy_export_rate_limit_hours` (24h) | Timestamp check in DDB |
| Password verification | 5 | 10 minutes | `enforce_lockout()` mechanism |
| Admin hold/release | 30 | 1 hour | Admin rate limiter |

### 13.5 Cascade Performance Optimization

The deletion cascade processes tables sequentially (not in parallel) to avoid overwhelming DynamoDB throughput. For users with large amounts of data (>10,000 messages, >1,000 files), the cascade can take several minutes. Optimizations:

1. **Batch writes**: Use `batch_writer()` for bulk deletes (25 items per batch, DDB limit).
2. **Parallel file S3 deletes**: Use `boto3.s3.delete_objects()` for batch S3 deletion (1000 keys per call).
3. **Progress tracking**: Update the request item with cascade step progress every 30 seconds.
4. **Timeout protection**: Each cascade step has a 5-minute timeout. If exceeded, the step is retried on the next scheduler cycle.

---

## 14. Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/deletion_scheduler.py` | Background deletion processor | ~120 |
| `app/services/cognito_auth.py` | Cognito password verification (if not existing) | ~30 |
| `frontend/e2e/privacy-deletion.spec.ts` | E2E tests | ~500 |

## 15. Files to Modify

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

## 16. E2E Test Plan

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

### Section 533: Data Export API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 533.1 | Create export request with all categories | POST `/ui/privacy/export` with all categories true; 201; status is `pending` |
| 533.2 | Export rate limiting prevents rapid requests | POST export; immediately POST again; 429 |
| 533.3 | Export request status transitions to completed | (Process synchronously in dev); GET request; status is `completed` or `pending` |
| 533.4 | Export with selective categories only exports chosen data | POST with only `profile` and `billing` true; verify export includes only those categories |
| 533.5 | Export with invalid category name returns 422 | POST with `categories: {"invalid_cat": true}`; 422 |

### Section 534: Admin Deletion Management API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 534.1 | Admin can list pending deletion requests | Root GET `/ui/admin/privacy/requests?status=pending`; response includes test deletion request |
| 534.2 | Admin can place retention hold | Root POST `/ui/admin/privacy/requests/{id}/hold` with reason; 200; request has `retention_hold=true` |
| 534.3 | Admin can release retention hold | Root POST `/ui/admin/privacy/requests/{id}/release-hold`; 200; `retention_hold=false` |
| 534.4 | Admin can view deletion audit trail | Root GET `/ui/admin/privacy/requests/{id}/audit`; response has entries for created, hold, release |
| 534.5 | Non-admin cannot place retention hold | Alice POST hold; 403 |
| 534.6 | Non-admin cannot view admin deletion list | Alice GET admin requests; 403 |

### Section 535: Privacy Page UI (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 535.1 | Delete Account dialog shows password and confirmation inputs | Navigate to `/settings/privacy`; click "Delete Account"; dialog has password input, confirm text input, and red delete button |
| 535.2 | Delete button is disabled until password and confirm text are entered | Dialog opens; delete button is disabled; type password + "DELETE MY ACCOUNT"; button becomes enabled |
| 535.3 | Grace period countdown shows remaining days | Create deletion request; navigate to privacy page; countdown shows ~30 days remaining |
| 535.4 | Cancel button on active deletion request works | Click "Cancel Deletion"; confirmation dialog appears; confirm; request cancelled |
| 535.5 | Export category checkboxes are all checked by default | Navigate to privacy page; all 11 category checkboxes are checked |
| 535.6 | Export request button triggers download link after completion | Click "Request Export"; wait for completion; download link appears |

### Section 536: Edge Cases and Concurrent Access (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 536.1 | Retention hold blocks deletion even after grace expires | Place hold; set grace_period_ends_at in past via DDB; scanner does not process |
| 536.2 | Multiple cancel attempts are idempotent | Cancel same request twice; second returns 409 (already cancelled) |
| 536.3 | Deletion request with wallet balance triggers refund ledger | Seed wallet balance; create deletion; process deletion; verify LEDGER entry with reason="deletion_refund" |
| 536.4 | Deletion with active subscriptions cancels them | Create subscription for user; process deletion; subscription status=cancelled |
| 536.5 | Export download URL expires after 7 days | Create export; verify download_expires_at is ~7 days in future |

**Total E2E tests: 31**

---

## 17. Security Considerations

### 17.1 Password Re-verification

- Password is verified against Cognito in production (AdminInitiateAuth with USER_PASSWORD_AUTH flow).
- In dev mode, any non-empty password is accepted (consistent with dev auth pattern).
- Failed password attempts are rate-limited by the existing `enforce_lockout()` mechanism.
- Password is never logged or stored; used only for the Cognito verification call.

### 17.2 Confirmation Text

- User must type exactly "DELETE MY ACCOUNT" to confirm. This prevents accidental deletion and ensures informed consent.
- Validated server-side; 422 if incorrect.

### 17.3 Grace Period Protection

- 30-day grace period gives users time to reconsider.
- During grace period, user retains full account access.
- Cancellation is allowed any time before the grace period ends.
- Admin retention hold blocks deletion even after grace period expires.

### 17.4 Data Anonymization vs Deletion

- **Anonymize** (keep structure, scrub PII): messages, billing ledger entries (within retention window), newsfeed posts.
- **Hard delete** (remove entirely): profile, sessions, MFA, API keys, contacts, calendar, addresses, files, push devices, analytics, tickets.
- This split ensures conversation context is preserved for other users while PII is fully removed.

### 17.5 Audit Trail

- All deletion lifecycle events are recorded in `T.data_request_audit` with actor, action, and timestamp.
- Audit trail is retained for 90 days after deletion (for compliance review).
- Admin actions (hold, release, approve) are logged with admin_sub.

### 17.6 Rate Limiting

- Deletion request: max 3 per user per 24 hours (prevents abuse after cancellation).
- Export request: max 1 per user per `privacy_export_rate_limit_hours` (default 24).
- Admin endpoints: inherit admin rate limiter.

---

## 18. Dependencies

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

## 19. Acceptance Criteria

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
13. All 31 E2E tests pass.

---

## Codebase References

### Backend — Services

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `gdpr_service.py` (~815 lines) | `app/services/gdpr_service.py` | whole file | **Exists** — ticket says ~810, actual ~815 |
| `create_deletion_request()` | `app/services/gdpr_service.py` | 123 | **Verified** |
| `process_export()` | `app/services/gdpr_service.py` | 402 | **Verified** |
| `process_deletion()` | `app/services/gdpr_service.py` | 660 | **Verified** |
| `delete_user_data()` | `app/services/account.py` | — | **Exists** (sessions/MFA/API key cleanup) |
| `list_push_devices()`, `revoke_push_device()` | `app/services/push.py` | — | **Exists** |
| `deletion_scheduler.py` | `app/services/deletion_scheduler.py` | — | <!-- NOTE: `deletion_scheduler.py` does not exist yet — new implementation required --> |
| `cognito_auth.py` | `app/services/cognito_auth.py` | — | <!-- NOTE: `cognito_auth.py` does not exist yet — new implementation required --> |

### Backend — Routers

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| Password verification stub (`pass` in prod) | `app/routers/privacy.py` | 148-151 | **Verified** — `pass` statement confirms this is a stub |
| `privacy_router` registration | `app/main.py` | 441 | **Verified** |
| `admin_privacy_router` registration | `app/main.py` | 442 | **Verified** |

### Backend — Settings (`app/core/settings.py`)

| Setting | Line | Default | Ticket Claims | Status |
|---------|------|---------|---------------|--------|
| `privacy_deletion_grace_period_days` | 1256 | **14** | 30 | **INCORRECT** — ticket says 30-day grace period in multiple places (sections 3.2, 19.3, 19.4, acceptance criteria), but the actual default is **14 days**. Frontend `PrivacyPage.tsx` line 243 also references "14-day grace period". |
| `privacy_export_max_items_per_table` | 1253 | 100000 | — | **Verified** |
| `privacy_export_s3_bucket` | 1254 | `""` | — | **Verified** |
| `privacy_export_s3_prefix` | 1255 | `"exports/"` | — | **Verified** |
| `privacy_deletion_batch_size` | 1257 | 25 | — | **Verified** |
| `privacy_anonymize_display_name` | 1258 | `"Deleted User"` | — | **Verified** |
| `privacy_anonymize_message_text` | 1259 | `"[This message was deleted]"` | — | **Verified** |

### DynamoDB Tables (`scripts/local-ddb-init.py`)

| Table | Line | PK / SK | GSIs | Status |
|-------|------|---------|------|--------|
| `data_requests` | 864 | `pk` / `sk` | ByStatus, ByType | **Verified** |
| `data_request_audit` | 874 | `pk` / `sk` | — | **Verified** |

### Frontend

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `PrivacyPage.tsx` | `frontend/src/pages/settings/PrivacyPage.tsx` | whole file | **Exists** — references "14-day grace period" at line 243 |

### Corrections

1. **Grace period default**: The ticket states "30-day grace period" in multiple places, but `app/core/settings.py:1256` sets `privacy_deletion_grace_period_days: int = 14`. The frontend also says "14-day". Either update the ticket to say 14, or update the setting default to 30 if the intent is to change it.
2. **`deletion_scheduler.py`**: Referenced as the background job for processing expired grace periods. This file does not exist — it is new implementation required by this ticket.
3. **`cognito_auth.py`**: Referenced for real password verification via Cognito `AdminInitiateAuth`. This file does not exist — it is new implementation required by this ticket.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_privacy_deletion.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_platform_018_create` | Create primary entity; 201 |
| 2 | `test_platform_018_read` | Read back entity; correct fields |
| 3 | `test_platform_018_update` | Update entity; 200; changes reflected |
| 4 | `test_platform_018_delete` | Delete entity; 200/204 |
| 5 | `test_platform_018_auth_required` | No auth; 401 |
| 6 | `test_platform_018_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/privacy-deletion.spec.ts` -- 15 tests

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
| PRIVACY-001 | Related | GDPR export shares data access patterns with deletion |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Feature-flag-gated** -- PRIVACY_DELETION_ENABLED controls feature independently.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/privacy-deletion.spec.ts`
