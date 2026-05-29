# PRIVACY-001: GDPR Data Export & Account Deletion

**Ticket**: PRIVACY-001
**Author**: Engineering
**Status**: Proposed
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 14-18 days

---

## 1. Executive Summary

The platform stores significant user data across 30+ DynamoDB tables, S3 buckets, and Cognito user pools. Under GDPR (Article 15 right of access, Article 17 right to erasure), CCPA, and UK GDPR, users have a legal right to export all their personal data in a portable format and request complete account deletion. Today the platform has a partial `delete_user_data()` function in `app/services/account.py` (line 71) that covers 10 table types <!-- CORRECTED: was "9 table types", actually 10 (9 in loop + alert_prefs separately at line 91) --> and no data export mechanism at all.

This feature builds a complete GDPR compliance module with three flows: (1) a data export system that compiles user data from all tables into a downloadable ZIP archive stored in S3, (2) a full account deletion pipeline with a 14-day grace period, billing record retention/anonymization, and cross-table purge, and (3) an admin review interface for approving, rejecting, and placing legal holds on deletion requests. The design uses two new DynamoDB tables (`data_requests` and `data_request_audit`) and background worker tasks for asynchronous processing.

This is a legal compliance requirement with potential regulatory penalties for non-compliance. The implementation must be thorough enough to satisfy a GDPR data subject access request (DSAR) audit while being operationally safe -- the 14-day grace period, admin review, and billing retention mechanisms prevent accidental data loss and maintain financial record integrity required by tax regulations (IRS 7-year retention, HMRC 6-year retention).

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to download all my personal data in a machine-readable format. | Export ZIP contains JSON files for all data categories; download link provided. |
| User | I want to delete my account and all associated data. | Deletion request created with 14-day grace period; all data purged after grace period. |
| User | I want to cancel a pending account deletion. | Cancel button available during grace period; account restored. |
| User | I want to see the status of my data requests. | Request history page shows pending/completed/cancelled requests. |
| Admin | I want to review and approve/reject deletion requests. | Admin dashboard with filterable request list and approval actions. |
| Admin | I want to place a legal hold on an account to prevent deletion. | Hold action blocks deletion; hold reason recorded in audit trail. |
| Compliance | I want an audit trail of all data request actions. | Every state transition logged in `data_request_audit` table. |
| Finance | I want billing records retained for the regulatory period. | Billing records anonymized (not deleted) for 7-year retention window. |

### 2.2 Current State Gaps

The existing `delete_user_data()` in `app/services/account.py` (line 71) handles: <!-- VERIFIED: function at line 71 -->
- Sessions (`T.sessions`) <!-- VERIFIED: line 75 -->
- TOTP devices (`T.totp`) <!-- VERIFIED: line 76 -->
- SMS devices (`T.sms`) <!-- VERIFIED: line 77 -->
- Recovery codes (`T.recovery`) <!-- VERIFIED: line 78 -->
- Email devices (`T.email`) <!-- VERIFIED: line 79 -->
- Alerts (`T.alerts`) <!-- VERIFIED: line 80 -->
- Push devices (`T.push_devices`) <!-- VERIFIED: line 81 -->
- API keys (`T.api_keys`) <!-- VERIFIED: line 82 -->
- Billing rows (`T.billing`) <!-- VERIFIED: line 83 -->
- Alert preferences (`T.alert_prefs`) <!-- CORRECTED: was omitted from list, actually handled separately at line 91 -->

**Not handled** (must be added):
- Messages (DDB `Messages`, `Conversations`, `Participants` tables)
- Files (S3 objects in `filemgr_bucket`, file manager DDB records)
- Newsfeed posts and comments (`app_single_table`)
- Profile data (`T.profile`)
- Calendar events (`T.calendar`)
- Contacts (`T.contacts`)
- Subscriptions (`T.subscriptions`)
- Tickets (`T.tickets`), questionnaires (`T.questionnaires`), projects (`T.projects`)
- Broadcast sessions and recordings
- Signature packets
- Cognito user record
- Video metadata, views, likes
- Message threads, reports, visibility overrides, pins
- Shopping cart, orders, entitlements

### 2.3 Regulatory Requirements

| Regulation | Right of Access | Right to Erasure | Retention Exceptions | Response Time |
|------------|----------------|-------------------|---------------------|---------------|
| GDPR (EU) | Art. 15: structured, machine-readable | Art. 17: complete erasure | Financial records, legal obligations | 30 days |
| CCPA (California) | Sec. 1798.100: categories + specific data | Sec. 1798.105: delete on request | Security, legal, regulatory | 45 days |
| UK GDPR | Same as EU GDPR | Same as EU GDPR | Same | 30 days |

---

## 3. Technical Architecture

### 3.1 System Diagram

```
+-------------------+       +---------------------+       +----------------------+
|   Privacy Page    |       |   Backend API       |       |   DynamoDB           |
| (/settings/       |       |  (privacy.py)       |       |                      |
|  privacy)         |       |                     |       | data_requests tbl    |
|                   |       |  POST /export       |------>| pk:USER#{sub}        |
| [Request Export]  |------>|  POST /delete-acct  |------>| sk:REQUEST#{id}      |
| [Delete Account]  |       |  POST /cancel       |       |                      |
| [Request History] |<------|  GET /requests      |<------| GSI: ByStatus        |
|                   |       |  GET /download      |       | GSI: ByType          |
+-------------------+       +---------------------+       +----------------------+
                                     |                             |
+-------------------+       +---------------------+       +----------------------+
| Admin Privacy Pg  |       | Background Workers  |       | data_request_audit   |
| (/admin/privacy)  |       |                     |       | pk:REQUEST#{id}      |
|                   |       | DataExportWorker    |       | sk:AUDIT#{ts}#{eid}  |
| [Approve/Reject]  |       |   - Query 30+ tbls  |       +----------------------+
| [Legal Hold]      |       |   - Download S3     |
| [Audit Log]       |       |   - Build ZIP       |       +----------------------+
+-------------------+       |   - Upload to S3    |------>| S3                   |
                            |                     |       | data-exports/        |
                            | DataDeletionWorker  |       |  {user}_{ts}.zip     |
                            |   - Anonymize billing|       +----------------------+
                            |   - Delete messages  |
                            |   - Delete S3 files  |       +----------------------+
                            |   - Delete DDB rows  |------>| Cognito              |
                            |   - Disable Cognito  |       | Disable + Delete     |
                            +---------------------+       +----------------------+
```

### 3.2 Data Flow -- Export

1. User clicks "Request Export" on Privacy page
2. Frontend calls `POST /ui/privacy/export` with category checkboxes
3. Backend creates `data_requests` item with `status=pending`, writes audit record
4. Background `DataExportWorker` picks up pending export requests (polling every 60s)
5. Worker queries each user-specific table partition, downloads S3 files
6. Worker assembles directory structure into ZIP, uploads to S3 export bucket
7. Worker updates request status to `completed`, sets `export_s3_key`
8. Worker calls `write_alert()` to notify user export is ready
9. User downloads via `GET /ui/privacy/export/{request_id}/download` (redirects to presigned S3 URL)
10. Export ZIP auto-expires after 7 days (S3 lifecycle or TTL-based cleanup)

### 3.3 Data Flow -- Deletion

1. User clicks "Delete My Account" and confirms with password
2. Frontend calls `POST /ui/privacy/delete-account` with password
3. Backend verifies password against Cognito (or mock in dev), creates request with `grace_period_ends_at = now + 14 days`
4. During grace period: user can cancel via `POST /ui/privacy/requests/{id}/cancel`
5. After grace period: background `DataDeletionWorker` executes full deletion
6. Worker processes tables in specific order (see Deletion Order below)
7. Worker writes final audit record with deletion summary
8. Worker disables and deletes Cognito user record

---

## 4. Data Model Deep Dive

### 4.1 New Table: `data_requests`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.data_requests_table_name, "data_requests"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByType", "partition_key": "request_type", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `pk` | S | `USER#{user_sub}` | `"USER#alice@test.local"` |
| `sk` | S | `REQUEST#{request_id}` | `"REQUEST#req_abc123def456"` |
| `request_id` | S | UUID | `"req_abc123def456"` |
| `user_sub` | S | Requesting user | `"alice@test.local"` |
| `request_type` | S | `export` or `deletion` | `"export"` |
| `status` | S | `pending`, `processing`, `completed`, `cancelled`, `failed`, `rejected`, `held` | `"pending"` |
| `created_at` | N | Unix timestamp | `1748380800` |
| `updated_at` | N | Unix timestamp | `1748380800` |
| `grace_period_ends_at` | N | Unix timestamp (deletion only) | `1749590400` |
| `completed_at` | N | Unix timestamp | `null` |
| `export_s3_key` | S | S3 key for the export ZIP | `"data-exports/alice_1748380800.zip"` |
| `export_expires_at` | N | Unix timestamp when download link expires | `1748985600` |
| `export_size_bytes` | N | Size of the export ZIP | `15728640` |
| `export_categories` | M | Categories included | `{"messages": true, "files": true}` |
| `deletion_summary` | M | Tables/counts deleted | `{"sessions": 12, "messages": 340}` |
| `admin_actor` | S | Admin who approved/rejected | `"root.admin@testdev.local"` |
| `admin_note` | S | Admin comment | `"Approved per user request"` |
| `retention_hold` | BOOL | Legal hold active | `false` |
| `retention_hold_reason` | S | Reason for legal hold | `null` |
| `deletion_reason` | S | User-provided reason | `"Moving to another platform"` |
| `ttl_epoch` | N | DDB TTL; export records expire after 90 days | `1756156800` |

**Example pending export item:**

```json
{
  "pk": "USER#alice@test.local",
  "sk": "REQUEST#req_abc123def456",
  "request_id": "req_abc123def456",
  "user_sub": "alice@test.local",
  "request_type": "export",
  "status": "pending",
  "created_at": 1748380800,
  "updated_at": 1748380800,
  "export_categories": {"messages": true, "files": true, "billing": true, "profile": true},
  "ttl_epoch": 1756156800
}
```

### 4.2 New Table: `data_request_audit`

```python
TableDef(
    _resolve_table_name(S.data_request_audit_table_name, "data_request_audit"),
    "pk",
    "sk",
),
```

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `pk` | S | `REQUEST#{request_id}` | `"REQUEST#req_abc123"` |
| `sk` | S | `AUDIT#{timestamp}#{event_id}` | `"AUDIT#1748380800#evt_xyz"` |
| `actor` | S | User or admin who performed the action | `"alice@test.local"` |
| `action` | S | `created`, `processing`, `completed`, `cancelled`, `approved`, `rejected`, `held`, `released`, `failed` | `"created"` |
| `details` | M | Event-specific metadata | `{"request_type": "export"}` |
| `created_at` | N | Unix timestamp | `1748380800` |

### 4.3 Access Patterns

| Access Pattern | Table/Index | Key Condition | Notes |
|---------------|-------------|---------------|-------|
| Get user's data requests | data_requests PK | `pk = USER#{user_sub}` | Returns all export + deletion requests |
| Get specific request | data_requests PK/SK | `pk = USER#{user_sub}, sk = REQUEST#{id}` | Single item |
| List pending requests (admin) | ByStatus GSI | `status = "pending"` | Sorted by created_at |
| List by type (admin) | ByType GSI | `request_type = "deletion"` | Sorted by created_at |
| Get audit trail | data_request_audit PK | `pk = REQUEST#{request_id}` | All events for a request |

### 4.4 Settings in `app/core/settings.py`

```python
# Privacy / GDPR
data_requests_table_name: str = os.environ.get("DATA_REQUESTS_TABLE_NAME", "data_requests")
data_request_audit_table_name: str = os.environ.get("DATA_REQUEST_AUDIT_TABLE_NAME", "data_request_audit")
privacy_export_enabled: bool = os.environ.get("PRIVACY_EXPORT_ENABLED", "1") not in ("0", "false", "False")
privacy_deletion_enabled: bool = os.environ.get("PRIVACY_DELETION_ENABLED", "1") not in ("0", "false", "False")
privacy_export_max_size_bytes: int = int(os.environ.get("PRIVACY_EXPORT_MAX_SIZE_BYTES", str(5 * 1024**3)))
privacy_export_ttl_days: int = int(os.environ.get("PRIVACY_EXPORT_TTL_DAYS", "7"))
privacy_deletion_grace_period_days: int = int(os.environ.get("PRIVACY_DELETION_GRACE_PERIOD_DAYS", "14"))
privacy_billing_retention_years: int = int(os.environ.get("PRIVACY_BILLING_RETENTION_YEARS", "7"))
privacy_export_s3_bucket: str = os.environ.get("PRIVACY_EXPORT_S3_BUCKET", "data-exports")
privacy_export_rate_limit_hours: int = int(os.environ.get("PRIVACY_EXPORT_RATE_LIMIT_HOURS", "24"))
privacy_deletion_poll_interval_seconds: int = int(os.environ.get("PRIVACY_DELETION_POLL_INTERVAL_SECONDS", "300"))
```

### 4.5 Table Handles in `app/core/tables.py`

```python
# Add to Tables dataclass:
data_requests: Any
data_request_audit: Any

# Add to T initialization:
data_requests=ddb.Table(S.data_requests_table_name),
data_request_audit=ddb.Table(S.data_request_audit_table_name),
```

---

## 5. API Contract Design

### 5.1 User Endpoints (require_ui_session) <!-- CORRECTED: `require_ui_session` is defined in `app/services/sessions.py` (line 283), not in `app/auth/deps.py` as CLAUDE.md suggests. It returns a dict with user_sub, session_id, role, ip. -->

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ui/privacy/export` | Request a data export |
| GET | `/ui/privacy/requests` | List user's own data requests |
| GET | `/ui/privacy/requests/{request_id}` | Get request status + download link |
| GET | `/ui/privacy/export/{request_id}/download` | Redirect to presigned S3 URL |
| POST | `/ui/privacy/delete-account` | Request account deletion (requires password) |
| POST | `/ui/privacy/requests/{request_id}/cancel` | Cancel a pending deletion request |

### 5.2 Admin Endpoints (admin role via require_ui_session) <!-- CORRECTED: There is no `require_admin_session` function in the codebase. Use `require_ui_session` and check `ctx["role"]` for admin/root privileges. -->

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ui/admin/privacy/requests` | List all data requests with filters |
| GET | `/ui/admin/privacy/requests/{request_id}` | Get request details |
| POST | `/ui/admin/privacy/requests/{request_id}/approve` | Approve a deletion request |
| POST | `/ui/admin/privacy/requests/{request_id}/reject` | Reject with reason |
| POST | `/ui/admin/privacy/requests/{request_id}/hold` | Place retention hold |
| POST | `/ui/admin/privacy/requests/{request_id}/release-hold` | Release retention hold |

### 5.3 POST `/ui/privacy/export`

**Request:**

```json
{
  "include_messages": true,
  "include_files": true,
  "include_billing": true,
  "include_profile": true
}
```

**Response (201):**

```json
{
  "request_id": "req_abc123def456",
  "request_type": "export",
  "status": "pending",
  "created_at": 1748380800
}
```

**Error responses:**
- `429`: Export already requested within 24 hours

### 5.4 POST `/ui/privacy/delete-account`

**Request:**

```json
{
  "password": "user_current_password",
  "reason": "Moving to another platform"
}
```

**Response (201):**

```json
{
  "request_id": "req_del_789xyz",
  "request_type": "deletion",
  "status": "pending",
  "created_at": 1748380800,
  "grace_period_ends_at": 1749590400
}
```

**Error responses:**
- `401`: Wrong password
- `403`: Account has retention hold
- `409`: Pending deletion request already exists

### 5.5 GET `/ui/privacy/requests`

**Response (200):**

```json
{
  "requests": [
    {
      "request_id": "req_abc123",
      "request_type": "export",
      "status": "completed",
      "created_at": 1748380800,
      "completed_at": 1748384400,
      "export_size_bytes": 15728640,
      "export_download_url": "https://s3.../data-exports/alice_1748380800.zip?..."
    },
    {
      "request_id": "req_del_789",
      "request_type": "deletion",
      "status": "pending",
      "created_at": 1748380800,
      "grace_period_ends_at": 1749590400
    }
  ]
}
```

### 5.6 GET `/ui/admin/privacy/requests`

**Query parameters:**
- `status` (string, optional): Filter by status
- `request_type` (string, optional): Filter by type
- `limit` (int, default 50): Page size
- `cursor` (string, optional): Pagination cursor

**Response (200):**

```json
{
  "requests": [
    {
      "request_id": "req_del_789",
      "user_sub": "alice@test.local",
      "request_type": "deletion",
      "status": "pending",
      "created_at": 1748380800,
      "grace_period_ends_at": 1749590400,
      "retention_hold": false,
      "deletion_reason": "Moving to another platform"
    }
  ],
  "next_cursor": null
}
```

### 5.7 Error Codes

| Status | Condition |
|--------|-----------|
| 201 | Request created successfully |
| 200 | Request listed/retrieved/action completed |
| 401 | Wrong password on deletion, or not authenticated |
| 403 | Retention hold blocks deletion, or non-admin accessing admin endpoints |
| 404 | Request not found |
| 409 | Duplicate pending request |
| 429 | Export rate limit (1 per 24 hours) |

---

## 6. Data Export Worker

### 6.1 Export Directory Structure

```
export_{user_sub}_{timestamp}/
  profile.json          -- Profile data from T.profile
  account.json          -- Account state, addresses
  messages/
    conversations.json  -- All conversations + participants
    messages.json       -- All messages (text, metadata; files as URLs)
  files/
    manifest.json       -- File manager tree structure
    {filename}          -- Actual file bytes from S3
  billing/
    history.json        -- Billing ledger entries
    payment_methods.json -- Payment method metadata (masked)
  calendar/
    events.json         -- Calendar events
  contacts/
    contacts.json       -- Contact list
  newsfeed/
    posts.json          -- All authored posts + comments
  subscriptions/
    subscriptions.json  -- Subscription records
  security/
    sessions.json       -- Session metadata (no tokens)
    api_keys.json       -- API key metadata (no secrets)
    mfa_devices.json    -- Device type + created_at (no secrets)
```

### 6.2 Tables Queried

| Table | PK Pattern | Data Extracted |
|-------|-----------|----------------|
| `T.profile` | `user_sub` | Display name, bio, avatar URL |
| `T.account_state` | `user_sub` | Account status, creation date |
| `T.addresses` | `user_sub` | Shipping/billing addresses |
| `T.billing` | `USER#{user_sub}` | Ledger entries, payment methods (masked) |
| `T.contacts` | `user_sub` | Contact list |
| `T.calendar` | Query by owner | Calendar events |
| `T.alerts` | `user_sub` | Alert history |
| `T.subscriptions` | Query by user | Subscription records |
| `Participants` | `user_id` | Conversation memberships |
| `Messages` | By conversation_id (from Participants) | Message content |
| `Conversations` | By conversation_id | Conversation metadata |
| `app_single_table` | `POST#{user_sub}#*` | Newsfeed posts |
| `file_manager` | `USER#{user_sub}#*` | File metadata + S3 downloads |
| `T.tickets` | By user | Support tickets |
| `T.questionnaires` | By user | Questionnaire responses |
| `T.signature_packets` | By owner | Signed documents |
| `T.projects` | By user | Project data |
| `T.video_metadata` | By uploader | Uploaded videos |

### 6.3 Size Limits and Timeouts

- Maximum export size: 5 GB (configurable via `PRIVACY_EXPORT_MAX_SIZE_BYTES`)
- File download timeout: 30 seconds per file
- Total export timeout: 30 minutes
- If export exceeds size limit, files are omitted and a manifest with S3 keys is provided instead
- Export ZIP compressed with `deflate` for space efficiency

### 6.4 Sensitive Data Handling

| Data Type | Included in Export | Redaction |
|-----------|--------------------|-----------|
| Profile (name, bio) | Yes | None |
| Email address | Yes | None |
| Payment method last4 | Yes | Full number never stored |
| API key secrets | No | Only key_id + created_at |
| Session tokens | No | Only session_id + created_at |
| MFA secrets | No | Only device type + created_at |
| TOTP seed | No | Excluded |
| Recovery codes | No | Excluded |
| Encrypted message content | Yes | Ciphertext only (user has the key) |
| Passwords | No | Never stored in plaintext |

### 6.5 Background Task Registration

```python
# app/main.py — follows existing pattern (see lines 323-328)
app.add_event_handler("startup", start_data_export_task)
app.add_event_handler("startup", start_data_deletion_task)
```
<!-- VERIFIED: Background task registration pattern matches existing code in app/main.py:323-328 (newsfeed_startup, start_scheduled_messages_task, start_broadcast_scheduler_task, start_broadcast_reminder_task). -->

---

## 7. Data Deletion Worker

### 7.1 Deletion Order

The deletion worker processes tables in a specific order to maintain referential integrity and ensure billing retention:

1. **Anonymize billing records** within retention window (replace `user_sub` with `DELETED#{sha256(user_sub)[:16]}`, strip PII fields)
2. **Delete non-retained billing records** (payment methods, wallet state)
3. **Delete messages** (all messages in conversations where user is sole remaining participant; mark as "deleted user" in shared conversations)
4. **Delete S3 files** (file manager bucket, avatar images, uploaded media)
5. **Delete file manager DDB records** (file_manager table)
6. **Delete newsfeed posts** (or anonymize if comments exist from other users)
7. **Delete calendar, contacts, subscriptions, tickets, questionnaires, projects**
8. **Delete video metadata, views, likes**
9. **Delete broadcast sessions, recordings, chat messages**
10. **Delete signature packets**
11. **Delete security records** (sessions, MFA devices, API keys, recovery codes)
12. **Delete profile and account state**
13. **Delete message threads, reports, pins, visibility overrides**
14. **Disable Cognito user** (prevents re-login during deletion window)
15. **Delete Cognito user record**
16. **Write final audit record** with deletion summary

### 7.2 Billing Retention

Financial records must be retained for a configurable period (default 7 years):

```python
BILLING_RETENTION_YEARS = int(os.environ.get("PRIVACY_BILLING_RETENTION_YEARS", "7"))
```

Records within the retention window are anonymized:
- `user_sub` replaced with `DELETED#{sha256(user_sub)[:16]}`
- `email`, `name`, `address` fields stripped
- Transaction amounts, dates, and reference IDs preserved
- `pk` remains `USER#{original_sub}` to maintain ledger integrity (but PII removed from all fields)

### 7.3 Conversation Handling

- **DM conversations**: If the other participant has also deleted their account, delete the entire conversation and all messages. Otherwise, replace the deleted user's messages with `[Deleted user]` placeholder and remove the participant record.
- **Group conversations**: Remove participant, replace messages with placeholder text. If all participants deleted, remove the conversation.
- **Helpdesk conversations**: Anonymize customer messages but preserve for support record integrity.

### 7.4 Deletion Summary

After processing, the worker writes a summary map to the request record:

```json
{
  "sessions": 12,
  "messages": 340,
  "files_s3": 45,
  "files_ddb": 45,
  "posts": 8,
  "comments": 23,
  "contacts": 15,
  "calendar_events": 30,
  "billing_deleted": 5,
  "billing_anonymized": 42,
  "videos": 3,
  "subscriptions": 2,
  "cognito_deleted": true
}
```

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
PrivacyPage (/settings/privacy)
  |-- ExportSection
  |     |-- Card "Download Your Data"
  |     |-- CategoryCheckboxes (messages, files, billing, profile)
  |     |-- RequestExportButton
  |     |-- ExportStatusBanner (pending/processing/ready)
  |     |-- DownloadButton (when ready, presigned URL)
  |-- DeletionSection
  |     |-- DangerCard "Delete Account"
  |     |-- DeleteAccountButton (red, opens dialog)
  |     |-- ActiveDeletionBanner (grace period countdown, cancel button)
  |-- RequestHistoryTable
        |-- Columns: Type, Status, Date, Actions
        |-- Rows: past export/deletion requests

DeleteAccountDialog (modal)
  |-- Step 1: WarningText (what will be deleted, 14-day grace period)
  |-- Step 2: PasswordInput
  |-- Step 3: ReasonTextarea (optional)
  |-- ConfirmButton "I understand, delete my account"

AdminPrivacyPage (/admin/privacy)
  |-- FilterBar (status, type)
  |-- RequestTable
  |     |-- Columns: User, Type, Status, Date, Actions
  |     |-- ActionButtons: Approve, Reject, Hold, Release
  |-- RequestDetailView (expandable)
        |-- AuditLog timeline
        |-- HoldReason display
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/settings/PrivacyPage.tsx` | Data export + account deletion UI |
| `frontend/src/pages/admin/AdminPrivacyPage.tsx` | Admin request review dashboard |
| `frontend/src/pages/settings/DeleteAccountDialog.tsx` | Confirmation dialog with password entry |
| `frontend/src/pages/settings/ExportStatusBanner.tsx` | Shows export progress/download link |
| `frontend/src/api/endpoints/privacy.ts` | Axios wrappers |

### 8.3 React Query Hooks

```typescript
// frontend/src/api/endpoints/privacy.ts
export const usePrivacyRequests = () => useQuery({
  queryKey: ["privacy", "requests"],
  queryFn: () => client.get("/ui/privacy/requests").then(r => r.data),
  refetchInterval: 10_000,  // Poll every 10s while export is processing
});

export const useRequestExport = () => useMutation({
  mutationFn: (body: ExportRequestBody) => client.post("/ui/privacy/export", body),
  onSuccess: () => queryClient.invalidateQueries(["privacy", "requests"]),
});

export const useDeleteAccount = () => useMutation({
  mutationFn: (body: DeleteAccountBody) => client.post("/ui/privacy/delete-account", body),
  onSuccess: () => queryClient.invalidateQueries(["privacy", "requests"]),
});

export const useCancelDeletion = () => useMutation({
  mutationFn: (requestId: string) => client.post(`/ui/privacy/requests/${requestId}/cancel`),
  onSuccess: () => queryClient.invalidateQueries(["privacy", "requests"]),
});

// Admin
export const useAdminPrivacyRequests = (filters: Filters) => useQuery({
  queryKey: ["admin", "privacy", "requests", filters],
  queryFn: () => client.get("/ui/admin/privacy/requests", { params: filters }).then(r => r.data),
});
```

### 8.4 Routes

```typescript
// App.tsx
{ path: "/settings/privacy", element: <PrivacyPage /> }
{ path: "/admin/privacy", element: <AdminPrivacyPage /> }
```

---

## 9. Security & Privacy Considerations

### 9.1 Authentication

- User endpoints: `require_ui_session` with CSRF enforcement. <!-- VERIFIED: `require_ui_session` at `app/services/sessions.py:283` enforces CSRF for non-GET cookie-auth requests -->
- Admin endpoints: `require_ui_session` with role check (role >= ADMIN). <!-- CORRECTED: was `require_admin_session`, which does not exist. Use `require_ui_session` + manual role check on `ctx["role"]`. -->
- Deletion requires password re-confirmation to prevent CSRF-based deletion attacks.
- Export download URL is a time-limited presigned S3 URL (expires after 1 hour).

### 9.2 Data Protection

- Export ZIP is stored in a dedicated S3 bucket with server-side encryption (AES-256).
- Export download requires authentication -- no public URLs.
- Export ZIPs auto-expire after 7 days via S3 lifecycle policy.
- Audit trail is append-only (no update or delete operations on `data_request_audit`).
- All status transitions are logged, creating a tamper-evident audit chain.

### 9.3 Abuse Prevention

- Export rate limit: 1 per 24 hours per user.
- Deletion requires password confirmation (prevents automated deletion attacks).
- 14-day grace period allows recovery from accidental or coerced deletions.
- Admin can place legal holds to prevent deletion during investigations.
- Retention holds are logged in the audit trail with a reason.

### 9.4 Data Isolation

- `GET /ui/privacy/requests` only returns the authenticated user's own requests (filtered by `pk = USER#{user_sub}`).
- Export worker only queries tables with the requesting user's PK. No cross-user data leakage.
- Admin endpoints require elevated role and are separately audited.

---

## 10. Performance & Scalability

### 10.1 Export Worker Performance

| Data Type | Estimated Items | Query Time | Download Time |
|-----------|----------------|------------|---------------|
| Profile + Account | 2-5 items | ~10ms | N/A |
| Messages (avg user) | ~5,000 | ~2s (paginated) | N/A |
| Files (avg user) | ~100 | ~500ms queries | ~60s S3 downloads |
| Billing ledger | ~200 | ~200ms | N/A |
| Calendar events | ~50 | ~100ms | N/A |
| Posts + comments | ~30 | ~100ms | N/A |
| **Total (avg user)** | ~5,400 items | ~3s queries | ~60s S3 |
| **Total export time** | | | ~2-5 minutes |

**Worst case** (power user with 100K messages, 1000 files): ~15-30 minutes. Covered by the 30-minute timeout.

### 10.2 Deletion Worker Performance

The deletion worker processes sequentially to maintain ordering guarantees. Estimated times:

| Phase | Operations | Time |
|-------|-----------|------|
| Billing anonymization | ~200 updates | ~10s |
| Message deletion | ~5,000 deletes | ~30s |
| S3 file deletion | ~100 deletes | ~20s |
| Other tables | ~500 deletes | ~15s |
| Cognito disable + delete | 2 API calls | ~2s |
| **Total** | ~5,800 operations | ~1-2 minutes |

### 10.3 Caching Strategy

- No caching needed for privacy requests (infrequent, user-specific).
- React Query `refetchInterval: 10_000` for polling export status.
- Admin list uses standard React Query caching with manual invalidation on actions.

### 10.4 Known Bottlenecks

- **Large file exports**: Users with many S3 files can cause the export to approach the 5GB limit. Files are downloaded sequentially. Mitigation: parallel S3 downloads (ThreadPoolExecutor with 10 workers).
- **DynamoDB pagination**: Tables like `Messages` may have millions of items per conversation. The export worker must paginate with `LastEvaluatedKey`. Filter expressions don't reduce page size (common gotcha per CLAUDE.md).
- **Cognito API rate limits**: Cognito has a 10 requests/second limit for `AdminDisableUser` and `AdminDeleteUser`. Not an issue for single deletions but relevant for batch processing.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flags

- `PRIVACY_EXPORT_ENABLED`: Toggle export functionality
- `PRIVACY_DELETION_ENABLED`: Toggle deletion functionality (can be enabled independently)

### 11.2 Incremental Deployment

1. **Phase 1**: Deploy `data_requests` and `data_request_audit` tables. Deploy privacy router with export endpoint only.
2. **Phase 2**: Deploy export worker. Test with internal accounts.
3. **Phase 3**: Enable export for all users. Deploy frontend PrivacyPage with export section.
4. **Phase 4**: Deploy deletion endpoint and worker behind `PRIVACY_DELETION_ENABLED=false`.
5. **Phase 5**: Enable deletion. Deploy DeleteAccountDialog and grace period UI.
6. **Phase 6**: Deploy admin review endpoints and AdminPrivacyPage.

### 11.3 Rollback

- Set `PRIVACY_EXPORT_ENABLED=false` and/or `PRIVACY_DELETION_ENABLED=false`.
- Pending requests remain in DDB but workers stop processing them.
- No data loss risk from rollback (workers are additive, not destructive, until they complete).
- If a deletion was in progress when rolled back, the worker should be idempotent -- re-running on the same request skips already-deleted items.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | Export request creation writes correct DDB item | `tests/test_privacy.py` |
| 2 | Export rate limit enforced (1 per 24 hours) | `tests/test_privacy.py` |
| 3 | Deletion request requires password verification | `tests/test_privacy.py` |
| 4 | Duplicate deletion request returns 409 | `tests/test_privacy.py` |
| 5 | Cancel deletion within grace period succeeds | `tests/test_privacy.py` |
| 6 | Cancel deletion after grace period fails | `tests/test_privacy.py` |
| 7 | Retention hold blocks deletion request | `tests/test_privacy.py` |
| 8 | Billing anonymization preserves amounts, strips PII | `tests/test_privacy.py` |
| 9 | Conversation handling: DM with active partner preserves messages with placeholder | `tests/test_privacy.py` |
| 10 | Conversation handling: DM with deleted partner removes entire conversation | `tests/test_privacy.py` |
| 11 | Audit trail records all state transitions | `tests/test_privacy.py` |
| 12 | Export worker generates correct ZIP structure | `tests/test_privacy.py` |
| 13 | Admin approval changes status | `tests/test_privacy.py` |
| 14 | Non-admin cannot access admin endpoints | `tests/test_privacy.py` |

### 12.2 E2E Tests

**File:** `frontend/e2e/privacy.spec.ts`

**Section A: Data Export API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | User requests a data export | POST returns request_id with status=pending |
| 2 | Export request rate limited to 1 per 24 hours | Second request within 24h returns 429 |
| 3 | Export status transitions to completed | Poll GET until status=completed (mock fast worker) |
| 4 | Export download returns presigned URL | GET download endpoint returns redirect |
| 5 | List requests returns user's own requests only | Alice cannot see Bob's requests |
| 6 | Unauthenticated export request returns 401 | No cookies; 401 |

**Section B: Account Deletion API (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | User requests account deletion with correct password | POST returns request with grace_period_ends_at |
| 8 | Deletion with wrong password returns 401 | POST with bad password; 401 |
| 9 | Duplicate deletion request returns 409 | Second POST; 409 |
| 10 | User cancels deletion within grace period | POST cancel; status=cancelled |
| 11 | Cancel after grace period returns 409 | Manually set grace_period_ends_at in past; cancel fails |
| 12 | Account with retention hold returns 403 on deletion request | Set hold; POST delete; 403 |
| 13 | Deletion summary includes all table counts after processing | Check deletion_summary map has expected keys |

**Section C: Admin Privacy Review (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | Admin lists all pending requests | GET returns filtered list |
| 15 | Admin approves a deletion request | POST approve changes status |
| 16 | Admin places retention hold | POST hold blocks deletion |
| 17 | Admin releases hold | POST release-hold allows deletion to proceed |
| 18 | Non-admin cannot access admin privacy endpoints | Returns 403 |

**Section D: Privacy UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 19 | Privacy page loads with export and deletion sections | Navigate to /settings/privacy; both cards visible |
| 20 | Request export shows pending status banner | Click export; banner with status visible |
| 21 | Delete account dialog requires password confirmation | Open dialog; submit without password; validation error |
| 22 | Active deletion shows grace period countdown with cancel button | Create deletion; countdown and cancel button visible |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `privacy_export_requested_total` | Counter | - | Export requests created |
| `privacy_export_completed_total` | Counter | - | Exports completed |
| `privacy_export_failed_total` | Counter | - | Export failures |
| `privacy_export_duration_seconds` | Histogram | - | Export processing time |
| `privacy_export_size_bytes` | Histogram | - | Export ZIP sizes |
| `privacy_deletion_requested_total` | Counter | - | Deletion requests created |
| `privacy_deletion_completed_total` | Counter | - | Deletions fully executed |
| `privacy_deletion_cancelled_total` | Counter | - | Deletions cancelled in grace period |
| `privacy_deletion_duration_seconds` | Histogram | - | Deletion processing time |
| `privacy_deletion_items_deleted` | Histogram | `table` | Items deleted per table |
| `privacy_retention_hold_active` | Gauge | - | Currently held accounts |

### 13.2 Dashboard Queries

- **Compliance SLA**: `privacy_export_completed_total / privacy_export_requested_total` -- should be > 99%
- **Export latency**: `histogram_quantile(0.95, privacy_export_duration_seconds)` -- must be < 30 minutes
- **Deletion backlog**: `privacy_deletion_requested_total - privacy_deletion_completed_total - privacy_deletion_cancelled_total`

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Export worker stuck | Export in `processing` status for > 30 minutes | Critical |
| Deletion worker stuck | Deletion in `processing` status for > 1 hour | Critical |
| Export failure rate | > 5% failure rate over 24 hours | Warning |
| High deletion volume | > 100 deletion requests in 1 hour | Warning (possible attack) |
| Retention hold count high | > 50 active holds | Info (review needed) |
| Export size approaching limit | p95 export size > 4GB (80% of 5GB limit) | Warning |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Should export include E2E encrypted message content?** The server only stores ciphertext; the export would include encrypted blobs that the user would need their key to decrypt. Recommendation: include ciphertext with a note explaining the encryption. The user is responsible for decrypting with their key.
2. **How to handle shared files?** If Alice shared a file with Bob and then deletes her account, should Bob lose access to the shared file? Recommendation: orphan shared files to a system account (the file remains but ownership is transferred).
3. **Should the admin approval step be required for all deletions, or only flagged accounts?** Recommendation: auto-approve unless the account has active billing disputes, legal holds, or high revenue (>$1000 lifetime spend).
4. **Cognito user pool cleanup in production**: The dev stack uses moto for Cognito. Production Cognito deletion needs careful handling of user pool limits and eventual consistency.
5. **Export notification channel**: Should the "export ready" notification be in-app only, or also email? Recommendation: both, since the user may not have the app open when the export completes.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Export worker OOM on large accounts | Medium | High | Stream files to ZIP (don't load all in memory); chunk S3 downloads |
| DDB throttling during deletion | Low | Medium | Exponential backoff; spread deletions across time |
| Incomplete deletion (missed table) | Medium | High | Comprehensive table inventory; integration test that verifies all tables are covered |
| Grace period race condition | Low | Medium | Atomic status check + update via DDB conditional expression |
| Cognito API errors during deletion | Low | Medium | Retry with exponential backoff; mark deletion as `failed` if retries exhausted |

### 14.3 Dependency Risks

- **All user-specific DDB tables**: The export and deletion workers must know about every table that stores user PII. Adding a new table (e.g., for a new feature) requires updating both workers.
- **S3 bucket access**: The export worker needs read access to all S3 buckets containing user data. The deletion worker needs delete access.
- **Cognito integration**: Deletion requires Cognito admin API access. Must handle the case where Cognito is not configured (dev mode).

---

## 15. Implementation Timeline

### Phase 1: Data Infrastructure (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add `data_requests` and `data_request_audit` tables to `scripts/local-ddb-init.py`. Add settings + table handles. |
| 2 | Create `app/services/data_requests.py` with CRUD operations, audit trail writing, status transitions. |
| 3 | Create `app/routers/privacy.py` with export and deletion request endpoints. Write Pydantic models. |

### Phase 2: Export Worker (Days 4-7)

| Day | Task |
|-----|------|
| 4 | Create `app/services/data_export_worker.py` scaffold. Implement profile, account, billing export. |
| 5 | Implement messages and conversations export (paginated queries, handle large conversations). |
| 6 | Implement file download from S3, calendar, contacts, subscriptions, newsfeed export. |
| 7 | ZIP assembly, S3 upload, status update, alert notification. Unit tests for export. |

### Phase 3: Deletion Worker (Days 8-11)

| Day | Task |
|-----|------|
| 8 | Create `app/services/data_deletion_worker.py`. Implement billing anonymization. |
| 9 | Implement message deletion/anonymization, S3 file deletion, file manager cleanup. |
| 10 | Implement remaining table deletions (calendar, contacts, subscriptions, etc.). |
| 11 | Implement Cognito disable/delete. Write deletion summary. Unit tests for deletion. |

### Phase 4: Admin + Frontend (Days 12-15)

| Day | Task |
|-----|------|
| 12 | Create `app/routers/admin_privacy.py` with admin review endpoints. |
| 13 | Create `PrivacyPage.tsx` with export section, deletion section, request history. |
| 14 | Create `DeleteAccountDialog.tsx` and `ExportStatusBanner.tsx`. Create `AdminPrivacyPage.tsx`. |
| 15 | Add API client, TypeScript types, React Query hooks. Wire routes. |

### Phase 5: E2E Tests + QA (Days 16-18)

| Day | Task |
|-----|------|
| 16 | Write E2E tests sections A-B (export and deletion APIs). |
| 17 | Write E2E tests sections C-D (admin review and UI). |
| 18 | Full test suite run, manual QA, cross-check all tables are covered, code review. |

---

## 16. Files to Create

| File | Purpose |
|------|---------|
| `app/services/data_requests.py` | CRUD for export/deletion requests; orchestrates data collection |
| `app/services/data_export_worker.py` | Background task that compiles export ZIPs |
| `app/services/data_deletion_worker.py` | Background task that executes full account purge |
| `app/routers/privacy.py` | User-facing endpoints for export/deletion |
| `app/routers/admin_privacy.py` | Admin review/approval endpoints |
| `frontend/src/pages/settings/PrivacyPage.tsx` | Data export + account deletion UI |
| `frontend/src/pages/admin/AdminPrivacyPage.tsx` | Admin request review dashboard |
| `frontend/src/pages/settings/DeleteAccountDialog.tsx` | Confirmation dialog with password entry |
| `frontend/src/pages/settings/ExportStatusBanner.tsx` | Shows export progress/download link |
| `frontend/src/api/endpoints/privacy.ts` | Axios wrappers |
| `frontend/e2e/privacy.spec.ts` | E2E tests |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register privacy and admin_privacy routers; register background workers |
| `app/core/settings.py` | Add `privacy_*` and `data_requests_*` settings |
| `app/core/tables.py` | Add `data_requests` and `data_request_audit` table handles |
| `app/models.py` | Add Pydantic models for data requests |
| `scripts/local-ddb-init.py` | Add `data_requests` and `data_request_audit` table definitions |
| `frontend/src/api/types.ts` | Add `DataRequest`, `DataRequestAudit` interfaces |
| `frontend/src/App.tsx` | Add `/settings/privacy` and `/admin/privacy` routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Privacy" nav link under Settings group |

---

## 18. Dependencies

| Dependency | Reason |
|------------|--------|
| `app/services/account.py::delete_user_data()` | Extend with additional tables; currently handles 10 table types <!-- CORRECTED: was "9 table types", actually 10 --> |
| `app/services/alerts.py::write_alert()` | Notifications for export ready, deletion confirmed <!-- VERIFIED: write_alert at line 265 --> |
| `app/core/aws.py` | S3 client for file downloads and export ZIP upload |
| Cognito integration | Disable/delete Cognito user record on account deletion |
| `app/services/profile.py` | Export profile data |
| `T.billing` | Billing record anonymization with retention logic |
| All user-specific DDB tables | Export and deletion must cover every table that stores user PII |

---

## 19. Acceptance Criteria

1. User can request a data export; export completes within 30 minutes and is downloadable for 7 days.
2. Export ZIP contains structured JSON for all user data categories.
3. User can request account deletion with password confirmation.
4. Deletion has a 14-day grace period during which the user can cancel.
5. After grace period, all user data is deleted (except anonymized billing records within retention window).
6. Admin can list, approve, reject, and place holds on deletion requests.
7. Every state transition is recorded in the audit trail.
8. Billing records within the 7-year retention window are anonymized, not deleted.
9. Conversations with other active users preserve message history with "[Deleted user]" placeholder.
10. Export rate limited to 1 per 24 hours per user.

---

## Appendix: Codebase Citations

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `delete_user_data()` | `app/services/account.py` | 71 | VERIFIED |
| Sessions deletion | `app/services/account.py` | 75 | VERIFIED |
| TOTP deletion | `app/services/account.py` | 76 | VERIFIED |
| SMS deletion | `app/services/account.py` | 77 | VERIFIED |
| Recovery codes deletion | `app/services/account.py` | 78 | VERIFIED |
| Email deletion | `app/services/account.py` | 79 | VERIFIED |
| Alerts deletion | `app/services/account.py` | 80 | VERIFIED |
| Push devices deletion | `app/services/account.py` | 81 | VERIFIED |
| API keys deletion | `app/services/account.py` | 82 | VERIFIED |
| Billing deletion | `app/services/account.py` | 83 | VERIFIED |
| Alert prefs deletion (omitted from original list) | `app/services/account.py` | 91 | CORRECTED: was missing from "9 table types" claim; actually 10 |
| `T.profile` table handle | `app/core/tables.py` | 29, 113 | VERIFIED |
| `T.calendar` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.contacts` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.subscriptions` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.tickets` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.questionnaires` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.projects` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.signature_packets` table handle | `app/core/tables.py` | exists | VERIFIED |
| `T.video_metadata` table handle | `app/core/tables.py` | exists | VERIFIED |
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED (was 265; file grew from ~680 to 899 lines) |
| `TableDef` dataclass | `scripts/local-ddb-init.py` | 29 | VERIFIED |
| `_resolve_table_name()` | `scripts/local-ddb-init.py` | 38 | VERIFIED |
| GSI definition format (dict with `index_name`, `partition_key`, `sort_key`) | `scripts/local-ddb-init.py` | throughout | VERIFIED |
| `attr_types` for numeric GSI sort keys | `scripts/local-ddb-init.py` | e.g., line 247, 517 | VERIFIED |
| Settings dataclass (frozen) | `app/core/settings.py` | entire file | VERIFIED (proposed new settings do not exist yet) |
| Tables dataclass | `app/core/tables.py` | entire file | VERIFIED (proposed new table handles do not exist yet) |
| `require_ui_session` auth dependency | `app/services/sessions.py` | 283 | VERIFIED |
| `require_admin_session` | N/A | N/A | CORRECTED: does not exist; use `require_ui_session` + role check |
| Background task registration pattern | `app/main.py` | 378, 466 | VERIFIED (was 323-328; line drift — `add_event_handler("startup", ...)`) |
| `now_ts()` | `app/core/time.py` | 2 | VERIFIED |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_privacy_export.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_privacy_001_create` | Create primary entity; 201 |
| 2 | `test_privacy_001_read` | Read back entity; correct fields |
| 3 | `test_privacy_001_update` | Update entity; 200; changes reflected |
| 4 | `test_privacy_001_delete` | Delete entity; 200/204 |
| 5 | `test_privacy_001_auth_required` | No auth; 401 |
| 6 | `test_privacy_001_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/privacy-export.spec.ts` -- 14 tests

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
| PLATFORM-018 | Related | Account deletion reuses export data access patterns |

### Merge Strategy

**Independent** -- New data_exports table; additive-only changes.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/privacy-export.spec.ts`
