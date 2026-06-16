# CRM Email Tickets — Email client, Inbound email & Email Templates

**Area:** Email client, Inbound email & Email Templates (SuiteCRM Tier 2)

**What SuiteCRM provides that testlogon currently lacks:**
SuiteCRM's Emails module provides per-user IMAP/SMTP account connections (inbox, sent, drafts, folders), a full in-app email compose/reply/forward UI, email threading via In-Reply-To/References header parsing, email archiving to CRM records (contacts, tickets, org accounts), a personal email signature editor, and inbound group mailbox processing that auto-creates support tickets from incoming email. The platform has solid outbound transactional email infrastructure (SES delivery via `app/services/alerts.send_alert_email`, bounce/complaint tracking in `app/services/email_delivery.py`, suppression list, HTML templates in `app/services/alert_email_templates.py`, an admin dashboard at `app/routers/admin_email.py`) but none of the email client capabilities. Campaign email sending is planned under MKT-009 (uses `send_alert_email` + `write_alert` — see `docs/ofbiz/specs/MKT-009.md`), and open/click tracking is covered by a separate PLANNED note in the gap analysis.

**Cross-cutting constraints for all tickets in this file:**
- All changes are **additive and flag-gated default-off**; existing surfaces (`send_alert_email`, `T.email_delivery`, admin email dashboard) are byte-for-byte unchanged with flags off.
- Single-table DynamoDB new tables use the standard PK/SK pattern; numeric GSI sort keys require `attr_types={"field": "N"}` in `scripts/local-ddb-init.py` per the CLAUDE.md gotcha.
- Reuse existing primitives: `app/core/crypto.kms_encrypt`/`kms_decrypt` for credential storage, `app/services/alerts.send_alert_email` + `audit_event` for email dispatch and audit, `app/services/email_delivery.record_email_sent`/`record_email_failure` for delivery tracking, `app/core/cursor.py` for pagination, `app/core/time.now_ts()`, `app/core/tables._safe_table`, `app/core/settings.S`.
- Never fork the outbound SES pipeline — extend `send_alert_email` in-place for HTML, add new tables/services for new capabilities.
- Dev/prod parity (SECOPS-007): no `dev_mode` branches that skip logic; same code path both environments. In dev mode IMAP/SMTP calls are stubbed via a mock back-end; SES calls use the existing dev-log path already inside `send_alert_email`.
- Hermetic offline tests: mock IMAP/SMTP clients patched at import, moto DynamoDB for new tables bound to frozen `T` handles via `object.__setattr__`, frozen `S` flags via `object.__setattr__`, no real AWS/network.
- Feature flags all default off: `EMAIL_CLIENT_ENABLED`, `INBOUND_MAILBOX_ENABLED`, `EMAIL_ARCHIVING_ENABLED`, `EMAIL_SIGNATURES_ENABLED`, `CAMPAIGN_EMAIL_TEMPLATES_ENABLED`. The existing `NOTIFICATION_EMAIL_TEMPLATES_ENABLED` flag (settings.py:2044) remains distinct.

---

### EML-001: HTML email body in system notification templates

**Type:** Feature  **Priority:** P0  **Estimate:** 1d

**Description**

Fix `send_alert_email` at `app/services/alerts.py:459` to accept an optional `html_body: str | None = None` parameter and pass it as `Body.Html.Data` in the SES `send_email` call alongside the existing `Body.Text.Data`. The gap analysis confirmed the SES call at line 477 only sends `{"Text": {"Data": body_text[:8000]}}` even though `render_alert_email_template` (called at line 772-773) already returns an HTML body. All callers of `send_alert_email` already pass a `body` string obtained from the template renderer; the fix is a backwards-compatible signature extension.

Changes required:
1. `app/services/alerts.py` — add `html_body: str | None = None` to `send_alert_email`. In the SES `Message.Body` dict, add `"Html": {"Data": html_body[:50000]}` when `html_body` is truthy. Dev-mode dev-log path writes `html_body` length to the log entry. Update the `record_email_sent` call signature passes through the `subject`.
2. Update all three call sites within `alerts.py` (lines 766, 778, 804): the HTML-template path (line 778) passes `html_body=body` (where `body` is the HTML string from `render_alert_email_template`); the ticket-template path (line 766) and the plain-text fallback (line 804) pass `html_body=None`.
3. No model changes needed; no new tables.

This is self-contained in `app/services/alerts.py`. No feature flag needed — it is purely additive to the existing `NOTIFICATION_EMAIL_TEMPLATES_ENABLED`-gated code path. The `send_alert_email` function is already called by `app/services/cart_reminders.py` and MKT-009 (`docs/ofbiz/specs/MKT-009.md:28`) with positional args, so a keyword-only `html_body` is safe.

**Acceptance Criteria**
- `send_alert_email(..., html_body="<h1>Hi</h1>")` causes the SES `Message.Body` to contain both `Text` and `Html` keys in prod mode.
- `send_alert_email(..., html_body=None)` continues to send `Text`-only (no regression).
- In dev mode, `html_body` presence/length is noted in the dev email log.
- HTML content is truncated to 50 000 chars (safe SES limit) before the SES call.
- Hermetic pytest confirms both branches (with and without HTML) produce correct SES payloads via a mocked `boto3.client("ses")`.

**Dependencies**
- No ticket dependencies. Standalone fix.

---

### EML-002: Admin outbound email settings (from-address, SES/SMTP config, audit log)

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a runtime-editable admin endpoint for outbound email settings so admins can update the from-address and toggle SES without a redeploy — parallel to `app/routers/billing_config.py` which uses the `T.billing_config` single-item DDB pattern (PK=`CONFIG`, SK=`GLOBAL`).

**New DynamoDB table:** `email_settings` (add to `scripts/local-ddb-init.py` and `T`/`Tables` in `app/core/tables.py`).

```
PK: CONFIG
SK: GLOBAL
from_email:       str
reply_to_email:   Optional[str]
ses_enabled:      bool
smtp_enabled:     bool   # reserved for SMTP override (not yet implemented in back-end)
updated_at:       N      # now_ts()
updated_by:       str    # actor user_sub
```

No GSIs needed (single-row global config).

**New service:** `app/services/email_settings.py`
- `get_email_settings() -> dict` — reads the DDB row; returns compiled defaults from `S.alerts_from_email` / `S.alerts_email_enabled` when the DDB row is absent.
- `update_email_settings(actor_sub, *, from_email, reply_to_email, ses_enabled) -> dict` — writes the row and calls `audit_event("email_settings_updated", actor_sub, ...)`.
- Validated: `from_email` must be a valid email via `app/core/normalize.normalize_email`.

**Router extension:** `app/routers/admin_email.py` (already exists, registers under `/ui/admin/email`) — append three endpoints after the existing email-log endpoint (line 132):
- `GET /ui/admin/email/settings` — `require_admin_or_root`, returns `EmailSettingsOut`.
- `PATCH /ui/admin/email/settings` — `require_root`, accepts `EmailSettingsUpdate`, returns `EmailSettingsOut`.
- `GET /ui/admin/email/settings/audit` — `require_admin_or_root`, returns last 50 `audit_event` rows from `T.alerts` filtered to `"email_settings_updated"`.

**Models** (add to `app/models.py`):
```python
class EmailSettingsOut(BaseModel):
    from_email: str
    reply_to_email: Optional[str] = None
    ses_enabled: bool
    smtp_enabled: bool
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None

class EmailSettingsUpdate(BaseModel):
    from_email: Optional[str] = None
    reply_to_email: Optional[str] = None
    ses_enabled: Optional[bool] = None
```

Wire `get_email_settings()` into `send_alert_email` so that when a DDB override row exists, its `from_email` takes precedence over `S.alerts_from_email`. This is a best-effort read (fall back to `S` on any DDB error).

**Acceptance Criteria**
- `GET /ui/admin/email/settings` returns current effective settings (ADMIN+); non-admin gets 403.
- `PATCH /ui/admin/email/settings` updates `from_email` and `ses_enabled`; ROOT only; invalid email returns 400.
- After a PATCH, `send_alert_email` in prod uses the updated `from_email`.
- `GET /ui/admin/email/settings/audit` returns the most recent changes.
- Hermetic pytest covers CRUD, authz, `normalize_email` validation, and DDB fallback.

**Dependencies**
- EML-001 (only for full HTML delivery; the settings endpoint itself is independent).

---

### EML-003: Per-user email account connections (IMAP/SMTP credential storage)

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Allow users to register personal IMAP (for inbox sync) and SMTP (for outbound personal email) account credentials. Credentials are encrypted at rest using KMS via the same `kms_encrypt`/`kms_decrypt` pattern already used in `app/services/provider_credentials.py:402` and `app/services/provider_oauth.py:312`.

**New DynamoDB table:** `user_email_accounts`

```
PK: USER#{user_sub}
SK: ACCT#{account_id}         (uuid4 hex)
account_id:      str
label:           str           max 100 chars
imap_host:       str
imap_port:       int           default 993
imap_use_ssl:    bool          default true
smtp_host:       str
smtp_port:       int           default 587
smtp_use_tls:    bool          default true
username:        str           email address used to authenticate
password_ct_b64: str           KMS-encrypted base-64 ciphertext (app/core/crypto.kms_encrypt)
is_default:      bool          default false
created_at:      N
updated_at:      N
status:          str           "active" | "error" | "unverified"
last_error:      Optional[str]
```

GSI `ByUser` (PK=`USER#{user_sub}`, SK=`created_at` N) for listing all accounts per user; declare `attr_types={"created_at": "N"}`.

**New service:** `app/services/user_email_accounts.py`
- `create_account(user_sub, payload) -> dict` — validates host/port, KMS-encrypts password, puts item.
- `list_accounts(user_sub) -> list[dict]` — queries GSI, returns items without `password_ct_b64`.
- `get_account(user_sub, account_id) -> dict | None`
- `update_account(user_sub, account_id, **fields) -> dict`
- `delete_account(user_sub, account_id)` — deletes DDB row.
- `verify_connection(user_sub, account_id) -> dict` — decrypts password, attempts IMAP `LOGIN` (dev: mock/stub that always returns `{"ok": True}`; prod: real `imaplib.IMAP4_SSL` connect+login+logout), updates `status` and `last_error`.

**New router:** `app/routers/user_email_accounts.py`, prefix `/ui/email/accounts`, tag `email-client`, gated by `S.email_client_enabled`. Auth: `require_ui_session`.
- `POST /` — create
- `GET /` — list (no passwords)
- `GET /{account_id}` — get
- `PATCH /{account_id}` — update
- `DELETE /{account_id}` — delete
- `POST /{account_id}/verify` — verify_connection

Register in `app/main.py` after the existing `admin_email_router`.

**Models** (add to `app/models.py`): `EmailAccountCreateIn`, `EmailAccountUpdateIn`, `EmailAccountOut`.

**Acceptance Criteria**
- `POST /ui/email/accounts` creates an account and returns it without `password_ct_b64`; KMS encryption confirmed by checking DDB item directly.
- `GET /ui/email/accounts` lists all accounts for the authenticated user only; password field absent.
- `PATCH /ui/email/accounts/{id}` updates label/hosts; password update re-encrypts.
- `DELETE /ui/email/accounts/{id}` removes the record; 404 on unknown id.
- `POST /ui/email/accounts/{id}/verify` returns `{"ok": True, "status": "active"}` in dev; updates DDB status field.
- With `email_client_enabled=False` all routes return 503.
- Hermetic pytest: moto DDB, KMS stubbed (mirrors `tests/test_gap_0220_0221_ssh_stored_key.py` approach).

**Dependencies**
- No prior EML tickets required. Feature flag `EMAIL_CLIENT_ENABLED` (default off).

---

### EML-004: IMAP inbox sync and email threading

**Type:** Feature  **Priority:** P2  **Estimate:** 4d

**Description**

Implement server-side IMAP inbox sync that fetches message headers and bodies from the user's registered IMAP account (EML-003) and stores them in DynamoDB for the in-app email client UI (EML-005).

**New DynamoDB table:** `user_email_messages`

```
PK: USER#{user_sub}#ACCT#{account_id}
SK: MSG#{uid_str:010d}          (IMAP UID, zero-padded)
uid:             int            IMAP UID
message_id:      str            Message-ID header
in_reply_to:     Optional[str]  In-Reply-To header
references:      list[str]      References header parsed as list
thread_id:       str            Computed: sha256(root Message-ID)[:16]
subject:         str
from_addr:       str
to_addrs:        list[str]
cc_addrs:        list[str]
date_ts:         N              Unix timestamp from Date header
folder:          str            IMAP folder name e.g. "INBOX", "Sent", "Drafts"
flags:           list[str]      e.g. ["\\Seen", "\\Answered"]
snippet:         str            First 200 chars of plain-text body
body_text:       str            Plain-text body (up to 32 KB stored in DDB)
body_html:       Optional[str]  HTML body (up to 64 KB stored in DDB, else S3 key)
has_attachments: bool
synced_at:       N
```

GSI `ByThread` — PK=`USER#{user_sub}#ACCT#{account_id}`, SK=`thread_id` (S); for thread-grouped view.
GSI `ByFolder` — PK=`USER#{user_sub}#ACCT#{account_id}#FOLDER#{folder}`, SK=`date_ts` N; for folder inbox list. Declare `attr_types={"date_ts": "N"}`.

**Thread-ID derivation:** walk the `References` list (falling back to `In-Reply-To`, then `Message-ID` itself) to find the oldest known `message_id` in the DDB table for this user/account pair; use `sha256(root_message_id)[:16]` as the stable `thread_id`. This links replies to their parent threads without a separate index table.

**New service:** `app/services/email_sync.py`
- `sync_inbox(user_sub, account_id, *, folder="INBOX", max_fetch=200) -> dict` — decrypts credentials via `user_email_accounts.get_account` + `kms_decrypt`, opens IMAP connection, fetches up to `max_fetch` UIDs since last sync (stored as `SYNC#{account_id}` row on `user_email_messages` table), batch-fetches headers + bodies, upserts rows via `T.user_email_messages.put_item` (idempotent on UID), updates last-sync cursor. In dev mode uses a `_MockImapClient` stub that returns two synthetic messages.
- `list_messages(user_sub, account_id, folder, cursor, limit) -> (list, cursor)` — queries `ByFolder` GSI newest-first via `ScanIndexForward=False`.
- `get_message(user_sub, account_id, uid) -> dict | None`
- `list_thread(user_sub, account_id, thread_id) -> list[dict]` — queries `ByThread` GSI.

**New endpoints** (add to `app/routers/user_email_accounts.py` from EML-003, same prefix `/ui/email/accounts`):
- `POST /{account_id}/sync` — trigger sync for one folder (default `INBOX`); returns `{"synced": int}`.
- `GET /{account_id}/messages` — list messages (folder, cursor, limit params).
- `GET /{account_id}/messages/{uid}` — get one message.
- `GET /{account_id}/threads/{thread_id}` — list all messages in a thread.

**Acceptance Criteria**
- `POST /{account_id}/sync` fetches and stores messages; idempotent (re-sync does not duplicate).
- `GET /{account_id}/messages` returns messages in descending `date_ts` order per folder.
- `GET /{account_id}/threads/{thread_id}` returns all messages sharing a thread-ID, chronological ascending.
- Thread-ID is consistent: replies to the same root always share a thread-ID.
- `body_html` larger than 64 KB is stored to S3 at `email-bodies/{user_sub}/{account_id}/{uid}.html`; `GET /{account_id}/messages/{uid}` returns a presigned URL in that case.
- With `email_client_enabled=False` all new routes return 503.
- Hermetic pytest: `_MockImapClient` in dev mode, moto DDB + S3 via `object.__setattr__`.

**Dependencies**
- EML-003 (credential store). Feature flag `EMAIL_CLIENT_ENABLED`.

---

### EML-005: In-app email client UI (inbox, thread view, compose/reply/forward)

**Type:** Feature  **Priority:** P2  **Estimate:** 4d

**Description**

Add a full in-app email client frontend page at `/email` consuming the EML-003/EML-004 backend APIs.

**Frontend pages:** `frontend/src/pages/email/`
- `EmailPage.tsx` — top-level layout: left sidebar (account selector + folder tree), message list panel, thread/compose panel. Responsive split-pane using `ResizablePanelGroup` (shadcn/ui).
- `EmailAccountSetup.tsx` — empty-state prompt to add first IMAP/SMTP account; links to `EmailAccountSettings.tsx`.
- `EmailAccountSettings.tsx` — CRUD for personal email accounts (EML-003 API).
- `FolderTree.tsx` — sidebar folder list (`INBOX`, `Sent`, `Drafts`, `Trash`, custom); badge for unread count.
- `MessageList.tsx` — virtualized list of `EmailMessageRow` cards (subject, from, snippet, date, thread-count badge). React Query `useInfiniteQuery` on `GET /ui/email/accounts/{id}/messages?folder=INBOX`.
- `ThreadView.tsx` — expands all messages in a thread (from `GET /ui/email/accounts/{id}/threads/{thread_id}`), collapsible, renders `body_html` in a sandboxed `<iframe>` or sanitized via `DOMPurify`.
- `ComposePanel.tsx` — compose new / reply / forward form (to, cc, subject, HTML body editor using `@tiptap/react`); calls `POST /ui/email/accounts/{id}/messages/send` (EML-004 send endpoint).

**API endpoints file:** `frontend/src/api/endpoints/email.ts` — wrappers for all EML-003 and EML-004 backend endpoints using the existing `api/client.ts` axios instance.

**Types file:** `frontend/src/api/types.ts` — add `EmailAccount`, `EmailMessage`, `EmailThread` interfaces mirroring `EmailAccountOut` and the message/thread shapes.

**Route:** add lazy route `{ path: "/email/*", element: <EmailPage /> }` in `frontend/src/App.tsx` (before the catch-all `*` route). Add "Email" nav entry in `frontend/src/components/layout/Sidebar.tsx` (Mail icon from `lucide-react`).

**Acceptance Criteria**
- `/email` renders the email client shell; unauthenticated users redirect to `/login`.
- Without an account registered, `EmailAccountSetup` empty-state is shown.
- After adding IMAP account and triggering sync, messages appear in `MessageList`.
- Clicking a message opens `ThreadView`; HTML bodies are rendered in a sandboxed iframe.
- Compose panel can send a new email (calls send endpoint).
- Reply auto-fills to/subject from the selected thread; `In-Reply-To` header is set.
- With `email_client_enabled=False` the page shows a feature-unavailable notice (the flag is read via a public `GET /ui/email/status` endpoint returning `{enabled: bool}`).

**Dependencies**
- EML-003, EML-004. Feature flag `EMAIL_CLIENT_ENABLED`.

---

### EML-006: User personal email signature

**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Allow users to create, update, and delete a personal email signature that is automatically appended to emails sent from the in-app compose panel (EML-005).

**Storage:** Add a new row type to the `user_email_accounts` table (EML-003) rather than a separate table:

```
PK: USER#{user_sub}
SK: SIGNATURE
signature_html:  str    HTML body of the signature (max 10 KB, DOMPurify-sanitised server-side)
signature_text:  str    Plain-text fallback (max 2 KB)
updated_at:      N
```

**New service functions** (add to `app/services/user_email_accounts.py`):
- `get_signature(user_sub) -> dict | None`
- `upsert_signature(user_sub, html, text) -> dict` — sanitises HTML (strip `<script>`, `<iframe>`, event attributes via `bleach` or equivalent; mirrors the `app/services/kyc_document_templates.py` HTML-safe approach), stores, and returns.
- `delete_signature(user_sub)`

**New endpoints** (add to `app/routers/user_email_accounts.py`):
- `GET /ui/email/signature` — returns `SignatureOut` or 404.
- `PUT /ui/email/signature` — upserts signature, returns `SignatureOut`.
- `DELETE /ui/email/signature` — deletes; 404 if none.

**Models** (add to `app/models.py`): `SignatureIn` (`signature_html: str`, `signature_text: str`), `SignatureOut` (same fields + `updated_at`).

The compose panel (EML-005 `ComposePanel.tsx`) calls `GET /ui/email/signature` on mount and appends the HTML/text to the outgoing message body.

The outbound send service (EML-004 `send_message`) calls `get_signature(user_sub)` and appends `signature_text` to the plain-text part and `signature_html` to the HTML part of the outbound MIME message.

**Acceptance Criteria**
- `PUT /ui/email/signature` stores and returns the signature; `<script>` tags are stripped.
- `GET /ui/email/signature` returns 404 when none exists.
- `DELETE /ui/email/signature` idempotently removes the signature.
- Outbound emails (EML-004 send) automatically include the signature when one is set.
- With `email_signatures_enabled=False` (new flag, default off) all three endpoints return 503 and the compose panel does not fetch/append the signature.
- Hermetic pytest: moto DDB, HTML sanitisation confirmed by checking stored value.

**Dependencies**
- EML-003, EML-005. Feature flag `EMAIL_SIGNATURES_ENABLED`.

---

### EML-007: Email archiving — relate email to CRM record

**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Allow users to relate a synced email message to a CRM record (contact, support ticket, or org account) so that a CRM entity shows a list of associated email correspondence. This extends the archived-email concept from SuiteCRM's "Relate to" button.

**New DynamoDB table:** `email_archive`

```
PK: ENTITY#{entity_type}#{entity_id}    e.g. ENTITY#ticket#tkt_abc123
SK: EMAIL#{date_ts:010d}#{message_id_hash}
entity_type:     str    "contact" | "ticket" | "org_account"
entity_id:       str
user_sub:        str    who archived it
account_id:      str    which EML-003 account the message came from
uid:             int    IMAP UID in user_email_messages
message_id:      str    RFC-2822 Message-ID
subject:         str
from_addr:       str
snippet:         str    first 200 chars of body
date_ts:         N      from message Date header
archived_at:     N      now_ts()
```

GSI `ByUser` — PK=`USER#{user_sub}`, SK=`archived_at` N; for listing a user's archived emails. Declare `attr_types={"date_ts": "N", "archived_at": "N"}`.

**New service:** `app/services/email_archive.py`
- `archive_email(user_sub, account_id, uid, entity_type, entity_id) -> dict` — looks up the message from `T.user_email_messages`, validates entity existence (contact via `T.contacts`, ticket via `T.tickets`; org_account: deferred until PTY ships), writes archive row, calls `audit_event("email_archived", user_sub, None, entity_type=entity_type, entity_id=entity_id)`.
- `list_archived_emails(entity_type, entity_id, *, limit, cursor) -> (list, cursor)` — queries primary key on `T.email_archive`.
- `unarchive_email(user_sub, entity_type, entity_id, message_id_hash)` — deletes row; 403 if `user_sub` doesn't match.

**New router:** `app/routers/email_archive.py`, prefix `/ui/email/archive`, registered in `app/main.py`. Gated by `S.email_archiving_enabled`.
- `POST /` — `ArchiveEmailIn` (account_id, uid, entity_type, entity_id). Auth `require_ui_session`.
- `GET /entity/{entity_type}/{entity_id}` — list archived emails for that record (auth: user must own or have admin access to entity).
- `DELETE /entity/{entity_type}/{entity_id}/{message_id_hash}` — unarchive.

**Models**: `ArchiveEmailIn`, `ArchivedEmailOut`.

**Acceptance Criteria**
- `POST /ui/email/archive` creates a row and returns it; unknown UID returns 404.
- `GET /ui/email/archive/entity/ticket/{ticket_id}` returns all emails archived against that ticket; only ticket owner or admin can call it.
- `DELETE` removes the row; 403 for another user's archive entry.
- With `email_archiving_enabled=False` all routes return 503.
- Hermetic pytest: moto DDB for `user_email_messages` + `email_archive` + `tickets`, `T` handles patched via `object.__setattr__`.

**Dependencies**
- EML-003, EML-004. Feature flag `EMAIL_ARCHIVING_ENABLED`.

---

### EML-008: Inbound group mailbox auto-ticket creation

**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add an inbound email-to-ticket pipeline: an SES inbound rule delivers raw email via SNS to a new internal endpoint that parses the email, creates or threads a support ticket, and replies via the existing ticket notification infrastructure. This is the SuiteCRM "Inbound Email" feature for support mailboxes.

**Architecture:** SES → SNS → `POST /internal/ses/inbound` (new endpoint in `app/routers/ses_notifications.py`). The existing `/internal/ses/notifications` endpoint at line 29 of that file handles delivery events; the new inbound endpoint is at a distinct path `/internal/ses/inbound` on the same router.

**New DynamoDB table:** `inbound_mailboxes`

```
PK: MAILBOX#{mailbox_id}
SK: META
mailbox_id:      str    uuid4 hex
address:         str    the monitored email address (e.g. support@example.com)
label:           str
auto_assign_sub: Optional[str]   default assignee user_sub
space_id:        Optional[str]   ticket space to file new tickets in
enabled:         bool
created_at:      N
updated_at:      N
created_by:      str    admin user_sub
```

GSI `ByAddress` — PK=`address` (S); for resolving incoming mail to a mailbox config. No numeric SK, no `attr_types` needed.

**Email-to-ticket mapping:**
- New ticket: From address not found in existing tickets → `STORE.create_ticket(owner_sub=resolved_user_or_sentinel, subject=email_subject, description=email_body_text, space_id=mailbox.space_id)`. The `owner_sub` is resolved by matching the `From` address against `T.users` email field; if no match, a sentinel user `inbound@system` is used and the email address is stored in ticket metadata.
- Thread reply: `References` or `In-Reply-To` header contains a known ticket ID (encoded as `<ticket-{ticket_id}@{domain}>`) → add a message to the existing ticket via the existing `STORE.add_ticket_message` path in `app/services/tickets.py`.
- The created/updated ticket fires the existing `audit_event("ticket_created", ...)` / `"ticket_replied"` events which trigger alert emails via `send_alert_email` through the alert pipeline at `app/services/alerts.py:762`.

**New service:** `app/services/inbound_email.py`
- `list_mailboxes(cursor, limit) -> (list, cursor)` — scan for admins.
- `create_mailbox(actor_sub, payload) -> dict`
- `update_mailbox(actor_sub, mailbox_id, **fields) -> dict`
- `delete_mailbox(actor_sub, mailbox_id)`
- `process_inbound_message(raw_mime: bytes) -> dict` — parses raw MIME (stdlib `email.parser.BytesParser`), resolves mailbox via `ByAddress` GSI, determines create-vs-thread, calls ticket service, returns `{"action": "created"|"threaded", "ticket_id": str}`.

**New admin endpoints** (`app/routers/admin_email.py`, after existing audit endpoints, `require_admin_or_root`):
- `GET /ui/admin/email/mailboxes`
- `POST /ui/admin/email/mailboxes`
- `PATCH /ui/admin/email/mailboxes/{mailbox_id}`
- `DELETE /ui/admin/email/mailboxes/{mailbox_id}`

**Inbound endpoint** (`app/routers/ses_notifications.py`):
```python
@router.post("/internal/ses/inbound")
async def ses_inbound(request: Request) -> Response:
    # Verifies SNS signature (same verify_sns_message call as /internal/ses/notifications)
    # Extracts the S3 key or raw content from the SNS message
    # Calls inbound_email.process_inbound_message(raw_mime)
```

The SNS message contains either an S3 object key (when SES is configured to write to S3 first) or a raw base64 MIME payload. In dev mode, `process_inbound_message` is callable directly from the admin UI via a `POST /ui/admin/email/mailboxes/test-inbound` endpoint that accepts a raw MIME string for testing.

**Acceptance Criteria**
- `POST /ui/admin/email/mailboxes` creates a mailbox config; `GET` lists it; `DELETE` removes it.
- `POST /internal/ses/inbound` with a valid SNS-signed payload and raw MIME creates a new ticket when the recipient matches a mailbox address.
- A reply email containing `<ticket-{ticket_id}@...>` in References threads onto the existing ticket.
- Unknown recipient address returns `{"action": "ignored"}` with 200.
- SNS signature verification is enforced (gated by `ses_sns_signature_verification_enabled`, same as existing path at `app/routers/ses_notifications.py:47`).
- With `inbound_mailbox_enabled=False` all `/ui/admin/email/mailboxes` routes return 503 and the `/internal/ses/inbound` endpoint returns 503.
- Hermetic pytest: SNS signature verification stubbed, moto DDB for `inbound_mailboxes` + `tickets`, `process_inbound_message` called directly with a synthetic MIME bytes payload.

**Dependencies**
- Requires `app/services/tickets.py` (existing). Feature flag `INBOUND_MAILBOX_ENABLED`. Does NOT require EML-003/004.

---

### EML-009: Campaign email HTML template library

**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a campaign-specific HTML email template resource so that MKT-009 campaign sends can use a custom per-campaign HTML body with recipient merge fields, rather than always falling back to the generic plain-text `send_alert_email` path. This extends `app/services/notification_templates.py` (which already stores `admin_messaging_templates` under `PK=TEMPLATE#{id}`, `SK=META`) with a `campaign` channel type and links a template to a `MarketingCampaignCreateIn` (MKT-003).

**Model changes** (add to `app/models.py`):
- Extend `NotificationTemplateCreate` with optional `campaign_id: Optional[str] = None` and `merge_fields: list[str]` (list of supported `{{variable}}` names beyond the standard set).
- Add `CampaignEmailTemplateOut` (alias / subclass of `NotificationTemplateOut` with `campaign_id` field).

**Service changes** (extend `app/services/notification_templates.py`):
- `create_campaign_template(actor_sub, payload) -> dict` — calls the existing `create_template` helper, sets `channel="campaign"`, stores `campaign_id` and `merge_fields` on the DDB item.
- `render_campaign_body(template_id, recipient_vars: dict) -> (str, str)` — renders subject and HTML body by substituting `{{var}}` placeholders using `_VAR_RE` regex (already at line 23 of `notification_templates.py`) with recipient-specific values. Returns `(subject, html_body)`. Invalid templates (missing required vars) log a warning and return a safe fallback.
- `list_campaign_templates() -> list[dict]` — filters `channel="campaign"`.

**Router extension** (`app/routers/admin_email.py`, `require_admin_or_root`):
- `GET /ui/admin/email/campaign-templates` — list campaign templates.
- `POST /ui/admin/email/campaign-templates` — create.
- `PATCH /ui/admin/email/campaign-templates/{template_id}` — update body/subject/merge_fields.
- `DELETE /ui/admin/email/campaign-templates/{template_id}` — soft-delete (set `active=False`).
- `POST /ui/admin/email/campaign-templates/{template_id}/preview` — render with sample vars, returns `{subject, html_body}` (mirrors existing `/ui/admin/email/preview` at line 97 of `admin_email.py`).

**MKT-009 integration point:** `app/services/marketing_campaigns.py` (MKT-009 — not yet built; described at `docs/ofbiz/specs/MKT-009.md`) should, before calling `send_alert_email`, call `render_campaign_body(campaign.template_id, recipient_vars)` when `campaign.template_id` is set, and pass the resulting `html_body` to `send_alert_email(..., html_body=html_body)` (EML-001). This ticket documents the contract; the actual wiring happens inside MKT-009 implementation.

**Acceptance Criteria**
- `POST /ui/admin/email/campaign-templates` creates a template with `channel="campaign"`.
- `POST .../preview` renders `{{first_name}}` and `{{unsubscribe_url}}` substitution correctly.
- Unknown `{{var}}` in the body is left as-is (not stripped, so admins see the issue).
- `render_campaign_body` returns `(subject, html_body)` with all known vars substituted.
- `list_campaign_templates` returns only `channel="campaign"` items, not `email`/`sms` templates.
- With `campaign_email_templates_enabled=False` all new endpoints return 503; existing `/ui/admin/email/` endpoints are unaffected.
- Hermetic pytest: moto DDB bound to `T.admin_messaging_templates`, render tested with complete and incomplete var sets.

**Dependencies**
- EML-001 (html_body param in `send_alert_email`). Extends `app/services/notification_templates.py` (existing). Downstream: MKT-009. Feature flag `CAMPAIGN_EMAIL_TEMPLATES_ENABLED`.

---

### EML-010: E2E tests for email client and inbound email

**Type:** Chore  **Priority:** P2  **Estimate:** 2d

**Description**

Add Playwright E2E and pytest unit tests covering the full EML ticket surface.

**Playwright spec:** `frontend/e2e/email-client.spec.ts` — uses `injectAuth(page, "alice")` cookie pattern (same as `messaging-features.spec.ts`). Sections:

1. **Email account management API** (EML-003): create account, list (password absent), update label, delete, verify-connection returns `{ok:true}` in dev.
2. **Inbox sync + message list** (EML-004): POST sync returns `{synced: N}`, GET messages returns list sorted by date_ts descending, GET thread groups replies.
3. **Email archiving API** (EML-007): archive a message to a ticket, GET archive for ticket, unarchive.
4. **Email client UI** (EML-005): navigate to `/email`, empty-state prompt visible; after account creation and sync, message list renders; clicking a message shows thread view.
5. **Email signature API** (EML-006): PUT signature, GET returns it, compose panel appends it (check that send payload body contains signature text).
6. **Admin mailbox management** (EML-008): charlie_admin creates a mailbox, list returns it, test-inbound endpoint creates a ticket, delete removes mailbox.
7. **Campaign template admin API** (EML-009): create template with merge fields, preview renders vars, list returns only campaign-channel items.

**Pytest unit tests** (`tests/test_eml_email_client.py`):
- `test_account_kms_encryption` — verifies `password_ct_b64` stored in DDB differs from plaintext.
- `test_thread_id_consistency` — same root Message-ID produces the same thread_id across calls.
- `test_process_inbound_creates_ticket` — calls `process_inbound_message` with a synthetic MIME payload; moto DDB `inbound_mailboxes` + `tickets` tables; verifies ticket row created.
- `test_process_inbound_threads_reply` — reply with matching References header adds to existing ticket.
- `test_render_campaign_body_substitution` — verifies `{{first_name}}` and `{{unsubscribe_url}}` substitution.
- `test_send_alert_email_html` (EML-001) — mock `boto3.client("ses")`, verify `Body.Html.Data` is present when `html_body` is passed.
- `test_email_settings_override` (EML-002) — verifies `get_email_settings()` reads from DDB and falls back to `S.alerts_from_email` when absent.

**Acceptance Criteria**
- All E2E sections pass with `just e2e` (gated under `email_client_enabled=True` in E2E env).
- All unit tests pass with `just test`.
- Tests are hermetic offline (no real IMAP/SMTP/SES calls; `_MockImapClient` used).

**Dependencies**
- EML-001 through EML-009 (all prior tickets). Follows all implementations.
