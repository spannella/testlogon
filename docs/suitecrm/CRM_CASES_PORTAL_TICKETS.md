# CRM Cases, Customer Support & Customer Portal — Implementation Tickets

**Area**: Cases, Customer Support & Customer Portal
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T1] Cases, Customer Support & Customer Portal — 17 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Cases module covers: sequential human-readable case numbers, a priority field (Urgent/High/Medium/Low), transactional email notifications to submitter and assigned agent with HTML templates, case linking to Account (B2B org) and Contact records, file/attachment upload per case, SLA management (response-time targets per tier, breach alerts, escalation rules), manual and rule-based case escalation, inbound email-to-case creation (SES → SNS → internal endpoint), a Knowledge Base with articles/categories/search/case-deflection suggestions, a Joomla-style customer self-service portal (case submission without a platform account), case merge/duplicate detection, case-to-case linking (duplicate/blocks/relates_to), canned responses/reply templates for agents, CSAT surveys sent on case closure, ticket analytics with resolution time and agent throughput, and watcher/CC lists.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (e.g. `crm_cases_enabled`). With the flag off all new routes return 404 and all new background workers are no-ops. Existing `app/routers/tickets.py`, `app/services/tickets.py`, and `app/routers/ticket_boards.py` are byte-for-byte unchanged.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables follow the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` — omitting causes `ValidationException` at query time (CLAUDE.md gotcha).
- **Reuse existing primitives — never fork**:
  - Email: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`); `render_ticket_email_template` at line 235 already handles `ticket_created` / `ticket_assigned` / `ticket_replied` — extend, not duplicate.
  - In-app alert: `app/services/alerts.write_alert` / `audit_event` (`app/services/alerts.py:356`, `644`).
  - HMAC tokens (portal link, email-verify): `app/core/crypto.mint_ws_token` / `verify_ws_token` (`app/core/crypto.py:35`) — same scheme as cart recovery links.
  - S3 upload: reuse the `app.core.aws_clients.s3_client` factory (pattern: `app/services/kyc_partner_api.py` `_store_document_bytes`).
  - Questionnaire/CSAT: `app/routers/questionnaires.py` draft/publish/respond pattern — extend, not fork.
  - KYC SLA pattern: `app/services/kyc_case_assignment.py` `KycCaseAssignmentService` lines 39-70 define `SLA_TIERS`, `_DEFAULT_SLA`, SLA config in DDB; mirror this for ticket SLA.
  - Background loops: `app.add_event_handler("startup", ...)` in `app/main.py` line 663 area.
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor`.
  - Auth: `app/services/sessions.require_ui_session` for cookie-auth; `app/auth/deps.require_admin_session` for admin; `app/auth/roles.Role` enum.
- **TicketStore is the write path**: All changes to ticket META rows must go through `TicketStore._conditional_update_meta` / `_apply_header_update_once` (`app/services/tickets.py:723`) to honour optimistic locking via `version`.
- **Planned upstream dependencies**: PTY-001..PTY-015 (`PARTY_CRM_TICKETS.md`) deliver Party/Contact/Account. Tickets that add `contact_id` / `account_id` fields should declare PTY as a soft prerequisite and may carry opaque string foreign keys that resolve once PTY ships.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS/network calls.

---

### CAS-001: CRM Cases feature flag, settings & DynamoDB scaffolding
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Scaffold all downstream CAS work: add the master feature flag, sub-flags, table-name settings, and new DynamoDB tables. No user-visible behaviour is introduced.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern at line 432 (`ticket_boards_enabled`):

```python
crm_cases_enabled: bool = os.environ.get("CRM_CASES_ENABLED", "0") not in ("0", "false", "False")

# Sub-flags (all default-off)
crm_cases_sla_enabled: bool = ...             # CRM_CASES_SLA_ENABLED
crm_cases_portal_enabled: bool = ...          # CRM_CASES_PORTAL_ENABLED
crm_cases_kb_enabled: bool = ...              # CRM_CASES_KB_ENABLED
crm_cases_csat_enabled: bool = ...            # CRM_CASES_CSAT_ENABLED
crm_cases_email_inbound_enabled: bool = ...   # CRM_CASES_EMAIL_INBOUND_ENABLED

# Table names
crm_cases_sla_config_table: str = os.environ.get("CRM_CASES_SLA_CONFIG_TABLE", "crm_cases_sla_config")
crm_cases_attachments_bucket: str = os.environ.get("CRM_CASES_ATTACHMENTS_BUCKET", "local-uploads")
crm_cases_attachments_s3_prefix: str = os.environ.get("CRM_CASES_ATTACHMENTS_S3_PREFIX", "ticket-attachments/")
crm_cases_counter_table: str = os.environ.get("CRM_CASES_COUNTER_TABLE", "crm_cases_counters")
crm_cases_links_table: str = os.environ.get("CRM_CASES_LINKS_TABLE", "crm_cases_links")
crm_cases_templates_table: str = os.environ.get("CRM_CASES_TEMPLATES_TABLE", "crm_cases_templates")
crm_cases_portal_sessions_table: str = os.environ.get("CRM_CASES_PORTAL_SESSIONS_TABLE", "crm_cases_portal_sessions")
crm_kb_articles_table: str = os.environ.get("CRM_KB_ARTICLES_TABLE", "crm_kb_articles")
```

**DynamoDB tables** (`scripts/local-ddb-init.py`) — each follows the `TableDef` factory used at line 696:

- `crm_cases_counters` — PK=`counter_id` / SK=`scope` (used for atomic case number sequence). No GSIs.
- `crm_cases_links` — PK=`ticket_id` / SK=`LINK#{related_ticket_id}`. GSI `ByRelated`: PK=`related_ticket_id`, SK=`created_at`. `attr_types={"created_at": "N"}`.
- `crm_cases_templates` — PK=`template_id` / SK=`META`. GSI `ByOwner`: PK=`owner_sub`, SK=`created_at`. `attr_types={"created_at": "N"}`.
- `crm_cases_portal_sessions` — PK=`token` / SK=`META`. GSI `ByEmail`: PK=`submitter_email`, SK=`created_at`. `attr_types={"created_at": "N"}`.
- `crm_cases_sla_config` — PK=`CONFIG` / SK=`SLA#{priority}` (mirrors `kyc_case_assignment.py:68`). No GSIs needed.
- `crm_kb_articles` — PK=`ARTICLE#{article_id}` / SK=`META`. GSI `ByCategory`: PK=`category`, SK=`published_at`. GSI `ByStatus`: PK=`status`, SK=`published_at`. `attr_types={"published_at": "N"}`.

Wire all six table handles in `app/core/tables.py` alongside `T.tickets`.

**Acceptance Criteria**
- `S.crm_cases_enabled` and all sub-flags default `False`; can be toggled via env.
- All six `T.*` handles resolve in a smoke pytest.
- `just restart` creates all six tables with correct GSIs; no `ValidationException`.
- No existing route, table, or flag is changed.

**Dependencies**
- None (scaffolding only).

---

### CAS-002: Sequential human-readable case number
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Add an auto-incrementing human-readable `case_number` (e.g. `CASE-0042`) to every ticket created while `S.crm_cases_enabled` is on. The number is generated via a DynamoDB atomic counter on `crm_cases_counters` (PK=`counter_id=TICKETS`, SK=`scope=GLOBAL`) using an `ADD 1` `update_item` with `ReturnValues="UPDATED_NEW"` — same pattern as any auto-increment on DDB (no scan needed).

Changes required:
- New `_next_case_number() -> str` helper in `app/services/tickets.py` that calls `T.crm_cases_counters.update_item(ADD #n :one, ReturnValues="UPDATED_NEW")` and returns `f"CASE-{n:04d}"`.
- `TicketStore.create_ticket` (line 411): when `S.crm_cases_enabled`, call `_next_case_number()` and persist `case_number` on the META row.
- `get_ticket` (line 522): surface `case_number` from the META item.
- `TicketOut` Pydantic model (`app/routers/tickets.py:58`): add `case_number: str | None = None`.
- `TicketListItemOut` (line 91): add same field.

The existing `create_ticket` already uses `put_item` with idempotent guard (`existing = self.get_ticket(resolved_ticket_id)` at line 431) — do not increment the counter on that branch.

**Acceptance Criteria**
- `POST /tickets` with `CRM_CASES_ENABLED=1` returns `{"ticket": {"case_number": "CASE-0001", ...}}`.
- Sequential: second ticket gets `CASE-0002`, etc.
- With `CRM_CASES_ENABLED=0` (default), `case_number` is `None` — no existing test breaks.
- Hermetic offline pytest: moto `crm_cases_counters` bound to `T.crm_cases_counters` via `object.__setattr__`.

**Dependencies**
- CAS-001 (counter table).

---

### CAS-003: Case priority field (Urgent / High / Medium / Low)
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Add a first-class `priority` field (enum: `urgent | high | medium | low`) to the ticket data model, distinct from the existing `complexity` label hack. Priority is set on creation and updateable by admins.

Changes required:
- `CreateTicketReq` (`app/routers/tickets.py:173`): add `priority: Literal["urgent","high","medium","low"] | None = "medium"`.
- `TicketStore.create_ticket` (`app/services/tickets.py:411`): persist `priority` on the META row.
- `TicketStore.get_ticket` (line 522): surface `priority`.
- `TicketOut` / `TicketListItemOut`: add `priority: str | None = None`.
- New `PATCH /tickets/{ticket_id}/priority` endpoint (admin only): body `{"priority": "<value>"}`, calls a new `TicketStore.update_priority` method that updates the META row via `_apply_header_update_once`.
- New GSI for priority-based listing: add `gsi_priority_pk` (`PRIORITY#{priority}`) and `gsi_priority_sk` (`UPDATED#{updated_at:013d}#TICKET#{ticket_id}`) on the META row; register `crm_cases_priority_index` in `S` and `scripts/local-ddb-init.py` with `attr_types={"gsi_priority_sk": "N"}` — only written when `S.crm_cases_enabled`.
- `GET /tickets` query param `priority=urgent|high|medium|low` uses the new GSI when flag is on.

**Acceptance Criteria**
- `POST /tickets` with `priority: "urgent"` persists and returns the field.
- `PATCH /tickets/{id}/priority` updates the field; non-admin gets 403.
- `GET /tickets?priority=urgent` returns only urgent tickets.
- With flag off, no GSI rows are written; existing tests unaffected.

**Dependencies**
- CAS-001 (scaffolding/settings), CAS-002 (confirms TicketOut model changes do not break existing tests).

---

### CAS-004: Case email notifications — transactional SES dispatch
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Wire ticket alert events to proper transactional email via `send_alert_email` (`app/services/alerts.py:459`). The existing `_emit_ticket_alerts` in `app/routers/tickets.py:362` already calls `audit_event` for each recipient, and `write_alert` (`alerts.py:356`) conditionally calls `send_alert_email` when the alert type is in the email-dispatch set. The gap: `render_ticket_email_template` (`alerts.py:235`) produces plain-text only, and email prefs are not checked per-user.

Changes required:
- Extend `render_ticket_email_template` (`alerts.py:235`) to return an HTML body variant (`html_body: str`) alongside the existing plain text, using the same template dict. Pass `html_body` as `Body.Html.Data` when calling `boto3_ses.send_email` inside `send_alert_email` (line 459). This is a PARTIAL fix for the gap analysis "HTML email body" item but scoped to ticket events.
- Add email dispatch path in `write_alert` for new event types: `ticket_escalated`, `ticket_sla_breach`, `ticket_csat_sent`, `ticket_watcher_added` — add them to the `_TICKET_EMAIL_EVENTS` set at `alerts.py:140`.
- When `S.crm_cases_enabled` is on, read the submitter's email from `app/services/profile.get_profile_identity(owner_sub)` and the assigned agent's email and send to both on `ticket_created`, `ticket_assigned`, `ticket_replied`, `ticket_status_changed`.
- With `S.crm_cases_enabled` off, the code path is identical to today — no regression.

**Acceptance Criteria**
- `POST /tickets` triggers an email to the submitter's email address (mocked by patching `send_alert_email`).
- Agent receives email on `ticket_assigned`.
- New event types (`ticket_escalated`, etc.) are in the email event set.
- Offline pytest: `send_alert_email` patched at source; no SES calls.

**Dependencies**
- CAS-001 (flag).

---

### CAS-005: Case linked to Contact and Account
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Add optional `contact_id` and `account_id` foreign-key fields to the ticket store. These are opaque strings now; they resolve to Party records once PTY-001..015 ship.

Changes required:
- `CreateTicketReq` (`app/routers/tickets.py:173`): add `contact_id: str | None = None` and `account_id: str | None = None`.
- `TicketStore.create_ticket` (`app/services/tickets.py:411`): persist both fields on the META row when `S.crm_cases_enabled`. Also write two new GSI keys:
  - `gsi_contact_pk` = `CONTACT#{contact_id}` / `gsi_contact_sk` = `UPDATED#{...}` when `contact_id` set.
  - `gsi_account_pk` = `ACCOUNT#{account_id}` / `gsi_account_sk` = `UPDATED#{...}` when `account_id` set.
- Register `crm_cases_contact_index` and `crm_cases_account_index` in `scripts/local-ddb-init.py` and `S` (both numeric SK, `attr_types={"gsi_contact_sk": "N"}` etc.).
- `get_ticket`: surface `contact_id`, `account_id` in `TicketOut`.
- New `GET /tickets?contact_id=<id>` and `GET /tickets?account_id=<id>` query paths (admin only) using the respective GSI.
- `_conditional_update_meta` (`app/services/tickets.py:723`): add `contact_id`, `account_id` to the SET/REMOVE block (mirror the `gsi_space_*` pattern for REMOVE-if-None).

**Acceptance Criteria**
- `POST /tickets` with `contact_id` and `account_id` → ticket returned with both fields set.
- `GET /tickets?contact_id=<id>` returns only tickets linked to that contact.
- `GET /tickets?account_id=<id>` returns only tickets for that account.
- With flag off, fields are ignored and no GSI rows written.
- PTY dependency soft: fields are stored and returned even without a live PTY module.

**Dependencies**
- CAS-001, CAS-002, CAS-003 (confirm TicketOut is stable).

---

### CAS-006: Case file attachment upload and download
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add file attachment support per ticket: multipart upload stores to S3, metadata stored on a sub-item in the tickets table.

**Backend** (`app/routers/tickets.py` and `app/services/tickets.py`):
- New `POST /tickets/{ticket_id}/attachments` endpoint: accepts `multipart/form-data` with fields `file` (UploadFile) and optional `description`. Auth: `require_ui_session`; owner or admin. Gated: `if not S.crm_cases_enabled: raise 404`.
- `TicketStore.add_attachment` method: writes a sub-item `pk=TICKET#{ticket_id}`, `sk=ATTACH#{ts:013d}#{attach_id}` with fields `attach_id`, `s3_key`, `bucket`, `filename`, `content_type`, `size_bytes`, `description`, `uploader_sub`, `created_at`. Upload via `s3_client.put_object(Bucket=S.crm_cases_attachments_bucket, Key=f"{S.crm_cases_attachments_s3_prefix}{ticket_id}/{attach_id}/{safe_filename}", Body=data, ContentType=content_type)`.
- New `GET /tickets/{ticket_id}/attachments` endpoint: lists all `ATTACH#` sub-items, returns presigned URLs (300s) in prod or `/mock/s3/...` URL in `S.dev_mode`. Mirrors the pattern in `app/services/kyc_partner_api.py:get_document_download`.
- New `DELETE /tickets/{ticket_id}/attachments/{attach_id}` endpoint: admin only; soft-deletes by setting `deleted_at` on the DDB item (does not remove from S3 to preserve audit trail).
- `get_ticket` (`app/services/tickets.py:522`): include attachment list (exclude `deleted_at` items) in the returned dict; `TicketOut` gains `attachments: list[AttachmentOut]`.

**Frontend** (`frontend/src/pages/tickets/TicketsPage.tsx`):
- Add a file-upload button in the ticket reply area and an attachment list panel on the ticket detail view. Reuse the `FilePickerDialog` shared component pattern at `frontend/src/components/shared/`.

**Acceptance Criteria**
- `POST /tickets/{id}/attachments` (multipart) stores to S3 and returns `attach_id` + URL.
- `GET /tickets/{id}/attachments` returns a presigned URL per attachment in prod (mock URL in dev).
- `DELETE /tickets/{id}/attachments/{attach_id}` soft-deletes; re-fetching excludes deleted item.
- Uploads > 10 MB rejected with 413.
- Offline pytest: `s3_client` patched to an in-memory `_FakeS3` dict.

**Dependencies**
- CAS-001, CAS-002, CAS-005.

---

### CAS-007: Ticket watchers / CC list
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Implement a watcher (CC) list on each ticket: users added as watchers receive the same email and in-app alerts as the assignee on every status change and reply.

`ticket_boards.py:241` already reads `ticket.get("watchers", [])` when building participant lists, so the field is anticipated — it just needs to be persisted and maintained.

Changes required:
- `TicketStore`: add `watchers: list[str]` to the META row on creation (default `[]`).
- New `TicketStore.add_watcher(ticket_id, watcher_sub)` and `remove_watcher(ticket_id, watcher_sub)` methods using `update_item` with `ADD` / `DELETE` on a DynamoDB StringSet attribute `watchers` — avoids read-modify-write races.
- New `POST /tickets/{ticket_id}/watchers` (body: `{"watcher_sub": "..."}`) and `DELETE /tickets/{ticket_id}/watchers/{watcher_sub}` endpoints. Auth: owner or admin; gated on `S.crm_cases_enabled`.
- `get_ticket` surfaces `watchers` list; `TicketOut` gains `watchers: list[str] = []`.
- `_emit_ticket_alerts` (`app/routers/tickets.py:362`): pass `ticket.get("watchers", [])` into `recipients` for `ticket_replied` and `ticket_status_changed` events.
- Emit `ticket_watcher_added` / `ticket_watcher_removed` audit events.

**Acceptance Criteria**
- `POST /tickets/{id}/watchers` adds the watcher; `GET /tickets/{id}` returns updated watchers list.
- `DELETE /tickets/{id}/watchers/{sub}` removes; owner cannot remove themselves.
- On `ticket_replied`, watchers each receive an in-app alert.
- `ticket_boards.py` helper `_board_ticket_participants` (line 237) already iterates `ticket.get("watchers", [])` — no change needed there.
- Hermetic test: `T.tickets` bound to moto; `write_alert` / `send_alert_email` patched.

**Dependencies**
- CAS-001.

---

### CAS-008: SLA management — tiers, breach detection, and escalation alerts
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add SLA enforcement on support tickets: configurable SLA tiers keyed by `priority` (mapping to first-response and resolution targets), per-ticket `sla_due_at` stamp, and a background checker that detects breaches and emits escalation alerts.

This mirrors the KYC SLA implementation in `app/services/kyc_case_assignment.py` (lines 39-70, `_DEFAULT_SLA`, `SLA_TIERS`, `_sla_sk`, `get_sla_config`, `_write_assignment`) — adapt for ticket priority tiers.

**Service** (`app/services/ticket_sla.py` — new file):
- `_DEFAULT_SLA_CONFIG: dict[str, dict[str, int]]` = mapping priority → `{"first_response_hours": N, "resolution_hours": N, "warning_pct": 80}`.
- `TicketSlaService`: reads/writes SLA config from `T.crm_cases_sla_config` (PK=`CONFIG`, SK=`SLA#{priority}`). Methods: `get_sla_config()`, `update_sla_config(priority, config_dict)`, `compute_sla_due_at(ticket) -> int` (uses `ticket["created_at"]` + configured hours), `check_breaches()` (scans open tickets by status GSI, compares `sla_due_at` vs `now_ts()`).
- `start_ticket_sla_checker_task()`: startup loop (poll interval `S.crm_cases_sla_check_interval_seconds`, default 300), gated on `S.crm_cases_sla_enabled`. Registered in `app/main.py` alongside `start_kyc_sla_checker_task` (line 663).

**Router additions** (`app/routers/tickets.py`):
- `TicketStore.create_ticket`: when `S.crm_cases_sla_enabled`, set `sla_due_at = TicketSlaService().compute_sla_due_at(ticket)` on the META row after creation.
- `GET /tickets/admin/sla-config` — return current SLA config; admin only.
- `PATCH /tickets/admin/sla-config/{priority}` — update first_response_hours / resolution_hours for a priority tier; root only.
- `sla_due_at: int | None`, `sla_breached: bool` added to `TicketOut`.
- When `check_breaches` finds a breached ticket: call `write_alert` / `send_alert_email` for `ticket_sla_breach` event to assignee and watchers.

**Settings** (`app/core/settings.py`):
```python
crm_cases_sla_check_interval_seconds: int = int(os.environ.get("CRM_CASES_SLA_CHECK_INTERVAL", "300"))
```

**Acceptance Criteria**
- `POST /tickets` with `priority="urgent"` and `CRM_CASES_SLA_ENABLED=1` → `TicketOut.sla_due_at` is set (≤ `created_at + first_response_hours * 3600`).
- `GET /tickets/admin/sla-config` returns the four-priority config dict.
- `check_breaches()` sets `sla_breached=True` on overdue tickets; alert fired once per breach (idempotent — check `breach_alerted_at` field on META).
- Background task registered on startup when flag on; no-op when off.
- Hermetic pytest: moto tables, `now_ts` patched, `send_alert_email` patched.

**Dependencies**
- CAS-001 (flag, `crm_cases_sla_config` table), CAS-003 (priority field).

---

### CAS-009: Case escalation — manual and rule-based
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a case escalation capability: an `escalation_level` counter and `escalated_at` / `escalated_by` fields on the ticket META row, a `POST /tickets/{ticket_id}/escalate` endpoint, and an auto-escalation path triggered by `check_breaches` (from CAS-008) when `escalation_level == 0`.

This mirrors KYC escalation in `app/services/kyc_cases.py:escalate_case` (KYC-008/GAP-0265) — adapt the same conditional-update pattern for tickets.

**Service** (`app/services/tickets.py` additions):
- `TicketStore.escalate_ticket(ticket_id, actor_sub, reason, new_assignee_sub=None)`: conditional `update_item` adding `escalation_level += 1`, `escalated_at`, `escalated_by`, optional `escalated_to_sub` re-assignment. Only for tickets in `open | in_progress | waiting_on_user` status (terminal statuses are a no-op). Emits `ticket_escalated` audit event.

**Router** (`app/routers/tickets.py`):
- `POST /tickets/{ticket_id}/escalate` — body `{"reason": str, "new_assignee_sub": str | None}`. Auth: admin only; gated on `S.crm_cases_enabled`.
- `TicketOut` gains `escalation_level: int = 0`, `escalated_at: int | None`, `escalated_by: str | None`.
- `send_alert_email` fired to owner + current watchers for `ticket_escalated` event.

**Auto-escalation** (in `TicketSlaService.check_breaches`, CAS-008):
- When `sla_breached=True` and `escalation_level == 0` and `S.crm_cases_sla_enabled`: call `STORE.escalate_ticket(ticket_id, actor_sub="system_sla_escalation", reason="SLA breach auto-escalation")`.

**Acceptance Criteria**
- `POST /tickets/{id}/escalate` increments `escalation_level` from 0 → 1 and records `escalated_by`.
- Second escalation: `escalation_level` 1 → 2 with new reason.
- Non-admin gets 403. Closed ticket returns 409 or no-op.
- Auto-escalation fires once on SLA breach (subsequent breaches: `escalation_level` increments further).
- Hermetic pytest.

**Dependencies**
- CAS-001, CAS-007 (watchers for alert recipients), CAS-008 (SLA breach hook).

---

### CAS-010: Case merge and duplicate detection
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Allow agents to merge a duplicate ticket into a canonical ticket: all messages and attachments are migrated; future replies on the source ticket redirect to the canonical.

**Service** (`app/services/tickets.py` additions):
- `TicketStore.merge_ticket(source_ticket_id, target_ticket_id, actor_sub)`:
  1. Reads both tickets (both must exist and not already be merged).
  2. Copies all `MSG#` and `ATTACH#` sub-items from source to target partition using batch writes.
  3. Sets `merged_into_ticket_id` on the source META row and `status="done"` via `_conditional_update_meta`.
  4. Writes an `ACT#` activity row `"ticket_merged"` on both source and target.
  5. Emits `audit_event("ticket_merged", ...)`.
- `get_ticket` returns `merged_into_ticket_id: str | None`; router returns 301 redirect with `Location: /tickets/{target_id}` when a caller GETs a merged ticket.

**Router** (`app/routers/tickets.py`):
- `POST /tickets/{ticket_id}/merge` — body `{"target_ticket_id": str}`. Admin only; gated on `S.crm_cases_enabled`.

**Acceptance Criteria**
- Merging source into target copies all messages to target; source status becomes `done`.
- `GET /tickets/{source_id}` returns 301 to target.
- Both tickets carry an `activity` entry `"ticket_merged"`.
- Merging an already-merged ticket returns 409 `ticket_already_merged`.
- Non-admin gets 403.
- Hermetic pytest.

**Dependencies**
- CAS-001, CAS-006 (attachments are part of the sub-items to migrate).

---

### CAS-011: Case-to-case relationship links
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Implement a ticket link sub-table (`crm_cases_links`, from CAS-001 scaffolding) supporting typed links between tickets: `duplicate`, `blocks`, `relates_to`.

**Service** (`app/services/ticket_links.py` — new file):
- `TicketLinkService`: methods `add_link(ticket_id, related_ticket_id, link_type)`, `remove_link(ticket_id, related_ticket_id)`, `list_links(ticket_id)`.
- Writes two rows (bidirectional): `pk=ticket_id, sk=LINK#{related_ticket_id}` with `link_type` + direction `source`, and the inverse.
- `list_links` queries `pk=ticket_id, begins_with(sk, "LINK#")` on `T.crm_cases_links`.

**Router** (`app/routers/tickets.py`):
- `GET /tickets/{ticket_id}/links` — owner or admin.
- `POST /tickets/{ticket_id}/links` — body `{"related_ticket_id": str, "link_type": "duplicate|blocks|relates_to"}`. Admin only.
- `DELETE /tickets/{ticket_id}/links/{related_ticket_id}` — admin only.
- All gated on `S.crm_cases_enabled`.
- `TicketOut` gains `links: list[TicketLinkOut] = []`.

**Acceptance Criteria**
- `POST /tickets/{id}/links` → bidirectional rows written.
- `GET /tickets/{id}/links` returns both incoming and outgoing links.
- `DELETE /tickets/{id}/links/{related_id}` removes both directions.
- Non-existent target ticket returns 404.
- `link_type` outside enum returns 422.
- Hermetic pytest: moto `crm_cases_links` bound via `object.__setattr__`.

**Dependencies**
- CAS-001 (`crm_cases_links` table).

---

### CAS-012: Canned responses / reply templates for agents
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Add a `TicketResponseTemplate` resource (title, body, category) so agents can quickly insert pre-written replies without typing from scratch. Stored in `T.crm_cases_templates` (CAS-001).

**Service** (`app/services/ticket_templates.py` — new file):
- `TicketTemplateService`: CRUD methods `create_template`, `get_template`, `update_template`, `delete_template`, `list_templates(category=None)`.
- DDB row: `pk=template_id`, `sk=META`, fields: `title`, `body`, `category`, `owner_sub`, `created_at`, `updated_at`.
- GSI `ByOwner` (PK=`owner_sub`, SK=`created_at`) for listing user's own templates.

**Router** (`app/routers/tickets.py` or new `app/routers/ticket_templates.py`):
- `GET /tickets/response-templates` — any authenticated user; returns all templates (`admin`) or own templates (`user`); query param `category=<str>`.
- `POST /tickets/response-templates` — admin only; body `{title, body, category}`.
- `PUT /tickets/response-templates/{template_id}` — admin only.
- `DELETE /tickets/response-templates/{template_id}` — admin only.
- All gated on `S.crm_cases_enabled`.
- Route `response-templates` declared **before** any `/{ticket_id}` path param (FastAPI matches in declaration order — same warning as KYC-007 `templates` route at `app/routers/kyc_cases.py`).

**Frontend** (`frontend/src/pages/tickets/TicketsPage.tsx`):
- Dropdown in ticket reply textarea populated from `GET /tickets/response-templates`; selecting one inserts body into the textarea.

**Acceptance Criteria**
- Admin can create/update/delete templates; non-admin gets 403.
- `GET /tickets/response-templates` returns templates; `?category=billing` filters correctly.
- Frontend dropdown inserts template body.
- Hermetic pytest.

**Dependencies**
- CAS-001 (`crm_cases_templates` table).

---

### CAS-013: Inbound email-to-ticket creation
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Enable inbound email to automatically create a support ticket: SES inbound routing → SNS → `POST /internal/ses/inbound` → parse raw email → `TicketStore.create_ticket`.

**Backend** (`app/routers/internal_ses_inbound.py` — new file, registered in `app/main.py`):
- `POST /internal/ses/inbound` — no auth (internal network only); accepts SNS `SubscriptionConfirmation` and `Notification` payloads.
- For `Notification`: parse base64-encoded raw email using `email.parser.BytesParser` (stdlib). Extract `From` (submitter email), `Subject` (ticket subject), plain-text body (description), and `Message-ID` header (for reply threading via `In-Reply-To`).
- Lookup user by email in `T.users` GSI; if no match, create a portal-style "email-only" ticket with `submitter_email` field (guest ticket path).
- Call `STORE.create_ticket(owner_sub=user_sub_or_guest, subject=subject, description=body, category="email_inbound")`.
- On subsequent emails with matching `In-Reply-To` header, call `STORE.add_message` on the existing ticket (thread stitching).
- Gated on `S.crm_cases_email_inbound_enabled`.

**Settings** (`app/core/settings.py`):
```python
crm_cases_inbound_email_address: str = os.environ.get("CRM_CASES_INBOUND_EMAIL", "support@example.com")
crm_cases_inbound_sns_topic_arn: str = os.environ.get("CRM_CASES_INBOUND_SNS_TOPIC", "")
```

**Infrastructure note**: In dev mode (`S.dev_mode`), a `POST /mock/ses/inbound` endpoint (adjacent to existing mock endpoints) simulates the SNS notification payload for E2E testing without real SES/SNS.

**Acceptance Criteria**
- `POST /internal/ses/inbound` with a valid SNS notification creates a ticket with `category="email_inbound"`.
- Reply email threads onto the existing ticket (matched by `In-Reply-To` header).
- Unknown sender creates a ticket with `submitter_email` set (no user_sub required).
- SNS `SubscriptionConfirmation` payload returns 200 without creating a ticket.
- Gated: with flag off, endpoint returns 404.
- Hermetic pytest: email bytes constructed inline; no real SNS.

**Dependencies**
- CAS-001 (flag), CAS-013 is the only ticket in this area without a hard CAS prerequisite beyond the flag.

---

### CAS-014: Customer self-service portal (guest ticket submission)
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Add a public-facing case submission flow that does not require a platform account: the submitter provides an email address, receives a verification link, and can submit a ticket and view replies without logging in.

**Backend**:
- `POST /public/cases/start` — no auth. Body `{email, subject, description}`. Generates an HMAC-signed, time-limited verification token (same scheme as `mint_ws_token` in `app/core/crypto.py:35`, secret=`UI_ACCESS_TOKEN_SECRET`). Sends verification email via `send_alert_email`. Writes a `pending_verification` session row to `T.crm_cases_portal_sessions` (PK=`token`, SK=`META`, TTL 1h).
- `GET /public/cases/verify/{token}` — validates HMAC token; marks session `verified=True`; returns a short-lived `portal_token` (15 min TTL). Redirects to `/support/new?portal_token=<token>`.
- `POST /public/cases/submit` — header `X-Portal-Token: <portal_token>` (no cookie auth). Validates portal token from `T.crm_cases_portal_sessions`. Calls `STORE.create_ticket(owner_sub=f"guest:{email}", ...)`. Returns `{ticket_id, case_number, public_ticket_url}`.
- `GET /public/cases/{ticket_id}` — validates portal token (email must match ticket's `submitter_email`); returns `TicketOut` with messages (no internal fields). Gated on `S.crm_cases_portal_enabled`.

**Frontend** (`frontend/src/pages/tickets/PortalPage.tsx` — new file):
- Route `/support/new`: email entry form → verification notice → ticket form → confirmation with ticket number.
- Route `/support/tickets/{ticket_id}`: read-only ticket view for portal users.
- Added to `frontend/src/App.tsx` with `auth: false`.

**Acceptance Criteria**
- `POST /public/cases/start` sends verification email and stores pending session.
- Invalid/expired token on `/verify` returns 401 `portal_token_invalid`.
- `POST /public/cases/submit` with valid portal token creates ticket and returns case number.
- `GET /public/cases/{id}` returns ticket messages to the portal user only.
- Portal token is single-use (consumed on first submit; `attribute_not_exists(consumed_at)` conditional write).
- With `CRM_CASES_PORTAL_ENABLED=0`, all `/public/cases/*` endpoints return 404.
- Hermetic pytest: HMAC mint/verify inline; `send_alert_email` patched.

**Dependencies**
- CAS-001 (`crm_cases_portal_sessions` table), CAS-002 (case number), CAS-004 (email notify).

---

### CAS-015: Knowledge Base — articles, categories, search, case deflection
**Type:** Feature  **Priority:** P2  **Estimate:** 4d

**Description**

Build a Knowledge Base module: article CRUD with rich-text body, hierarchical categories, full-text prefix search, a "suggested articles" hook on ticket creation for case deflection, article ratings, and an admin management UI.

**Service** (`app/services/kb_articles.py` — new file):
- DDB table `crm_kb_articles` (from CAS-001): PK=`ARTICLE#{article_id}` / SK=`META`. Fields: `title`, `body_html`, `category`, `tags`, `status` (enum `draft|published|archived`), `author_sub`, `view_count`, `helpful_count`, `not_helpful_count`, `created_at`, `updated_at`.
- `KbArticleService`: `create_article`, `get_article`, `update_article`, `publish_article`, `archive_article`, `list_articles(category=None, status="published")`, `increment_view_count`, `rate_article(helpful: bool)`, `search_articles(q)`.
- Search: token-prefix pattern mirroring `app/services/messaging_search.py` — build prefix tokens on `title` words (max prefix len 8), store as a `search_tokens` StringSet on the article row. `search_articles(q)` scans the prefix token set (DDB `contains` FilterExpression, or a dedicated `SEARCH_TOKEN#{token}/ARTICLE#{id}` fan-out pattern matching the message search index if volume warrants).
- Category hierarchy: `parent_category_id` field on category META items (separate `CATEGORY#` SK prefix on same table). Mirrors PRD-004 category tree pattern (referenced in gap analysis).

**Router** (`app/routers/kb_articles.py` — new file, registered in `app/main.py`):
- Public (no auth): `GET /public/kb/articles`, `GET /public/kb/articles/{id}`, `GET /public/kb/search?q=`.
- Authenticated: `POST /kb/articles/{id}/rate` (body `{helpful: bool}`), `GET /kb/articles/{id}/related`.
- Admin: `POST /kb/articles`, `PUT /kb/articles/{id}`, `DELETE /kb/articles/{id}`, `POST /kb/articles/{id}/publish`, `POST /kb/categories`, `PUT /kb/categories/{id}`.
- All admin paths gated on `S.crm_cases_kb_enabled` **and** `require_admin_session`.

**Case deflection hook**: in `create_ticket` endpoint (`app/routers/tickets.py:766`), when `S.crm_cases_kb_enabled`, call `KbArticleService().search_articles(subject_words[:3])` and include top-3 results in `TicketOut.suggested_articles: list[KbArticleSummaryOut]`.

**Frontend** (`frontend/src/pages/tickets/KbPage.tsx` — new file):
- Public article browser with category tree, search bar, article view with helpful/not-helpful buttons.
- On ticket create form: show "Before you submit, check these articles" panel if suggestions exist.

**Acceptance Criteria**
- `POST /kb/articles` (admin) → article created in draft. `POST .../publish` → status=published, visible at `GET /public/kb/articles`.
- `GET /public/kb/search?q=password` returns articles with "password" in title.
- Ticket creation with `CRM_CASES_KB_ENABLED=1` returns `suggested_articles` (may be empty list).
- `POST /kb/articles/{id}/rate` increments `helpful_count` / `not_helpful_count`.
- `GET /public/kb/articles/{id}` increments `view_count` atomically.
- Hermetic pytest: moto `crm_kb_articles` table.

**Dependencies**
- CAS-001 (`crm_kb_articles` table), CAS-002 (for suggested_articles in TicketOut). KB is independent of SLA/portal.

---

### CAS-016: CSAT survey on ticket closure
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

On ticket status transition to `done`, automatically send a CSAT survey link to the ticket owner. Reuse the questionnaire infrastructure in `app/routers/questionnaires.py` (publish/respond pattern) rather than building a separate survey mechanism.

**Approach**:
- A "CSAT template" questionnaire is published once by the admin (a 1-question 1–5 rating + optional comment form). Its `questionnaire_id` is stored in `S.crm_cases_csat_questionnaire_id` (settings key).
- `app/services/ticket_csat.py` — new file:
  - `send_csat_survey(ticket_id, owner_sub)`: creates a pre-filled `ResponseSession` for the CSAT questionnaire (calls the questionnaire service's `start_session` for the stored questionnaire), stores session link, sends email via `send_alert_email` with a link to `/q/{slug}?session_id={session_id}&ref=ticket:{ticket_id}`.
  - `get_csat_result(ticket_id)`: reads the completed session from `T.questionnaires` and returns rating + comment.
- Hook in `app/routers/tickets.py` `set_ticket_status` (line 991): when new status is `"done"` and `S.crm_cases_csat_enabled`, call `send_csat_survey(ticket_id, ticket["owner_sub"])` in a best-effort `try/except`.
- `TicketOut` gains `csat_score: int | None` and `csat_comment: str | None` (read lazily from `get_csat_result`).

**Settings** (`app/core/settings.py`):
```python
crm_cases_csat_questionnaire_id: str = os.environ.get("CRM_CASES_CSAT_QUESTIONNAIRE_ID", "")
```

**Frontend** (`frontend/src/pages/tickets/TicketsPage.tsx`):
- When `csat_score` is set, show a star rating badge on the closed ticket.

**Acceptance Criteria**
- Setting ticket status to `done` with `CRM_CASES_CSAT_ENABLED=1` calls `send_csat_survey` (verified by patching).
- CSAT survey failure never blocks the status update (best-effort `try/except`).
- With `CRM_CASES_CSAT_ENABLED=0`, no survey is sent.
- `TicketOut.csat_score` is populated when the session is completed.
- Hermetic pytest: questionnaire session patched; `send_alert_email` patched.

**Dependencies**
- CAS-001 (flag), CAS-004 (email dispatch).

---

### CAS-017: Ticket analytics — resolution time, volume, agent throughput
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Add a ticket analytics endpoint going beyond the existing `GET /tickets/admin/summary` (which only returns status counts and stale count). Provide resolution time distribution, volume per period, and per-agent throughput.

**Service additions** (`app/services/tickets.py`):
- `TicketStore.get_analytics(*, period_days: int = 30) -> dict`: scans closed tickets (`status=done`) from the status GSI for the period. Computes:
  - `resolution_time_p50_seconds`, `resolution_time_p90_seconds`, `resolution_time_avg_seconds` (from `created_at` to last `ACT#ticket_status_changed` with `status=done`).
  - `volume_by_day: dict[str, int]` (YYYY-MM-DD → count of tickets created).
  - `by_assignee: list[{assignee_sub, resolved_count, avg_resolution_seconds}]` — grouped from closed tickets that have `assigned_to_sub`.
  - `open_by_priority: dict[str, int]` — count of open tickets per priority.

**Router** (`app/routers/tickets.py`):
- `GET /tickets/admin/analytics` — admin only; query param `period_days: int = 30` (max 90). Returns `TicketAnalyticsOut` model. Gated on `S.crm_cases_enabled`. Route declared **before** `/{ticket_id}` path.

**Frontend** (`frontend/src/pages/tickets/TicketsPage.tsx` or new `TicketAnalyticsDashboard.tsx`):
- Bar chart of volume_by_day (reuse recharts already used in `frontend/src/pages/` analytics pages).
- Table of per-agent throughput with avg resolution time.
- Priority breakdown pie chart.

**Acceptance Criteria**
- `GET /tickets/admin/analytics` returns `{resolution_time_p50_seconds, volume_by_day, by_assignee, open_by_priority}`.
- Non-admin gets 403.
- With 0 closed tickets in period, returns zeroed metrics (no 500).
- `period_days > 90` returns 422.
- Hermetic pytest: create test tickets with synthetic `created_at` / `done` activity records.

**Dependencies**
- CAS-001, CAS-003 (priority field needed for `open_by_priority`).
