# Jira ↔ Internal Ticketing Sync Plan

## 1. Objectives
- Allow authenticated users to view Jira issues relevant to them inside the internal ticketing UI (assigned to me, reported by me, watched by me, and project-filtered views).
- Enable bi-directional synchronization so internal tickets can be pushed to Jira and Jira updates can flow back into internal tickets.
- Preserve clear source-of-truth rules, auditability, and conflict visibility.

## 2. Scope
### In scope
- Jira Cloud integration using OAuth 2.0 (3LO) for end-user delegated access.
- Optional Jira service account mode for workspace-level syncing (admin-configured).
- Ticket mapping between internal ticket entities and Jira issues.
- Syncing core fields: title/summary, description, status, assignee, priority, labels, comments, attachments metadata, and links.
- Webhook ingestion for near-real-time updates from Jira.
- Scheduled backfill and reconciliation jobs.
- Sync status surfaces in API + UI.

### Out of scope (phase 1)
- Jira Data Center/on-prem support.
- Custom Jira workflow automation replication.
- Full attachment binary mirroring (phase 1 stores references and optional pull-on-demand).
- Multi-external-target sync beyond Jira.

## 3. Product Flows
1. **Connect Jira account**
   - User clicks “Connect Jira.”
   - OAuth completes; token and site selection are saved.
   - User picks default Jira project(s) and sync preferences.

2. **See current Jira tickets in app**
   - Ticket list has tabs/filters: Internal, Jira, Unified.
   - Jira tab queries local mirror first; falls back to live pull if stale.
   - Each issue shows origin badge (`jira`, `internal`, `linked`).

3. **Link/push internal ticket to Jira**
   - From internal ticket details: “Create Jira issue” or “Link existing Jira issue.”
   - Mapping record is created with external IDs and sync policy.
   - Initial push writes internal ticket fields to Jira.

4. **Bi-directional updates**
   - Jira webhook updates local mirror + mapped internal tickets.
   - Internal ticket changes enqueue outbound Jira update jobs.
   - Conflicts are detected and shown with “last synced / needs review.”

## 4. Architecture
### 4.1 Components
- **Integration API layer**
  - Endpoints for connect/disconnect, project discovery, link/unlink, and sync status.
- **Jira connector service**
  - Handles OAuth, API calls, pagination, retries, and rate limits.
- **Sync orchestrator**
  - Consumes domain events + webhooks and applies mapping/conflict logic.
- **Event queue + workers**
  - Asynchronous jobs for push/pull/reconcile operations.
- **Persistence**
  - Stores credentials, connection state, external issue mirror, mapping table, sync logs.
- **Observability**
  - Metrics, structured logs, dead-letter queue handling, alerting.

### 4.2 Proposed data model additions
- `jira_connections`
  - `id`, `workspace_id`, `user_id` (nullable for service-account mode), `cloud_id`, `site_url`, `auth_type`, `scopes`, `access_token_ref`, `refresh_token_ref`, `expires_at`, `status`, `created_at`, `updated_at`.
- `ticket_external_links`
  - `id`, `internal_ticket_id`, `provider` (`jira`), `external_issue_id`, `external_issue_key`, `project_key`, `link_mode` (`push_only`, `pull_only`, `bidirectional`), `field_mapping_version`, `sync_state`, `last_synced_at`, `last_sync_direction`, `conflict_state`, `created_by`, `created_at`, `updated_at`.
- `jira_issue_mirror`
  - `external_issue_id`, `external_issue_key`, `cloud_id`, `project_key`, `summary`, `description`, `status`, `priority`, `assignee_account_id`, `reporter_account_id`, `labels`, `updated_at_remote`, `ingested_at`.
- `ticket_sync_events`
  - immutable audit rows for each sync attempt (`direction`, `result`, `error_code`, `payload_hash`, `trace_id`).

## 5. Sync Rules and Conflict Strategy
### 5.1 Field mapping (initial)
- Internal `subject` ↔ Jira `summary`.
- Internal `description` ↔ Jira `description` (ADF conversion adapter required).
- Internal `status` ↔ Jira status via configurable mapping table.
- Internal `assignee_sub` ↔ Jira `assignee.accountId` (requires identity mapping table).
- Internal `priority` ↔ Jira `priority.name`.
- Internal comments ↔ Jira comments (with source marker to prevent loops).
- Internal attachments ↔ Jira attachment links or metadata records.

### 5.2 Direction rules
- **Inbound (Jira → internal):** webhook-first, poll fallback every N minutes.
- **Outbound (internal → Jira):** event-driven on create/update/comment/status change.
- **Loop prevention:** store origin metadata + remote update IDs and skip echo updates.

### 5.3 Conflict handling
- Optimistic sync using remote `updated` timestamps and local `updated_at`.
- If both sides changed same mapped field between syncs:
  - mark `conflict_state=needs_review`,
  - preserve both values,
  - show conflict banner in UI,
  - allow one-click “keep Jira” or “keep internal.”

## 6. Security and Compliance
- Store OAuth tokens in encrypted secrets manager; never in plain DB.
- Use least-privilege scopes (`read:jira-work`, `write:jira-work`, `offline_access` as needed).
- Verify Jira webhook signatures/secrets and enforce replay protection.
- Add per-workspace allowlist for Jira site URLs.
- Record all sync actions in immutable audit logs (actor + system actions).
- Add admin kill switch to disable outbound sync globally.

## 7. API and UI Work Plan
### 7.1 API endpoints (new/updated)
- `POST /integrations/jira/connect`
- `GET /integrations/jira/callback`
- `GET /integrations/jira/projects`
- `POST /tickets/{id}/external-links/jira`
- `POST /tickets/{id}/external-links/jira/link-existing`
- `DELETE /tickets/{id}/external-links/{linkId}`
- `GET /tickets?source=internal|jira|unified`
- `GET /tickets/{id}/sync-status`
- `POST /integrations/jira/webhook`

### 7.2 UI changes
- Integrations settings page for Jira connection and project preferences.
- Ticket list filters: source + sync health.
- Ticket details panel showing linked Jira issue key/status.
- Conflict resolution modal.
- Activity timeline entries for sync operations.

## 8. Delivery Phases
### Phase 0 — Discovery and design (1 week)
- Confirm current internal ticket domain model coverage.
- Finalize Jira auth model (user OAuth only vs hybrid with service account).
- Produce schema migration design and API contract draft.

### Phase 1 — Read-only Jira visibility (1–2 weeks)
- Implement OAuth connect flow.
- Ingest Jira issues into mirror table via initial pull + incremental poll.
- Expose Jira issues in read-only ticket list.
- Ship observability baseline and rate-limit handling.

### Phase 2 — Linking and outbound push (1–2 weeks)
- Add “Create Jira issue” and “Link existing” actions.
- Build outbound event pipeline for mapped field updates.
- Add sync status indicators and audit events.

### Phase 3 — Inbound webhooks + bi-directional sync (2 weeks)
- Register Jira webhooks and verify signatures.
- Process inbound updates and apply to internal tickets.
- Implement loop prevention and conflict detection.

### Phase 4 — Hardening + rollout (1 week)
- Backfill/reconciliation jobs.
- DLQ and replay tooling.
- Feature-flagged gradual rollout by workspace.
- Runbook, SLOs, and on-call alerts.

## 9. Testing Strategy
- **Unit tests**
  - Field mapping adapters (including ADF conversion).
  - Conflict detector and loop-prevention logic.
  - Jira API client retry/rate-limit behavior.
- **Integration tests**
  - OAuth callback and token refresh paths.
  - Webhook ingestion and signature verification.
  - End-to-end create/update/comment sync in both directions.
- **Contract tests**
  - Jira payload schema fixtures for issue and webhook events.
- **Load/resilience tests**
  - Burst webhook simulation and queue backpressure behavior.

## 10. Risks and Mitigations
- **Jira API limits** → cached reads, adaptive backoff, prioritized queues.
- **Workflow/status mismatch** → explicit per-project mapping and validation UI.
- **Identity mismatch** → maintain user mapping table with fallbacks/unassigned behavior.
- **Sync loops** → source metadata, idempotency keys, and checksum comparisons.
- **Data drift** → periodic reconciliation job + discrepancy dashboard.

## 11. Implementation Checklist
- [ ] DB migrations for connection, link, mirror, and sync event tables.
- [ ] OAuth connect/disconnect flow.
- [ ] Jira API client + pagination/retry.
- [ ] Mirror ingestion job and scheduler.
- [ ] Ticket link/unlink endpoints.
- [ ] Outbound sync worker.
- [ ] Webhook receiver + verifier.
- [ ] Inbound apply engine.
- [ ] Conflict UX.
- [ ] Metrics dashboards + alerts.
- [ ] Feature flags + rollout plan.
- [ ] Runbook + support docs.

## 12. Success Metrics
- ≥95% of linked ticket updates synchronized within 60 seconds.
- <1% sync failure rate after retries (excluding validation errors).
- 100% sync actions logged with traceable audit records.
- Reduction in manual cross-system updates by at least 50% within pilot cohort.
