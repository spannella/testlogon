# Jira Integration DB Migration Plan (JTS-003)

## 1) Objective
Define the migration design for Jira integration entities using the existing DynamoDB-based ticketing storage strategy.

Covered entities:
- `jira_connections`
- `ticket_external_links`
- `jira_issue_mirror`
- `ticket_sync_events`

## 2) Current Storage Strategy
The application currently uses the `tickets` DynamoDB table with composite `pk/sk` keys and GSIs for ticket query patterns. Jira entities will be added as new entity types in this table (single-table extension strategy), reusing existing operational patterns.

## 3) Target Entity Shapes

### 3.1 `jira_connections`
- **PK/SK:**
  - `pk = WORKSPACE#{workspace_id}`
  - `sk = JIRA_CONN#{connection_id}`
- **Core fields:**
  - `entity_type = jira_connection`
  - `workspace_id`, `connection_id`, `user_id` (nullable service account mode)
  - `cloud_id`, `site_url`, `auth_type`, `scopes`
  - `access_token_ref`, `refresh_token_ref`, `expires_at`, `status`
  - `created_at`, `updated_at`
- **Index fields:**
  - `gsi_jira_workspace_pk/sk`
  - `gsi_jira_sync_state_pk/sk`

### 3.2 `ticket_external_links`
- **PK/SK:**
  - `pk = TICKET#{internal_ticket_id}`
  - `sk = JIRA_LINK#{link_id}`
- **Core fields:**
  - `entity_type = ticket_external_link`
  - `workspace_id`, `provider=jira`, `link_id`
  - `external_issue_id`, `external_issue_key`, `project_key`
  - `link_mode`, `sync_state`, `conflict_state`
  - `last_synced_at`, `last_sync_direction`
  - `created_by`, `created_at`, `updated_at`
- **Index fields:**
  - `gsi_jira_issue_pk/sk`
  - `gsi_jira_workspace_pk/sk`
  - `gsi_jira_sync_state_pk/sk`

### 3.3 `jira_issue_mirror`
- **PK/SK:**
  - `pk = JIRA_ISSUE#{external_issue_id}`
  - `sk = MIRROR`
- **Core fields:**
  - `entity_type = jira_issue_mirror`
  - `workspace_id`, `external_issue_id`, `external_issue_key`
  - `cloud_id`, `project_key`
  - `summary`, `description`, `status`, `priority`
  - `assignee_account_id`, `reporter_account_id`, `labels`
  - `updated_at_remote`, `ingested_at`, `updated_at`
- **Index fields:**
  - `gsi_jira_issue_pk/sk`
  - `gsi_jira_workspace_pk/sk`
  - `gsi_jira_sync_state_pk/sk`

### 3.4 `ticket_sync_events`
- **PK/SK:**
  - `pk = TICKET#{internal_ticket_id}`
  - `sk = SYNC_EVENT#{timestamp}#{event_id}`
- **Core fields:**
  - `entity_type = ticket_sync_event`
  - `workspace_id`, `event_id`, `internal_ticket_id`
  - `direction`, `result`, `error_code`, `payload_hash`, `trace_id`
  - `created_at`
- **Index fields:**
  - `gsi_jira_workspace_pk/sk`
  - `gsi_jira_sync_state_pk/sk`

## 4) Required GSI Additions
Add the following GSIs to the `tickets` table:
1. `tickets_jira_workspace_index_name`
   - PK: `gsi_jira_workspace_pk`
   - SK: `gsi_jira_workspace_sk`
2. `tickets_jira_issue_index_name`
   - PK: `gsi_jira_issue_pk`
   - SK: `gsi_jira_issue_sk`
3. `tickets_jira_sync_state_index_name`
   - PK: `gsi_jira_sync_state_pk`
   - SK: `gsi_jira_sync_state_sk`

## 5) Forward Migration Procedure

### Phase A — Prepare
1. Deploy application code that can read/write both pre-Jira and Jira-extended entities safely.
2. Add new settings/env vars for Jira GSI names.
3. Validate no conflicting attribute names in existing rows.

### Phase B — Provision Indexes
1. Apply infra/migration changes to create the three Jira GSIs on the `tickets` table.
2. Wait for each index to become `ACTIVE` before proceeding.
3. Run verification script:
   - check index presence,
   - check key schema,
   - execute sample read/write smoke queries.

### Phase C — Enable Write Paths (Dark)
1. Deploy `JiraTicketSyncStore` write paths behind feature flags.
2. Keep integration disabled (`JIRA_SYNC_ENABLED=false`) while performing dark-write tests in non-prod.
3. Validate write/read correctness for each entity type.

### Phase D — Controlled Activation
1. Enable `JIRA_SYNC_ENABLED=true` only for pilot workspace allowlist.
2. Enable read-only mode first (`JIRA_SYNC_READ_ENABLED=true`; outbound/inbound disabled).
3. Gradually enable outbound/inbound sync modes after stability checks.

## 6) Rollback Procedure

### 6.1 Immediate operational rollback
- Set:
  - `JIRA_SYNC_OUTBOUND_ENABLED=false`
  - `JIRA_SYNC_INBOUND_ENABLED=false`
  - `JIRA_SYNC_OUTBOUND_KILL_SWITCH=true`
- Optionally disable all integration paths:
  - `JIRA_SYNC_ENABLED=false`

### 6.2 Application rollback
- Roll back to previous application version that ignores Jira entity types.
- Jira rows remain in table but are inert and do not affect legacy ticket paths.

### 6.3 Index rollback policy
- Do **not** immediately drop GSIs during incident rollback.
- Keep indexes in place until root-cause analysis is complete and data retention export (if needed) is done.
- Schedule index deletion as a separate controlled change window only if feature is fully abandoned.

## 7) Data Retention and Archival Policy (Sync Events)

### 7.1 Retention durations
- `ticket_sync_events` hot retention in primary table: **90 days** minimum.
- Extended audit retention in archive storage: **400 days** (or per compliance policy).

### 7.2 Archival approach
- Nightly archival job scans `ticket_sync_events` older than 90 days.
- Writes JSONL/Parquet archive files to secure object storage partitioned by date/workspace.
- Stores immutable checksum manifest for chain-of-custody validation.

### 7.3 Deletion after archive
- After successful archival verification, old events are deleted in controlled batches.
- Deletion job is idempotent and resumable.
- Deletion failures are logged and retried without dropping unarchived records.

### 7.4 Access and audit
- Archive access restricted to compliance/support roles.
- Every archive read action is audited with actor, reason, and trace id.

## 8) Validation Checklist
- [ ] New GSIs present and active in target environment.
- [ ] Smoke query by workspace/issue/sync-state succeeds.
- [ ] Each Jira entity type round-trips through store methods.
- [ ] Rollback flag path verified in staging.
- [ ] Archival job dry-run completed and manifest verified.

## 9) Risks and Mitigations
- **GSI backfill latency** → deploy during low-traffic window; monitor consumed capacity.
- **Write amplification from sync events** → enforce retention + archival pipeline early.
- **Unexpected query hot partitions** → use bounded page sizes and per-workspace throttling.
- **Rollback pressure** → rely on flag-based shutdown before infra rollback.

## 11) Automation Artifacts
- Migration script: `scripts/migrations/20260405_jira_ticket_indexes_migration.py`
  - Supports `--dry-run` (default) and `--apply`.
- Verification script: `scripts/verify_jira_ticket_indexes.py`
  - Exits non-zero when required Jira indexes are missing.

## 10) Acceptance Coverage (JTS-003)
This migration design satisfies JTS-003 by providing:
1. Explicit forward migration procedure with phased activation.
2. Explicit rollback procedures (operational, app, and index strategy).
3. Documented retention and archival policy for `ticket_sync_events`.
