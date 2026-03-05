# Messaging FINRA Compliance Archive Plan

> This is a technical implementation plan intended to support FINRA-aligned archival controls. It is not legal advice; compliance/legal counsel should validate final policy and retention requirements.

## Goals

- Archive all messaging records in an immutable, tamper-evident store suitable for regulated supervision and eDiscovery workflows.
- Preserve full lifecycle history (create/edit/delete/revoke) with actor attribution and deterministic replay.
- Enforce retention and legal-hold controls independently from user-facing message lifecycle semantics.
- Provide operational observability, alerting, and rollback-safe staged rollout.

## Current foundations in this codebase

- Message reporting context already uses server-side capture with retention/legal-compliance constraints and immutable snapshot references.
- Runtime feature-flag infrastructure already exists for staged rollout controls.
- Existing observability patterns (metrics, structured logs, dashboards, alerts) can be mirrored for compliance archive paths.

## Proposed architecture

## 1) Canonical archive event model

Create immutable archive events for all relevant messaging lifecycle actions:

- `message.sent`
- `message.edited`
- `message.deleted` / `message.revoked`
- attachment add/remove/update events
- conversation membership changes (join/leave/role changes)
- moderation/report actions as supplemental compliance metadata

### Event envelope (minimum)

- `event_id` (deterministic + unique)
- `event_ts` (server-side authoritative timestamp)
- `tenant_id` / `workspace_id`
- `conversation_id`
- `message_id`
- `actor_user_id`
- `effective_user_id` (for impersonation/admin actions)
- `event_type`
- `payload` (canonicalized JSON)
- `payload_hash` (sha256 over canonical payload)
- `prev_hash` (for hash-chain tamper evidence)
- `schema_version`

## 2) Immutable storage and tamper evidence

- Persist serialized archive events to immutable object storage partitions (e.g., by tenant/date/hour).
- Enable write-once retention/object-lock (WORM) controls in storage where available.
- Build append-only manifest files per partition with rolling checksums.
- Maintain chain-head metadata (per tenant/day partition) in a durable metadata store.

## 3) Retention + legal hold controls

- Retention policy engine by tenant/product profile.
- Separate retention schedule for compliance archive from operational message tables.
- Legal hold API to pin records by scope:
  - user
  - conversation
  - date range
  - case id
- Purge jobs must skip all held records.

## 4) Access and supervision workflows

- Compliance-only query APIs (strict RBAC + audit trail).
- eDiscovery export by case/query filter:
  - JSONL records
  - checksum manifest
  - signed export bundle metadata
- Supervisory workflow hooks:
  - keyword/risk rule enrichment
  - queue for reviewer assignment

## 5) Replay and verification

- Deterministic replay service to reconstruct timeline from archive event stream.
- Integrity checker that validates:
  - object presence
  - payload hash
  - hash-chain continuity
  - manifest checksum consistency

## Implementation phases

## Phase 0 — Policy + schema contract (1–2 weeks)

Deliverables:

- Compliance record taxonomy and event schema specification.
- Retention class matrix and legal-hold requirements.
- eDiscovery query/export contract.

Exit criteria:

- Compliance/legal sign-off on data fields, retention minimums, and supervisory access model.

## Phase 1 — Archive ingest pipeline (2–3 weeks)

Deliverables:

- Archive event emitter on all message write/mutation paths.
- Immutable object-store sink + partition manifests.
- Chain-head metadata persistence.

Exit criteria:

- End-to-end write success for all primary message operations.
- Tamper-evidence primitives in place.

## Phase 2 — Full-fidelity capture (2 weeks)

Deliverables:

- Coverage for edits, deletes/revokes, attachments, and membership metadata.
- Archive references for attachment objects + checksums.

Exit criteria:

- Coverage matrix shows all in-scope messaging mutations generate archive events.

## Phase 3 — Retention/legal hold + supervision hooks (2 weeks)

Deliverables:

- Retention engine and legal-hold APIs.
- Hold-aware purge workflow.
- Supervisory enrichment event feed.

Exit criteria:

- Hold-protected records remain non-purgeable.
- Retention jobs pass policy conformance tests.

## Phase 4 — Compliance access + export (2 weeks)

Deliverables:

- Compliance query endpoints with least-privilege RBAC.
- Signed export bundles + checksum manifests.
- Case tracking metadata for export requests.

Exit criteria:

- Compliance users can query and export without reading mutable operational tables.

## Phase 5 — Operations hardening (1 week)

Deliverables:

- Metrics, logs, dashboard, and alert policies for archive ingest and integrity.
- Replay/repair runbooks and incident procedures.
- Staging simulation of ingest failures and integrity alarms.

Exit criteria:

- Alerts fire in controlled simulation and on-call runbook validated.

## Config and rollout controls

Add independent rollout flags (runtime-togglable):

- `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED`
- `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS`
- `MESSAGING_COMPLIANCE_EXPORT_ENABLED`
- `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED`

Recommended rollout:

1. Dark launch (shadow writes only).
2. Canary tenants/workspaces.
3. Incremental ramp (25% → 50% → 100%).
4. Enable fail-closed enforcement only after sustained SLO stability.

Rollback:

- Disable archive enforcement flag first to avoid write-path outages.
- Keep shadow writes enabled where possible for forensic continuity.
- Trigger replay/backfill job for any missed intervals.

## Data model sketch

- `message_archive_events`
  - partition: tenant/date
  - sort: ts/event_id
  - fields: envelope + storage key + hash links
- `message_archive_chain_heads`
  - partition-level latest hash state
- `message_legal_holds`
  - scope + status + case metadata
- `message_archive_exports`
  - request metadata + result artifact references + checksums

## Security and controls

- Server-side capture only (clients cannot provide archive payload IDs).
- Encryption at rest and in transit for archive and export artifacts.
- Strict RBAC and audited access for compliance APIs.
- Immutable audit entries for hold placement/removal and export actions.

## Test strategy

- Unit tests:
  - canonicalization + hash correctness
  - retention policy evaluator
  - hold matching behavior
- Integration tests:
  - message mutation → archive write
  - export generation + checksum verification
  - replay integrity over mixed event types
- Chaos/simulation:
  - object-store write failures
  - delayed sink recovery + backfill
  - chain integrity mismatch detection

## Acceptance criteria

- Every in-scope messaging mutation produces an immutable archive event.
- Archive integrity can be verified cryptographically and operationally.
- Retention and legal-hold constraints are enforced by policy and test coverage.
- Compliance query/export workflows are available with auditable access controls.
- Rollback and recovery procedures are validated in staging.
