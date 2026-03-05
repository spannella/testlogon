# Messaging FINRA Compliance Archive — Implementation Tickets

This ticket set maps to `docs/messaging-finra-compliance-archive-plan.md` and breaks delivery into scoped work items across compliance architecture, archival pipeline, controls, and operations.

---

## Epic FCA-A — Compliance requirements and canonical contract

### FCA-001 — Compliance requirement baseline and legal mapping
- **Type:** Compliance / Platform
- **Priority:** P0
- **Size:** M
- **Description:** Capture FINRA-facing retention/supervision requirements and map them to technical controls.
- **Deliverables:**
  - Requirement matrix (record classes, retention minimums, legal-hold expectations, supervision obligations).
  - Gap analysis against current messaging data paths.
  - Legal/compliance sign-off workflow document.
  - Baseline artifact: `docs/messaging-finra-compliance-baseline.md`.
- **Acceptance criteria:**
  - Engineering and compliance share a signed baseline requirements artifact.
  - In-scope record categories are explicitly enumerated.
- **Dependencies:** None.

### FCA-002 — Define canonical archive event schema (versioned)
- **Type:** Backend / Architecture
- **Priority:** P0
- **Size:** M
- **Description:** Define immutable, versioned schema for all archived messaging events.
- **Deliverables:**
  - JSON schema for archive envelope (`event_id`, actor/effective actor, payload hash, prev hash, schema version).
  - Event taxonomy (`message.sent`, `message.edited`, `message.deleted`, etc.).
  - Canonical serialization rules for deterministic hashing.
  - Artifacts:
    - `app/services/messaging_compliance_archive_schema.py`
    - `docs/messaging-compliance-archive-event-schema-v1.json`
- **Acceptance criteria:**
  - Schema is machine-validated and versioned.
  - Hash reproducibility tests pass across environments.
- **Dependencies:** FCA-001.

### FCA-003 — Define compliance query/export contract
- **Type:** Backend / API
- **Priority:** P1
- **Size:** S
- **Description:** Specify queryable fields and export bundle contract for eDiscovery and audit use.
- **Deliverables:**
  - API contract for compliance search/filter/pagination.
  - Export bundle manifest format (checksums, signature metadata, case identifiers).
  - Artifacts:
    - `docs/messaging-compliance-query-export-contract.md`
    - `docs/messaging-compliance-query-response-v1.json`
    - `docs/messaging-compliance-export-bundle-manifest-v1.json`
- **Acceptance criteria:**
  - Contract supports legal case-based retrieval without mutable DB dependency.
- **Dependencies:** FCA-002.

---

## Epic FCA-B — Immutable archive ingest and storage

### FCA-004 — Build archive write service abstraction
- **Type:** Backend / Platform
- **Priority:** P0
- **Size:** M
- **Description:** Add service-layer abstraction to emit archive events from messaging write paths.
- **Deliverables:**
  - `archive_writer` interface and implementation.
  - Non-blocking and fail-closed modes controlled by runtime flag.
  - Artifacts:
    - `app/services/messaging_archive_writer.py`
    - shared router call-sites via `emit_messaging_archive_event(...)`
- **Acceptance criteria:**
  - Messaging paths call a shared archive writer, not ad hoc storage code.
- **Dependencies:** FCA-002.

### FCA-005 — Persist immutable archive objects with partition manifests
- **Type:** Backend / Data
- **Priority:** P0
- **Size:** M
- **Description:** Store serialized archive events in immutable object partitions and maintain append manifests.
- **Deliverables:**
  - Object key strategy (`tenant/date/hour/...`).
  - Append-only manifest writer with checksum entries.
  - Environment-backed storage configuration.
  - Artifacts:
    - `app/services/messaging_archive_writer.py` (`FileArchiveWriter`)
    - `MESSAGING_COMPLIANCE_ARCHIVE_STORAGE_MODE`
    - `MESSAGING_COMPLIANCE_ARCHIVE_ROOT_DIR`
- **Acceptance criteria:**
  - Archive writes are append-only and discoverable by partition.
  - Manifest and object checksums reconcile.
- **Dependencies:** FCA-004.

### FCA-006 — Implement tamper-evidence hash chain metadata
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** M
- **Description:** Add per-partition hash chain linkage and chain-head persistence.
- **Deliverables:**
  - `prev_hash`/`payload_hash` chain updates.
  - Chain-head metadata table and updater.
  - Integrity verification utility.
  - Artifacts:
    - `verify_partition_chain(...)` in `app/services/messaging_archive_writer.py`
    - `DDB_MESSAGE_ARCHIVE_CHAIN_HEADS` / `MessageArchiveChainHeads`
- **Acceptance criteria:**
  - Chain continuity validation catches gaps/tampering.
- **Dependencies:** FCA-005.

### FCA-007 — Archive attachment references and immutable content checksums
- **Type:** Backend / Data
- **Priority:** P1
- **Size:** M
- **Description:** Ensure attachments referenced by messages are archived with immutable metadata.
- **Deliverables:**
  - Attachment checksum capture (`sha256`, size, content-type).
  - Immutable archive reference model for attachment artifacts.
- **Acceptance criteria:**
  - Attachments in archived events are verifiable and replayable.
- **Dependencies:** FCA-005.

---

## Epic FCA-C — Messaging-path integration and coverage

### FCA-008 — Emit archive events on message create/edit/revoke/delete lifecycle
- **Type:** Backend / Messaging
- **Priority:** P0
- **Size:** L
- **Description:** Integrate archive emission into all message mutation endpoints and jobs.
- **Deliverables:**
  - Hooks for send, edit, revoke/delete, scheduled delivery transitions.
  - Backfill support for missed writes.
- **Acceptance criteria:**
  - Every in-scope mutation emits exactly one canonical archive event.
- **Dependencies:** FCA-004.

### FCA-009 — Include conversation membership/role transitions in archive context
- **Type:** Backend / Messaging
- **Priority:** P1
- **Size:** M
- **Description:** Capture membership changes needed for supervisory reconstruction.
- **Deliverables:**
  - Event emission on participant join/leave/role/assignment changes.
  - Linkage to conversation timeline state.
- **Acceptance criteria:**
  - Replay can reconstruct who could view/interact at a given time.
- **Dependencies:** FCA-008.

### FCA-010 — Archive moderation/report events as supplemental compliance records
- **Type:** Backend / Moderation
- **Priority:** P2
- **Size:** S
- **Description:** Emit report and moderation outcomes into compliance archive stream.
- **Deliverables:**
  - Event mapping for report submit/status transitions.
  - Cross-reference report IDs in archive payload.
- **Acceptance criteria:**
  - Moderation actions are queryable in compliance timeline.
- **Dependencies:** FCA-008.

---

## Epic FCA-D — Retention, legal hold, and policy enforcement

### FCA-011 — Retention policy engine for compliance archive
- **Type:** Backend / Compliance
- **Priority:** P0
- **Size:** M
- **Description:** Enforce configurable retention windows by tenant/product policy.
- **Deliverables:**
  - Policy evaluator service.
  - Retention class configuration and defaults.
  - Purge eligibility evaluator.
- **Acceptance criteria:**
  - Retention decisions are deterministic and auditable.
- **Dependencies:** FCA-001, FCA-005.

### FCA-012 — Legal hold management APIs and storage
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Implement legal-hold create/release/list APIs with strict access controls.
- **Deliverables:**
  - `message_legal_holds` data model.
  - RBAC-protected endpoints for hold lifecycle.
  - Hold audit events.
- **Acceptance criteria:**
  - Records under hold cannot be purged.
  - Hold actions are fully auditable.
- **Dependencies:** FCA-011.

### FCA-013 — Hold-aware purge workflow
- **Type:** Backend / Ops
- **Priority:** P1
- **Size:** M
- **Description:** Implement purge/retention job that excludes held records and logs decisions.
- **Deliverables:**
  - Scheduled retention job.
  - Skip reasons and purge ledger.
- **Acceptance criteria:**
  - Purge never removes held records.
  - Dry-run mode validates policy before deletion.
- **Dependencies:** FCA-011, FCA-012.

---

## Epic FCA-E — Compliance access, export, and supervision workflows

### FCA-014 — Compliance query endpoints with strict RBAC
- **Type:** Backend / API
- **Priority:** P0
- **Size:** M
- **Description:** Provide search/list APIs over immutable archive storage and metadata.
- **Deliverables:**
  - Query endpoints for user/conversation/date filters.
  - Pagination and deterministic sorting.
  - Least-privilege policy integration.
- **Acceptance criteria:**
  - Compliance users can query archived records without operational DB dependence.
- **Dependencies:** FCA-003, FCA-005.

### FCA-015 — eDiscovery export job and signed manifest artifacts
- **Type:** Backend / Compliance
- **Priority:** P0
- **Size:** M
- **Description:** Build case-driven export generation with checksum manifests and signatures.
- **Deliverables:**
  - Export job orchestration and status model.
  - Manifest generation with per-record checksums and aggregate digest.
  - Artifact access controls and expiry policy.
- **Acceptance criteria:**
  - Export bundles are verifiable and case-traceable.
- **Dependencies:** FCA-014.

### FCA-016 — Supervisory review feed integration
- **Type:** Backend / Moderation
- **Priority:** P2
- **Size:** S
- **Description:** Publish compliance archive events to supervision/risk review queue.
- **Deliverables:**
  - Rule-trigger integration points.
  - Review assignment metadata.
- **Acceptance criteria:**
  - Supervisory systems can subscribe without impacting archive integrity.
- **Dependencies:** FCA-014.

---

## Epic FCA-F — Observability, rollout, and reliability hardening

### FCA-017 — Archive observability metrics and structured logs
- **Type:** Backend / Ops
- **Priority:** P0
- **Size:** S
- **Description:** Instrument ingest success/failure, latency, integrity errors, and export outcomes.
- **Deliverables:**
  - Metrics for archive writes, retries, integrity check failures, export success/failure.
  - Structured log fields for actor/tenant/event/object_key/result.
- **Acceptance criteria:**
  - Metrics and logs visible in staging and production observability stack.
- **Dependencies:** FCA-004.

### FCA-018 — Dashboard + alert thresholds for archive health
- **Type:** Ops
- **Priority:** P1
- **Size:** S
- **Description:** Add dashboards/alerts for ingest reliability and integrity regressions.
- **Deliverables:**
  - Dashboard JSON with ingest/error/integrity panels.
  - Alert rules for sustained write failures and any integrity-chain mismatch.
- **Acceptance criteria:**
  - Alerts trigger in controlled simulation tests.
- **Dependencies:** FCA-017.

### FCA-019 — Feature flags and staged rollout execution
- **Type:** Platform / Release
- **Priority:** P1
- **Size:** S
- **Description:** Gate compliance archive capabilities and execute canary rollout.
- **Deliverables:**
  - Runtime flags:
    - `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED`
    - `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS`
    - `MESSAGING_COMPLIANCE_EXPORT_ENABLED`
    - `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED`
  - Rollout checklist with rollback criteria.
- **Acceptance criteria:**
  - Capabilities can be toggled without deploy.
  - Rollback drill validated in staging.
- **Dependencies:** FCA-004, FCA-018.

### FCA-020 — Reliability drills: replay, backfill, and incident runbooks
- **Type:** Ops / QA
- **Priority:** P1
- **Size:** M
- **Description:** Validate operational recovery workflows under failure scenarios.
- **Deliverables:**
  - Replay/backfill tooling and runbook.
  - Simulated object-store failure and recovery drill report.
  - Integrity mismatch response runbook.
- **Acceptance criteria:**
  - On-call can recover from archive sink outages without record-loss.
- **Dependencies:** FCA-006, FCA-017.

---

## Epic FCA-G — Test and audit assurance

### FCA-021 — Unit tests for canonical hashing and chain linkage
- **Type:** Backend / QA
- **Priority:** P0
- **Size:** S
- **Description:** Add deterministic unit coverage for canonical payload hashing and chain updates.
- **Deliverables:**
  - Canonicalization tests.
  - Hash-chain continuity tests.
- **Acceptance criteria:**
  - Hash outcomes are deterministic across platforms.
- **Dependencies:** FCA-002, FCA-006.

### FCA-022 — Integration tests for archive write coverage across messaging flows
- **Type:** Backend / QA
- **Priority:** P0
- **Size:** M
- **Description:** Verify all in-scope messaging mutation endpoints generate archive events.
- **Deliverables:**
  - Endpoint-to-event coverage matrix in tests.
  - Failure mode tests (sink unavailable, retry paths).
- **Acceptance criteria:**
  - CI fails if any lifecycle path regresses on archive emission.
- **Dependencies:** FCA-008.

### FCA-023 — Compliance access-control and audit trail tests
- **Type:** Security / QA
- **Priority:** P0
- **Size:** M
- **Description:** Validate RBAC boundaries and immutable audit logs for compliance actions.
- **Deliverables:**
  - Unauthorized access tests.
  - Legal hold and export action audit assertions.
- **Acceptance criteria:**
  - Unauthorized cross-tenant/query access is prevented by tests.
- **Dependencies:** FCA-012, FCA-014, FCA-015.

### FCA-024 — End-to-end evidence package validation
- **Type:** Compliance / QA
- **Priority:** P1
- **Size:** M
- **Description:** Validate export bundle integrity and replay consistency for audit/regulator response.
- **Deliverables:**
  - Golden-case export fixtures with checksums/signatures.
  - Replay verification report.
- **Acceptance criteria:**
  - Evidence package passes integrity checks and can be independently verified.
- **Dependencies:** FCA-015, FCA-020.

---

## Suggested execution order (critical path)

1. FCA-001 → FCA-002 → FCA-004 → FCA-005 → FCA-006
2. FCA-008 → FCA-011 → FCA-012 → FCA-013
3. FCA-014 → FCA-015 → FCA-017 → FCA-018 → FCA-019
4. FCA-021 → FCA-022 → FCA-023 → FCA-024

## Milestone exit definition

- Immutable archive ingest and tamper evidence are operational.
- Retention and legal hold controls are enforced and audited.
- Compliance search/export workflows are production-ready.
- Observability, alerts, and rollback drills are validated.
