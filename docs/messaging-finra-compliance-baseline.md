# Messaging FINRA Compliance Baseline and Legal Mapping (FCA-001)

> Purpose: establish a shared engineering/compliance baseline for FINRA-oriented messaging archive controls.
>
> This is an implementation baseline artifact, not legal advice.

## Document control

- **Ticket:** FCA-001
- **Owner (Engineering):** _TBD_
- **Owner (Compliance):** _TBD_
- **Owner (Legal):** _TBD_
- **Version:** 1.0-draft
- **Status:** Draft → Review → Approved
- **Last updated:** 2026-03-01

---

## 1) Requirement matrix (record classes, retention, legal hold, supervision)

| Record class | In scope | Example events | Regulatory intent mapping | Baseline retention expectation | Legal hold expectation | Supervision expectation | Notes |
|---|---|---|---|---|---|---|---|
| Message content (text) | Yes | `message.sent`, `message.edited`, `message.deleted/revoked` | Books/records style communication preservation for business messaging | 6 years default baseline (final value to be legal-approved) | Must suspend purge for matching scope/case | Reviewable via compliance query + export | Retention clock policy (created vs last-modified) requires legal decision |
| Message metadata | Yes | sender, recipients/participants, timestamps, conversation id | Provenance and sequence reconstruction | 6 years baseline | Included with held records | Must support chronology reconstruction | Must use server-authoritative timestamps |
| Attachment metadata | Yes | file name, size, type, checksum, immutable reference | Preserve evidence of communicated artifacts | 6 years baseline | Included with hold | Reviewable and exportable | Binary storage strategy defined in FCA-007 |
| Attachment binary/content | Conditional (policy) | image/video/file payload in immutable archive store | Preserve communicated content where required | 6 years baseline when in scope | Included with hold | Discoverable/exportable | Tenant/product policy may limit classes |
| Conversation membership state | Yes | participant join/leave/role changes | Establish who had access at event time | 6 years baseline | Included with hold | Supervisory context for access scope | Needed for replay/evidence chain |
| Moderation/report actions | Yes (supplemental) | report created/status changed | Evidence of escalations and handling | 6 years baseline | Included with hold | Queryable for case investigation | Not substitute for primary communication record |
| System delivery state | Yes | scheduled delivery transitions, retries/failures | Completeness of communication lifecycle | 6 years baseline | Included with hold | Explain timeline anomalies | Needed for deterministic replay |
| Feature-flag/config decisions impacting archive | Yes | archive enabled/disabled, fail-closed mode changes | Demonstrate control operation over time | 6 years baseline | Included with hold | Auditable controls evidence | Emit immutable config-change audit events |

### Open legal/compliance decisions (must be resolved before FCA-002)

1. Confirm authoritative minimum retention period per product/legal entity and jurisdiction profile.
2. Confirm whether direct-message attachment binaries are always in scope or policy-scoped.
3. Confirm whether draft/failed sends are records or operational telemetry only.
4. Confirm approved legal-hold scope hierarchy (tenant, user, conversation, date range, case id).
5. Confirm permitted redaction policy for privileged/sensitive material in exports.

---

## 2) Gap analysis against current messaging implementation

Legend:

- **Status**: ✅ aligned, ⚠️ partial, ❌ missing
- **Priority**: P0 immediate blocker, P1 near-term, P2 follow-up

| Capability | Current state | Status | Gap | Priority | Target ticket(s) |
|---|---|---|---|---|---|
| Immutable archive for all messaging events | Plan exists, no implemented archive write path yet | ❌ | Need canonical archive writer + immutable sink | P0 | FCA-004, FCA-005 |
| Versioned canonical event schema | Conceptual schema in plan | ⚠️ | Need machine-validated schema and canonicalization rules | P0 | FCA-002 |
| Tamper-evident chain verification | Described in plan, not implemented | ❌ | Need hash chain + chain-head table + verifier | P0 | FCA-006 |
| Retention engine for compliance archive | Message-controls docs mention retention considerations for report context only | ⚠️ | Need independent retention policy engine for archive records | P0 | FCA-011 |
| Legal hold controls | Not implemented | ❌ | Need hold APIs, storage, and hold-aware purge enforcement | P0 | FCA-012, FCA-013 |
| Compliance query APIs over immutable store | Not implemented | ❌ | Need RBAC-protected compliance query plane | P0 | FCA-014 |
| eDiscovery export bundles with manifests | Not implemented | ❌ | Need signed/checksummed export workflow | P0 | FCA-015 |
| Messaging lifecycle coverage (send/edit/revoke/delete) | Operational messaging exists but not archive-emitting | ⚠️ | Need event emission hooks across all mutation paths | P0 | FCA-008 |
| Membership/role transition archival context | Membership state exists operationally | ⚠️ | Need archive events for access reconstruction | P1 | FCA-009 |
| Supervisory feed integration | Not implemented | ❌ | Need compliance stream integration for supervision tooling | P2 | FCA-016 |
| Archive observability and alerts | Message-controls observability exists for hide/pin/report only | ⚠️ | Need archive-specific metrics/logs/dashboard/alerts | P0 | FCA-017, FCA-018 |
| Runtime rollout controls for archive | Pattern exists for messaging flags | ⚠️ | Need dedicated archive feature flags + staged rollout execution | P1 | FCA-019 |
| Recovery drills (replay/backfill/incidents) | Not implemented | ❌ | Need runbooks + validated staging drills | P1 | FCA-020 |
| Compliance/security test assurance | Existing tests cover message-controls features only | ⚠️ | Need hashing, coverage, RBAC, export integrity suites | P0 | FCA-021..FCA-024 |

### Summary assessment

- **Immediate blockers (P0):** canonical schema, archive ingest, immutability/tamper evidence, retention/legal hold, compliance query/export, and assurance tests.
- **Near-term controls (P1):** rollout flags, membership context archiving, and recovery drills.
- **Follow-up optimization (P2):** supervisory downstream integration.

---

## 3) Legal/compliance sign-off workflow

## 3.1 Workflow stages

1. **Draft baseline (Engineering owner)**
   - Populate matrix and gaps.
   - Link proposed ticket sequencing.
2. **Compliance review**
   - Validate supervisory and retention assumptions.
   - Identify required control evidence for audits/exams.
3. **Legal review**
   - Confirm retention minima, hold behavior, export/redaction constraints.
4. **Joint approval**
   - Engineering + Compliance + Legal sign baseline.
   - Freeze v1 requirements for implementation epics FCA-002 onward.
5. **Change control**
   - Any scope/regulatory interpretation change opens a delta addendum and re-approval.

## 3.2 Required approval artifacts

- Approved baseline matrix (this document).
- Approved exception list (if any out-of-scope record classes).
- Approved retention and legal-hold policy memo.
- Approved compliance-access RBAC policy.
- Approved export-handling/security policy.

## 3.3 Sign-off record

| Role | Name | Decision | Date | Notes |
|---|---|---|---|---|
| Engineering Lead | _TBD_ | Pending | _TBD_ |  |
| Compliance Officer | _TBD_ | Pending | _TBD_ |  |
| Legal Counsel | _TBD_ | Pending | _TBD_ |  |
| Security Lead | _TBD_ | Pending | _TBD_ |  |
| Product Owner | _TBD_ | Pending | _TBD_ |  |

### Approval gate criteria

This artifact is considered **Approved** when:

- all P0 requirement rows have non-ambiguous decisions,
- retention baseline and legal-hold semantics are explicitly accepted by legal/compliance,
- sign-off table includes Engineering + Compliance + Legal approvals,
- resulting decisions are reflected in active implementation tickets.

---

## 4) In-scope record categories (enumerated baseline)

The baseline in-scope categories for archive implementation are:

1. message text lifecycle events,
2. message metadata and provenance,
3. attachment metadata (and binaries per policy decision),
4. conversation membership/access-state transitions,
5. moderation/report supplemental events,
6. system delivery state transitions,
7. control-plane config/feature decisions that impact archive behavior.

Any category not listed above requires explicit disposition in an addendum before implementation exclusion.
