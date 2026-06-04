# LEGAL-001: Unified Per-User Legal Investigation Dump

**Ticket**: LEGAL-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Estimated effort**: 6-9 days
**Dependencies**: PRIVACY-001 (GDPR data export), ENTERPRISE-004 (audit log export), messaging compliance export (`app/services/messaging_archive_export.py`), KYC-023 (data encryption)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform already has strong, legally-defensible export tooling — but it is
**split across three independent subsystems**, with no single orchestrator that
produces a complete dump for one subject (user/entity) in response to a
subpoena, court order, or law-enforcement request:

1. **Messaging compliance export** — case-bound, immutable JSONL + signed (HMAC)
   manifest (`app/routers/messaging.py:12300`, `app/services/messaging_archive_export.py`).
2. **GDPR/CCPA data export (DSAR)** — per-user ZIP of profile, messages, billing,
   files, calendar, contacts, subscriptions, security metadata
   (`app/routers/privacy.py`, `app/services/gdpr_service.py`).
3. **Enterprise audit-log export** — unified audit events across 5 sources, CSV/
   NDJSON + signed manifest (`app/routers/audit_export.py`,
   `app/services/audit_export_pipeline.py`).

To respond to a legal request about one user today, an operator must run all
three exports separately, with different auth, different output formats, and no
single chain-of-custody manifest tying them together. There is also **no
law-enforcement authorization workflow** (request reference, requesting agency,
legal basis, four-eyes approval) and **no single chain-of-custody record**.

This ticket adds a thin **orchestration + chain-of-custody layer** on top of the
existing exporters — it should reuse them, not re-implement them.

### 1.2 How It Works (proposed)

1. A root/legal-ops operator opens a **Legal Investigation** for a target
   `user_id`, recording: legal basis (subpoena / court order / law-enforcement /
   internal investigation), an external reference (case/warrant number),
   requesting party, scope (which data domains), and an optional date range.
2. The request goes through **four-eyes approval** (a second authorized operator
   approves) before any data is gathered — recorded in the audit trail.
3. On approval, a background worker invokes the three existing exporters for the
   target subject + date range:
   - GDPR/account export (`gdpr_service`),
   - messaging compliance export (`messaging_archive_export`),
   - audit-log export filtered to `actor_user_id == target` and
     `target_user_id == target` (`audit_export_pipeline`).
   It also gathers the gaps the GDPR export currently misses where feasible
   (orders/entitlements, broadcast recordings refs, signature packets,
   KYC case timeline+decisions — see KYC-224/KYC-025 dependency).
4. The worker assembles a single **investigation bundle** (ZIP) with:
   - each sub-export and its individual signed manifest,
   - a **top-level chain-of-custody manifest** (subject id, legal basis, external
     ref, approver(s), generation time, per-file SHA256, aggregate HMAC
     signature, key id),
   - a human-readable `README`/index describing contents.
5. The bundle is stored in S3 with a configurable TTL and access is itself
   audited (every download logged). Optionally a legal/preservation hold is
   auto-placed on the subject so their data can't be deleted while the
   investigation is open.

### 1.3 Design Principles

- **Reuse, don't reimplement**: orchestrate the existing exporters; only add the
  request lifecycle, gap-collection, and chain-of-custody manifest.
- **Authorization + four-eyes**: dedicated legal-investigation role; second-person
  approval required before data is gathered; CSRF + audited.
- **Tamper-evident chain of custody**: single signed top-level manifest covering
  all sub-files (SHA256 + HMAC, reuse the existing signing/key-id helpers).
- **Preservation-aware**: opening an investigation can place a legal hold that
  blocks deletion/retention purge for the subject.
- **Everything audited**: request creation, approval, generation, and each
  download are append-only audit events.

---

## 2. Implementation

### 2.1 Data model / tables

- `LegalInvestigations` (DDB): `investigation_id`, `subject_user_id`,
  `legal_basis`, `external_ref`, `requesting_party`, `scope[]`, `date_from/to`,
  `status` (draft → pending_approval → approved → generating → ready → expired),
  `requested_by`, `approved_by`, timestamps, `bundle_s3_key`, `manifest_hash`.
- `legal_investigation_audit` (append-only): every state transition + download.

### 2.2 API (`app/routers/legal_investigation.py`, root/legal-ops only)

- `POST /ui/admin/legal/investigations` — open (draft).
- `POST /ui/admin/legal/investigations/{id}/approve` — four-eyes approval
  (must be a different operator than `requested_by`).
- `GET /ui/admin/legal/investigations` / `/{id}` — list / status.
- `GET /ui/admin/legal/investigations/{id}/download` — fetch bundle (audited).
- Register in `app/main.py`; gate behind `LEGAL_INVESTIGATION_ENABLED`.

### 2.3 Orchestration worker (`app/services/legal_investigation_pipeline.py`)

- Invoke `gdpr_service` export, `messaging_archive_export`, and
  `audit_export_pipeline` (target-filtered) for the subject + range.
- Collect the GDPR-export gaps where available (orders/entitlements, broadcast
  recording refs, signature packets, KYC timeline via KYC-224 once built).
- Assemble ZIP + top-level chain-of-custody manifest (reuse the HMAC/key-id
  signing helpers from the audit/messaging exporters).

### 2.4 Settings (`app/core/settings.py`)

- `LEGAL_INVESTIGATION_ENABLED` (default false in prod, true in dev),
  `LEGAL_INVESTIGATION_BUNDLE_TTL_DAYS`, `LEGAL_INVESTIGATION_REQUIRE_FOUR_EYES`
  (default true), `LEGAL_INVESTIGATION_AUTO_HOLD` (default true).

### 2.5 Frontend (admin/legal-ops)

- A "Legal Investigations" section under admin: open request form, approvals
  queue, status list, audited download. Restricted to the legal-ops/root role.

---

## 3. Testing

- **E2E** (`frontend/e2e/legal-investigation.spec.ts`, new): open → four-eyes
  approval (original requester cannot approve) → generate → bundle contains the
  three sub-exports + a verifiable top-level manifest; download is audited;
  auto-hold blocks subject deletion while open; feature-flag off → 404/403.
- **pytest**: manifest signature verification, target-filtering of audit export,
  state-machine transitions, four-eyes enforcement.

## 4. Out of Scope

- The individual exporters themselves (already implemented).
- Bulk/multi-user litigation discovery (separate future ticket).
- Sealed-data / law-enforcement portal UX beyond the internal admin tool.
- KYC regulator bundle internals (tracked by KYC-224; consumed here once built).
