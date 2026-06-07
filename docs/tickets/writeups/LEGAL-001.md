# LEGAL-001: Unified Per-User Legal Investigation Dump — Investigation & Implementation Write-up

## 1. Summary & Classification

LEGAL-001 adds a thin orchestration and chain-of-custody layer on top of three existing, separately-invokable export subsystems (GDPR/DSAR export, messaging compliance export, enterprise audit-log export) so that a legal-ops/root operator can respond to a subpoena or law-enforcement request for a single subject in one operation, with a tamper-evident signed bundle and a four-eyes approval workflow.

- **Type**: Feature (compliance infrastructure / legal tooling)
- **Priority**: Medium
- **Status**: UNBUILT — no `legal_investigation` router, service, pipeline, or frontend exists; `grep -rn "legal_investigation"` returns zero results across the entire codebase.
- **Owning area**: Legal / Compliance / Root-level admin tooling
- **User persona**: Root/legal-ops operator responding to subpoena or court order; a second authorized operator approving the request.
- **Dependencies**: Three existing exporters (all confirmed implemented):
  - `app/services/gdpr_service.py` — DSAR/CCPA export (`create_export_request`, line 100)
  - `app/services/messaging_archive_export.py` — compliance export with HMAC-signed manifest (`build_case_export_bundle`, line 39)
  - `app/services/audit_export_pipeline.py` — unified audit events, target-user-filterable (`create_export_job` with `actor_user_id`/`target_user_id` params, line 80)
- **PII scope**: bundle contains decrypted PII (messages, profile, documents); access must be restricted to `role == ROOT` or a dedicated `legal_ops` scope; every download must be logged.
- **SECOPS-007**: `LEGAL_INVESTIGATION_ENABLED` must default `true` in dev (for E2E), `false` in prod. No mock services needed — all three underlying exporters already work in dev mode with DDB local.

## 2. Current-State Investigation (what exists today)

### Export subsystem 1: GDPR/DSAR (`app/services/gdpr_service.py`)

`create_export_request(user_sub, categories)` (line 100) creates a DDB record in `T.gdpr_requests` and enqueues (or in dev mode, synchronously processes) an export ZIP covering: profile, messages, billing, files, calendar, contacts, subscriptions, security metadata. It is scoped to the `user_sub` of the requesting user — an operator would need to invoke it on behalf of a target.

`create_deletion_request` (line 123) integrates with `KycEncryptionService.destroy_user_keys` (via lazy import at `app/services/gdpr_service.py:151`).

**Gap for legal use**: The DSAR export does not cover: orders/entitlements, broadcast recording references, signature packets, KYC case timeline and decisions. The ticket acknowledges these gaps and says "collect where feasible."

### Export subsystem 2: Messaging compliance (`app/services/messaging_archive_export.py`)

`build_case_export_bundle(...)` (line 39) produces an immutable JSONL + HMAC-signed manifest. Currently invoked by `app/routers/messaging.py` (~line 12300) for compliance case exports. It uses `_sign_manifest(key=..., payload=...)` (line 34) with an HMAC-SHA256 over canonical JSON, referencing a `manifest_signing_key` and `manifest_signing_key_id`.

**Reuse for legal**: Can be called directly on the target `user_sub`'s conversation set.

### Export subsystem 3: Audit log (`app/services/audit_export_pipeline.py`)

`create_export_job(categories, format, from_ts, to_ts, created_by, actor_user_id=None, target_user_id=None)` (line 74) supports filtering by `actor_user_id` and `target_user_id`. In dev mode, runs synchronously and stores content inline in DDB (up to 400KB cap). The manifest is HMAC-signed (`_compute_manifest_signature`, line 235; `verify_manifest_signature`, line 246).

**Reuse for legal**: Pass `actor_user_id=target_sub` and `target_user_id=target_sub` to capture all audit events where the subject acted or was acted upon.

### Signing infrastructure (`app/services/messaging_archive_export.py:34`, `app/services/audit_export_pipeline.py:235`)

Both exporters use `hmac.new(key.encode("utf-8"), payload, hashlib.sha256)`. The legal bundle's top-level manifest can use the same pattern, reusing helpers from `app/core/crypto.py` and the per-exporter signing keys from settings.

### Four-eyes / authorization precedents

The KYC-025 appeal design and the platform's admin/root role system (`app/auth/deps.py`, `app/auth/roles.py`) already provide the pattern: require `role == ROOT` (or a dedicated `legal_ops` scope), enforce that the approver's `sub` differs from the requester's `sub`.

### S3 / storage

`app/core/dev_s3.py` (moto in-process) handles S3 in dev. The bundle ZIP would be stored under a configurable `LEGAL_INVESTIGATION_S3_BUCKET` prefix with a TTL tag.

## 3. Gap / Threat Analysis

### Authorization risk (PII access)

The bundle contains the full decrypted PII of the subject. Unauthorized access to `/download` would be a GDPR Article 32 breach. Every download must be: (a) restricted to `ROOT` or legal-ops scope, (b) logged to the append-only audit table, (c) rate-limited.

### Four-eyes enforcement

Without the constraint `approver_sub != requester_sub`, a single operator can self-approve a legal investigation, undermining the authorization control.

### Preservation hold

If `LEGAL_INVESTIGATION_AUTO_HOLD=true`, opening an investigation must place a hold on the subject that blocks `run_retention_purge` (KYC), GDPR deletion, and messaging archive purge until the investigation is closed or expired. Without this guard, data could be purged before the bundle download.

### Chain-of-custody integrity

The top-level manifest must include SHA256 of each sub-export file and an aggregate HMAC signature so that any tampering (adding/removing files, modifying content) is detectable.

### All code sites that must change / be created

1. `app/services/legal_investigation_pipeline.py` — **new**: orchestration worker; invokes three exporters; assembles ZIP + top-level manifest; writes S3 key and manifest hash back to DDB.
2. `app/routers/legal_investigation.py` — **new**: 4 endpoints (open, approve, list/status, download).
3. `app/main.py` — register `legal_investigation_router`; add startup handler if async worker needed.
4. `app/core/settings.py` — 4 new settings flags.
5. `scripts/local-ddb-init.py` — `LegalInvestigations` table + `legal_investigation_audit` table.
6. `frontend/src/pages/admin/LegalInvestigationsPage.tsx` — **new** admin page.
7. `frontend/src/api/endpoints/legalInvestigation.ts` — **new** API client.
8. `frontend/src/App.tsx` — add `/admin/legal/investigations` route.
9. `frontend/e2e/legal-investigation.spec.ts` — **new** E2E spec.
10. `tests/test_legal_investigation.py` — **new** pytest file.
11. `app/services/gdpr_service.py` — modify deletion flow to check for open legal hold before proceeding.
12. `app/services/kyc_cases.py` — `run_retention_purge` must skip subjects with open legal holds.

## 4. Proposed Design / Fix

### 4.1 DynamoDB tables (`scripts/local-ddb-init.py`)

**LegalInvestigations table**:
```
PK: investigation_id (S)
SK: "META"
Attributes: subject_user_id (S), legal_basis (S), external_ref (S), requesting_party (S),
  scope (L), date_from (N), date_to (N), status (S), requested_by (S), approved_by (S),
  requested_at (N), approved_at (N), generated_at (N), bundle_s3_key (S), manifest_hash (S),
  expires_at (N), ttl (N)
GSI: subject-status-index (PK=subject_user_id, SK=status)
GSI: status-requested-index (PK=status, SK=requested_at) -- attr_types={"requested_at":"N"}
```

**legal_investigation_audit table** (append-only):
```
PK: investigation_id (S)
SK: {timestamp}#{event_id} (S)
Attributes: actor_sub (S), action (S), ip_address (S), created_at (N)
GSI: actor-index (PK=actor_sub, SK=created_at) -- attr_types={"created_at":"N"}
```

### 4.2 New service (`app/services/legal_investigation_pipeline.py`)

```python
def create_investigation(*, requested_by: str, subject_user_id: str, legal_basis: str,
    external_ref: str, requesting_party: str, scope: list[str],
    date_from: int, date_to: int) -> dict:
    """Create investigation in 'draft' → immediately move to 'pending_approval'."""

def approve_investigation(*, investigation_id: str, approver_sub: str) -> dict:
    """Four-eyes: approver_sub must differ from requested_by. Transitions to 'approved'.
    If LEGAL_INVESTIGATION_AUTO_HOLD: place preservation hold on subject."""

def run_investigation_pipeline(investigation_id: str) -> None:
    """Background worker: invoke 3 exporters, assemble ZIP + top-level manifest, upload to S3."""

def download_bundle(*, investigation_id: str, accessor_sub: str, ip_address: str) -> bytes:
    """Fetch bundle from S3, log access to audit table, return bytes."""

def _build_top_level_manifest(*, investigation_id: str, sub_exports: list[dict],
    subject_user_id: str, legal_basis: str, external_ref: str,
    approver_sub: str, generated_at: int) -> dict:
    """SHA256 each sub-file + aggregate HMAC signature using manifest signing key."""
```

**Scope of sub-exports invoked**:

| Scope value | Exporter | Parameters |
|---|---|---|
| `"messaging"` | `messaging_archive_export.build_case_export_bundle` | all conversations of `subject_user_id`, date range |
| `"audit"` | `audit_export_pipeline.create_export_job` | `actor_user_id=subject_user_id`, `target_user_id=subject_user_id`, date range |
| `"profile"` | `gdpr_service.create_export_request` | `user_sub=subject_user_id`, categories covering profile/billing/files/calendar/contacts |
| `"kyc"` | Direct `T.kyc_cases` scan for subject (KYC-025 once built; otherwise skip) | case timeline + decisions |

**Top-level chain-of-custody manifest** (JSON):
```json
{
  "investigation_id": "linv_abc123",
  "subject_user_id": "alice-uuid",
  "legal_basis": "subpoena",
  "external_ref": "SDNY-2026-12345",
  "requesting_party": "US Attorney SDNY",
  "requested_by": "root-operator-sub",
  "approved_by": "second-operator-sub",
  "scope": ["messaging", "audit", "profile"],
  "date_from": 0,
  "date_to": 9999999999,
  "generated_at": 1748600000,
  "files": [
    {"filename": "messaging_export.jsonl", "sha256": "abc..."},
    {"filename": "audit_export.ndjson", "sha256": "def..."},
    {"filename": "profile_export.zip", "sha256": "ghi..."}
  ],
  "manifest_sha256": "jkl...",
  "hmac_signature": "mno...",
  "key_id": "legal-manifest-key-1"
}
```

### 4.3 New router (`app/routers/legal_investigation.py`)

```
POST /ui/admin/legal/investigations
  Auth: require_ui_session + ROOT or legal_ops scope
  Body: { subject_user_id, legal_basis, external_ref, requesting_party, scope[], date_from, date_to }
  Response: { investigation_id, status: "pending_approval" }

POST /ui/admin/legal/investigations/{id}/approve
  Auth: require_ui_session + ROOT or legal_ops scope + approver_sub != requested_by
  Response: { ok, status: "approved" }
  Triggers: background worker run_investigation_pipeline

GET /ui/admin/legal/investigations
  Auth: ROOT/legal_ops
  Response: paginated list with status, subject_user_id, requested_at

GET /ui/admin/legal/investigations/{id}
  Auth: ROOT/legal_ops
  Response: full investigation record + bundle_s3_key (if ready)

GET /ui/admin/legal/investigations/{id}/download
  Auth: ROOT/legal_ops
  Response: ZIP file stream (audited — logs to legal_investigation_audit)
  Rate limit: 3 per investigation per hour
```

Gate all endpoints: `if not S.legal_investigation_enabled: raise HTTPException(404)`.

### 4.4 Settings (`app/core/settings.py`)

```python
legal_investigation_enabled: bool = os.environ.get("LEGAL_INVESTIGATION_ENABLED", "true").lower() in ("1","true","yes","on")
legal_investigation_bundle_ttl_days: int = int(os.environ.get("LEGAL_INVESTIGATION_BUNDLE_TTL_DAYS", "90"))
legal_investigation_require_four_eyes: bool = os.environ.get("LEGAL_INVESTIGATION_REQUIRE_FOUR_EYES", "true").lower() in ("1","true","yes","on")
legal_investigation_auto_hold: bool = os.environ.get("LEGAL_INVESTIGATION_AUTO_HOLD", "true").lower() in ("1","true","yes","on")
```

### 4.5 Preservation hold integration

Add a `legal_hold` flag to user profile or a separate `legal_holds` DDB table. Before purging KYC rejected cases (`app/services/kyc_cases.py:818`), messaging archive (`app/services/messaging_archive_purge.py`), and processing GDPR deletion (`app/services/gdpr_service.py:123`), check for an open legal hold on the subject.

### 4.6 Frontend (`frontend/src/pages/admin/LegalInvestigationsPage.tsx`)

- Open request form: subject user ID lookup, legal basis dropdown, external ref field, scope checkboxes, date range.
- Pending approvals queue for the second operator.
- Status list: shows investigation ID, subject, status, requested/approved timestamps, "Download" button when `status == "ready"`.
- Download link streams the ZIP directly.

Route in `App.tsx`: `<Route path="admin/legal/investigations" element={<LegalInvestigationsPage />} />`.

### 4.7 Dev/Prod parity (SECOPS-007)

- In dev mode: pipeline runs synchronously, moto S3 stores bundle, DDB local stores records. Same code path as prod.
- Signing key: use `S.manifest_signing_key` (already in settings) or add `LEGAL_MANIFEST_SIGNING_KEY` env var.
- Four-eyes in E2E: root operator opens; a second root session (seeded in `e2e_admin_session_setup.py`) approves.

## 5. Testing, Verification & Rollout

### pytest (`tests/test_legal_investigation.py`)

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_create_investigation_pending_approval` | Open → `pending_approval` state |
| 2 | `test_approve_four_eyes_enforcement` | Original requester cannot approve |
| 3 | `test_approve_transitions_to_approved` | Different operator approves successfully |
| 4 | `test_pipeline_invokes_three_exporters` | Pipeline calls gdpr, messaging, audit exporters |
| 5 | `test_manifest_sha256_covers_all_files` | Top-level manifest SHA256 matches files |
| 6 | `test_manifest_hmac_signature_verifiable` | HMAC signature verifies with known key |
| 7 | `test_download_logs_audit_entry` | Download logs to `legal_investigation_audit` |
| 8 | `test_preservation_hold_blocks_gdpr_deletion` | `create_deletion_request` fails while hold is active |
| 9 | `test_feature_flag_off_returns_404` | All endpoints return 404 when flag off |
| 10 | `test_bundle_ttl_expiry_marks_expired` | Investigation moves to `expired` after TTL |

### Playwright E2E (`frontend/e2e/legal-investigation.spec.ts`)

- Open investigation → four-eyes approval (original requester cannot approve) → bundle generated → download contains three sub-exports + verifiable top-level manifest (check SHA256 of downloaded ZIP's manifest file).
- Download is audited: GET audit log → entry with `action="download"` and accessor sub.
- Auto-hold blocks subject deletion while investigation is open.
- Feature flag `LEGAL_INVESTIGATION_ENABLED=false` → endpoints return 404/503.

### Observability

Add to `app/metrics.py`:
- `legal_investigation_created_total` (counter)
- `legal_investigation_approved_total` (counter)
- `legal_investigation_bundle_generated_total` (counter, label: `scope_count`)
- `legal_investigation_downloads_total` (counter)
- `legal_investigation_pipeline_duration_seconds` (histogram)

### Rollout

1. Deploy with `LEGAL_INVESTIGATION_ENABLED=false` in prod. Dev/CI with `true`.
2. Validate E2E suite passes in full.
3. Enable for root/legal-ops users only (no feature-flag ramp needed — already restricted to root).
4. Full availability.

**Rollback**: set `LEGAL_INVESTIGATION_ENABLED=false`. Existing bundle S3 objects and DDB records remain; no data is lost. Preservation holds must be manually released if rollback occurs while investigations are open.

**Effort**: M–L (6-9 days as estimated by ticket).
