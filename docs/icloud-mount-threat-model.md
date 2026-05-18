# iCloud Mount Threat Model (ICLOUD-002)

- **Ticket:** ICLOUD-002
- **Method:** STRIDE
- **Date:** 2026-03-25
- **Scope:** credential intake, credential storage/lifecycle, mounted file access via `/v1/fs`, and supporting ops/observability paths
- **Decision dependency:** ADR-0001 (server-side credential/session integration)
- **Related docs:**
  - `docs/adr/0001-icloud-access-approach-for-mvp.md`
  - `docs/icloud-mount-credential-retention-revocation-policy.md`
  - `docs/runbooks/icloud-mount-incident-response-playbook.md`

---

## 1) Scope and assumptions

### In scope

- `POST /v1/fs/mounts/icloud/initiate` and `POST /v1/fs/mounts/icloud/verify` onboarding flows.
- Credential/session artifact handling in `filemanager_mount_secrets` and AWS Secrets Manager/KMS.
- Mounted operations routed through provider dispatcher (`list/stat/read/write/delete/move`).
- Mount health/circuit-breaker transitions and reconcile workflows.
- Audit events, metrics, dashboards, and incident response controls.

### Out of scope

- Apple internal service-side controls.
- End-user endpoint malware protections beyond normal customer responsibilities.
- Non-iCloud provider threat modeling.

### Security assumptions

- Request authentication/authorization for file-manager APIs is enforced by existing platform auth.
- Secrets are encrypted at rest in Secrets Manager with KMS keys and IAM separation.
- Feature flags and kill-switch controls can disable iCloud mount operations without deploy.

---

## 2) System context, data-flow, and trust boundaries

## 2.1 Components

1. User Browser (untrusted client)
2. Files UI
3. Filemanager Router (`/v1/fs/*`, `/v1/fs/mounts/*`)
4. Mount metadata service/table (status, ownership, policy, cursor)
5. Mount secret service (Secrets Manager integration)
6. AWS Secrets Manager + KMS
7. iCloud provider adapter + transport integration
8. Audit/metrics/logging plane

## 2.2 Trust boundaries

- **TB1: Internet/API boundary** (browser ↔ backend API)
- **TB2: App/data boundary** (router/service ↔ mount metadata store)
- **TB3: Secrets boundary** (app ↔ Secrets Manager/KMS)
- **TB4: Upstream provider boundary** (app ↔ iCloud provider integration)
- **TB5: Observability boundary** (operational telemetry with redaction requirements)

## 2.3 Data-flow diagram (text)

```text
[User Browser]
   | 1) initiate/verify/rotate/revoke + /v1/fs mounted ops (HTTPS)
   v
[Files UI] ---> [Filemanager Router + Dispatcher] ----------------------+
                  | 2) mount state read/write                            |
                  v                                                      |
            [Mount Metadata Store]                                       |
                  | 3) secret ref lookup                                 |
                  v                                                      |
         [Mount Secret Service] ---- 4) Get/Put/Rotate/Revoke --------> [AWS Secrets Manager + KMS]
                  |
                  | 5) provider request (list/read/write/delete/move)
                  v
           [iCloud Provider Integration]

All services emit redacted logs/metrics/audits -----------------------> [Observability Plane]
```

---

## 3) Asset inventory

- iCloud auth/session artifacts (high sensitivity)
- Mount metadata (mount_id, owner, path, status, secret_ref)
- File content and metadata for mounted paths
- User identities/session claims
- Audit records and operational telemetry
- Reconcile state/cursors and health transition history

---

## 4) STRIDE analysis

## 4.1 Spoofing

### Threats

- **T-S1:** Attacker replays or forges onboarding/verify requests to hijack mount ownership.
- **T-S2:** Stolen service credentials are used to read mount secrets.
- **T-S3:** Upstream provider session impersonation through leaked auth artifacts.

### Mitigations

- **C-S1:** Strong authN/authZ checks and owner binding on every mount action.
- **C-S2:** Secrets Manager IAM least-privilege with workload identity separation.
- **C-S3:** No secret values returned to clients; only secret references in mount records.
- **C-S4:** Rotation/revoke APIs and lockout/rate-limit controls on verify paths.

### Owner(s)

Security Engineering, Filemanager Backend, Infra/SRE.

---

## 4.2 Tampering

### Threats

- **T-T1:** Mount metadata tampering (`owner_user_sub`, `status`, `secret_ref`, `provider`).
- **T-T2:** Path confusion/path traversal in mounted operations.
- **T-T3:** Drift-induced stale metadata causing unintended writes/deletes.

### Mitigations

- **C-T1:** Conditional/owner-bound updates and validation in mount service methods.
- **C-T2:** Canonical path normalization and mount prefix resolution checks.
- **C-T3:** Reconcile worker with drift report + safe dry-run mode before repair.
- **C-T4:** Conflict policy controls + idempotency on write paths.

### Owner(s)

Filemanager Backend Team.

---

## 4.3 Repudiation

### Threats

- **T-R1:** Users/admins dispute mount lifecycle actions (initiate/verify/rotate/revoke).
- **T-R2:** Inability to attribute mounted file operations to actor/request context.

### Mitigations

- **C-R1:** Structured audit events with actor, provider, mount_id, path, outcome.
- **C-R2:** Request/correlation identifiers propagated across router/service boundaries.
- **C-R3:** Immutable log retention policy for security investigations.

### Owner(s)

Security + Observability + Filemanager Backend.

---

## 4.4 Information disclosure

### Threats

- **T-I1:** Credential/session artifacts leak via logs/errors/traces.
- **T-I2:** Excessive internal access to secrets or mounted data.
- **T-I3:** Cross-tenant mount resolution exposes wrong user data.

### Mitigations

- **C-I1:** Redaction controls and sensitive-field suppression in logs/audit payloads.
- **C-I2:** Secrets in KMS-backed store; strict access policy and monitored secret reads.
- **C-I3:** Owner + mount binding checks on all mount operations.
- **C-I4:** Support break-glass controls with approvals and audit trails.

### Owner(s)

Security Engineering, Backend API, Infra/SRE.

---

## 4.5 Denial of service

### Threats

- **T-D1:** Flooding of onboarding/verify or mounted operations.
- **T-D2:** Upstream throttling/transient failures causing retry storms.
- **T-D3:** Large-file workloads causing resource exhaustion.

### Mitigations

- **C-D1:** Per-user/per-IP rate limits and lockout controls.
- **C-D2:** Exponential backoff + retry budget + circuit-breaker state transitions.
- **C-D3:** Streaming transfers, bounded concurrency, timeout/size guardrails.
- **C-D4:** Kill-switch + staged rollout controls for blast-radius reduction.

### Owner(s)

SRE + Filemanager Backend.

---

## 4.6 Elevation of privilege

### Threats

- **T-E1:** User escalates to another tenant/user mount via crafted path/mount id.
- **T-E2:** Privileged operator bypasses policy without traceability.
- **T-E3:** Reconciliation or override endpoints abused to force unauthorized state.

### Mitigations

- **C-E1:** Ownership checks + entitlement enforcement on every route.
- **C-E2:** Admin-scope and break-glass governance with immutable logs.
- **C-E3:** Manual override endpoints gated and audited; status transitions validated.

### Owner(s)

Filemanager Backend + Security.

---

## 5) Threat-to-control matrix

| Threat ID | Primary controls | Control owner |
|---|---|---|
| T-S1 | C-S1, C-S4 | Filemanager Backend |
| T-S2 | C-S2, C-I2 | Infra/SRE + Security |
| T-S3 | C-S3, C-S4 | Filemanager Backend |
| T-T1 | C-T1 | Filemanager Backend |
| T-T2 | C-T2 | Filemanager Backend |
| T-T3 | C-T3, C-T4 | Filemanager Backend |
| T-R1 | C-R1, C-R2 | Backend + Observability |
| T-R2 | C-R1, C-R3 | Security + Observability |
| T-I1 | C-I1, C-I2 | Security + Backend |
| T-I2 | C-I2, C-I4 | Security + Infra/SRE |
| T-I3 | C-I3 | Filemanager Backend |
| T-D1 | C-D1 | Backend + SRE |
| T-D2 | C-D2, C-D4 | Backend + SRE |
| T-D3 | C-D3 | Backend |
| T-E1 | C-E1 | Filemanager Backend |
| T-E2 | C-E2 | Security |
| T-E3 | C-E3 | Filemanager Backend + Security |

---

## 6) Residual risks and compensating controls

| Residual risk | Why not fully eliminated | Compensating controls | Risk owner | Status |
|---|---|---|---|---|
| R-01 Upstream iCloud behavior changes break auth/session semantics | External provider dependency | staged rollout, feature flags, kill-switch, rapid revoke/reconnect playbook | Product + Backend | Open |
| R-02 Compromise of user-provided auth artifacts | Credential-based architecture for MVP | KMS-backed secret storage, rotation/revoke APIs, high-signal auth-failure alerts | Security + Backend | Open |
| R-03 Operational redaction misses in new logs/fields | Continuous feature evolution can add fields | mandatory redaction tests and review checklist for new mount telemetry fields | Security + Observability | In progress |
| R-04 Support/operator misuse of elevated access | Some break-glass access is operationally required | JIT access approvals, session logging, quarterly recertification | Security + IT | Open |
| R-05 False-positive degradation impacts customer availability | Circuit-breaker thresholds are heuristic | threshold tuning + override controls + customer comms templates | SRE + Product | Accepted |

---

## 7) Security review and completion checklist

- [x] Data-flow diagram and trust boundaries documented.
- [x] STRIDE threats documented for credential intake/storage/mounted access.
- [x] Mitigations mapped to explicit controls and owners.
- [x] Residual risks and compensating controls documented.
- [x] Security review completed for ICLOUD-002 (Application Security Lead, 2026-03-25).
- [x] Engineering review completed for ICLOUD-002 (File Manager Engineering Lead, 2026-03-25).

---

## 8) Traceability to acceptance criteria

This document satisfies ICLOUD-002 by providing:

1. STRIDE-style threat model with trust boundaries and data-flow diagram.
2. Threat-to-control mapping with ownership.
3. Residual risk register with compensating controls and status.

