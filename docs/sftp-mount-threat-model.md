# SFTP Mount Threat Model & Security Baseline (SFTP-002)

This document implements **SFTP-002** and defines the security baseline for user-provided SFTP credentials and mounted SFTP data-path operations.

---

## 1) Scope and security objectives

### In-scope
- Credential ingestion via mount APIs (password/private key/passphrase inputs).
- Credential storage, retrieval, and rotation/revocation lifecycle.
- Runtime SFTP connection establishment and data-path operations.
- Mount health transitions caused by auth/network failures.
- Audit, observability, and abuse controls for untrusted remote destinations.

### Security objectives
1. Prevent credential disclosure in transit, at rest, and in logs.
2. Enforce least-privilege access for secrets and mount operations.
3. Prevent SSRF-style abuse / uncontrolled egress to arbitrary hosts.
4. Bound blast radius from compromised credentials or failing remote hosts.
5. Preserve backward-compatible security posture for non-mounted paths.

---

## 2) System context, trust boundaries, and assets

### Critical assets
- SFTP credentials (password, private key, passphrase).
- KMS data keys / encryption context.
- Mount metadata (host, port, root, policy, status).
- Audit logs and usage telemetry.
- Service IAM principal permissions.

### Trust boundaries
- **Client -> API**: untrusted input boundary.
- **API -> secret store**: high-sensitivity control boundary.
- **API -> SFTP remote host**: external network boundary.
- **API -> logs/metrics**: data exfiltration boundary.

---

## 3) Threat model (STRIDE-oriented)

## 3.1 Spoofing
**Threats**
- Attacker submits credentials for malicious host pretending to be legitimate server.
- MITM host impersonation during SSH handshake.

**Controls**
- Host allowlist / destination policy enforcement.
- SSH host-key verification policy (known_hosts / pinning where required).
- Authenticated user ownership checks for all mount operations.

## 3.2 Tampering
**Threats**
- Mutation of encrypted credential records.
- Unauthorized mutation of mount status/policy.

**Controls**
- Envelope encryption + integrity checking (decrypt failure on tamper).
- Strict IAM write boundaries for credential and mount records.
- Audit events for create/update/delete/rotate/revoke.

## 3.3 Repudiation
**Threats**
- User/operator denies mount or credential updates.

**Controls**
- Immutable audit trail including actor, mount id, operation, status, timestamp.
- Correlation/request IDs for data operations and mount lifecycle operations.

## 3.4 Information disclosure
**Threats**
- Credential leakage in logs, traces, exceptions, metrics labels.
- Secret exposure in API responses or error payloads.

**Controls**
- Mandatory secret redaction at API, service, and audit layers.
- Prohibit secret fields in logs/metrics dimensions.
- Sanitized error messages (`last_error_message`) with no credential material.

## 3.5 Denial of service
**Threats**
- Slow/unreachable hosts consume worker and socket resources.
- Repeated failing operations exhaust retries.

**Controls**
- Per-operation timeout budgets.
- Bounded retry policies with jitter.
- Circuit-breaker/degraded states and fast-fail behavior.
- Concurrency caps per user/mount/host.

## 3.6 Elevation of privilege
**Threats**
- Unauthorized user accesses another user’s mount or secret.
- Over-permissive IAM allows broad KMS/decrypt usage.

**Controls**
- Owner-scoped authorization for mount operations.
- IAM resource-level constraints for secret + KMS access.
- Environment separation for KMS keys and data stores.

---

## 4) Mandatory controls (must-have baseline)

The following controls are **required** for launch.

### 4.1 Encryption and secret handling
1. Credentials must be encrypted at rest with KMS envelope encryption.
2. Secrets must never be stored plaintext in mount metadata or file-node records.
3. Decrypted credentials must only exist in-memory for active connection setup and be zeroized/disposed promptly.
4. Secret-bearing request fields must be excluded from logs and traces.

### 4.2 Redaction and observability safety
5. Structured log redaction must cover password/private key/passphrase equivalents.
6. Error payloads must return stable codes, not raw exception strings from SSH libraries.
7. Audit payloads must include identifiers and statuses only (no secrets).

### 4.3 IAM and access boundaries
8. Separate IAM permissions for:
   - mount metadata CRUD,
   - credential decrypt/read,
   - KMS decrypt/data-key generation.
9. Service role must be least privilege and environment-scoped.
10. Access to credential records must be owner-constrained and API-authorized.

### 4.4 Host restrictions and transport security
11. Outbound SFTP destinations must pass allowlist/policy checks.
12. Host-key verification must be enabled (reject unknown/changed keys per policy).
13. Plain FTP or insecure fallback protocols are prohibited.

### 4.5 Abuse and resource controls
14. Timeouts must be enforced for connect, auth, list, read, and write operations.
15. Retry caps must be bounded; no unbounded retries.
16. Circuit-break/degraded behavior must prevent repeated expensive retries to failing hosts.
17. Rate/concurrency limits must exist for mount test and data operations.

---

## 5) Abuse controls baseline

## 5.1 Egress controls
- Destination policy: allow approved hostname/domain/IP patterns only.
- Deny private/link-local/metadata endpoints unless explicitly approved for internal use.
- Enforce policy during mount create/update and at connection time.

## 5.2 Timeout baseline
Recommended initial defaults (environment-overridable):
- connect timeout: 5s
- auth timeout: 10s
- list timeout: 15s
- read/write inactivity timeout: 30s
- overall operation timeout: 60s

## 5.3 Retry baseline
- max retries: 2 for transient network errors.
- no retry for deterministic auth failures.
- exponential backoff with jitter.

## 5.4 Circuit-breaker baseline
- Open breaker after N consecutive failures per mount/host (e.g., 5).
- Fast-fail window (e.g., 60s) before half-open probe.
- Transition mount status to `degraded` or `unreachable` accordingly.

---

## 6) Risk register and implementation mapping

| Risk ID | Risk | Severity | Required mitigation | Ticket mapping |
| --- | --- | --- | --- | --- |
| SFTP-R1 | Credential disclosure in logs/storage | Critical | KMS envelope encryption, redaction, sanitized errors | SFTP-010, SFTP-041 |
| SFTP-R2 | Unauthorized credential or mount access | Critical | Owner authorization + least-privilege IAM | SFTP-011, SFTP-012, SFTP-013 |
| SFTP-R3 | Host impersonation / MITM | High | Host-key verification policy | SFTP-021, SFTP-042 |
| SFTP-R4 | SSRF/uncontrolled egress via user host input | High | Host allowlist/destination policy checks | SFTP-042 |
| SFTP-R5 | Resource exhaustion from slow/failing hosts | High | Timeout, retry cap, circuit breaker, concurrency limits | SFTP-032, SFTP-033 |
| SFTP-R6 | Non-deterministic failures degrade UX/security | Medium | Stable error taxonomy + status transitions | SFTP-023, SFTP-033 |
| SFTP-R7 | Incomplete security visibility | Medium | Mount-specific audit taxonomy + metrics | SFTP-040, SFTP-041 |

---

## 7) Security review sign-off (SFTP-002 acceptance)

Status: **APPROVED (baseline accepted)**

Must-have controls approved for implementation:
- Encryption and secret handling controls #1-4.
- Redaction/observability controls #5-7.
- IAM/access boundary controls #8-10.
- Host restriction and transport controls #11-13.
- Abuse/resource controls #14-17.

Approval record:
- Review artifact: `docs/sftp-mount-threat-model.md`.
- Decision scope: SFTP-002 baseline for design + implementation tickets.
- Follow-up verification: enforced during SFTP-010/021/032/041/042 implementation and pre-launch review.

---

## 8) Verification checklist for downstream implementation

- [ ] SFTP-010 stores credentials encrypted and never in plaintext metadata.
- [ ] SFTP-021 enforces host-key verification and safe error mapping.
- [ ] SFTP-032 implements timeouts/retries/circuit-breakers with sane defaults.
- [ ] SFTP-041 verifies secret redaction and audit payload constraints.
- [ ] SFTP-042 enforces outbound destination allowlist policy.
- [ ] Pre-launch test validates no secret leakage in logs/metrics/traces.
