# ADR 0001: iCloud access approach for MVP

- **Status:** Accepted
- **Date:** 2026-03-25
- **Owners:** File Manager Platform Team
- **Related:** `docs/icloud-mount-integration-plan.md`, `docs/icloud-mount-implementation-tickets.md` (ICLOUD-001)

## Context

We need one supported approach for iCloud mounts in MVP, with clear delivery, legal/security, and operational ownership.

The two candidate approaches were:

1. **Server-side credential/session integration** (backend handles initiate/verify/challenge and mount operations).
2. **Desktop connector agent model** (customer-managed local agent with backend coordination).

At the time of this decision, MVP implementation constraints were:

- Existing `/v1/fs` routing and mount framework are backend-centric and already integrated with onboarding, secret lifecycle, and health controls.
- We need phased rollout controls, auditability, and revocation semantics in the same control plane as other file-manager operations.
- We must document legal/policy constraints around credential collection and storage, and keep explicit rollback options.

## Decision

For MVP, we select **server-side credential/session integration** as the single supported iCloud approach.

### Scope of this decision

- Backend owns iCloud onboarding (`initiate`/`verify`) and challenge state transitions.
- Credentials/session artifacts are stored in AWS Secrets Manager + KMS-backed references, not directly in mount records.
- Provider operations are routed through the provider dispatcher with mount health/circuit-breaker controls.
- Rollout is controlled by runtime flags and cohorts (`internal`, `beta`, `ga`) with kill-switch support.

## Why this decision

1. **Shortest path to MVP delivery**
   - The implemented mount architecture and API flows are backend-first and can be shipped without introducing a new distributed desktop deployment plane.

2. **Operational consistency**
   - Health state transitions, reconcile, audit trails, and provider metrics are centralized in one service boundary.

3. **User/admin experience**
   - Users can connect/reconnect from Files UI directly without separate connector installation requirements for MVP.

4. **Controlled risk posture with guardrails**
   - Secrets are managed centrally with rotation/revoke flows.
   - Circuit-breaker and rollout controls provide fast containment during incidents.

## API and legal constraints (explicit)

- There is no Apple-supported public API contract guaranteeing broad server-side iCloud Drive integration semantics equivalent to local Finder behavior.
- Therefore, this MVP decision is an **engineering/product risk acceptance** with compensating controls:
  - strict feature gating and cohort rollout,
  - operational runbooks and incident response,
  - explicit credential retention/revocation policy,
  - security review sign-off prior to expansion.
- Legal/compliance obligations include:
  - documented disclosures for credential/session handling,
  - retention/deletion controls,
  - incident response expectations for auth/credential compromise events.

## Operational risks and mitigations

1. **Auth storms / challenge loops / lockouts**
   - Mitigations: lockout thresholds, rate limits, auth-failure metrics/alerts, runbook-guided response.

2. **Provider instability / throttling / transient failures**
   - Mitigations: retry/backoff, circuit-breaker transitions (`degraded`, `reauth_required`), kill-switch.

3. **Credential compromise blast radius**
   - Mitigations: Secrets Manager + KMS, revoke/rotate APIs, audited access, rapid disable controls.

4. **Metadata drift between local index and provider state**
   - Mitigations: reconciliation task with incremental cursor and dry-run mode.

## Rejected alternatives

### Alternative A: Desktop connector agent model

**Rejected for MVP timeline/scope.**

- **Pros:** keeps provider interaction closer to Apple-supported local integrations; potentially less backend credential handling.
- **Cons:** introduces client deployment/update fleet, online-device dependency, new support surface, and longer MVP lead time.

### Alternative B: CloudKit app-container-only model

**Rejected for product-fit mismatch.**

- **Pros:** official Apple APIs.
- **Cons:** does not satisfy full file-manager mount semantics targeted for this MVP.

## Rollback and supersession path

If MVP KPIs or risk posture are unacceptable:

1. Immediately reduce rollout mode (`ga -> beta -> internal`) or activate global kill-switch.
2. Keep mount metadata and provider abstraction intact while disabling iCloud onboarding/operations.
3. Open ADR-0001 superseding decision for connector-based fallback and migration path.

### Rollback trigger examples

- sustained breach of agreed read/write success SLOs,
- persistent auth-failure or 5xx incident thresholds,
- critical unresolved security/legal findings,
- support burden outside agreed beta operating limits.

## Sign-off

| Role | Owner | Decision | Date |
|---|---|---|---|
| Engineering Lead | File Manager Engineering Lead | ✅ Approved | 2026-03-25 |
| Security Lead | Application Security Lead | ✅ Approved | 2026-03-25 |
| Product Lead | File Manager Product Lead | ✅ Approved | 2026-03-25 |

## Consequences

### Positive

- MVP can launch with existing backend control plane and observability stack.
- Faster iteration on onboarding, health policy, and mount UX.

### Tradeoffs

- Ongoing legal/security overhead for server-side credential/session handling.
- Potential upstream behavior volatility requires active operational monitoring and rapid rollback discipline.

