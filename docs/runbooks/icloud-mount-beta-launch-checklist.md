# iCloud Mount Beta Launch Checklist (ICLOUD-063)

This checklist is the go/no-go gate for iCloud mount rollout from internal dogfood to external beta.

## Scope and launch phases

- **Phase 0: Internal dogfood** (employees only, selected tenant cohort)
- **Phase 1: External limited beta** (allowlisted customers/tenants)
- **Phase 2: Beta expansion** (broader beta with controlled ramp)

Each phase requires explicit sign-off in the matrix below.

---

## Dependency gates (must be complete before Phase 1 external beta)

- [ ] **ICLOUD-050** complete (provider health metrics + dashboards + alert thresholds).
- [ ] **ICLOUD-061** complete (failure-injection integration tests for MFA/auth expiry/throttling/partial-write failure and recovery behaviors).
- [ ] **ICLOUD-062** complete (feature flags + staged rollout controls by environment/tenant + kill-switch validation).

---

## 1) SLO and reliability gates

### Required SLO definitions

- **Read success rate SLO:** `>= 99.5%` for mounted-provider reads over 24h.
- **Write success rate SLO:** `>= 99.0%` for mounted-provider writes over 24h.
- **p95 provider latency SLO:**
  - reads `<= 1500ms`
  - writes `<= 2500ms`
- **Auth verification completion SLO:** `>= 98%` successful verify outcomes for non-expired credentials.

### Pre-launch checks

- [ ] SLO definitions approved by Product + SRE.
- [ ] Dashboard panels exist for p50/p95 latency and error-rate by `provider,mount_id`.
- [ ] Last 7-day baseline reviewed for internal cohort.
- [ ] No open P0/P1 incidents in iCloud mount service path.

---

## 2) Alerting and on-call readiness gates

### Required alerts (must be enabled before beta)

- [ ] Sustained auth failure alert: `provider_auth_expired/auth_failed` above threshold for 15m.
- [ ] 5xx provider error-rate alert above threshold for 10m.
- [ ] Reconcile drift growth alert (drift backlog not converging).
- [ ] Circuit-breaker transition surge alert (mounts entering degraded/reauth_required unexpectedly).

### On-call checks

- [ ] On-call rotation has iCloud mount escalation contact list.
- [ ] Runbooks linked in alert annotations.
- [ ] Last incident drill completed within 30 days.
- [ ] Incident channels and paging policies verified in production.

References:

- `docs/runbooks/icloud-mount-incident-response-playbook.md`
- `docs/runbooks/icloud-mount-oncall-quick-reference.md`

---

## 3) Support readiness gates

- [ ] Support macro/templates created for onboarding failures, auth-expiry reconnect, and revoke/rotate guidance.
- [ ] Tier-1 and Tier-2 support walkthrough completed and recorded.
- [ ] Internal FAQ published for known failure modes and expected user actions.
- [ ] Ownership map for backend/frontend/ops escalation is documented.

### Required customer-facing recovery playbook coverage

- [ ] MFA challenge loops
- [ ] expired auth / reconnect required
- [ ] throttling and temporary provider outages
- [ ] degraded read-only mode and expected UX

---

## 4) Legal and policy gates

- [ ] Legal-approved customer copy for iCloud beta availability and limitations.
- [ ] Updated credential retention + revocation policy linked in beta materials.
- [ ] Data handling disclosures validated for all target regions.
- [ ] Security sign-off confirms no unresolved critical residual risks.

References:

- `docs/icloud-mount-credential-retention-revocation-policy.md`
- `docs/icloud-mount-threat-model.md`

---

## 5) Rollback and kill-switch gates

- [ ] Global kill-switch (`FILEMGR_ICLOUD_MOUNT_KILL_SWITCH`) verified in staging within last 7 days.
- [ ] Rollout mode rollback validated (`ga -> beta -> internal -> disabled`) without deploy.
- [ ] Rollback runbook includes blast-radius comms, customer guidance, and re-enable criteria.
- [ ] Data integrity checks defined for rollback windows (mounted writes, reconcile status, secret state).

### Rollback decision triggers

Rollback must be initiated if any are true for >15 minutes:

- auth-failure alert in critical state,
- provider 5xx rate exceeds critical threshold,
- p95 latency exceeds 2x SLO with customer impact,
- mount status transitions to `degraded/reauth_required` spike beyond approved limit.

### Rollback execution owner map

| Function | Primary | Backup | SLA |
|---|---|---|---|
| Kill-switch flip | SRE On-call | Backend On-call | 5 min |
| Cohort rollback (ga→beta/internal) | Backend On-call | Feature owner | 10 min |
| Customer comms for rollback | Support lead | PM | 15 min |
| Legal/compliance notification (if needed) | Legal partner | Security | 30 min |

---

## 6) Launch-day execution checklist

- [ ] Freeze non-essential changes touching filemanager mount paths.
- [ ] Confirm current rollout mode and target cohort list.
- [ ] Announce launch window in eng/support channels.
- [ ] Start live metrics watch (ops + feature team pair).
- [ ] Execute synthetic onboarding + browse + upload + revoke checks.
- [ ] Record decision and timestamp for phase promotion.

### Go/No-Go decision log (required per phase)

| Phase | Decision | Timestamp (UTC) | Incident risk | Rollback readiness | Decision owner | Notes |
|---|---|---|---|---|---|---|
| Phase 0 (Internal dogfood) | GO / NO-GO |  | Low / Med / High | Ready / Not ready |  |  |
| Phase 1 (External beta) | GO / NO-GO |  | Low / Med / High | Ready / Not ready |  |  |
| Phase 2 (Expansion) | GO / NO-GO |  | Low / Med / High | Ready / Not ready |  |  |

---

## 7) Stakeholder sign-off matrix

| Area | Owner | Phase 0 (Internal) | Phase 1 (External beta) | Phase 2 (Expansion) | Notes |
|---|---|---|---|---|---|
| Product | PM | ☐ | ☐ | ☐ | |
| Engineering | Tech Lead | ☐ | ☐ | ☐ | |
| SRE/Operations | On-call Lead | ☐ | ☐ | ☐ | |
| Security | Security Reviewer | ☐ | ☐ | ☐ | |
| Legal/Compliance | Legal Partner | ☐ | ☐ | ☐ | |
| Support | Support Manager | ☐ | ☐ | ☐ | |

### Required sign-off evidence

- [ ] Product sign-off notes linked.
- [ ] SRE sign-off includes alert screenshots / dashboard links.
- [ ] Security sign-off includes latest threat model review date.
- [ ] Legal sign-off includes approved customer copy revision ID.
- [ ] Support sign-off includes training recording or attendance log.

## 8) Post-launch review requirements

- [ ] 24h review completed with metrics snapshot and incident summary.
- [ ] 7-day review completed with SLO attainment and support ticket trends.
- [ ] Lessons learned captured and ticket backlog updated.
- [ ] Go/no-go recommendation for next phase documented with sign-offs.

---

## Suggested sprint sequencing (program reference)

- **Sprint 1:** ICLOUD-001, 002, 003, 010 (start), 011
- **Sprint 2:** ICLOUD-010 (finish), 012, 013, 020, 021, 060 (start)
- **Sprint 3:** ICLOUD-022, 030, 031, 040, 062
- **Sprint 4:** ICLOUD-032, 041, 042, 050, 051, 061
- **Sprint 5+:** ICLOUD-023, 052, 053, 033, 063

## MVP cutline (read-only beta)

### Must-have

- ICLOUD-001, 002, 003, 010, 011, 012, 020, 021, 022, 030, 031, 040, 050, 060, 062

### Deferred to post-beta

- Write-path tickets (ICLOUD-032+), cache, reconciliation.
