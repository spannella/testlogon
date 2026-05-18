# iCloud Mount Incident Response Playbook (ICLOUD-053)

## Scope

This playbook defines on-call handling for iCloud mount incidents in file manager, specifically:

1. **Authentication storms** (`auth_failed`, repeated verify failures, lockouts).
2. **Provider outages** (elevated 5xx/throttling latency/error rates).
3. **Credential compromise** (suspected leaked app password/session token/secrets access abuse).

Related operational surfaces:
- `filemgr_provider_operation_total`
- `filemgr_provider_operation_latency_seconds`
- `filemgr_provider_auth_failures_total`
- `filemgr_mount_secret_access_total`
- Mount status states: `active`, `degraded`, `unavailable`, `reauth_required`, `revoked`.

---

## Paging Criteria

### Page immediately (P1)

Trigger page when **any** condition holds for 15 minutes:

- Provider 5xx ratio > 2% for iCloud traffic.
- Auth failure rate > 0.05 events/sec for any `(provider, mount_id)` with multi-tenant impact.
- Verify endpoint lockouts spike > 3x baseline and affect > 20 tenants.
- Suspected credential compromise (unauthorized secret read, forced rotations/revokes, or confirmed leak).

### Pager threshold matrix (authoritative)

| Signal | Threshold | Window | Severity | Expected first ack |
|---|---:|---:|---|---|
| Provider 5xx rate | `> 2%` by `(provider,mount_id)` | 15m | P1 | 5 minutes |
| Auth failure rate | `> 0.05 events/sec` by `(provider,mount_id)` | 15m | P1 | 5 minutes |
| Mount unavailable surge | `>= 10 mounts` entering `unavailable` | 10m | P1 | 5 minutes |
| Verify lockout spike | `> 3x` baseline and `> 20` tenants | 15m | P1 | 5 minutes |
| Secret compromise indicator | Any confirmed anomalous secret access | immediate | Security P1 | immediate |

If ack is missed, escalate according to the matrix below without waiting for the full `Escalate After` timer.

### Ticket + async triage (P2)

- Single-tenant mount degradation without customer-visible SLA breach.
- Temporary provider throttling that self-recovers < 10 minutes.
- Reconcile drift job issues in dry-run mode with no writes applied.

---

## Escalation Matrix

| Severity | Primary On-Call | Secondary | Escalate After | Final Escalation |
|---|---|---|---|---|
| P1 | Backend Platform On-Call | SRE On-Call | 15 min no mitigation | Incident Commander + Security On-Call |
| P2 | Backend Platform On-Call | Product Engineer (Filemanager) | 4 business hours | Engineering Manager |
| Security (any sev) | Security On-Call | Backend Platform On-Call | Immediate | CISO delegate |

### Escalation rules

- If customer data exposure is possible, engage **Security On-Call immediately**.
- If cloud provider health issue persists > 30 minutes, engage **SRE** and update status page.
- If revoke/rotation automation fails, escalate to **Incident Commander**.
- If mount state transitions continue to worsen (`degraded -> unavailable`) after first mitigation, escalate to **Incident Commander** and **Product Owner** for customer-impact decisions.

---

## Incident Triage Checklist

1. Validate alert and affected dimension(s): `provider`, `mount_id`, `error_class`, `reason`.
2. Determine blast radius:
   - tenants impacted,
   - read vs write impact,
   - auth vs outage pattern.
3. Confirm current mount states (`active/degraded/reauth_required/revoked`) and transition velocity.
4. Check Secrets Manager access anomalies and recent rotations/revokes.
5. Start incident channel and assign roles (IC, Comms, Ops, Security liaison if needed).

---

## Scenario A: Auth Storm Runbook

### Detection indicators

- `filemgr_provider_auth_failures_total` sharply rising.
- `/v1/fs/mounts/icloud/verify` outcomes dominated by `auth_failed`.
- Large number of mounts transitioning to `reauth_required`.

### Immediate actions

1. Rate-limit and lockout controls: verify they are active and effective.
2. Freeze high-risk onboarding retries if abuse suspected.
3. For affected mounts, force state override to `reauth_required` when necessary to prevent churn.
4. Initiate targeted or global credential rotation campaign as needed.

### Recovery

- Ask users to reconnect credentials via onboarding verify flow.
- Clear manual overrides after auth success normalizes.
- Confirm auth failure ratio falls below threshold for 30 minutes before closing.

---

## Scenario B: Provider Outage Runbook

### Detection indicators

- Elevated provider `server_error`/`throttled` error class.
- p95 latency regression on provider operations.
- Mounts auto-transitioning to `degraded`.

### Immediate actions

1. Validate external provider incident status.
2. Keep degraded mounts in read-only mode to protect data consistency.
3. Pause non-critical write-heavy workflows.
4. Increase reconciliation dry-run checks only (avoid churning writes during outage).

### Recovery

- Monitor p50/p95 latency and failure ratios.
- Allow auto-recovery to `active` after successful operations hit threshold.
- Remove temporary traffic-shaping controls and validate write path.

---

## Scenario C: Credential Compromise Runbook

### Detection indicators

- Unexpected Secrets Manager reads/rotations/revokes.
- Security signal of leaked token/password.
- Unusual mount activity across multiple tenants or geographies.

### Immediate containment

1. Revoke affected mount credentials immediately (`/revoke`).
2. Force mount status to `revoked` where compromise is suspected.
3. Rotate KMS-backed secrets and invalidate active onboarding sessions.
4. Preserve forensic timeline (audit events, secret access logs, operator actions).

### Eradication and recovery

- Perform controlled re-onboarding with fresh credentials.
- Require MFA/challenge completion before returning mounts to `active`.
- Confirm no anomalous secret access for 24h post-recovery.

---

## Customer Communications Templates

Canonical message templates now live in:

- `docs/runbooks/icloud-mount-customer-comms-templates.md`

### Initial customer advisory (degradation/outage, short form)

> We are currently investigating elevated errors affecting iCloud mount operations in Files. You may see slower responses or temporary read-only behavior for mounted iCloud paths. Local (non-mounted) file paths continue operating normally. We will provide updates every 30 minutes until resolved.

### Security advisory (credential compromise suspected, short form)

> We detected suspicious activity involving iCloud mount credentials and have proactively revoked affected mount sessions. As a precaution, please reconnect your iCloud mount from Files > Connect iCloud and complete verification. We are continuing investigation and will share a full post-incident summary.

### Recovery confirmation

> Mitigation is complete and iCloud mount operations have returned to normal service levels. We are monitoring closely and will publish an incident report with timeline, impact, and preventive actions.

---

## Post-Incident Requirements

1. Publish incident timeline and root-cause analysis within 3 business days.
2. Document metric/alert tuning updates.
3. Create follow-up tickets for control gaps (rate-limit, circuit breaker, reconciliation, secrets access).
4. Update this playbook and dashboard runbook links if procedures changed.
5. Attach customer-comms transcript and timeline checkpoints (initial advisory, update cadence, resolution notice).
