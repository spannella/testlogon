# Jira Sync Rollout & Migration Runbook

## Purpose

This runbook defines the **safe rollout sequence** for Jira ↔ internal ticket sync, including:

- preflight checks,
- DynamoDB index migration steps,
- staged feature-flag enablement,
- rollback paths,
- on-call incident response actions.

It is intended for operators, release engineers, and on-call responders.

---

## Scope

Applies to these Jira sync capabilities:

- OAuth connect/callback
- Jira project discovery
- Jira issue mirror (backfill + incremental)
- ticket link creation/unlink
- outbound sync worker
- inbound webhook apply
- conflict detection/resolution

---

## Key Components

- API routes:
  - `app/routers/jira_integrations.py`
  - `app/routers/admin_jira_integration.py`
- Feature-flag and startup validation:
  - `app/services/jira_feature_flags.py`
- Persistence:
  - `app/services/jira_ticket_sync_store.py`
- Migration scripts:
  - `scripts/migrations/20260405_jira_ticket_indexes_migration.py`
  - `scripts/verify_jira_ticket_indexes.py`

---

## Rollout Phases

1. **Preflight / Readiness**
2. **Schema Migration + Verification**
3. **Read-only Mirror Pilot**
4. **Linking + Sync Pilot**
5. **Expanded Rollout**
6. **Steady-state Operations**

---

## 1) Preflight Checks

Run these checks before any feature enablement.

### 1.1 Configuration validation

- Confirm required env/config keys are set:
  - Jira OAuth authorize/token/resources URLs
  - Jira OAuth client id / secret ref
  - required DynamoDB index names
  - webhook signing secret (if webhook signature validation is enabled)
- Confirm startup validation passes (`validate_jira_integration_startup_config`).

### 1.2 Infrastructure readiness

- Confirm DynamoDB table exists and has throughput headroom.
- Confirm SQS queues for outbound/webhook processing are configured.
- Confirm KMS/secrets path for token refs is accessible by runtime roles.

### 1.3 Access controls

- Confirm workspace allowlist for pilot tenants is configured.
- Confirm admin users can access runtime kill-switch endpoint.

### 1.4 Dry-run scripts

- Execute migration script in dry-run mode first.
- Execute index verification script and ensure expected indexes are reported.

---

## 2) Schema Migration Sequence

### 2.1 Run migration (change window)

1. Run:
   - `scripts/migrations/20260405_jira_ticket_indexes_migration.py`
2. Wait for index status `ACTIVE` for all required GSIs.

### 2.2 Post-migration verification

1. Run:
   - `scripts/verify_jira_ticket_indexes.py`
2. Validate:
   - all required Jira indexes present,
   - no missing/incorrect index names,
   - script exits successfully.

### 2.3 Migration rollback

If migration fails mid-flight:

- Stop rollout immediately.
- Keep feature flags disabled.
- Re-run verifier to capture exact missing/mismatched indexes.
- Open incident if partial schema causes production risk.
- Re-run migration in controlled window after root-cause is addressed.

> Note: Index creation is generally additive; prefer **feature rollback** over destructive index changes.

---

## 3) Feature-Flag Rollout Plan

Roll out in this order:

1. `enabled=true`, `read_enabled=true`, keep inbound/outbound off.
2. Mirror backfill + incremental polling for pilot workspace(s).
3. Enable linking endpoints for pilot users.
4. Enable outbound sync.
5. Enable inbound sync/webhook apply.
6. Expand workspace allowlist gradually.

### 3.1 Recommended gating checkpoints

Proceed only when each checkpoint is healthy:

- OAuth connect success rate acceptable
- mirror lag within SLA
- outbound retry/terminal-failure rates acceptable
- webhook dedup/auth rejection rates stable
- conflict rate below expected threshold

---

## 4) Rollback Procedures

Prefer this order for minimizing blast radius:

1. **Activate outbound kill-switch** (`/admin/integrations/jira/flags/outbound-kill-switch`).
2. Disable inbound sync flag.
3. Disable outbound sync flag.
4. Disable read/mirror flag (if severe).
5. Narrow workspace allowlist to known-safe subset.

### 4.1 Data rollback stance

- Do **not** delete link/event history during active incident response.
- Preserve sync events for forensic analysis.
- Use conflict resolution tools to reconcile business state after stabilization.

---

## 5) On-Call / Incident Playbook

### 5.1 Trigger conditions

Open incident if any of these occur:

- webhook signature failures spike unexpectedly
- replay dedup anomalies (sudden duplicates or no dedup)
- outbound terminal failures sustained above threshold
- conflict volume spikes beyond baseline
- queue backlog and processing latency breach SLA

### 5.2 First 15 minutes actions

1. Enable outbound kill-switch.
2. Confirm current flag state and workspace allowlist.
3. Check queue depth and worker health.
4. Sample recent sync events for dominant error codes.
5. Validate webhook secret/signature configuration.

### 5.3 Triage matrix

- **Auth/OAuth failures**:
  - verify OAuth secret refs and token endpoint reachability.
- **Webhook auth failures**:
  - verify signing secret rotation and header normalization.
- **Outbound failures (429/5xx)**:
  - reduce rollout scope, monitor retries/backoff behavior.
- **Conflict spikes**:
  - inspect mapping changes; temporarily disable inbound apply if required.

### 5.4 Recovery criteria

Resume rollout only after:

- error rates return to baseline,
- queue backlogs recover,
- no ongoing data divergence alerts,
- on-call + owning team sign-off.

---

## 6) Pilot Cohort Success Gates (Go/No-Go)

Before promotion from pilot cohort to broader rollout, all pilot workspaces must satisfy:

- **Sync latency target**:
  - P95 `jira_sync_latency_seconds{direction="outbound"}` < 600s over trailing 7 days.
  - P95 `jira_sync_latency_seconds{direction="inbound"}` < 600s over trailing 7 days.
- **Terminal failure target**:
  - terminal failure rate < 1.0% over trailing 7 days:
    - `sum(jira_sync_events_total{result="failed", error_code=~"jira_terminal_error|conflict_detected"}) / sum(jira_sync_events_total)`
- **SLO conformance**:
  - no P1 incidents attributable to Jira sync in the trailing 7 days,
  - webhook acceptance remains aligned with 99.9% objective.

If any target is missed:

1. pause cohort expansion,
2. keep rollout scope fixed (or reduce allowlist),
3. track corrective actions with owner/date in GA review notes.

---

## 7) GA Readiness Review & Sign-off

GA decision must be captured in `docs/jira-ga-readiness-review.md` and include:

- pilot metric evidence for latency and failure targets,
- incident summary for pilot window,
- explicit sign-off from:
  - engineering owner,
  - security owner,
  - support owner.

No GA promotion should proceed without all three approvals recorded.

---

## 8) Operational Checks (Steady State)

Daily/shift checks:

- mirror freshness by workspace/project
- outbound success/retry/terminal rates
- inbound apply success/conflict rates
- webhook dedup and auth rejection rates
- unresolved conflict backlog

Weekly checks:

- audit workspace allowlist changes
- review kill-switch usage history
- validate token refresh health and secret rotation hygiene

---

## 9) Change Management Template

For each rollout change, record:

- change owner
- target workspace(s)
- flags changed + timestamps
- verification output links
- metrics snapshots before/after
- rollback decision + rationale (if any)

---

## 10) Appendix: Suggested Command Sequence

1. Verify indexes:
   - `python scripts/verify_jira_ticket_indexes.py`
2. Run migration (if needed):
   - `python scripts/migrations/20260405_jira_ticket_indexes_migration.py --apply`
3. Verify again:
   - `python scripts/verify_jira_ticket_indexes.py`
4. Enable read-only pilot flags.
5. Validate mirror health.
6. Enable outbound, then inbound, for pilot allowlist.
7. Monitor and expand gradually.
