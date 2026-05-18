# Jira Sync GA Readiness Review (JTS-040)

## Purpose

Provide a single, auditable record for staged rollout outcomes and GA go/no-go decision.

This document must be completed at the end of pilot and approved before general availability.

---

## Rollout Cohorts

1. **Cohort A (internal dogfood)**  
   Internal workspaces only, read-only mirror and linking enabled.
2. **Cohort B (pilot customers)**  
   Limited allowlist of external workspaces, outbound + inbound sync enabled.
3. **Cohort C (expanded rollout)**  
   Broad allowlist expansion after pilot success criteria are met.
4. **GA**  
   Default-available for eligible workspaces, with standard onboarding controls.

---

## Pilot Window

- Start date (UTC): `________________`
- End date (UTC): `________________`
- Workspaces in cohort: `________________`
- Total synced events evaluated: `________________`

---

## Success Metrics (Required for GA)

### 1) Sync latency targets

- Outbound P95 sync latency < **600s** over trailing 7 days.
- Inbound P95 sync latency < **600s** over trailing 7 days.

Evidence links / dashboard snapshots:

- `________________`
- `________________`

### 2) Failure-rate target

- Terminal sync failure rate < **1.0%** over trailing 7 days.

Evidence query:

`sum(jira_sync_events_total{result="failed", error_code=~"jira_terminal_error|conflict_detected"}) / sum(jira_sync_events_total)`

Evidence links / snapshots:

- `________________`

### 3) Incident quality gate

- No unresolved P1 incidents attributable to Jira sync in pilot window.

Incident references:

- `________________`

---

## Pilot Outcome Summary

- **Latency target status**: ✅ Pass / ❌ Fail
- **Failure-rate target status**: ✅ Pass / ❌ Fail
- **Incident gate status**: ✅ Pass / ❌ Fail
- **Overall pilot decision**: ✅ Promote / ❌ Hold

If hold/fail, required remediation actions and owners:

1. `________________`
2. `________________`

---

## GA Checklist (Owner Sign-off Required)

- [ ] Rollout runbook current and validated (`docs/jira-sync-rollout-runbook.md`)
- [ ] Alerting and dashboards validated (`docs/jira-observability-dashboards-and-alerts.md`)
- [ ] Support escalation workflow and KB article published
- [ ] Security review completed for OAuth/webhook/token handling
- [ ] On-call handoff complete with incident drills

### Sign-off

| Function | Owner | Decision | Date (UTC) | Notes |
|---|---|---|---|---|
| Engineering | `________________` | Approve / Block | `________________` | `________________` |
| Security | `________________` | Approve / Block | `________________` | `________________` |
| Support | `________________` | Approve / Block | `________________` | `________________` |

**GA Decision (final):** Approve / Block  
**Decision date (UTC):** `________________`  
**Release manager:** `________________`

