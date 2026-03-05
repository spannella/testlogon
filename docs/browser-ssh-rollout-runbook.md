# Browser SSH Terminal Rollout Plan and On-Call Runbook (SSH-018)

## Purpose
This runbook defines the staged rollout for Browser SSH terminal and the incident response procedures for common operational failures.

## Owners and escalation
- **Primary owner:** Platform/API team (Browser SSH feature owner)
- **Secondary owner:** SRE/on-call
- **Security consult:** Security owner for policy/access/redaction concerns
- **Escalation order:** Feature owner on-call -> SRE on-call -> Security on-call

---

## 1) Staged rollout plan

### Phase A: Internal (staff-only)
**Goal:** Validate core session behavior and operational telemetry with trusted users.

**Entry criteria**
- `BROWSER_SSH_TERMINAL_ENABLED=1` only in internal environment.
- Role gating enabled via `BROWSER_SSH_TERMINAL_ALLOWED_ROLES` (internal admin/root roles only).
- Destination policy configured to known-safe internal hosts/ports.

**Success criteria (24h minimum)**
- No sustained increase in connect failures.
- No unresolved websocket outage incidents.
- No leaked sensitive fields in logs/audit review sample.

### Phase B: Beta (limited tenant cohort)
**Goal:** Validate product usability and failure handling under wider but controlled traffic.

**Entry criteria**
- Phase A success criteria met.
- On-call team briefed with this runbook.
- Alert channels verified.

**Rollout**
- Expand allowlist to beta targets.
- Keep conservative per-user limits/timeouts/rate limits.

**Success criteria (72h minimum)**
- Error rates within expected baseline.
- No high/critical security findings.
- Recovery playbooks executed successfully in a game-day drill.

### Phase C: General availability (GA)
**Goal:** Production-wide availability with stable operations.

**Entry criteria**
- Phase B criteria met and signed off by feature owner + SRE.
- Security owner confirms no unresolved High/Critical issues or records explicit risk acceptance.

**Rollout**
- Expand feature flag enablement progressively to full scope.
- Maintain policy controls and monitor denials/throttles.

---

## 2) Rollback plan (verified in staging)

### Immediate rollback (no deploy)
1. Disable feature flag:
   - set `BROWSER_SSH_TERMINAL_ENABLED=0`
2. Restart service process to apply environment update (per environment standard).
3. Confirm rollback:
   - `GET /api/browser-ssh/config` returns `enabled=false`.
   - `GET /browser-ssh` returns `404` (feature route guarded).

### Partial rollback options
- Tighten destination access quickly:
  - restrict `BROWSER_SSH_ALLOWED_HOSTS` / `BROWSER_SSH_ALLOWED_PORTS`
  - extend denylist via `BROWSER_SSH_DENIED_HOSTS` / `BROWSER_SSH_DENIED_PORTS`
- Reduce blast radius:
  - lower `BROWSER_SSH_MAX_SESSIONS_PER_USER`
  - lower `BROWSER_SSH_CONNECT_RATE_LIMIT_COUNT`

### Staging rollback verification checklist
- [ ] Enable feature and confirm `/browser-ssh` route available.
- [ ] Disable feature flag and restart service.
- [ ] Validate `/api/browser-ssh/config` and `/browser-ssh` guard behavior.
- [ ] Validate websocket connect attempts fail post-rollback.
- [ ] Record evidence in release ticket.

---

## 3) Incident triage playbook

### A. SSH connect failures (auth/connect/policy)
**Symptoms**
- Users report cannot connect.
- Increased `error` payloads (`auth_failed`, `connect_failed`, `policy_denied_*`).

**Triage steps**
1. Confirm feature/config state:
   - `GET /api/browser-ssh/config`
2. Check policy errors:
   - Review denylist/allowlist env settings for host/port mismatch.
3. Check authz errors:
   - Validate role list (`BROWSER_SSH_TERMINAL_ALLOWED_ROLES`) and user role mapping.
4. Check destination reachability from gateway host (network/DNS/port).
5. Check audit stream for repeated `browser_ssh_connect_access_denied` and session start failures.

**Mitigations**
- Correct misconfigured host/port policy.
- Temporarily narrow rollout cohort while investigating.
- If broad impact persists, execute immediate rollback.

### B. WebSocket outage / instability
**Symptoms**
- Frequent disconnects, handshake failures, or terminal freeze.
- Elevated timeout/rate-limit/session-limit errors.

**Triage steps**
1. Confirm service health:
   - `GET /api/browser-ssh/health`
2. Validate app instance health/resources (CPU, memory, restart loops).
3. Review gateway logs by `session_id` for failure patterns.
4. Inspect active-session and denial/throttle metrics for anomaly spikes.

**Mitigations**
- Scale out/restart unhealthy instances.
- Temporarily reduce cohort (rollback to internal/beta subset).
- If unresolved, set `BROWSER_SSH_TERMINAL_ENABLED=0` and communicate incident status.

---

## 4) Operational checks and dashboards

### Key signals
- `browser_ssh_active_sessions`
- `browser_ssh_connect_denied_total{reason}`
- `browser_ssh_connect_throttled_total{reason}`
- `browser_ssh_session_lifecycle_total{event,outcome}`
- `browser_ssh_session_duration_seconds{outcome}`

### Suggested alerts
- Connect denial rate above baseline for 10m.
- Throttled rate spikes indicating abuse or configuration mismatch.
- Session duration collapse or websocket disconnect surge.

---

## 5) Communication templates

### Internal incident update
- **Impact:** (who/what affected)
- **Start time:**
- **Detected via:** (alert/dashboard/user report)
- **Current mitigation:**
- **Next update ETA:**

### Rollback announcement
- Browser SSH temporarily disabled via feature flag due to active incident.
- No credential persistence change; session establishment paused while remediation is in progress.

---

## 6) Post-incident actions
- Capture root cause and timeline.
- Add regression test(s) for missed scenario.
- Update this runbook and rollout gates based on incident learnings.
- Confirm security review for any redaction/audit gaps.
