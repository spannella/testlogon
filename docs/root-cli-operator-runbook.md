# Root CLI Operator Runbook

## Purpose
Use this runbook during break-glass events requiring server-side privileged actions through `rootctl`.

This document is written to be executable end-to-end by on-call operators and incident commanders without additional tribal knowledge.

---

## 1) When to use CLI vs API/UI

### Prefer API/UI when:
- The user can still authenticate normally.
- Standard admin workflows are functioning and not degraded.
- There is no urgency requiring direct break-glass intervention.
- The operation does **not** require immutable-root recovery controls.

### Use `rootctl` when:
- Root recovery is required (root password/MFA/verification/security metadata).
- API/UI control plane is degraded or unavailable.
- You need tightly controlled incident actions with explicit `reason`, `ticket`, `request_id`, and `correlation_id`.
- You need deterministic, scriptable JSON output for incident evidence capture.

### Hard rule
`rootctl` is a break-glass control, **not** a convenience path. If API/UI is healthy and sufficient, use API/UI.

---

## 2) Required approvals and escalation points

Before running mutating commands:
1. **Incident declaration** created (SEV/INC ticket ID).
2. **Two-party authorization**:
   - Incident Commander (IC) approval.
   - Security On-Call approval.
3. **Escalation gate for root recovery** (`root ...` commands):
   - Platform Owner (or delegate) explicit acknowledgement in ticket timeline.
4. Record approvals in the ticket before execution.

If any approval cannot be obtained, escalate to:
- Security Manager on-call,
- then Engineering Director on-call.

---

## 3) Pre-flight checklist (mandatory)

- Confirm execution host is approved for privileged operations.
- Export/record identifiers:
  - `REQUEST_ID` (incident step id, e.g. `INC-123-step-04`)
  - `CORRELATION_ID` (single id for multi-target/bulk flow)
- Confirm actor identity is configured root subject.
- Use `--output json` for all operational runs.
- Use `--dry-run` first for all mutating flows.
- Prepare evidence log file and terminal transcript capture.

Suggested helper:
```bash
export REQUEST_ID="INC-123-step-04"
export CORRELATION_ID="INC-123-bulk-01"
```

---

## 4) Standard execution pattern

For every mutating command family:
1. Run dry-run variant.
2. Review JSON output and guardrail checks.
3. Execute live command with same arguments (minus `--dry-run`).
4. Capture command, stdout JSON, and exit code in incident notes.
5. Query audit timelines using same `correlation_id`.

Template:
```bash
scripts/rootctl <group> <command> \
  --actor-sub root \
  --reason "<incident reason>" \
  --ticket "<INC/CHG>" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --output json
```

---

## 5) Root recovery procedures

### A) Root password reset

Dry run:
```bash
scripts/rootctl root reset-password \
  --actor-sub root \
  --reason "root credential containment" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --new-password '<secure temp password>' \
  --dry-run --output json
```

Execute:
```bash
scripts/rootctl root reset-password \
  --actor-sub root \
  --reason "root credential containment" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --new-password '<secure temp password>' \
  --output json
```

Expected outcomes:
- password updated,
- root sessions revoked,
- root API keys revoked,
- audit event emitted with request/correlation ids.

### B) Root MFA reset
```bash
scripts/rootctl root reset-mfa \
  --factor all \
  --actor-sub root \
  --reason "lost root factor during incident" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --output json
```

### C) Root verification/security metadata updates
- `root set-verification`
- `root set-email`
- `root set-security-profile`

Run with identical safety metadata (`reason/ticket/request/correlation`) and archive JSON response.

---

## 6) User lifecycle procedures

### A) Deactivate compromised user (destructive guardrail)
```bash
scripts/rootctl user deactivate \
  --target-user-sub '<user_sub>' \
  --confirm '<user_sub>' \
  --actor-sub root \
  --reason "account containment" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --output json
```

### B) Bulk deactivation (multi-target)
```bash
scripts/rootctl user deactivate-bulk \
  --target-user-sub 'u1@example.com' \
  --target-user-sub 'u2@example.com' \
  --actor-sub root \
  --reason "bulk containment" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --output json
```

Verify bulk summary:
- `summary.total_targets`
- `summary.success_count`
- `summary.failure_count`
- per-target `results[]`

### C) Delete user (soft/hard)
Requires explicit `--confirm <target_user_sub>`.
Use hard delete only with legal/security approval recorded in ticket.

---

## 7) Admin lifecycle procedures

### A) Grant admin
```bash
scripts/rootctl admin grant \
  --target-user-sub '<user_sub>' \
  --actor-sub root \
  --reason "incident staffing" \
  --ticket "INC-123" \
  --request-id "$REQUEST_ID" \
  --correlation-id "$CORRELATION_ID" \
  --output json
```

### B) Revoke admin
Same as grant with `admin revoke`.

### C) Admin create
Use for controlled break-glass onboarding when no suitable admin exists.
Always include ticket and capture generated credentials handling evidence.

---

## 8) Evidence capture checklist (required)

For each command executed, capture:
- Full command (redact secrets/password args).
- Exit code.
- JSON stdout/stderr payload.
- `request_id`.
- `correlation_id`.
- `audit_event` and any `event_id` values.

Post-execution security evidence:
- `rootctl audit role --correlation-id <id> --output json` (if role-related).
- `rootctl audit security --correlation-id <id> --output json`.
- SIEM search URL/query proving ingest for same `correlation_id`.
- Any webhook delivery failure events (`alerts_delivery_failure`) and remediation notes.

---

## 9) Post-incident closeout

- Revoke temporary escalations granted during incident.
- Confirm no stale privileged sessions remain.
- Attach evidence bundle to incident ticket.
- File follow-up tasks for any delivery failures or manual workarounds.
- Security owner sign-off required before incident closure.

---

## 10) Failure handling

If command fails:
1. Keep original `request_id` and `correlation_id` for retries in same step.
2. Do **not** switch to ad-hoc DB edits.
3. Query audit/security timeline for partial effects.
4. Escalate to platform owner + security on-call before retrying destructive actions.

If SIEM/webhook delivery fails:
- Treat as security observability incident.
- Record `alerts_delivery_failure` evidence and open follow-up action.
- Continue containment actions only with IC+Security acknowledgement.
