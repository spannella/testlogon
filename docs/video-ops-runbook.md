# Video operations runbook (VWD-022)

This runbook is the primary on-call guide for live video channel incidents.

## Scope

Covers critical actions for:
- channel restart
- input failover
- DRM key/license fallback

---

## 1) Channel restart runbook

### Trigger conditions
- Channel state stuck in `RECOVERING` / `IDLE` while event is active.
- Repeated output errors and no healthy output manifests.

### Preconditions
- Incident ticket opened and severity assigned.
- Confirm active tenant/event impact scope.
- Verify no scheduled maintenance in progress.

### Steps
1. Capture current channel health evidence (state, alarms, error rates).
2. Pause non-essential configuration changes.
3. Execute controlled restart:
   - stop channel
   - verify stop completed
   - start channel
4. Validate recovery:
   - output manifests update
   - playback start success recovers
   - output errors return to baseline
5. Post an incident update with recovery timestamp and affected tenants.

### Recovery target
- End-to-end playback recovery within **15 minutes**.

### Escalation
- If restart fails twice, escalate to platform engineering immediately.

---

## 2) Input failover runbook

### Trigger conditions
- Input loss alarm active.
- Primary ingest unreachable or unstable.

### Steps
1. Confirm primary input failure through channel metrics/logs.
2. Switch to configured backup input.
3. Verify continuity:
   - segment production resumes
   - player rebuffer remains within threshold
4. Keep primary path quarantined until RCA starts.

### Recovery target
- Failover completion within **15 seconds** from detected loss.

### Validation checklist
- `InputLoss` alarm clears.
- HLS/DASH manifests continue advancing.
- No sustained playback entitlement reject spike.

---

## 3) DRM key/license fallback runbook

### Trigger conditions
- DRM key error alarm active.
- License provider 5xx rate above threshold.

### Steps
1. Confirm provider health degradation and blast radius.
2. Enable fallback mode:
   - route to configured fallback key path/provider
   - keep entitlement validation enabled
3. Validate:
   - license issuance success rate recovers
   - playback starts recover for at least one profile per DRM family
4. Monitor for stale-key serving duration limit.

### Recovery target
- License path recovery within **20 seconds**.

### Guardrails
- Do not disable entitlement signature/audience checks.
- Do not exceed stale key fallback window policy.

---

## Communications template

- **What happened:**
- **Impact:** tenants/events/devices affected
- **Action taken:** restart/failover/fallback steps
- **Current status:** recovering/monitoring/resolved
- **Next update ETA:**

## Post-incident follow-up

- Capture timeline + MTTD/MTTR.
- Attach dashboard snapshots and alarm history.
- File follow-up tasks for threshold tuning and automation gaps.
