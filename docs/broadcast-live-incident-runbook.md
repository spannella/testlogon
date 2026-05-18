# Broadcast Live Incident Response Runbook (BRD-020)

This runbook is the on-call playbook for live broadcast failures.

## 1) Ownership and escalation matrix

| Severity | Trigger | Initial owner | Escalation (0-10m) | Escalation (10m+) |
|---|---|---|---|---|
| Sev-1 | Multi-session outage, no playback globally, key auth failures across regions | Broadcast on-call | Platform on-call + SRE | Security on-call (if DRM/auth), Product incident commander |
| Sev-2 | Single session hard-down or degraded output | Broadcast on-call | Platform on-call | Service owner |
| Sev-3 | Intermittent playback/quality issues | Broadcast on-call | Service owner | Next business-day review |

Paging route defaults:
- non-prod validation route: `nonprod-oncall`
- production route: `broadcast-oncall` then `platform-oncall`

## 2) Universal triage checklist

1. Confirm incident scope:
   - affected `session_id`s
   - provider (`local|aws`)
   - first failure timestamp and current state.
2. Capture evidence:
   - `/broadcast/sessions/{session_id}`
   - `/metrics` snippets for broadcast KPIs
   - reconciler snapshot (`provider_state_snapshot`) and recent transition reasons.
3. Classify incident type:
   - ingest failure
   - no output playback
   - DRM key issue
   - watermark misconfiguration.
4. Apply class-specific mitigation below.
5. Record timeline and commands in incident ticket.
6. If unresolved in 10 minutes, escalate per matrix.

## 3) Incident classes and mitigations

### A) Ingest failure (RTMP input unavailable)

Symptoms:
- session stuck in `provisioning`/`ready`
- input-loss metrics increase (`broadcast_input_loss_total`)
- provider status reports input loss/drift.

Mitigation:
1. Verify ingest endpoint + stream key validity.
2. Restart session (`stop` then `start`) if safe.
3. For AWS: confirm MediaLive input attachment exists and state is recoverable.
4. If still failing, transition to `error`, create replacement session, rotate key reference.

Rollback/containment:
- disable new starts for impacted profile/provider and route traffic to backup profile.

### B) No output playback (origin/CDN path broken)

Symptoms:
- `cloudfront_playback_url` exists but player fails
- output-error metrics rise (`broadcast_output_errors_total`)
- start success but no manifest/segments.

Mitigation:
1. Validate signed playback token (`/broadcast/playback/verify`).
2. Validate MediaPackage endpoint URL and CloudFront mapping.
3. Reissue playback URL/token.
4. If endpoint unhealthy, stop/start session to reprovision output path.

Rollback/containment:
- bypass CDN to origin endpoint for internal emergency playback validation.

### C) DRM key issues

Symptoms:
- playback denied with key/auth errors
- DRM-enabled profiles fail while non-DRM profiles work.

Mitigation:
1. Validate DRM token/key endpoints and credentials reference.
2. Verify key material exists and length/format is valid.
3. Rotate DRM credential reference if compromised/expired.
4. Restart session after key path validation.

Rollback/containment:
- switch profile to non-DRM emergency preset only with product/security approval.

### D) Watermark misconfiguration

Symptoms:
- missing, oversized, or misplaced watermark in HLS renditions.

Mitigation:
1. Validate watermark asset path and ffmpeg filter settings.
2. Revert to known-good watermark asset.
3. Restart worker/session and confirm across renditions.

Rollback/containment:
- temporarily disable watermark overlay for affected profile with approval; restore after fix.

## 4) Recovery verification checklist

- Session state is `live` and stable for >= 10 minutes.
- Playback URL validates and streams successfully.
- DRM path validates (if enabled).
- Watermark visually correct on all active renditions.
- Broadcast metrics return below alert thresholds.

## 5) Post-incident requirements

After mitigation:
1. Open postmortem using `docs/templates/broadcast-postmortem-template.md`.
2. Link all evidence, timeline, and root-cause data.
3. Track prevention actions with owners and due dates.
