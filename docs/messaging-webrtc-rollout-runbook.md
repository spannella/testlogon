# Messaging WebRTC Direct Calls — Rollout & Kill-Switch Runbook (WRTC-003)

## Document control
- **Status:** Ready for implementation rollout
- **Version:** v1
- **Last updated:** 2026-03-24
- **Owners:** Messaging On-call, Product, SRE
- **Related:**
  - `docs/messaging-webrtc-direct-chat-spec.md`
  - `docs/messaging-webrtc-direct-chat-implementation-plan.md`
  - `docs/messaging-webrtc-direct-chat-tickets.md`

---

## 1) Purpose
Define safe rollout controls for `messaging_webrtc_direct_call_v1`, including:
- cohort gating,
- emergency kill-switch behavior,
- validation checks,
- rollback procedure,
- and communication templates.

---

## 2) Feature flags and configuration

## 2.1 Primary gate
- **Flag key:** `messaging_webrtc_direct_call_v1`
- **Default state:** `false`
- **Evaluation location:** backend authorization + frontend UI render
- **Blast radius control:** tenant, user cohort, and environment selectors

## 2.2 Secondary safety gates
- `messaging_webrtc_direct_call_invite_enabled` (start-call action)
- `messaging_webrtc_direct_call_accept_enabled` (accept path)
- `messaging_webrtc_direct_call_video_enabled` (video mode only)

> If secondary flags are absent in code at first launch, treat them as rollout requirements before GA.

---

## 3) Rollout stages

| Stage | Cohort | Target exposure | Entry criteria | Exit criteria |
|---|---|---:|---|---|
| 0 | Internal engineering | 1-2% of internal users | Baseline smoke checks green | 24h stable, no sev incidents |
| 1 | Internal + support | 5% | Stage 0 metrics stable | 48h stable, low failure rate |
| 2 | Beta tenants | 10-20% | Stage 1 sign-off | SLOs met for 72h |
| 3 | Broader production | 50% | Stage 2 sign-off | SLOs met for 7 days |
| 4 | General availability | 100% | Stage 3 sign-off + product approval | steady-state ops |

---

## 4) Pre-rollout checklist
- [ ] Product spec and signaling contract are approved.
- [ ] TURN credentials issuance path verified in target environment.
- [ ] Dashboards and alerts are live for setup success and failure reasons.
- [ ] Support playbook updated with user-facing troubleshooting.
- [ ] Kill switch tested in staging (new calls blocked, active calls not force-dropped).
- [ ] On-call owner assigned for rollout window.

---

## 5) SLO/SLI rollout gates

## 5.1 Minimum gates to advance stage
- Call setup success rate >= 97% (invite accepted -> media connected).
- p50 connect latency <= 3.0s.
- p95 connect latency <= 8.0s.
- Error spike threshold: no sustained >2x baseline for 30 minutes.

## 5.2 Hard stop triggers
- Sev1/Sev2 incident attributed to signaling/call routing.
- Setup success < 92% for 15 min.
- Authentication/authorization regression.
- Elevated crash rate in call UI path.

---

## 6) Kill-switch behavior

## 6.1 Emergency disable objective
- Stop **new** call initiation immediately.
- Preserve currently connected calls until normal end.
- Keep existing message timelines intact.

## 6.2 Actions
1. Set `messaging_webrtc_direct_call_v1=false` globally.
2. If supported, set `messaging_webrtc_direct_call_invite_enabled=false`.
3. Verify “Start audio/video call” actions disappear or are disabled.
4. Verify backend rejects new invite events with deterministic error (`feature_disabled`).
5. Post incident update in #messaging-oncall channel.

## 6.3 Post-disable validation
- New invite attempts fail deterministically.
- Accept/decline endpoints for new sessions are blocked.
- Active established calls continue until user ends.
- Error volume stabilizes within 15 minutes.

---

## 7) Rollback procedure by stage

### Stage 0/1 rollback
- Disable primary flag for internal cohorts.
- Keep beta/prod disabled.
- Collect logs and failure samples.

### Stage 2 rollback
- Disable beta tenant cohort.
- Preserve internal cohort if unaffected for investigation.
- Publish support advisory for beta participants.

### Stage 3/4 rollback
- Activate global kill switch.
- Optionally leave audio enabled and disable video if issue is media-mode specific.
- Trigger incident management and assign comms owner.

---

## 8) Verification commands/checks (operator-level)
> Adapt command names to final service tooling.

1. Confirm flag values for cohort:
   - `flags get messaging_webrtc_direct_call_v1 --env prod`
2. Confirm backend reject path when disabled:
   - `curl -X POST /api/messages/calls/invite ...` -> expect `feature_disabled`
3. Confirm metrics health:
   - setup success rate dashboard panel >= gate threshold
4. Confirm client gating:
   - DM header hides/disables call buttons for disabled cohort

---

## 9) Communication templates

## 9.1 Internal rollout start
"Starting WebRTC direct-call rollout Stage {N} at {TIME UTC}. On-call owner: @{owner}. Kill switch validated in staging."

## 9.2 Rollback notice
"Rolling back WebRTC direct-call rollout Stage {N} due to {reason}. Kill switch activated at {TIME UTC}. Investigating under incident {ID}."

## 9.3 Stage completion
"WebRTC direct-call rollout Stage {N} completed. Gate metrics held for {duration}. Proceeding to Stage {N+1}."

---

## 10) Ownership matrix

| Area | Primary | Secondary |
|---|---|---|
| Flag operations | Messaging on-call | SRE on-call |
| Frontend UI gating | Frontend messaging owner | Web platform on-call |
| Backend authorization/reject path | Messaging backend owner | API on-call |
| Incident comms | Incident commander | Product manager |

---

## 11) WRTC-003 acceptance mapping
- ✅ Feature flags and kill switch documented.
- ✅ Cohort rollout strategy defined.
- ✅ Emergency disable behavior defined.
- ✅ Staging kill-switch validation steps defined.

---

## 12) WRTC-050 observability dashboard and alert interpretation

- **Dashboard artifact:** `docs/dashboards/messaging-webrtc-calls-dashboard.json`
- **Primary panels to watch during rollout:**
  - call setup success rate (5m)
  - setup latency p50/p95
  - call duration p50/p95
  - TURN relay ratio
  - failure taxonomy by reason/stage
  - TURN credential issuance failure rate

### 12.1 Alert thresholds (baseline)
- **Critical:** setup success rate `< 92%` for `15m`
- **Warning:** setup success rate `< 95%` for `15m`
- **Critical:** setup p95 latency `> 8s` for `10m`
- **Warning:** TURN relay ratio `> 70%` for `15m`
- **Warning:** TURN issuance failure ratio `> 20%` for `10m`

### 12.2 Interpretation guidance
- Setup success regressions with stable TURN ratio often indicate signaling or auth regressions.
- Rising TURN ratio with rising setup latency usually indicates degraded p2p reachability/NAT environment changes.
- Concentrated failure reasons in one browser/platform suggest client-specific regressions; use dashboard platform/browser filters first before global rollback.
- If any critical threshold is sustained, pause rollout progression and execute kill-switch section immediately.
