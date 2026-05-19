# Messaging WebRTC Cross-Browser QA Matrix (WRTC-052)

Date: 2026-04-05  
Owner: QA + Messaging On-call

## Scope covered

Browsers:
- Chromium (stable)
- Firefox (stable)
- Safari (stable)

Platforms:
- macOS desktop
- Windows desktop (Chromium/Firefox)
- iOS Safari (permission and fallback checks)

## Critical scenario matrix

| ID | Scenario | Chromium | Firefox | Safari | Notes |
|---|---|---|---|---|---|
| QA-01 | Outgoing audio call setup to connect | ✅ Pass | ✅ Pass | ✅ Pass | Setup success + latency within gate thresholds |
| QA-02 | Outgoing video call setup to connect | ✅ Pass | ✅ Pass | ⚠️ Pass (camera prompt timing differs) | Safari requires explicit re-allow after tab restore in some cases |
| QA-03 | Incoming call accept/decline UX | ✅ Pass | ✅ Pass | ✅ Pass | Decline/busy messaging verified |
| QA-04 | Mid-call transient network drop + recover | ✅ Pass | ✅ Pass | ⚠️ Pass (slower recover) | Reconnect retries/failure path validated |
| QA-05 | Delayed/out-of-order event does not resurrect ghost UI | ✅ Pass | ✅ Pass | ✅ Pass | Stale event guard observed |
| QA-06 | Simultaneous competing call attempts resolve deterministically | ✅ Pass | ✅ Pass | ✅ Pass | Busy code surfaced (`callee_busy`) |
| QA-07 | Microphone/camera permission denial UX | ✅ Pass | ✅ Pass | ✅ Pass | Browser-specific permission copy verified |
| QA-08 | Device switching (mic/cam) while call connected | ✅ Pass | ⚠️ Partial | ⚠️ Partial | Firefox/Safari device picker behavior differs; tracked below |
| QA-09 | TURN fallback behavior under restricted NAT simulation | ✅ Pass | ✅ Pass | ✅ Pass | TURN ratio telemetry and setup continuity verified |
| QA-10 | End-call + teardown cleanup | ✅ Pass | ✅ Pass | ✅ Pass | No stuck tracks/ghost controls after end |

## Automated evidence

- Frontend lifecycle/state tests:
  - `frontend/src/pages/messages/callStateMachine.test.ts`
  - `frontend/src/pages/messages/ConversationView.call_flows.test.tsx`
- Backend reliability/security tests:
  - `tests/test_messaging_call_lifecycle.py`
  - `tests/test_messaging_call_signaling.py`

### Evidence command log

- `pytest -q tests/test_messaging_call_metrics.py`
  - Result: pass on 2026-04-05 (UTC)

## Manual evidence summary

- QA session logs retained in release evidence package: `qa/releases/webrtc-v1/2026-04-05/`.
- Browser-specific permission dialogs captured and reviewed by QA lead.
- Network drop/recover scenarios replayed with controlled offline/online transitions and delayed event injection.

## Defect summary

### Critical / High defects

| Defect | Severity | Status | Decision |
|---|---|---|---|
| None open at certification time | - | - | - |

### Deferred defects (approved)

| Defect | Severity | Impact | Approval |
|---|---|---|---|
| Firefox/Safari device switch UX parity gaps (`QA-08`) | Medium | Non-blocking; feature remains functional with manual re-select flow | Approved by PM + QA lead for GA with follow-up ticket |

## Sign-off

- QA Lead: ✅ Signed
- Messaging Engineering Lead: ✅ Signed
- Product Owner: ✅ Signed
