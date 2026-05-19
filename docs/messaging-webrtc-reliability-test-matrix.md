# Messaging WebRTC Reliability Test Matrix (WRTC-042)

Date: 2026-04-05  
Owner: Messaging Reliability

## Objective

Validate reliability behavior for network edge cases in 1:1 direct-call flows:

- Simultaneous/competing call attempts
- Recipient already-on-call handling
- Mid-call transient connectivity drops and reconnect
- Background tab / delayed signaling delivery ordering

## Matrix

| ID | Scenario | Expected result | Status |
|---|---|---|---|
| R-01 | Two callers invite same callee concurrently | Second invite rejected with deterministic busy code (`callee_busy`) | ✅ |
| R-02 | Caller starts second call while already active in another call | New invite rejected with deterministic busy code (`caller_busy`) | ✅ |
| R-03 | Mid-call network drop (offline→online) | Client enters reconnecting state, attempts recovery, resumes connected if recovery succeeds | ✅ |
| R-04 | Reconnect retries exhausted | Client moves to failure state with explicit reconnect failure message | ✅ |
| R-05 | Delayed/older call event arrives after newer terminal event | Stale event ignored; no ghost incoming call UI | ✅ |
| R-06 | Recipient already on active call receives invite | Invite rejected as busy, caller sees busy outcome | ✅ |

## Execution notes (staging)

- Staging matrix was executed for server-side deterministic outcomes and client reducer behavior using a mix of unit-test harnesses and controlled event replay.
- Call reliability telemetry and timeline output were manually spot-checked for deterministic ordering during edge-case simulation.

## Evidence

- Backend lifecycle contention test: `tests/test_messaging_call_lifecycle.py` (`callee_busy` behavior)
- Signaling hardening + replay/timestamp checks: `tests/test_messaging_call_signaling.py`
- Client delayed-event and flow regression: `frontend/src/pages/messages/ConversationView.call_flows.test.tsx`
- Client reconnect/state behavior: `frontend/src/pages/messages/callStateMachine.test.ts`
