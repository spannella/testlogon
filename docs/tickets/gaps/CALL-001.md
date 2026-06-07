# CALL-001 Gaps

- [MED] HTTP-layer unit tests missing — `tests/test_messaging_call_signaling_endpoint.py` does not exist — feature gate, rate limit, model validation, auth, and error-map logic have no dedicated test coverage — Fix: create pytest module (~150 lines) covering 10 test cases listed in §4.1 — Effort: S
- [LOW] TS type mismatch: screen-share signal types absent from frontend interface — `frontend/src/api/endpoints/messaging.ts:1025` — `SignalingPayload.type` omits `"webrtc.screen_share_start" | "webrtc.screen_share_stop"` accepted by backend regex — Fix: extend union type when CALL-013 lands — Effort: S
- [LOW] No dedicated E2E signaling spec — `frontend/e2e/webrtc-signaling.spec.ts` does not exist — IDOR, replay, and state-gate checks only tested via service-layer unit tests, not HTTP — Fix: create focused Playwright spec (~120 lines) per §4.2 — Effort: S
- [LOW] Env vars undocumented in `.env.local.example` — five `MESSAGING_WEBRTC_SIGNALING_*` vars have defaults but no example entry — operators unaware of tunable skew/TTL/rate-limit values — Fix: add vars to `.env.local.example` alongside existing `MESSAGING_WEBRTC_*` block per §4.5 — Effort: S
