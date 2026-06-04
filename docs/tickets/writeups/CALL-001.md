# CALL-001: Expose Signaling HTTP Endpoint for Offer/Answer/ICE Exchange — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: WebRTC direct calls require a transport mechanism for exchanging SDP offers, SDP answers, and trickle ICE candidates between peers. Before this ticket the backend signaling validation framework was complete but had no HTTP ingress point — there was no way to actually submit a `webrtc.offer`, `webrtc.answer`, or `webrtc.ice_candidate` to the relay service. This ticket exposes `POST /messaging/messages/calls/{call_id}/signal` and wires it to `route_signaling_event()` in the existing service layer.

- **Type**: Feature (new HTTP endpoint + client-side API wrapper)
- **Priority**: High — blocks CALL-002 (RTCPeerConnection setup) and all downstream media tickets
- **Status**: Implemented — endpoint exists at `app/routers/messaging.py:14160`; frontend wrappers exist at `frontend/src/api/endpoints/messaging.ts:1024`; service-layer unit tests exist at `tests/test_messaging_call_signaling.py` (517 lines, 21 tests); HTTP-layer unit tests (`tests/test_messaging_call_signaling_endpoint.py`) and dedicated E2E spec (`frontend/e2e/webrtc-signaling.spec.ts`) do not yet exist.
- **Area**: Backend messaging router + signaling service; frontend API layer; SSE event fan-out
- **Who is affected**: Any authenticated call participant. The IDOR risk (routing signals to non-participants) is the key security concern.
- **Cross-references**: [[CALL-002]] (RTCPeerConnection consumes this endpoint), [[SECOPS-007]] (dev/prod parity for TURN/STUN), [[SEC-005]] (IDOR on participant check)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Signaling Service Layer — fully implemented

`app/services/messaging_call_signaling.py` (364 lines) contains the complete business logic. Key anchors:

- **`ALLOWED_SIGNALING_TYPES`** (line 14): 17 types including `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`, recording signals, screen-share signals, and voicemail signals. The set is env-configurable via `MESSAGING_WEBRTC_SIGNALING_MAX_SKEW_SECONDS`, `MESSAGING_WEBRTC_SIGNALING_NONCE_TTL_SECONDS`, `MESSAGING_WEBRTC_SIGNALING_MAX_PAYLOAD_BYTES`.
- **`STATE_ALLOWED_SIGNALING_TYPES`** (line 41): maps each call state to permitted event types. `"accepted"` state allows `webrtc.offer/answer/ice_candidate`; `"connected"` adds recording signals; `"invited"` restricts to `call.*` lifecycle events only. Voicemail signals are permitted in terminal states (`declined`, `missed`, `busy`).
- **`SignalingValidationError`** (line 60): carries a `.code` field (`"unauthorized"`, `"forbidden"`, `"stale_timestamp"`, `"replay_detected"`, `"invalid_state"`, etc.) for programmatic HTTP mapping.
- **`SignalingAck`** (line 66): frozen dataclass with `event_id`, `call_id`, `conversation_id`, `event_type`, `delivered_to`, `status` (`"delivered"` or `"duplicate"`).
- **`route_signaling_event()`** (line 190): the main entry point. Performs: envelope validation (`_validate_envelope`, line 117) → actor-sender match check (line 217) → participant lookup via DDB query on `Participants` table GSI1 (line 221) → call session load from `T.message_call_sessions` (line 233) → state-gated type check (line 255) → replay guard via conditional DDB `put_item` on `UserEvents` with `attribute_not_exists(event_id)` (line 260) → payload size check (line 279) → event delivery write to `UserEvents` table with `user_id=recipient_user_id` as PK (line 303). Emits structured metrics via `_record_signaling_metric` (line 169).

The replay guard (`_reserve_signaling_nonce`, line 143) writes a nonce item with PK `SIGNALING_NONCE#{conversation_id}` and event_id `nonce#{conversation_id}#{sender_user_id}#{nonce}`, TTL-expired after `NONCE_TTL_SECONDS` (600 s). If the conditional write fails (duplicate), `route_signaling_event` returns `status="duplicate"` — idempotent without error.

### 2.2 HTTP Endpoint — implemented at messaging.py:14062–14204

The signaling endpoint was added at the bottom of `app/routers/messaging.py` under the comment block `# WebRTC Signaling Relay` (line 14062):

- **`CallSignalingIn`** (line 14067): Pydantic model. `type` field has `pattern=r"^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$"` — restricts to `webrtc.*` only; call lifecycle events have dedicated endpoints and must not bypass the lifecycle state machine. `call_id` is taken from the URL path, not the body, preventing mismatch attacks. `sender_user_id` is derived from auth, not accepted from the body.
- **`CallSignalingOut`** (line 14077) and **`CallSignalingErrorOut`** (line 14086): Response models.
- **`_SIGNALING_ERROR_STATUS_MAP`** (line 14091): maps `SignalingValidationError.code` → HTTP status. `"replay_detected"` and `"invalid_state"` → 409; `"call_not_found"` → 404; `"unauthorized"/"forbidden"` → 403; `"*_failed"` → 503; `"rate_limited"` → 429.
- **Rate limit helpers** (lines 14107–14147): `SIGNALING_RATE_LIMIT_WINDOW_SECONDS` (default 10s) and `SIGNALING_RATE_LIMIT_MAX` (default 60) read from env. `_enforce_signaling_rate_limit()` increments a DDB counter on `tbl_events` at key `SIGNALING_RATE#{user_id}#{bucket}`. Fails open — if the DDB call itself throws, signaling is not blocked.
- **Feature gate** (line 14115): `_enforce_webrtc_signaling_enabled()` checks `S.messaging_webrtc_direct_call_kill_switch` and `S.messaging_webrtc_direct_call_enabled` (defined at `app/core/settings.py:1139–1140`). Returns 403 with `code: "feature_disabled"` if either blocks.
- **Handler `send_signaling_event`** (line 14165): auth via `Depends(get_messaging_user_id)` (same as all other call endpoints, line 1549). Constructs the service envelope with `version=1` hardcoded and `sender_user_id=user_id` from auth, calls `route_signaling_event`, converts `SignalingValidationError` to HTTP exceptions.

### 2.3 SSE Fan-out — already works, no changes needed

The `UserEvents` table (PK `user_id`) is polled by `GET /messaging/events/stream` (line 11785). Events written by `route_signaling_event` with `user_id=recipient_user_id` are automatically delivered. `useMessagingStream.ts` registers listeners for `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate` in its `EVENT_TYPES` array (lines 203–204) and dispatches them as `CustomEvent("messaging:webrtc-signal")` (line 152).

### 2.4 Frontend API wrapper — implemented at messaging.ts:1024

`SignalingPayload` (line 1024), `SignalingAck` (line 1034), and `sendSignalingEvent()` (line 1043) exist. Note: `SignalingPayload.type` is typed as `"webrtc.offer" | "webrtc.answer" | "webrtc.ice_candidate"` — the screen-share types (`webrtc.screen_share_start/stop`) accepted by the backend's `CallSignalingIn.type` pattern are not yet exposed through this TS interface. `fetchTurnCredentials()` (line 1065) is also present.

### 2.5 Dev vs prod behavior

In dev mode (`DEV_MODE=1`): `S.messaging_webrtc_direct_call_enabled` defaults to `false` (env var `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`); tests must set `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true` in the test environment. All DDB operations use DynamoDB Local (port 8001). No AWS is contacted. The nonce TTL cleanup is handled by DynamoDB Local's TTL scan (which is lazy but sufficient for testing). In prod: same code path, real DynamoDB.

---

## 3. Gap / Threat Analysis

### 3.1 Security: IDOR on signaling relay

The highest-risk surface is the participant check in `route_signaling_event` (line 226). An authenticated user who is a member of _some_ conversation could attempt to inject signaling events into a call session they are not part of by supplying a `conversation_id` they belong to but a `call_id` from another call. The current defense-in-depth is:

1. `participant_resolver(conversation_id)` loads `Participants` GSI1 — so `sender_user_id` must be in the conversation.
2. `call_participants = {caller_user_id, callee_user_id}` from `CallSessionRecord` (line 244) — both sender and recipient must also be call participants.
3. The `call_session.conversation_id` is cross-checked against the envelope `conversation_id` (line 241).

This means three independent checks must pass. A call participant from conversation A cannot inject signals into a call in conversation B. The rate limit on `tbl_events` uses `SIGNALING_RATE#{user_id}#{bucket}` — a separate user_id prefix from actual event PKs, so there is no key collision risk.

### 3.2 Replay attacks

The nonce guard uses `attribute_not_exists(event_id)` on a compound key. The nonce is scoped to `(conversation_id, sender_user_id, nonce)`. An attacker replaying an exact `(event_id, nonce)` pair within the 600-second TTL window will receive `replay_detected` (409). After TTL expiry, the same nonce can technically be reused — this is by design (nonces are ephemeral per-session). Callers must use unique nonces per event (the frontend uses `crypto.randomUUID()` in `webrtc.ts:generateNonce`).

### 3.3 Missing tests

- `tests/test_messaging_call_signaling_endpoint.py` does not exist. The HTTP layer (feature gate, rate limit, model validation, error mapping, auth dependency) has no dedicated test coverage. The 21 service-layer unit tests in `tests/test_messaging_call_signaling.py` test `route_signaling_event` in isolation but do not exercise the HTTP handler.
- `frontend/e2e/webrtc-signaling.spec.ts` does not exist. End-to-end signaling delivery (POST → SSE → recipient browser) is tested indirectly in `frontend/e2e/webrtc-calls.spec.ts` (661 lines) but not in an isolated signaling spec.

### 3.4 Minor type mismatch

`SignalingPayload.type` in `messaging.ts:1024` is `"webrtc.offer" | "webrtc.answer" | "webrtc.ice_candidate"` — missing `"webrtc.screen_share_start" | "webrtc.screen_share_stop"` which the backend's `CallSignalingIn.type` pattern accepts. Screen-share signaling from CALL-013 will need to extend this union type to avoid TypeScript type errors when that ticket lands.

---

## 4. Proposed Design / Fix

### 4.1 HTTP-layer unit tests — `tests/test_messaging_call_signaling_endpoint.py`

Create a pytest module using the FastAPI `TestClient` with moto-mocked DynamoDB. Test cases must cover:

- **Feature gate**: when `S.messaging_webrtc_direct_call_enabled=False`, endpoint returns 403 `feature_disabled`.
- **Kill switch**: when `S.messaging_webrtc_direct_call_kill_switch=True`, endpoint returns 403 `feature_disabled`.
- **Unauthenticated**: no session cookies or bearer token → 401.
- **Model validation**: missing `event_id`, `nonce` too short (< 8 chars), `type` not matching pattern → 422.
- **Successful delivery**: mock `route_signaling_event` to return a `SignalingAck`; assert response shape matches `CallSignalingOut`.
- **SignalingValidationError propagation**: mock the service to raise `SignalingValidationError("forbidden", "...")` and verify the endpoint returns 403 with `{"code": "forbidden", ...}` body.
- **Rate limiting**: inject a pre-populated DDB counter that exceeds `SIGNALING_RATE_LIMIT_MAX` and verify 429.
- **Sender cannot be overridden**: submit body with `sender_user_id` field (not in `CallSignalingIn` schema, so it is silently dropped) and confirm that the envelope passed to the service uses the auth-derived `user_id`.

The `call_id` path parameter is URL-encoded and must not exceed 128 chars — add a test for that boundary.

### 4.2 E2E signaling spec — `frontend/e2e/webrtc-signaling.spec.ts`

A focused spec (distinct from `webrtc-calls.spec.ts`) that exercises the signaling HTTP endpoint directly:

- Use `apiPost(page, "alice", ...)` to submit a `webrtc.offer` after a call is in `accepted` state and assert that Bob's SSE stream delivers the event (poll `UserEvents` DDB or wait for Bob's page to receive a `messaging:webrtc-signal` event).
- Assert 403 when a third user (Charlie) attempts to signal into Alice/Bob's call.
- Assert 409 when the same `(event_id, nonce)` is submitted twice.
- Assert 409 when signaling `webrtc.offer` in `invited` state (wrong state for that type).

### 4.3 TS type extension for screen-share signals

When CALL-013 (screen sharing) lands, extend `SignalingPayload.type` in `messaging.ts:1024` to include `"webrtc.screen_share_start" | "webrtc.screen_share_stop"`, keeping parity with `CallSignalingIn.type` (backend regex, line 14068).

### 4.4 Dev/Prod parity (SECOPS-007)

No AWS dependency is introduced: `route_signaling_event` writes only to `UserEvents` (DDB, both envs), reads from `Participants` and `CallSessions` (DDB, both envs). The rate limit counter also uses `tbl_events` (same table). In dev the `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true` env var must be set; in prod it is set per-deployment. TURN credentials are a separate concern (CALL-002, `messaging_turn_credentials.py`). The signaling endpoint itself is purely DDB-bound.

### 4.5 `.env.local.example` additions

The following env vars are read at runtime with defaults but are not documented in `.env.local.example`:

```
MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_WINDOW_SECONDS=10
MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_MAX=60
MESSAGING_WEBRTC_SIGNALING_MAX_SKEW_SECONDS=120
MESSAGING_WEBRTC_SIGNALING_NONCE_TTL_SECONDS=600
MESSAGING_WEBRTC_SIGNALING_MAX_PAYLOAD_BYTES=8192
```

These should be added to `.env.local.example` alongside the existing `MESSAGING_WEBRTC_*` block. The TTL and skew values in particular should be surfaced because operators may want to tighten the skew window in high-security deployments or extend the nonce TTL for clients operating across slow mobile networks.

### 4.6 Latency profile of the signaling critical path

Understanding the DDB write sequence matters for setting the right `poll_ms` on the SSE stream. The `route_signaling_event()` critical path involves:

1. Participant lookup: `Participants` table query on `GSI1` (line 87–91 of signaling service) → 1 DDB round-trip.
2. Call session load: `T.message_call_sessions.get_item` (via `get_call_session`) → 1 DDB round-trip.
3. Replay guard: `UserEvents.put_item` with `attribute_not_exists(event_id)` (line 163) → 1 DDB round-trip.
4. Event delivery: `UserEvents.put_item` (line 303) → 1 DDB round-trip.

Estimated p50 latency for the HTTP round-trip: 35–50ms (DDB Local). The SSE stream polls every `poll_ms` milliseconds (default 1000ms per `GET /messaging/events/stream` endpoint). This means signaling events can be delayed up to 1 second from POST to delivery. For production call quality, set `poll_ms=200–500` for sessions with active calls. This optimization is out of scope for CALL-001 but should be filed as a follow-up.

### 4.7 `call_id` path parameter injection risk

The `call_id` path parameter in `POST /messaging/messages/calls/{call_id}/signal` is a string accepted directly by FastAPI. Because it is validated downstream in `route_signaling_event` via `_require_str(envelope, "call_id", max_len=128)` (signaling service line 127), an attacker cannot submit a `call_id` longer than 128 characters to cause a DDB key overflow — DynamoDB keys are limited to 1024 bytes and FastAPI does not impose a path-segment length limit by default. The service layer's `max_len=128` guard provides the necessary defense. For defense-in-depth, the `CallSignalingIn` model does not include `call_id` in the body (it comes from the URL path only), and the endpoint hardcodes it into the envelope — there is no opportunity for `call_id` to be overridden from the request body.

---

## 5. Testing, Verification & Rollout

### Pytest unit tests (offline, no AWS)

| Test | Assertion |
|---|---|
| `test_feature_gate_disabled` | `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=false` → POST returns 403 `feature_disabled` |
| `test_kill_switch` | `MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH=true` → 403 |
| `test_unauthenticated` | no session → 401 |
| `test_invalid_type_field` | `type="call.end"` → 422 (rejected by pattern field) |
| `test_nonce_too_short` | `nonce="abc"` (6 chars) → 422 |
| `test_successful_delivery` | mock service returns `SignalingAck` → 200 with matching JSON |
| `test_forbidden_propagation` | service raises `SignalingValidationError("forbidden", …)` → 403 `{"code":"forbidden"}` |
| `test_replay_detection` | service raises `SignalingValidationError("replay_detected", …)` → 409 |
| `test_rate_limit_exceeded` | DDB counter pre-seeded above threshold → 429 |
| `test_sender_not_in_body` | `sender_user_id` cannot be spoofed via request body |

Run: `.venv/bin/pytest tests/test_messaging_call_signaling_endpoint.py -v`

### Playwright E2E (`frontend/e2e/webrtc-signaling.spec.ts`)

Auth via `injectAuth(page, "alice")` and `injectAuth(page, "bob")`. Seed a DM conversation and call session in `beforeAll` using the `execSync` DDB write pattern from `webrtc.spec.ts:96–155`. Test timeout 30 s. No fake media flags needed (pure HTTP signaling).

### Manual/QA steps

1. Start dev stack: `just up`.
2. Set `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true` in `.env.local` and restart backend.
3. In two browser tabs (Alice, Bob), open a DM conversation.
4. Open the browser DevTools Network panel and submit a `POST /messaging/messages/calls/{call_id}/signal` with a valid `webrtc.offer` body.
5. Verify Bob's SSE stream in the other tab emits a `webrtc.offer` event with the correct payload.

### Observability

`app/metrics.py:1379–1432` defines `record_webrtc_signaling_event(outcome, reason, event_type)` and `record_webrtc_signaling_latency(...)`. These are called by `_record_signaling_metric` in the service layer (line 169). Prometheus counters are emitted for every `route_signaling_event` call. Tie to SECOPS-001 for security event telemetry on `outcome="error"` events.

### Rollout

Feature-flagged behind `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`. Enable for internal tenants first (`MESSAGING_WEBRTC_DIRECT_CALL_MODE=internal`), then selective cohort, then full rollout. Kill switch (`MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH`) allows instant disable without deploy.

**Rollback**: disable the kill switch env var; the endpoint returns 403 to all callers without any DDB migration.

**Effort estimate**: S — the core logic is implemented. Remaining work is the HTTP-layer test file (~150 lines of pytest) and the focused E2E spec (~120 lines). Half a day.
