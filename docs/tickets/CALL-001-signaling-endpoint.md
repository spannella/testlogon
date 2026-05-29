# CALL-001: Expose Signaling HTTP Endpoint for Offer/Answer/ICE Exchange

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-24  
**Priority**: High  
**Estimated effort**: 3-5 days

---

## 1. Overview & Motivation

### The Gap

The WebRTC call system currently has a complete backend signaling validation and routing framework (`app/services/messaging_call_signaling.py`) that validates envelopes, enforces replay protection, checks call state transitions, and writes signaling events into the Events DynamoDB table for SSE delivery.

<!-- NOTE: The HTTP endpoint now EXISTS at app/routers/messaging.py:13244-13288 (POST /messages/calls/{call_id}/signal). The remaining work is the unit test file for the HTTP layer (tests/test_messaging_call_signaling_endpoint.py) and the E2E test file (frontend/e2e/webrtc-signaling.spec.ts). -->

The existing call lifecycle endpoints (`POST /messages/calls/invite`, `/accept`, `/decline`, `/end`) handle high-level call state transitions (invited -> accepted -> connected -> ended), but the actual WebRTC session establishment -- the exchange of SDP offers, SDP answers, and ICE candidates between peers -- has no transport mechanism over HTTP.

### Why This Is Needed

Without a signaling HTTP endpoint, the frontend WebRTC implementation cannot:

1. **Exchange SDP offers/answers**: After a call is accepted, the caller must send an SDP offer and receive an SDP answer to establish media negotiation. There is no way to transmit these payloads today.

2. **Trickle ICE candidates**: ICE candidates discovered during connectivity checks must be relayed to the remote peer in near-real-time. Without a relay mechanism, peers cannot establish optimal network paths (direct P2P or via TURN).

3. **Support renegotiation**: Mid-call changes (e.g., enabling video, screen sharing) require new offer/answer exchanges. The lifecycle endpoints only manage high-level state.

4. **Complete the WebRTC flow**: The TURN credential endpoint (`POST /messages/calls/{call_id}/turn-credentials`) already exists, the SSE stream already dispatches `call.*` events to the frontend via `CustomEvent("messaging:call-event")`, and the signaling validation logic is fully implemented. The only missing piece is the HTTP ingress point.

### Architecture After This Change

```
Frontend (Caller)                    Backend                         Frontend (Callee)
     |                                  |                                  |
     |-- POST /calls/invite ----------->|-- SSE call.invite ------------->|
     |                                  |                                  |
     |<-- SSE call.accept --------------|<-- POST /calls/{id}/accept -----|
     |                                  |                                  |
     |-- POST /calls/{id}/signal ------>|                                  |
     |   {type: webrtc.offer, ...}      |-- SSE webrtc.offer ------------>|
     |                                  |                                  |
     |<-- SSE webrtc.answer ------------|<-- POST /calls/{id}/signal -----|
     |                                  |   {type: webrtc.answer, ...}     |
     |                                  |                                  |
     |-- POST /calls/{id}/signal ------>|-- SSE webrtc.ice_candidate ---->|
     |<-- SSE webrtc.ice_candidate -----|<-- POST /calls/{id}/signal -----|
     |   (trickle ICE, bidirectional)   |                                  |
```

---

## 2. Current State Analysis

### 2.1 Signaling Service Layer (`app/services/messaging_call_signaling.py`)

The signaling module (359 lines) is production-ready. Key components:
<!-- NOTE: The HTTP endpoint now exists — see `send_signaling_event` at app/routers/messaging.py:13249. -->

**Constants and Configuration (lines 14-40)** (see `app/services/messaging_call_signaling.py:14-40`):
- `ALLOWED_SIGNALING_TYPES` (line 14): Now 17 types — includes recording signals (`call.recording_request/accept/decline/started/stopped`), screen share (`webrtc.screen_share_start/stop`), and voicemail signals (`call.voicemail_start/complete`) in addition to the original 8
- `MAX_SIGNALING_SKEW_SECONDS` (line 34): 120s (env-configurable)
- `NONCE_TTL_SECONDS` (line 35): 600s for replay guard entries
- `MAX_SIGNALING_PAYLOAD_BYTES` (line 36): 8192 bytes (sufficient for SDP + ICE)
- `TERMINAL_CALL_STATES` (line 37): `{"ended", "missed", "declined", "busy", "failed", "canceled"}`
- `STATE_ALLOWED_SIGNALING_TYPES` (line 41): Maps call states to permitted signaling event types:
  - `"invited"` -> `{call.invite, call.ring, call.accept, call.decline, call.end}`
  - `"accepted"` -> `{webrtc.offer, webrtc.answer, webrtc.ice_candidate, call.end, webrtc.screen_share_start, webrtc.screen_share_stop}`
  - `"connected"` -> `{webrtc.offer, ..., call.end, call.recording_*, webrtc.screen_share_*}`
  - `"declined"/"missed"/"busy"` -> `{call.voicemail_start, call.voicemail_complete}` (CALL-014)

**Core Function `route_signaling_event()` (lines 186-356)** (see `app/services/messaging_call_signaling.py:186`):

This is the function the HTTP endpoint calls. It performs:

1. **Envelope validation** (`_validate_envelope`, line 113): Extracts and validates `type`, `version` (must be 1), `event_id`, `call_id`, `conversation_id`, `sender_user_id`, `recipient_user_id`, `nonce` (8-128 chars), `sent_at` (within skew window).

2. **Actor verification** (line 213): `sender_user_id` must match the authenticated `actor_user_id`.

3. **Participant check** (lines 217-227): Both sender and recipient must be conversation participants; they must differ.

4. **Call session validation** (lines 229-254): Loads `CallSessionRecord`, verifies `conversation_id` matches, confirms both users are call participants, validates the event type is allowed for the current call state. Also allows voicemail signals in terminal states (CALL-014, line 248).

5. **Replay guard** (lines 256-264): Uses `_reserve_signaling_nonce()` (line 139) which does a conditional DDB `put_item` with `attribute_not_exists(event_id)`. Nonces are TTL-expired after 600s.

6. **Payload validation** (lines 266-281): Payload must be a JSON-serializable object under 8192 bytes.

7. **Event delivery** (lines 283-356): Writes event item to the Events table with `user_id=recipient_user_id` as PK. The SSE stream (`GET /events/stream`) polls this table by `user_id`, so the recipient will receive the event on their next poll cycle.

**Return type `SignalingAck`** (lines 66-73) (see `app/services/messaging_call_signaling.py:66`): Contains `event_id`, `call_id`, `conversation_id`, `event_type`, `delivered_to`, `status` (either `"delivered"` or `"duplicate"`).

**Error type `SignalingValidationError`** (lines 60-63) (see `app/services/messaging_call_signaling.py:60`): Has a `code` field for programmatic error classification.

### 2.2 Call Lifecycle Endpoints (`app/routers/messaging.py`, lines 12896-13145)

The existing call endpoints follow a consistent pattern (see `app/routers/messaging.py:12896`):
- Auth via `Depends(get_messaging_user_id)` (supports cookie auth, Bearer, and API key principal) (see `app/routers/messaging.py:1549`)
- Request/response models defined inline as Pydantic `BaseModel` classes
- Error handling wraps service-layer exceptions via `_call_error_to_http()` helper (line 12956)
- All endpoints are on the `router` (prefix `/messaging`)
- Path pattern: `/messages/calls/{call_id}/<action>`

Models defined (lines 12900-12942) (see `app/routers/messaging.py:12900`):
- `CallInviteIn` (line 12900), `CallInviteOut` (line 12910) — includes `paid` and `rate_cents_per_min` fields for CALL-011
- `CallAcceptIn` (line 12922), `CallDeclineIn` (line 12926), `CallEndIn` (line 12930)
- `CallActionOut` (line 12935) — includes `voicemail_eligible` field for CALL-014

Error status map `_CALL_ERROR_STATUS_MAP` (lines 12945-12953) (see `app/routers/messaging.py:12945`): Maps error codes to HTTP status codes.

### 2.3 SSE Stream (`GET /messaging/events/stream`, lines 11785-11820)

The SSE endpoint (see `app/routers/messaging.py:11785`) polls the Events DynamoDB table (`_ddb_fetch_events`) every `poll_ms` milliseconds, projects events via `_project_event_for_user()`, and streams them as typed SSE events using `_sse_pack()` (line 11815).

Key behavior: Events written to the Events table with `user_id=<recipient>` are automatically picked up by that user's SSE stream. The event `type` field becomes the SSE event name, which the frontend registers listeners for.

### 2.4 Frontend SSE Handler (`frontend/src/hooks/useMessagingStream.ts`)

The hook (217 lines) handles call events (see `frontend/src/hooks/useMessagingStream.ts:148-184`):
- `EVENT_TYPES` array (line 148) registers listeners for `call.invite`, `call.accept`, `call.decline`, `call.end`, `call.missed`, `call.recording_*`, `call.billing_tick`, `call.balance_*`, AND `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate` (lines 181-183)
- Any event with type starting with `"call."` is dispatched as `CustomEvent("messaging:call-event")` on `window` (lines 121-130)
- Events starting with `"webrtc."` are dispatched as `CustomEvent("messaging:webrtc-signal")` (lines 132-141)

<!-- NOTE: The gap described in the original spec is now closed — webrtc.offer/answer/ice_candidate are already in EVENT_TYPES and the webrtc dispatch block exists. -->

### 2.5 Call Session Records (`app/services/messaging_call_sessions.py`)

`CallSessionRecord` dataclass (lines 19-50) (see `app/services/messaging_call_sessions.py:19`): `call_id`, `conversation_id`, `caller_user_id`, `callee_user_id`, `initial_mode`, `state` (Literal type), `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `network_path`, `lifecycle_events`, `idempotency_records`. Also includes BCAST-011 fields (`broadcast_session_id`, line 35), CALL-011 pay-per-minute billing fields (lines 37-48), and CALL-014 voicemail linkage (`voicemail_message_id`, line 50).

The `state` field drives which signaling events are permitted (see `STATE_ALLOWED_SIGNALING_TYPES` at `app/services/messaging_call_signaling.py:41`).

### 2.6 Existing Unit Tests (`tests/test_messaging_call_signaling.py`, 517 lines)

Covers: successful delivery, spoofed sender rejection, non-participant rejection, delivery failure, stale timestamp, invalid event type, version mismatch, replay detection, payload size limit, call-not-found, call state validation, and duplicate delivery idempotency. Uses dependency injection (custom `participant_resolver`, `call_session_resolver`, `put_item`, `replay_guard`) for isolation.

---

## 3. Technical Design

### 3.1 Endpoint Specification

```
POST /messaging/messages/calls/{call_id}/signal
```

**Path**: Follows the existing pattern (`/messages/calls/{call_id}/...` for TURN credentials, accept, decline, end).

**Auth**: `Depends(get_messaging_user_id)` -- consistent with all other call endpoints. Supports cookie+CSRF, Bearer token, and API key principal.

**Rate Limiting**: Per-user burst limit of 60 signaling events per 10-second window. This accommodates ICE trickle bursts (typically 10-30 candidates within seconds) while preventing abuse. Implemented as a DDB-based sliding window counter (see `_enforce_signaling_rate_limit` at `app/routers/messaging.py:13206`; similar pattern to `_enforce_report_rate_limits` at line 6691).

### 3.2 Request Model

```python
class CallSignalingIn(BaseModel):
    """Incoming signaling envelope for WebRTC offer/answer/ICE exchange."""
    type: str = Field(
        ...,
        description="Signaling event type: webrtc.offer | webrtc.answer | webrtc.ice_candidate",
        pattern=r"^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate)$",
    )
    event_id: str = Field(..., min_length=1, max_length=128)
    conversation_id: str = Field(..., min_length=1, max_length=128)
    recipient_user_id: str = Field(..., min_length=1, max_length=128)
    nonce: str = Field(..., min_length=8, max_length=128)
    sent_at: int = Field(..., description="Unix timestamp (seconds)")
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="SDP or ICE candidate payload (max 8KB serialized)",
    )
```

**Design decisions**:
- `type` is restricted to `webrtc.*` events only. Call lifecycle events (`call.invite`, `call.accept`, etc.) already have dedicated endpoints and should NOT be sent through this generic signaling endpoint. This prevents clients from bypassing the lifecycle state machine.
- `call_id` comes from the URL path parameter, not the body, preventing mismatch attacks.
- `sender_user_id` is NOT in the request body -- it is derived from the authenticated user. This prevents sender spoofing at the API layer (the service layer also validates this, providing defense-in-depth).
- `version` is hardcoded to 1 by the endpoint when constructing the envelope for the service layer.

### 3.3 Response Model

```python
class CallSignalingOut(BaseModel):
    """Acknowledgment of successful signaling event delivery."""
    event_id: str
    call_id: str
    conversation_id: str
    event_type: str
    delivered_to: str
    status: str  # "delivered" or "duplicate"
```

### 3.4 Error Response Model

```python
class CallSignalingErrorOut(BaseModel):
    code: str
    message: str
```

### 3.5 Error Status Mapping

```python
_SIGNALING_ERROR_STATUS_MAP = {
    "validation_error": 400,
    "unsupported_version": 400,
    "stale_timestamp": 400,
    "unauthorized": 403,
    "forbidden": 403,
    "call_not_found": 404,
    "call_lookup_failed": 503,
    "participant_lookup_failed": 503,
    "replay_detected": 409,
    "replay_guard_failed": 503,
    "invalid_state": 409,
    "delivery_failed": 503,
    "rate_limited": 429,
}
```

### 3.6 Rate Limiting Design

```python
SIGNALING_RATE_LIMIT_WINDOW_SECONDS = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_WINDOW_SECONDS", "10")
)
SIGNALING_RATE_LIMIT_MAX = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_MAX", "60")
)
```

Implementation: Before calling `route_signaling_event()`, the endpoint checks a DDB counter at key `SIGNALING_RATE#{user_id}#{window_bucket}`. If count exceeds `SIGNALING_RATE_LIMIT_MAX`, return 429. Counter uses TTL for auto-cleanup.

This approach is intentionally generous for legitimate use (a typical WebRTC session exchanges ~30-50 ICE candidates plus 2-4 offer/answer pairs) while blocking runaway clients or attack scripts.

### 3.7 SSE Relay Mechanism

No additional code is needed for SSE relay. The `route_signaling_event()` function already writes the event to the Events table with:
```python
event_item = {
    "user_id": recipient_user_id,  # PK -- determines which user's stream receives it
    "event_id": event_id,
    "type": event_type,            # "webrtc.offer" / "webrtc.answer" / "webrtc.ice_candidate"
    "payload": payload,            # SDP or ICE candidate data
    "created_at": ts,
    "conversation_id": conversation_id,
    "sender_id": sender_user_id,
    "call_id": call_id,
    "read": False,
    "ttl": ts + 7 * 24 * 3600,
}
```

The SSE stream endpoint (`GET /events/stream`) polls by `user_id` PK and emits events with `event: <type>`. The frontend EventSource listener will receive these as typed events.

**Frontend change required**: Add `"webrtc.offer"`, `"webrtc.answer"`, `"webrtc.ice_candidate"` to the `EVENT_TYPES` array in `useMessagingStream.ts` so that `EventSource.addEventListener` is registered for these types.

### 3.8 Feature Gating

The endpoint should respect the existing WebRTC feature flags (see `app/core/settings.py:1041-1042`):
- `S.messaging_webrtc_direct_call_enabled` (line 1041) must be `True`
- `S.messaging_webrtc_direct_call_kill_switch` (line 1042) must be `False`

If disabled, return 403 with `code: "feature_disabled"`.

### 3.9 Endpoint Handler Pseudocode

```python
@router.post(
    "/messages/calls/{call_id}/signal",
    response_model=CallSignalingOut,
    responses={
        400: {"model": CallSignalingErrorOut},
        403: {"model": CallSignalingErrorOut},
        404: {"model": CallSignalingErrorOut},
        409: {"model": CallSignalingErrorOut},
        429: {"model": CallSignalingErrorOut},
        503: {"model": CallSignalingErrorOut},
    },
)
async def send_signaling_event(
    call_id: str,
    body: CallSignalingIn,
    user_id: str = Depends(get_messaging_user_id),
):
    # 1. Feature gate check
    _enforce_webrtc_signaling_enabled()

    # 2. Rate limit check
    _enforce_signaling_rate_limit(user_id)

    # 3. Construct canonical envelope for service layer
    envelope = {
        "type": body.type,
        "version": 1,
        "event_id": body.event_id,
        "call_id": call_id,  # from URL path
        "conversation_id": body.conversation_id,
        "sender_user_id": user_id,  # from auth
        "recipient_user_id": body.recipient_user_id,
        "nonce": body.nonce,
        "sent_at": body.sent_at,
        "payload": body.payload,
    }

    # 4. Route through signaling service
    try:
        ack = route_signaling_event(envelope=envelope, actor_user_id=user_id)
    except SignalingValidationError as exc:
        raise HTTPException(
            status_code=_SIGNALING_ERROR_STATUS_MAP.get(exc.code, 400),
            detail={"code": exc.code, "message": str(exc)},
        )

    # 5. Return acknowledgment
    return CallSignalingOut(
        event_id=ack.event_id,
        call_id=ack.call_id,
        conversation_id=ack.conversation_id,
        event_type=ack.event_type,
        delivered_to=ack.delivered_to,
        status=ack.status,
    )
```

### 3.10 Latency Considerations

The critical path for signaling delivery:
1. HTTP request parsing + auth (~2ms)
2. Rate limit DDB check (~5-10ms)
3. `route_signaling_event()`:
   - Participant lookup: 1 DDB `get_item` (~5ms)
   - Call session lookup: 1 DDB `get_item` (~5ms)
   - Replay guard: 1 DDB conditional `put_item` (~8ms)
   - Event delivery: 1 DDB conditional `put_item` (~8ms)
4. Response serialization (~1ms)

**Total estimated p50 latency**: ~35ms  
**SSE delivery lag**: Additional 0-1000ms depending on `poll_ms` parameter (default 1000ms).

For sub-200ms total signaling latency, consider reducing the default `poll_ms` to 200-500ms for users with active calls. This is out of scope for CALL-001 but noted as a future optimization (CALL-002).

---

## 4. Implementation Plan

### Step 1: Add Pydantic Models (in `app/routers/messaging.py`)

<!-- NOTE: IMPLEMENTED — CallSignalingIn at line 13151, CallSignalingOut at 13161, CallSignalingErrorOut at 13170 (see app/routers/messaging.py:13151-13173). Actual CallSignalingIn.type pattern also includes webrtc.screen_share_start|webrtc.screen_share_stop. -->

**Location**: After `CallActionOut` (line 12935), before `_CALL_ERROR_STATUS_MAP` (line 12945).

**Lines to add**: ~40 lines

```python
class CallSignalingIn(BaseModel):
    type: str = Field(..., pattern=r"^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate)$")
    event_id: str = Field(..., min_length=1, max_length=128)
    conversation_id: str = Field(..., min_length=1, max_length=128)
    recipient_user_id: str = Field(..., min_length=1, max_length=128)
    nonce: str = Field(..., min_length=8, max_length=128)
    sent_at: int
    payload: dict = Field(default_factory=dict)


class CallSignalingOut(BaseModel):
    event_id: str
    call_id: str
    conversation_id: str
    event_type: str
    delivered_to: str
    status: str


class CallSignalingErrorOut(BaseModel):
    code: str
    message: str
```

### Step 2: Add Error Status Map and Feature Gate Helper

<!-- NOTE: IMPLEMENTED — _SIGNALING_ERROR_STATUS_MAP at line 13175, _enforce_webrtc_signaling_enabled at 13199, _enforce_signaling_rate_limit at 13206 (see app/routers/messaging.py:13175-13231). -->

**Location**: After the new models, alongside `_CALL_ERROR_STATUS_MAP` (line 12945).

**Lines to add**: ~35 lines

```python
_SIGNALING_ERROR_STATUS_MAP = {
    "validation_error": 400,
    "unsupported_version": 400,
    "stale_timestamp": 400,
    "unauthorized": 403,
    "forbidden": 403,
    "call_not_found": 404,
    "call_lookup_failed": 503,
    "participant_lookup_failed": 503,
    "replay_detected": 409,
    "replay_guard_failed": 503,
    "invalid_state": 409,
    "delivery_failed": 503,
    "rate_limited": 429,
}

SIGNALING_RATE_LIMIT_WINDOW_SECONDS = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_WINDOW_SECONDS", "10")
)
SIGNALING_RATE_LIMIT_MAX = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_MAX", "60")
)


def _enforce_webrtc_signaling_enabled() -> None:
    if S.messaging_webrtc_direct_call_kill_switch:
        raise HTTPException(status_code=403, detail={"code": "feature_disabled", "message": "WebRTC signaling is disabled"})
    if not S.messaging_webrtc_direct_call_enabled:
        raise HTTPException(status_code=403, detail={"code": "feature_disabled", "message": "WebRTC direct calls are not enabled"})


def _enforce_signaling_rate_limit(user_id: str) -> None:
    now = int(now_ts())
    bucket = now // SIGNALING_RATE_LIMIT_WINDOW_SECONDS
    counter_key = f"SIGNALING_RATE#{user_id}#{bucket}"
    try:
        resp = tbl_events.update_item(
            Key={"user_id": counter_key, "event_id": "counter"},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#c": "counter", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":ttl": now + SIGNALING_RATE_LIMIT_WINDOW_SECONDS * 2,
            },
            ReturnValues="UPDATED_NEW",
        )
        count = int(resp.get("Attributes", {}).get("counter", 0))
        if count > SIGNALING_RATE_LIMIT_MAX:
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "Signaling rate limit exceeded"},
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Fail open -- do not block signaling if rate limit check fails
```

### Step 3: Add Endpoint Handler

<!-- NOTE: IMPLEMENTED — send_signaling_event at line 13249, SIGNALING_ENDPOINT_RESPONSES at 13234, route at /messages/calls/{call_id}/signal (see app/routers/messaging.py:13244-13288). -->

**Location**: After `timeout_call_endpoint` (line 13113), in a new section.

**Lines to add**: ~45 lines

**File**: `app/routers/messaging.py`

```python
# ---------------------------------------------------------------------------
# WebRTC Signaling Relay
# ---------------------------------------------------------------------------

SIGNALING_ENDPOINT_RESPONSES = {
    400: {"model": CallSignalingErrorOut, "description": "Invalid signaling envelope"},
    403: {"model": CallSignalingErrorOut, "description": "Feature disabled or forbidden"},
    404: {"model": CallSignalingErrorOut, "description": "Call session not found"},
    409: {"model": CallSignalingErrorOut, "description": "Replay detected or invalid state"},
    429: {"model": CallSignalingErrorOut, "description": "Rate limit exceeded"},
    503: {"model": CallSignalingErrorOut, "description": "Service temporarily unavailable"},
}


@router.post(
    "/messages/calls/{call_id}/signal",
    response_model=CallSignalingOut,
    responses=SIGNALING_ENDPOINT_RESPONSES,
)
async def send_signaling_event(
    call_id: str,
    body: CallSignalingIn,
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_signaling import SignalingValidationError, route_signaling_event

    _enforce_webrtc_signaling_enabled()
    _enforce_signaling_rate_limit(user_id)

    envelope = {
        "type": body.type,
        "version": 1,
        "event_id": body.event_id,
        "call_id": call_id,
        "conversation_id": body.conversation_id,
        "sender_user_id": user_id,
        "recipient_user_id": body.recipient_user_id,
        "nonce": body.nonce,
        "sent_at": body.sent_at,
        "payload": body.payload,
    }

    try:
        ack = route_signaling_event(envelope=envelope, actor_user_id=user_id)
    except SignalingValidationError as exc:
        raise HTTPException(
            status_code=_SIGNALING_ERROR_STATUS_MAP.get(exc.code, 400),
            detail={"code": exc.code, "message": str(exc)},
        )

    return CallSignalingOut(
        event_id=ack.event_id,
        call_id=ack.call_id,
        conversation_id=ack.conversation_id,
        event_type=ack.event_type,
        delivered_to=ack.delivered_to,
        status=ack.status,
    )
```

### Step 4: Update Frontend SSE Handler

<!-- NOTE: IMPLEMENTED — webrtc.offer/answer/ice_candidate already in EVENT_TYPES at lines 181-183 and webrtc.* dispatch block at lines 132-141 (see frontend/src/hooks/useMessagingStream.ts:132-183). -->

**File**: `frontend/src/hooks/useMessagingStream.ts`

**Change**: Add three entries to the `EVENT_TYPES` array (after line 177):

```typescript
const EVENT_TYPES = [
  // ... existing entries ...
  "call.invite",
  "call.accept",
  "call.decline",
  "call.end",
  "webrtc.offer",       // NEW
  "webrtc.answer",      // NEW
  "webrtc.ice_candidate", // NEW
];
```

**Also**: The `handleEvent` function already handles `eventType.startsWith("call.")` to dispatch `CustomEvent`. WebRTC signaling events start with `"webrtc."` not `"call."`, so add a parallel dispatch block:

```typescript
if (eventType.startsWith("webrtc.")) {
  window.dispatchEvent(
    new CustomEvent("messaging:webrtc-signal", {
      detail: {
        ...data,
        event_type: eventType,
      },
    }),
  );
}
```

### Step 5: Add Frontend API Endpoint Wrapper

<!-- NOTE: IMPLEMENTED — SignalingPayload at line 929, SignalingAck at 939, sendSignalingEvent at 948 (see frontend/src/api/endpoints/messaging.ts:929-953). -->

**File**: `frontend/src/api/endpoints/messaging.ts`

```typescript
export interface SignalingPayload {
  type: "webrtc.offer" | "webrtc.answer" | "webrtc.ice_candidate";
  event_id: string;
  conversation_id: string;
  recipient_user_id: string;
  nonce: string;
  sent_at: number;
  payload: Record<string, unknown>;
}

export interface SignalingAck {
  event_id: string;
  call_id: string;
  conversation_id: string;
  event_type: string;
  delivered_to: string;
  status: "delivered" | "duplicate";
}

export async function sendSignalingEvent(
  callId: string,
  data: SignalingPayload,
): Promise<SignalingAck> {
  const resp = await client.post(`/messaging/messages/calls/${callId}/signal`, data);
  return resp.data;
}
```

### Step 6: Environment Variable Defaults

<!-- NOTE: These env vars are read at runtime via os.environ.get() with defaults in messaging_call_signaling.py:34-36 and messaging.py:13191-13196. They have NOT been added to .env.local.example yet. -->

**File**: `.env.local.example`

Add:
```
MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_WINDOW_SECONDS=10
MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_MAX=60
MESSAGING_WEBRTC_SIGNALING_MAX_SKEW_SECONDS=120
MESSAGING_WEBRTC_SIGNALING_NONCE_TTL_SECONDS=600
MESSAGING_WEBRTC_SIGNALING_MAX_PAYLOAD_BYTES=8192
```

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/routers/messaging.py` | Add models, helpers, endpoint | ~120 |
| `frontend/src/hooks/useMessagingStream.ts` | Add event types + dispatch | ~10 |
| `frontend/src/api/endpoints/messaging.ts` | Add API wrapper | ~25 |
| `.env.local.example` | Add env var documentation | ~5 |
| **Total** | | **~160** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_messaging_call_signaling_endpoint.py`)

<!-- NOTE: This file does not exist yet — new implementation required. The existing tests/test_messaging_call_signaling.py (517 lines) covers the service layer but not the HTTP endpoint layer. -->

New file, ~300 lines. Tests the HTTP layer using the FastAPI test client.

**Test cases**:

1. **Happy path: webrtc.offer delivery**
   - Seed a call session in "accepted" state
   - POST valid offer envelope
   - Assert 200, status="delivered", delivered_to=recipient

2. **Happy path: webrtc.answer delivery**
   - Same setup, send answer from callee to caller
   - Assert 200, delivered

3. **Happy path: webrtc.ice_candidate delivery**
   - Send ICE candidate in both directions
   - Assert 200 each time

4. **Duplicate delivery (idempotent)**
   - Send same event_id twice
   - First returns "delivered", second returns "duplicate"
   - Both return 200 (not error)

5. **Feature disabled (kill switch)**
   - Set `messaging_webrtc_direct_call_kill_switch=True`
   - Assert 403, code="feature_disabled"

6. **Feature disabled (not enabled)**
   - Set `messaging_webrtc_direct_call_enabled=False`
   - Assert 403, code="feature_disabled"

7. **Invalid type rejected**
   - Send `type: "call.invite"` (lifecycle event, not allowed through this endpoint)
   - Assert 422 (Pydantic validation) or 400

8. **Stale timestamp**
   - Set `sent_at` to 5 minutes ago
   - Assert 400, code="stale_timestamp"

9. **Replay nonce rejected**
   - Send valid event, then send different event with same nonce
   - Assert 409, code="replay_detected"

10. **Call not found**
    - Use non-existent call_id in URL
    - Assert 404, code="call_not_found"

11. **Invalid state (offer while invited)**
    - Call in "invited" state, send webrtc.offer
    - Assert 409, code="invalid_state"

12. **Non-participant rejected**
    - Authenticated as user C, try to send signaling for call between A and B
    - Assert 403, code="forbidden"

13. **Recipient not in call**
    - Send to a user who is in the conversation but not in this call
    - Assert 403, code="forbidden"

14. **Payload too large**
    - Send payload exceeding 8KB
    - Assert 400, code="validation_error"

15. **Rate limit exceeded**
    - Send 61 events within 10 seconds
    - Assert 429 on the 61st

16. **Auth required (no session)**
    - Send request without authentication
    - Assert 401 or 403

17. **CSRF required (cookie auth)**
    - Send with cookie auth but missing CSRF header
    - Assert 403

### 5.2 E2E Tests (`frontend/e2e/webrtc-signaling.spec.ts`)

<!-- NOTE: This file does not exist yet — new implementation required. -->

New file, ~400 lines. Tests the full round-trip: HTTP POST -> DynamoDB -> SSE stream -> frontend event.

**Section 80: Signaling API (10 tests)**:

1. `Alice sends webrtc.offer to Bob after call accepted` -- verify 200 + ack
2. `Bob sends webrtc.answer back to Alice` -- verify 200 + ack
3. `Alice sends ICE candidate to Bob` -- verify 200 + ack
4. `Bob sends ICE candidate to Alice` -- verify 200 + ack
5. `Duplicate event_id returns status=duplicate` -- verify idempotency
6. `Signaling rejected before call accepted (state=invited)` -- verify 409
7. `Signaling rejected after call ended` -- verify 409
8. `Non-participant cannot send signaling` -- verify 403
9. `Invalid type (call.invite) rejected` -- verify 422
10. `Stale timestamp rejected` -- verify 400

**Section 81: SSE Delivery (5 tests)**:

1. `Bob receives webrtc.offer via SSE after Alice sends it` -- POST from Alice, poll Bob's SSE stream, verify event arrives
2. `Alice receives webrtc.answer via SSE after Bob sends it` -- reverse direction
3. `ICE candidates arrive via SSE within 2 seconds` -- timing assertion
4. `Frontend dispatches "messaging:webrtc-signal" custom event` -- inject page listener, verify CustomEvent fires
5. `Multiple ICE candidates arrive in order` -- send 5 candidates, verify they arrive in FIFO order by event_id

**Section 82: Rate Limiting (3 tests)**:

1. `61st signaling event in 10s window returns 429` -- burst 61 requests
2. `Rate limit resets after window expires` -- send 60, wait 10s, send 1 more -- should succeed
3. `Rate limit is per-user (Bob unaffected by Alice's rate)` -- Alice exhausts limit, Bob can still send

**Test Setup (beforeAll)**:
- Seed sessions via `e2e_admin_session_setup.py`
- Create a DM conversation between Alice and Bob
- Create a call via `POST /messages/calls/invite`
- Accept the call via `POST /messages/calls/{id}/accept`
- This puts the call in "accepted" state, enabling webrtc.* signaling

### 5.3 Edge Cases to Cover

1. **Concurrent offer/answer race**: Both peers send offer simultaneously. The service layer allows this (both are valid in "accepted" state). The frontend must handle "glare" (simultaneous offers) -- out of scope for this ticket but the backend should not block it.

2. **Large SDP payloads**: A typical SDP offer is 2-4KB. Ensure the 8KB limit is sufficient for video calls with multiple codecs and ICE candidates embedded in the SDP.

3. **ICE candidate trickle burst**: A typical peer discovers 10-30 ICE candidates within 1-3 seconds. The rate limit (60/10s) accommodates this with headroom.

4. **Network partition recovery**: If the SSE connection drops and reconnects, the `after` cursor parameter ensures missed signaling events are replayed from the Events table (TTL = 7 days, far exceeding any realistic reconnection window).

5. **Call state transitions during signaling**: A call can be ended while ICE candidates are still being sent. The service layer correctly returns `invalid_state` for post-terminal signaling attempts. The frontend should handle 409 gracefully (not retry, just log).

6. **Clock skew between client and server**: The 120-second skew window (`MAX_SIGNALING_SKEW_SECONDS`) is generous enough for mobile clients with slightly drifted clocks but tight enough to prevent replay of old events.

7. **Nonce collision**: The 8-128 character nonce space with 600s TTL makes collision probability negligible for legitimate use. The conditional write guarantees at-most-once delivery regardless.

### 5.4 Performance/Load Testing Notes

For production deployment, consider:
- Load test with 100 concurrent calls (200 signaling streams) to verify DynamoDB throughput
- Measure p99 end-to-end latency (POST to SSE delivery) under load
- Verify TTL cleanup removes old nonce guards and signaling events correctly
- Monitor `messaging_webrtc_signaling_events_total` and `messaging_webrtc_signaling_latency_seconds` metrics (already wired in the service layer)

---

## Appendix A: Sequence Diagram — Full Signaling Flow

```
Caller Frontend          Backend                    DynamoDB              Callee Frontend
    |                       |                          |                       |
    |-- POST /signal ------>|                          |                       |
    |   {type:offer, ...}   |-- put_item(nonce) ------>|                       |
    |                       |<-- ok -------------------|                       |
    |                       |-- put_item(event) ------>|                       |
    |                       |<-- ok -------------------|                       |
    |<-- 200 {ack} ---------|                          |                       |
    |                       |                          |                       |
    |                       |   [SSE poll_ms later]    |                       |
    |                       |                          |<-- query(user=callee) -|
    |                       |                          |-- Items: [offer] ---->|
    |                       |                          |                       |
    |                       |                          |  CustomEvent fired:   |
    |                       |                          |  "messaging:webrtc-signal"
    |                       |                          |                       |
    |                       |<-- POST /signal ---------|                       |
    |                       |   {type:answer, ...}     |                       |
    |                       |-- put_item(nonce) ------>|                       |
    |                       |-- put_item(event) ------>|                       |
    |                       |-- 200 {ack} ------------>|                       |
    |                       |                          |                       |
    |<-- SSE webrtc.answer--|<-- query(user=caller) ---|                       |
    |                       |                          |                       |
    |   [ICE trickle begins in both directions]        |                       |
```

## Appendix B: Related Tickets

- **CALL-002**: Reduce SSE poll interval for active calls (adaptive polling)
- **CALL-003**: WebSocket upgrade path for signaling (sub-100ms latency)
- **CALL-004**: Signaling event delivery confirmation (read receipts for ICE)
- **CALL-005**: Group call signaling (mesh/SFU topology negotiation)

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/services/messaging_call_signaling.py` | 1-359 | Signaling validation + routing service (fully implemented) |
| `app/services/messaging_call_signaling.py` | 14-33 | `ALLOWED_SIGNALING_TYPES` — 17 types including recording/screenshare/voicemail |
| `app/services/messaging_call_signaling.py` | 41-57 | `STATE_ALLOWED_SIGNALING_TYPES` — state-to-event mapping |
| `app/services/messaging_call_signaling.py` | 60-63 | `SignalingValidationError` class |
| `app/services/messaging_call_signaling.py` | 66-73 | `SignalingAck` dataclass |
| `app/services/messaging_call_signaling.py` | 113-136 | `_validate_envelope()` |
| `app/services/messaging_call_signaling.py` | 139-162 | `_reserve_signaling_nonce()` — DDB conditional write replay guard |
| `app/services/messaging_call_signaling.py` | 186-356 | `route_signaling_event()` — core routing function |
| `app/services/messaging_call_sessions.py` | 19-50 | `CallSessionRecord` dataclass (incl. billing + voicemail fields) |
| `app/services/messaging_call_sessions.py` | 133 | `create_call_session()` |
| `app/services/messaging_call_sessions.py` | 165 | `get_call_session()` |
| `app/routers/messaging.py` | 12896-12960 | Call lifecycle models (`CallInviteIn/Out`, `CallActionOut`, `_CALL_ERROR_STATUS_MAP`) |
| `app/routers/messaging.py` | 12963-13145 | Call lifecycle endpoints (`create_call_invite`, `accept`, `decline`, `end`, `timeout`) |
| `app/routers/messaging.py` | 13151-13173 | `CallSignalingIn`, `CallSignalingOut`, `CallSignalingErrorOut` models |
| `app/routers/messaging.py` | 13175-13189 | `_SIGNALING_ERROR_STATUS_MAP` |
| `app/routers/messaging.py` | 13191-13231 | Rate limit constants + `_enforce_webrtc_signaling_enabled` + `_enforce_signaling_rate_limit` |
| `app/routers/messaging.py` | 13234-13288 | `SIGNALING_ENDPOINT_RESPONSES` + `send_signaling_event` endpoint handler |
| `app/routers/messaging.py` | 1549 | `get_messaging_user_id` auth dependency |
| `app/routers/messaging.py` | 11785-11820 | SSE stream endpoint (`events_stream`) |
| `app/routers/messaging.py` | 6691 | `_enforce_report_rate_limits` (similar DDB counter pattern) |
| `app/core/settings.py` | 1041-1042 | `messaging_webrtc_direct_call_enabled`, `messaging_webrtc_direct_call_kill_switch` |
| `app/core/settings.py` | 1047-1050 | TURN settings (`turn_enabled`, `turn_urls`, `turn_secret`, `turn_ttl`) |
| `frontend/src/hooks/useMessagingStream.ts` | 148-184 | `EVENT_TYPES` array (includes webrtc.offer/answer/ice_candidate) |
| `frontend/src/hooks/useMessagingStream.ts` | 121-141 | `call.*` and `webrtc.*` CustomEvent dispatchers |
| `frontend/src/api/endpoints/messaging.ts` | 929-953 | `SignalingPayload`, `SignalingAck`, `sendSignalingEvent()` |
| `tests/test_messaging_call_signaling.py` | 1-517 | Unit tests for signaling service layer (21 tests) |
| `tests/test_messaging_call_signaling_endpoint.py` | — | Does not exist yet — HTTP endpoint unit tests needed |
| `frontend/e2e/webrtc-signaling.spec.ts` | — | Does not exist yet — E2E tests needed |
