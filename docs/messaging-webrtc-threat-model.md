# Messaging WebRTC Direct Call Threat Model (WRTC-041)

Date: 2026-04-05  
Owner: Messaging + Security Engineering

## Scope

This threat model covers 1:1 direct-call signaling and lifecycle controls for messaging WebRTC calls, including:

- Signaling envelope validation (`app/services/messaging_call_signaling.py`)
- Call lifecycle mutation surfaces (`app/services/messaging_call_lifecycle.py`)
- TURN credential issuance authorization (`app/services/messaging_turn_credentials.py`)
- Event-stream and call-state client behavior (`frontend/src/pages/messages/*`)

Out of scope for this iteration:

- Media-plane cryptography details beyond DTLS-SRTP defaults
- Global anti-abuse policy tuning and account trust scoring

## Trust boundaries

1. **Authenticated client ↔ API**: bearer/cookie-authenticated requests; user identity asserted server-side.
2. **API ↔ DynamoDB**: persistence for call sessions, timeline events, and signaling delivery queue.
3. **Client ↔ signaling transport**: event payloads are untrusted until validated against authenticated actor and conversation membership.

## Threats and mitigations

### 1) Spoofed signaling sender

**Threat:** Caller forges `sender_user_id` to impersonate another user in the same conversation.

**Mitigations:**
- `sender_user_id` must match authenticated `actor_user_id`.
- Sender and recipient must both be participants in the conversation.
- Sender/recipient self-targeting is rejected.

**Status:** Resolved in current service checks and tested.

---

### 2) Replay of prior signaling envelopes

**Threat:** Attacker replays a prior valid invite/offer/answer/ICE payload to force duplicate state transitions.

**Mitigations:**
- Required `nonce` and `sent_at` fields in signaling envelope.
- Timestamp skew enforcement (`stale_timestamp` rejection outside configured window).
- Nonce reservation guard with TTL (`replay_detected` on duplicate nonce usage).

**Residual risk:** Cross-region race windows are low-probability but not impossible under eventual consistency.

**Risk disposition:** Accepted (low severity) pending distributed nonce-hash replication in a future hardening pass.

---

### 3) Unauthorized lifecycle mutation

**Threat:** Non-participant attempts to accept/decline/end someone else’s call session.

**Mitigations:**
- Lifecycle service requires role-correct actor (caller/callee/participant depending on transition).
- Session-level state machine enforces legal transitions and prevents terminal re-entry.

**Status:** Resolved.

---

### 4) TURN credential abuse

**Threat:** User requests TURN credentials for calls they are not part of or for invalid states.

**Mitigations:**
- TURN issuance validates feature gating, call existence, participant authorization, and call state.
- Short TTL credentials and issuance metrics reduce blast radius and aid detection.

**Status:** Resolved.

## High-risk findings

No unresolved high-risk findings remain for WRTC-041 scope.

## Remediation tracking

- [x] Enforce anti-spoof sender checks on signaling ingress.
- [x] Add replay protection (`nonce`) and stale timestamp rejection.
- [x] Add security tests for spoofed sender, stale timestamp, and replay attempts.
- [x] Document residual risks and formal risk acceptance.

## References

- `app/services/messaging_call_signaling.py`
- `tests/test_messaging_call_signaling.py`
- `app/services/messaging_call_lifecycle.py`
- `app/services/messaging_turn_credentials.py`
