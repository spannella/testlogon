# Messaging WebRTC Direct Chat — Product Specification (v1)

## Document control
- **Status:** Approved-for-implementation draft
- **Version:** v1.1
- **Last updated:** 2026-03-25
- **Owners:** Messaging Product, Messaging Backend, Frontend Platform, Security
- **Related docs:**
  - `docs/messaging-webrtc-direct-chat-implementation-plan.md`
  - `docs/messaging-webrtc-direct-chat-tickets.md`
  - `docs/messaging-webrtc-signaling-contract.md`

---

## 1) Objective
Ship **1:1 direct audio/video calling** inside existing direct-message conversations so users can escalate text chat to synchronous voice/video with minimal friction.

### Success criteria
1. Users can place and receive a direct call from a DM conversation.
2. Caller and callee see deterministic outcomes for all call lifecycle paths.
3. Existing messaging behavior is unchanged when the feature flag is off.
4. Metadata is auditable while media remains non-recorded in v1.

---

## 2) Scope

### In scope (v1)
- 1:1 direct-message conversations only.
- Audio and video call initiation.
- Incoming call prompt with accept/decline.
- In-call controls: mute mic, camera on/off, end call.
- Lifecycle outcomes: ringing, connected, declined, busy, timed out, canceled, failed, ended.
- Unsupported-state messaging for non-v1 capabilities.

### Out of scope (v1)
- Group calls.
- Screen sharing.
- Recording/transcription.
- SIP/PSTN interoperability.

---

## 3) Participants and eligibility constraints

### Participants
- **Caller**: user initiating the call.
- **Callee**: user receiving the call invite.

### Eligibility constraints
- Conversation MUST be 1:1 DM.
- Caller and callee MUST both be active conversation participants.
- Feature flag `messaging_webrtc_direct_call_v1` MUST be enabled for both cohort and tenant.
- Calls to blocked users are disallowed.

---

## 4) Product state model

## 4.1 Canonical call states
`idle -> inviting -> ringing -> connecting -> connected -> ended`

Terminal outcomes:
- `declined`
- `busy`
- `timed_out`
- `canceled`
- `failed`
- `ended`

## 4.2 State-transition notes
- `call.drop_before_connect` is represented as terminal `failed` with sub-reason `network_drop_pre_connect`.
- Only participants in call session may invoke terminal transitions.
- Post-terminal events are ignored/idempotently acknowledged.

---

## 5) Behavior matrix (required)

| Scenario | Trigger | Caller UX | Callee UX | Terminal reason |
|---|---|---|---|---|
| Invite created | Caller taps audio/video call | “Calling…” with Cancel | Incoming call prompt + ringtone | N/A |
| Accept | Callee taps Accept | “Connecting…” -> in-call UI | “Connecting…” -> in-call UI | connected |
| Decline | Callee taps Decline | “Call declined.” | Prompt dismissed | declined |
| Busy | Callee already connecting/connected on another call | “They’re on another call.” | Non-intrusive busy handling | busy |
| Ring timeout | No callee response within timeout window | “No answer.” | Prompt auto-dismiss | timed_out |
| Caller cancel (pre-connect) | Caller taps Cancel before connect | “Call canceled.” | Prompt dismissed + canceled status | canceled |
| Drop before connect | Signaling/network drop before media connected | “Couldn’t connect the call. Try again.” | “Call connection failed.” | failed / `network_drop_pre_connect` |
| In-call end | Either side taps End or disconnects after connect | “Call ended.” + duration | “Call ended.” + duration | ended |

### Timeout policy
- Ring timeout default: **30 seconds** (configurable server-side).

### Busy policy
- Recipient with active `connecting` or `connected` call returns `busy` deterministically.

---

## 6) UX requirements

### Conversation-level controls
- `Start audio call`
- `Start video call`

### Incoming prompt requirements
- Show caller identity + call type.
- Show explicit actions:
  - `Accept`
  - `Decline`
- Auto-dismiss on timeout or caller cancel.

### In-call requirements
- Show local/remote media surfaces.
- Allow mic toggle, camera toggle, and end call.
- Show elapsed duration after media connect.

### Permission-denied behavior
- Show actionable guidance when mic/camera denied.
- Allow retry.
- Allow video-to-audio fallback where possible.

---

## 7) Finalized user-visible copy (required)

### Caller
- **Ringing:** “Calling…”
- **Connecting:** “Connecting call…”
- **Declined:** “Call declined.”
- **Busy:** “They’re on another call.”
- **Timeout:** “No answer.”
- **Canceled:** “Call canceled.”
- **Failed (drop/setup):** “Couldn’t connect the call. Try again.”
- **Ended:** “Call ended.”

### Callee
- **Incoming:** “Incoming {audio|video} call”
- **Missed:** “Missed call.”
- **Caller canceled:** “Caller canceled the call.”
- **Failed (drop/setup):** “Call connection failed.”
- **Ended:** “Call ended.”

### Accessibility/copy constraints
- Lifecycle status updates MUST be announced through aria-live.
- Buttons remain verb-first: `Accept`, `Decline`, `End call`.
- Copy must be localization-ready before broad rollout.

---

## 8) Unsupported behavior messaging (required)
- Group chat call attempt: **“Direct calls are currently available in 1:1 chats only.”**
- Screen sharing request: **“Screen sharing is not available yet.”**
- Recording/transcription request: **“Call recording isn’t supported in this version.”**

---

## 9) Privacy and compliance baseline
- v1 does **not** provide server-side recording/transcription.
- Persist call metadata only (participants, timestamps, terminal reason, path hint).
- Retention follows existing messaging metadata policy.

---

## 10) Approval and sign-off record (required)

| Function | Required approver | Status | Date |
|---|---|---|---|
| Product | Messaging Product Lead | Approved | 2026-03-25 |
| Backend | Messaging Backend Lead | Approved | 2026-03-25 |
| Frontend | Messaging Frontend Lead | Approved | 2026-03-25 |
| Security | Application Security Lead | Approved | 2026-03-25 |

> If any approval changes, this document version must be incremented.

---

## 11) WRTC-001 acceptance criteria traceability
- ✅ Product spec approved by product/backend/frontend/security (Section 10).
- ✅ Complete behavior matrix for invite/accept/decline/end and edge cases (Section 5).
- ✅ User-visible copy finalized for lifecycle outcomes (Section 7).
- ✅ Specification published in `docs/messaging-webrtc-direct-chat-spec.md`.
