# Messaging Plan: DM Lottery Messages with Weighted Outcomes

## Objective
Add a new DM message type where a sender configures **N weighted choices** (with percentages totaling 100%). When the recipient unlocks the message, a short spinner animation plays and the server reveals one randomly selected preloaded outcome according to configured weights.

Outcome payloads support:
- Text
- Image
- Video

## Product Behavior and Rules
### Sender experience
- Sender creates a "Lottery Message" in a DM compose flow.
- Sender provides 2..N outcomes (configurable max, e.g. 10).
- Each outcome has:
  - label/title (optional)
  - weight percentage (required)
  - payload type (`text | image | video`)
  - payload content (text body or media asset reference)
- UI enforces a valid total weight (exactly 100% with allowed precision rules).
- Sender preview shows the configured chance distribution and unlock presentation.

### Recipient experience
- Recipient sees a locked lottery card in the conversation.
- On tap/click "Unlock":
  1. Client calls server unlock endpoint.
  2. Server atomically selects outcome using configured weights.
  3. Client plays short spinner animation while waiting/reconciling result.
  4. Selected outcome is revealed and persisted for that recipient.
- Unlock is one-time and idempotent per recipient per message.
- Re-open shows the same selected outcome (no reroll).

### Core constraints
- Lottery messages are DM-only (not group) in first iteration.
- Outcome cannot be altered after send.
- Sender cannot see recipient result until unlocked (policy decision: optionally visible via receipts).
- Weighted draw is authoritative on server.

## Data Model and Storage
Add a dedicated message metadata shape:
- `message_type = lottery_dm`
- `lottery_config` (immutable after send):
  - `version`
  - `outcomes[]`:
    - `outcome_id`
    - `weight_bps` (basis points to avoid float precision; total = 10_000)
    - `payload_type`
    - `text_content` or `media_asset_id`
    - `display_label`
- `lottery_unlocks` (per recipient state):
  - `message_id`
  - `recipient_id`
  - `selected_outcome_id`
  - `rng_roll` (optional diagnostic)
  - `unlocked_at`
  - unique constraint on `(message_id, recipient_id)`

Implementation notes:
- Prefer integer weights (`weight_bps`) over decimals to remove rounding ambiguity.
- Store media via existing attachment/media pipeline and reference immutable asset IDs.

## API Contract
### Send lottery message
`POST /messages/lottery`
- Validates DM context and outcome constraints.
- Validates total `weight_bps == 10_000`.
- Persists message + immutable lottery config.

### Unlock lottery message
`POST /messages/{message_id}/lottery/unlock`
- Authenticates recipient authorization.
- In a transaction:
  - If unlock record exists, return existing selection.
  - Else perform weighted draw, persist unlock record, return selection.
- Response includes selected outcome payload metadata for render.

### Fetch message timeline
- Lottery message includes:
  - `lock_state: locked | unlocked`
  - If unlocked by current user, includes selected outcome payload.
  - Does not leak all weighted internals unless explicitly intended by product.

## Weighted Random Selection
Server-side algorithm:
1. Build cumulative ranges from ordered `weight_bps`.
2. Generate uniform integer `r` in `[1, 10_000]` using cryptographically secure RNG.
3. Select first outcome where `r <= cumulative_weight`.

Hardening:
- Deterministic tests for boundary values.
- Validate no zero/negative weights unless explicitly supported.
- Keep RNG and draw logic in shared backend utility with unit tests.

## Client UX and Animation Plan
### Composer
- Add "Lottery" compose mode in DM.
- Dynamic outcome editor (add/remove entries, type picker text/image/video).
- Real-time validation and percent balancing UX.

### Conversation rendering
- Locked state card with CTA: "Unlock".
- Unlock flow states: `idle -> unlocking -> revealing -> revealed`.
- Spinner animation:
  - lightweight CSS/Canvas/Lottie implementation
  - fixed short duration (e.g. 1.2-2.0s) plus network reconciliation
  - supports reduced-motion accessibility fallback

### Reveal rendering
- Text outcome displayed inline.
- Image/video outcome rendered with existing media components and policies.
- Persist and replay revealed state across app reload/devices.

## Security, Abuse, and Policy
- Restrict outcome payloads to existing content policy checks/moderation pipeline.
- Prevent payload tampering via immutable config and signed media references.
- Rate-limit unlock endpoint to limit abuse.
- Audit log: message created, unlocked, and outcome selected (without sensitive media URLs).
- Ensure no client-only RNG affects selected outcome.

## Observability and Analytics
Track:
- Lottery sends count.
- Unlock attempts/success.
- Unlock latency (API + UI reveal time).
- Distribution sanity metrics (aggregate selected percentages vs expected over large sample sizes).
- Error codes: invalid-config, unauthorized, already-unlocked, media-unavailable.

## Rollout Strategy
1. Ship backend + API behind feature flag (`messaging.dm_lottery`).
2. Enable internal users only.
3. Run distribution verification in staging with synthetic traffic.
4. Gradual production ramp by cohort.
5. Keep kill switch for fast disable.

## Testing Plan
### Backend tests
- Schema validation and weight total constraints.
- Weighted draw boundary/unit tests.
- Idempotent unlock semantics under concurrent requests.
- Authorization and DM-only enforcement.

### Frontend tests
- Composer validation for percentages and required payloads.
- Unlock state machine and spinner-to-reveal transitions.
- Persistence of revealed outcome on reload.
- Accessibility checks (labels, reduced motion behavior).

### End-to-end tests
- Sender creates weighted lottery with mixed payload types.
- Recipient unlocks once; repeated unlock returns same result.
- Multi-device recipient consistency.

## Implementation Milestones
- **M1: Spec + contract finalization**
  - Lock payload schema, precision rules, and policy decisions.
- **M2: Backend primitives**
  - Migration, send endpoint, weighted draw utility, unlock transaction semantics.
- **M3: Frontend UX**
  - Composer, locked card, spinner, reveal rendering.
- **M4: Reliability and analytics**
  - Metrics, audit events, concurrency hardening.
- **M5: Flagged rollout**
  - Staging verification, cohort ramp, production launch.
