# Messaging Plan: View-Once Images/Videos and Listen-Once Audio

## Objective
Add support for one-time-consumption media in messenger:
- View-once images
- View-once videos
- Listen-once audio messages

## Scope and Behavioral Specification
Define and align server/client behavior before implementation:
- Sender can mark media as one-time consumption at compose time.
- Recipient can open/play exactly once per message recipient entry.
- Message state transitions from `pending` to `consumed` after first valid consume event.
- UX and policy decisions to finalize:
  - Backup/restore behavior for one-time media.
  - Forward/copy/save/share restrictions.
  - Group message semantics (per recipient one-time consumption).
  - Unread count and notification behavior before/after consume.
  - Failure handling when open/play is interrupted.

## Data Model and API Contract
Add message metadata and per-recipient consumption state:
- `consumption_policy`: `none | view_once | listen_once`
- `media_kind`: `image | video | audio`
- `consumption_state`: `pending | consumed | expired | failed`
- `consumed_at` timestamp (per recipient)
- `consumption_attempt_id` for idempotent consume requests

Implementation notes:
- Persist consumption state per recipient, not as a single shared message flag.
- Add migrations and version API schema updates to avoid client breakage.

## Upload, Storage, and Delivery Controls
Treat once-media as highly constrained assets:
- Attach ephemeral policy metadata at upload.
- Serve via short-lived grants/URLs.
- Enforce no-store cache controls for once-media responses.
- Keep thumbnails/previews minimal and policy-compliant.

## Server Consumption Protocol (Authoritative)
Implement server-enforced one-time access:
1. Recipient requests media access.
2. Server validates recipient authorization and current consumption state.
3. If state is unconsumed, issue one-time grant and atomically transition state.
4. Subsequent requests return `already_consumed`/`expired` responses.

Concurrency and idempotency:
- Use transactional compare-and-set to prevent multi-device race double-consume.
- Support safe retries with `consumption_attempt_id`.

## Client UX Plan
### Composer
- Add toggles:
  - `View once` for image/video attachments
  - `Listen once` for audio recordings

### Conversation UI
- Render badges for one-time media type.
- Replace playable content with consumed state after first successful consume.
- Sync consumed state across recipient devices.

### Accessibility
- Provide explicit labels and state announcements for assistive technologies.

## Security and Privacy Hardening
- Restrict forwarding/export flows as policy allows.
- Minimize decrypted media persistence (prefer in-memory handling).
- Ensure telemetry/logging excludes media keys and sensitive URLs.
- Review replay and token theft attack paths.

## Observability and Operations
Track rollout and runtime health with non-sensitive metrics:
- Sent counts by one-time media type.
- Open/play success and failure rates.
- Grant latency and consume conflict rates.
- Error codes: `already_consumed`, `grant_expired`, `retryable_network`.

## Test Plan
Automated and manual validation across:
- 1:1 and group chats.
- Multi-device recipient race conditions.
- Offline-to-online transitions.
- Interrupted playback/open flows.
- State sync after app restart.
- Regression coverage for normal media behavior.

## Feature flag and kill-switch runbook
Operational enable/disable and staged rollout controls are documented in:
- `docs/messaging-once-media-feature-flags-runbook.md`
- `docs/messaging-once-media-rollout-checklist.md`

## Rollout Strategy
1. Ship behind feature flag for internal testing.
2. Expand to limited beta cohort.
3. Ramp gradually with metric-based gates.
4. Keep kill switch available for rapid rollback.

## Milestones
- **M1: Specification and schema**
  - Finalize behavior and API contracts.
  - Land DB migrations and message schema extensions.

- **M2: Backend enforcement**
  - One-time grant endpoint and atomic consume transition.
  - Idempotency, retry semantics, and core telemetry.

- **M3: Client implementation**
  - Composer toggles, message rendering, and consume UX.
  - Multi-device state sync handling.

- **M4: Hardening and QA**
  - Security controls and race-condition verification.
  - Full regression and rollout checklist.

- **M5: Launch**
  - Controlled ramp, monitoring, and production release.
