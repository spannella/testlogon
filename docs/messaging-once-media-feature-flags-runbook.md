# Messaging Once-Media Feature Flags Runbook (MOM-003)

## Purpose
Use these flags to roll out one-time-consumption messaging media safely and to provide a rapid kill switch when issues are detected.

This runbook covers:
- backend and client feature gating,
- per-media-type toggles,
- emergency disable steps,
- staging validation criteria before production promotion.

## Flag definitions

### Global gate
- `MESSAGING_ONCE_MEDIA_ENABLED` (default: `0`)
  - `1`: once-media feature family can be enabled via sub-flags.
  - `0`: hard disable for once-media send/open flows across backend + clients.

### Backend gates
- `MESSAGING_ONCE_MEDIA_SEND_ENABLED` (default: `0`)
  - `1`: backend accepts once-media send metadata and persists once-media policy fields.
  - `0`: backend rejects once-media send intent and falls back to normal media behavior.
- `MESSAGING_ONCE_MEDIA_CONSUME_ENABLED` (default: `0`)
  - `1`: backend consume/grant endpoints process once-media consume state transitions.
  - `0`: backend consume/grant endpoint path is disabled.

### Client gates
- `CLIENT_ONCE_MEDIA_COMPOSER_ENABLED` (default: `0`)
  - `1`: show `View once` / `Listen once` toggles in composer where applicable.
  - `0`: hide once-media compose controls.
- `CLIENT_ONCE_MEDIA_OPEN_ENABLED` (default: `0`)
  - `1`: enable once-media open/play consume UX.
  - `0`: client displays unsupported/disabled placeholder for once-media content.

### Per-media-type rollout gates
- `MESSAGING_ONCE_MEDIA_IMAGE_ENABLED` (default: `0`)
- `MESSAGING_ONCE_MEDIA_VIDEO_ENABLED` (default: `0`)
- `MESSAGING_ONCE_MEDIA_AUDIO_ENABLED` (default: `0`)

Interpretation:
- Media-type flags are effective only when global + matching backend/client gate paths are enabled.
- This supports progressive rollout by media type.

## Effective behavior matrix

| Global | Backend send/consume | Client composer/open | Media-type flag | Expected behavior |
|---|---|---|---|---|
| Off | Any | Any | Any | Once-media fully disabled (no send/open flows) |
| On | Off | On | On | Composer may show gated controls, but send/open rejected by backend (use only for preflight testing) |
| On | On | Off | On | Backend supports once-media, client UI hidden/disabled |
| On | On | On | Off | Feature disabled for specific media type |
| On | On | On | On | Once-media enabled for selected media type |

## Progressive rollout sequence

1. **Stage 0: Defaults (all off)**
   - Keep all once-media flags at `0`.
   - Confirm normal media paths are unaffected.

2. **Stage 1: Internal (images only)**
   - Enable:
     - `MESSAGING_ONCE_MEDIA_ENABLED=1`
     - `MESSAGING_ONCE_MEDIA_SEND_ENABLED=1`
     - `MESSAGING_ONCE_MEDIA_CONSUME_ENABLED=1`
     - `CLIENT_ONCE_MEDIA_COMPOSER_ENABLED=1`
     - `CLIENT_ONCE_MEDIA_OPEN_ENABLED=1`
     - `MESSAGING_ONCE_MEDIA_IMAGE_ENABLED=1`
   - Keep video/audio flags at `0`.

3. **Stage 2: Beta (add video)**
   - Enable `MESSAGING_ONCE_MEDIA_VIDEO_ENABLED=1`.
   - Monitor error and consume-success metrics before proceeding.

4. **Stage 3: Expansion (add audio)**
   - Enable `MESSAGING_ONCE_MEDIA_AUDIO_ENABLED=1`.
   - Continue staged ramp by cohort/environment.

## Emergency disable (kill switch)

If severe UX, data integrity, or security issues occur:

1. Set `MESSAGING_ONCE_MEDIA_ENABLED=0`.
2. Redeploy or refresh runtime config.
3. Verify expected outcomes:
   - Composer once-media toggles are hidden.
   - Once-media open/play consume flow is unavailable.
   - Standard media send/open behavior remains functional.
4. Keep per-media-type flags unchanged (optional) to preserve intended rollout config for re-enable.
5. Open incident follow-up with timeline, symptoms, and mitigation summary.

## Staging validation checklist (required before production)

- [ ] With all once-media flags `0`, normal image/video/audio messaging works unchanged.
- [ ] With global on + image-only flag, once-image send/open works while video/audio once-controls remain unavailable.
- [ ] With media-type flag off, corresponding once-media toggle is not shown.
- [ ] Disabling `CLIENT_ONCE_MEDIA_COMPOSER_ENABLED` hides once-media compose controls.
- [ ] Disabling `CLIENT_ONCE_MEDIA_OPEN_ENABLED` prevents consume UX and shows disabled placeholder.
- [ ] Disabling `MESSAGING_ONCE_MEDIA_SEND_ENABLED` causes deterministic backend rejection of once-media send intent.
- [ ] Disabling `MESSAGING_ONCE_MEDIA_CONSUME_ENABLED` disables consume endpoint flow with deterministic error mapping.
- [ ] Emergency kill switch (`MESSAGING_ONCE_MEDIA_ENABLED=0`) validated end-to-end in staging.

## Observability checks during rollout

Monitor these indicators after each flag change:
- Once-media send attempts by media type.
- Consume success/failure rates by media type.
- Error rates for `already_consumed`, `grant_expired`, and `retryable_network`.
- Client-side unsupported/disabled placeholder events.

If thresholds are breached, roll back to previous safe flag state.


## Related runbooks

- `docs/messaging-once-media-threat-model.md`
- `docs/messaging-once-media-support-moderation-runbook.md`
- `docs/messaging-once-media-observability.md`
