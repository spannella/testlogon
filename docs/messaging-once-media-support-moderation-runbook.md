# Once-Media Support & Moderation Runbook (MOM-042)

## Purpose

Define support and moderation workflows for reported once-media abuse, including triage, evidence handling, escalation, and emergency rollback coordination.

## Intake and triage

### Required report fields

- Reporter user id
- Conversation id
- Message id
- Approximate send/open timestamp
- Report reason category (`spam`, `harassment`, `sexual_content`, `self_harm`, `scam`, `other`)
- Whether media was still `pending` or already `consumed` at report time

### Initial triage SLA

- **P0 safety/self-harm/credible threat**: immediate on-call moderation escalation
- **P1 abuse/scam with active spread**: triage within 15 minutes
- **P2 general policy violations**: triage within 4 hours

## Evidence handling workflow

1. Pull message metadata (no token/url disclosure):
   - `consumption_policy`, `media_kind`, `consumption_state`, `consumed_at`, sender/recipient ids.
2. Pull audit events for grant/consume attempts and failure codes.
3. Pull telemetry aggregates by cohort/media kind to detect campaign-level spikes.
4. Record case note with metadata only.

> Do not request raw grant tokens or signed URLs from end users.

## Moderation actions

### Message-level actions

- Revoke/delete message for all recipients where policy and tooling permit.
- Block sender ability to send once-media temporarily.
- Add sender to risk review queue for repeated violations.

### Account-level actions

- Temporary messaging suspension.
- Permanent enforcement for severe/repeat abuse.
- Escalation to trust & safety incident commander for coordinated abuse rings.

## Support response templates

### Reporter acknowledgement

- Confirm receipt and that once-media behavior may limit post-consume content recovery.
- Confirm moderation review is in progress.

### Resolution update

- State whether enforcement was applied, without exposing private account details.
- Provide safety resources if report category requires it.

## Incident operations checklist (with rollback)

When abuse or reliability risk exceeds threshold:

1. Page messaging + trust/safety on-call.
2. Confirm scope by cohort/media kind using once-media dashboard panels.
3. Enable emergency kill switch:
   - Set `MESSAGING_ONCE_MEDIA_ENABLED=0` (global off).
   - Confirm composer toggles and consume/open flows are disabled.
4. If needed, disable sub-flags (`MESSAGING_ONCE_MEDIA_SEND_ENABLED`, `MESSAGING_ONCE_MEDIA_OPEN_ENABLED`) per environment.
5. Announce incident status in ops channel and support channel.
6. Open incident ticket with timeline and affected cohorts.
7. Re-enable only via staged ramp after remediation and sign-off.

Reference: `docs/messaging-once-media-feature-flags-runbook.md`.

## Escalation matrix

- Tier 1 support -> Tier 2 support lead
- Tier 2 support lead -> Moderation on-call
- Moderation on-call -> Security on-call + Messaging on-call (if exploit/replay suspected)
- Incident commander -> Product/Legal communications as needed

## Compliance and data minimization

- Case records must not include media blobs, signed URLs, or grant tokens.
- Store only policy/state metadata and durable audit identifiers.
- Retain case notes per support retention policy.
