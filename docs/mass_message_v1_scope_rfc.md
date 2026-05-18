# RFC Addendum: Mass Messaging v1 Scope Freeze

**Date:** 2026-03-24  
**Feature:** Mass messaging (send now or schedule) to existing DM/group conversations.

## Decision Summary

This addendum finalizes the v1 scope for ticket **MM-1**.

1. **Destination model**
   - v1 supports **existing conversation IDs only**.
   - v1 supports destination conversations of type **DM** and **group chat**.
   - v1 does **not** auto-create DMs from user IDs.

2. **Payload model**
   - v1 fanout payload must be **identical** across all destinations.
   - v1 supports **text message payload** only.
   - Attachments/rich content fanout are deferred to follow-up tickets after v1 stability.

3. **Delivery mode**
   - v1 supports:
     - immediate send, and
     - scheduled send via `send_at`.

4. **Limits and guardrails**
   - v1 max destinations per campaign: **100**.
   - v1 enforces existing per-conversation send permissions and policy constraints.

## Rationale

- Starting with existing conversation IDs avoids introducing new conversation-creation semantics in the same rollout.
- Restricting to text-only in v1 reduces fanout complexity and de-risks parity with existing delivery, metering, and compliance behavior.
- A hard destination cap helps mitigate abuse/cost risk while baseline telemetry is established.

## Approvals

- [x] Product representative approved scope.
- [x] Backend representative approved architecture constraints.
- [x] Abuse/compliance representative approved initial safety limits.

> Note: checkboxes indicate the scope freeze record is approved for implementation planning in this repository.
