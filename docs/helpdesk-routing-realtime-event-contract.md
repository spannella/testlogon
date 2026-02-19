# Helpdesk Routing Realtime Event Contract (HB-016)

This document defines the realtime lifecycle events emitted by messaging helpdesk routing to `/messaging/events` and `/messaging/events/stream` consumers.

## Event types

- `helpdesk.conversation.alerted`
- `helpdesk.conversation.assigned`
- `helpdesk.conversation.released`
- `helpdesk.conversation.no_agents_online`

## Payload schema (`payload`)

All four event types share the same payload envelope:

- `schema_version` (int)
- `conversation_id` (string)
- `event_id` (string)
- `event_type` (string)
- `occurred_at` (unix seconds)
- `routing_group_id` (string)
- `from_state` (string)
- `to_state` (string)
- `routing_state` (string)
- `assignment_version` (int)
- `active_agent_user_id` (string)
- `metadata` (object)

## Compatibility rules

- `schema_version` is currently `1`.
- New optional fields may be added in future schema versions.
- Existing fields are stable and should not be removed/renamed within the same major schema version.
- Unknown fields must be ignored by clients.
- Clients should branch behavior by `event_type` and treat missing/empty optional values defensively.
