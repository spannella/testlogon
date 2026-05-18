# Jira Ticketing Integration Discovery Notes

## Scope
This discovery artifact implements **JIRA-SYNC-001** from `JIRA_TICKETING_SYNC_TICKETS.md`.

## Current Internal Ticketing Domain (as implemented)

### Core service
- `app/services/tickets.py` is the primary domain service for ticket operations.
- Ticket IDs are generated as `tkt_<12-hex>` and stored with a partition pattern `pk=TICKET#{ticket_id}` plus typed sort keys.

### Main entities
- `ticket_meta` (header): owner, assignee, status, priority-like metadata, timestamps, and versioning for optimistic updates.
- `ticket_message`: user/admin messages threaded under each ticket.
- `ticket_activity`: immutable event-style activity records (`ticket_opened`, `ticket_assigned`, `ticket_status_changed`, etc.).
- `ticket_space` support and space-scoped listing/indexes are present.

### Existing operational behavior
- Status transitions are validated in service logic.
- Listing supports owner, assignee, status, and space-oriented query paths.
- Mutations create activity entries and update timestamp-based sort keys for recency ordering.

## API Surface Observed
- User/admin ticket operations are exposed via routers (`app/routers/tickets.py` and related ticket-space routes).
- Existing list/detail/message semantics are internal-system-native; there is no Jira external-link contract yet.

## Gaps to close for Jira sync
1. No connector/auth model for external Jira sites.
2. No first-class link table between internal ticket IDs and external issue IDs/keys.
3. No inbound webhook endpoint and verification flow for Jira events.
4. No outbound async sync pipeline with idempotency controls.
5. No conflict representation and resolution API for concurrent edits.

## Proposed sequencing confirmation
1. Build foundations (schema + flags + ADR).
2. Implement OAuth + Jira client.
3. Ship read-only Jira visibility.
4. Add linking and outbound sync.
5. Add inbound webhook sync + conflict resolution.
6. Harden with observability, replay tooling, and staged rollout.

## Non-goals for this ticket
- No Jira API calls or sync behavior are implemented here.
- No database schema changes are introduced by this ticket.
