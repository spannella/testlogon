# ADR-0002: Jira ↔ Internal Ticket Sync Directionality, Conflict Ownership, and Non-goals

- **Status:** Accepted
- **Date:** 2026-03-24
- **Deciders:** Backend owner, Frontend owner, Security owner (tracked via ticket JIRA-SYNC-001 sign-off)
- **Related ticket:** `JIRA-SYNC-001`
- **Related planning docs:**
  - `JIRA_TICKETING_SYNC_PLAN.md`
  - `JIRA_TICKETING_SYNC_TICKETS.md`

## Context
We need to integrate Jira Cloud with internal ticketing so users can:
1. View relevant Jira issues in the internal product.
2. Sync linked tickets bi-directionally without data-loss or update loops.

Internal ticketing already has a stable domain model and activity stream, but no external ticket identity, connector auth state, or sync conflict lifecycle.

## Decision

### 1) Sync directionality model
Adopt **bi-directional sync for explicitly linked tickets only**, with separate read-only Jira visibility for unlinked issues.

- **Unlinked Jira issues:** mirrored and visible in read-only mode.
- **Linked items:** eligible for bi-directional field sync based on approved mapping.
- **No global “sync everything” mode** in initial rollout.

### 2) Source-of-truth boundaries
- **Identity + linkage truth:** internal system (`ticket_external_links`).
- **Issue rendering truth for Jira-origin rows:** Jira mirror as the local read model, refreshed by webhook/poll.
- **Shared mapped fields on linked tickets:** eventually consistent with conflict detection when concurrent edits occur.

### 3) Conflict ownership and resolution
- Conflicts are owned by the **internal product UX** (not silent overwrite by background workers).
- On same-field concurrent edits, system records both candidate values and sets ticket/link sync state to conflict.
- Resolution actions are explicit: `keep_internal` or `keep_jira`, each producing an auditable sync event.

### 4) Loop prevention
Use origin metadata + remote update IDs + idempotency keys. Echoed updates caused by our own outbound writes are dropped during inbound processing.

## Consequences

### Positive
- Safer rollout with clear blast-radius controls.
- Deterministic conflict semantics and auditability.
- Reduced risk of silent data loss.

### Trade-offs
- More implementation complexity (link table, conflict states, apply engine).
- Users may need to resolve conflicts manually in some scenarios.

## Non-goals (initial rollout)
1. Jira Data Center/on-prem support.
2. Automatic sync for all Jira issues without explicit linking.
3. Full fidelity replication of all Jira custom fields/workflows.
4. Cross-provider ticket sync beyond Jira.
5. Binary attachment mirroring as default behavior.

## Rollout alignment
This ADR aligns to milestone sequencing in `JIRA_TICKETING_SYNC_TICKETS.md`:
- Milestone A: read-only visibility.
- Milestone B/C: linked bi-directional sync and conflict handling.
- Milestone D: hardening and GA rollout controls.
