# SEC-025: Broadcast Session IDOR + Moderation Report-Flood + Q&A Vote Race

**Ticket**: SEC-025 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4). Related: SEC-005 (admin job-retry IDOR).

## Problem
- **Broadcast session IDOR**: `app/routers/broadcast.py:495-575`
  (`/sessions/{id}/start|stop`, `DELETE /sessions/{id}`) check `_require_operator_role`
  but **not session ownership** (unlike `get_session_route` at :627). Any operator can
  start/stop/delete another creator's session → stream hijack / forced termination.
- **Moderation report-flood auto-takedown**: `app/routers/moderation.py:27-30,174-222`
  caps reports at 8/user/60s and 20/IP/60s — trivially bypassed with multiple
  accounts/proxies to drive content past the auto-takedown threshold → censor a
  victim's content / get them suspended (no subnet throttle, no per-content dedup,
  no human-review gate for coordinated reports).
- **Q&A upvote TOCTOU**: `app/services/broadcast_qa.py:214-254` — the
  "not already voted" ConditionExpression has a check-then-write race; concurrent
  requests double-count, rigging question ranking.

## Fix
- Add `session.created_by == ctx.user_sub` (or ROOT) ownership check to broadcast
  start/stop/delete.
- Moderation: subnet (/24) + account-age weighting, per-content report dedup,
  exponential backoff, and require human review before auto-takedown above a threshold.
- Q&A: make the vote atomic (single `ADD upvoters :uid` + conditional count via a
  versioned update or TransactWrite) so re-votes can't double-increment.

## Testing
pytest: a non-owner operator gets 403 on start/stop/delete of another's session;
N reports from one /24 count as throttled; double-submitting an upvote increments by 1.
