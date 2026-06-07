# SYND-001 Gaps — Syndicate Creation & Membership Management

- [HIGH] list_pending_requests exposes join requests to any authenticated user — `app/routers/syndicates.py:267-280` + `app/services/syndicates.py:462-468` — router comment says "Admin-only check done in service" but service has no admin guard; any user can enumerate pending join requests for any syndicate — Fix: add `svc._require_admin(syndicate_id, session["user_sub"])` before service call in the `list_requests` router handler — Effort: S

- [MED] get_audit_log endpoint has no membership or admin guard — `app/routers/syndicates.py:283-300` + `app/services/syndicates.py:482-489` — any authenticated user can read the full audit history (member user IDs, actions, timestamps) of any syndicate — Fix: add `svc._require_admin(syndicate_id, session["user_sub"])` or at minimum `svc._require_is_member(syndicate_id, session["user_sub"])` in the router handler — Effort: S

- [MED] _add_member stores `display_name = user_id` instead of the actual profile display name — `app/services/syndicates.py:535-538` — member list responses always show raw user IDs as display names rather than human-readable names, degrading UX across all member-list endpoints — Fix: call `get_profile(user_id)` and use `profile.get("display_name", user_id)` before writing the member item — Effort: S

- [LOW] No rate-limiting on invite, join-request, or syndicate-creation endpoints — `app/routers/syndicates.py` — spec requires max 20 invites/hour/syndicate, 10 requests/user/hour, 5 syndicates/user/day; none of these guards are implemented — Fix: integrate platform rate-limiter decorator on the three endpoints — Effort: M
