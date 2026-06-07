# GROUP-001 gaps

- [LOW] `display_name` never populated from user profile on join/invite — `app/routers/user_groups.py:161` passes `display_name=""` — member display names stored as empty string; contributor list and treasury ledger show user_sub instead of real name — Fix: resolve display_name from `T.profile` at join/invite time (same pattern as messaging) — Effort: S

- [LOW] `list_members` allows any authenticated user to enumerate members of a private group — `app/routers/user_groups.py:139-153` checks private visibility but the membership status check uses `status != "active"` which is correct; however it also allows invited/pending users who have never been active to access the member list — Fix: ensure only `status == "active"` membership grants member list access — Effort: S

- [MED] Pagination missing on `list_members`, `list_user_groups`, and `search_public_groups` — `app/services/user_groups.py:391,415,439` all fetch all items without cursor-based pagination — large groups (up to 10,000 members per `user_group_max_members`) will cause unbounded DDB reads and response bloat — Fix: add `cursor`/`limit` parameters and `ExclusiveStartKey` loop matching the ticket spec — Effort: M

- [LOW] Admin succession scan uses `list_all_members` which issues a full query per succession event; for large groups this is slow — `app/services/user_groups.py:612` — Fix: add a dedicated GSI on `role` + `joined_at` or `promoted_at` for efficient moderator lookup — Effort: M

- [LOW] No rate limiting on group creation, join-request, or invitation endpoints as described in ticket section 9 — router has no rate-limit decorators and settings has no group-specific rate limits — Fix: apply `RateLimiter` dependency at route level per ticket spec (5/hour create, 10/hour join, 50/hour invite) — Effort: S
