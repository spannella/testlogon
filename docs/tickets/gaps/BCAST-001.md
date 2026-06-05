# BCAST-001 Gap List

- [HIGH] SEC-025 IDOR on lifecycle routes — `broadcast.py:360,402,453` — any admin/root can start/stop/delete another broadcaster's session; no session ownership check — Fix: add `_require_operator_and_owner(session_id, ctx)` helper before lifecycle operations — Effort: S
- [HIGH] Status-filter list exposes all creators' sessions — `broadcast.py:316` — non-admin broadcaster can enumerate all sessions platform-wide via `?status=live` — Fix: scope `list_sessions_by_status` to `creator_id=ctx["user_sub"]` for non-admin callers — Effort: S
- [MED] Audit log no per-operator scoping — `broadcast.py:531` — any operator can omit `actor` param and retrieve audit entries for all actors — Fix: restrict non-root operators to entries where `actor == ctx["user_sub"]` — Effort: S
- [LOW] `BroadcastSessionCreateIn.profile_id` not validated at create time — `broadcast.py:286` — operator can create session linked to another broadcaster's profile, inheriting their DRM credentials — Fix: verify profile exists and `profile.created_by == ctx["user_sub"]` (or admin) before `create_session()` — Effort: S
- [LOW] Missing `broadcast_aws_teardown_timeout_seconds` setting — `broadcast_provider.py:400` — teardown hard-codes 90s; cannot be tuned per environment — Fix: add `broadcast_aws_teardown_timeout_seconds` to `settings.py` and use in provider — Effort: S
