# webfix — web-UI bug sweep (backend hotfixes)

Backend half of the 5-bug web-UI sweep found driving the TestLogon SPA on the
A15 phone Chrome. The two backend bugs were live-hotfixed on PROD
(`i-08f937fc705ebea75`, `/home/ubuntu/testlogon`) via SSM and mirrored into the
dev clone. The three frontend bugs (routing basename, orders empty/error state,
ad-analytics account picker, alerts tab wrap) are plain `frontend/` edits.

## BUG 2 — `/ui/me` missing `admin_profile` (scopes)
`app/routers/ui_session.py`.

PROD already returned `role` + `is_admin` (an earlier B7-SUPPORT hotfix that is
NOT on main/dev-clone). What was missing was `admin_profile` — the SPA reads
`me.admin_profile.{type,scopes}` to render scope-gated admin nav
(ModerationBoard / DMCA / video-review). Without it, a *scoped* moderation admin
saw the general-admin surface / hidden moderation nav.

Fix: when `is_admin`, resolve the authoritative admin profile and include
`admin_profile: {type, scopes}` in the response. Source of truth is the `users`
table row (`admin_profile`), which `admin_roles` writes; falls back to the
claim-derived profile on the `AuthenticatedUser`, then a general profile.

NOTE: the dev-clone/main baseline `/ui/me` is a one-line
`{user_sub, session_id, ip}` return (no role at all). The dev clone was patched
to the FULL shape (role + is_admin + admin_profile via `require_ui_session` ctx +
`get_authenticated_user` dependency). PROD had the divergent B7 variant, so the
PROD patch only *adds* `admin_profile` on top of the existing role/is_admin.
`apply_webfix_backend.py` targets the PROD (B7) anchor.

## BUG 3 — `GET /ui/orders?limit=50` → 400 for admins
`app/routers/order_lifecycle.py`.

`list_orders_endpoint` raised `400 {code: scope_required}` when an ADMIN listed
with no `user_id`/`status`. The SPA Orders page calls `GET /ui/orders?limit=50`
with no filters, so an admin viewing their own orders got a raw "Bad Request".

Fix: when no scope is supplied, default `target_user` to the caller's own
`user_sub` for admins too (matching the non-admin path and the page's "your
orders" intent). Admins can still pass `?user_id=`/`?status=` to widen.

## Files
- `apply_webfix_backend.py` — idempotent in-place patcher (run on PROD via SSM as
  the code owner; asserts anchors, writes both files). Backups on PROD:
  `app/routers/ui_session.py.bak_webfix2_<ts>` and
  `app/routers/order_lifecycle.py.bak_webfix2_<ts>`.
- `verify_webfix_backend.py` — seeds a scoped-admin into `users`, logs in via
  `/ui/session/start`, asserts `/ui/me` (role/is_admin/admin_profile) and
  `/ui/orders?limit=50` → 200, cleans up. (On PROD the SSM instance role cannot
  PutItem to `users`, so this is the DEV verification path; PROD was verified via
  code-present grep + `/ui/me` 401-unauth liveness + clean restart to openapi 200.)
- `app_routers_ui_session.py.webfix-bug2-admin-profile.patch` — unified diff (PROD).
- `app_routers_order_lifecycle.py.webfix-bug3-orders-400.patch` — unified diff (PROD).

## Rollout
1. probe PROD anchors present (pristine B7 baseline).
2. `cp .bak_webfix2_<ts>` both files.
3. `apply_webfix_backend.py` → AST OK → `chown ubuntu:ubuntu`.
4. `pkill -f "uvicorn app.main"` (as SSM-root) → `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`.
5. openapi 200 (verified). Also applied to the dev `:8000` uvicorn for on-phone re-verify.

## Moderation-admin seed shape (phase-2 re-verify)
Scopes live on the `users` table row as `admin_profile`
(`app/auth/roles.py`: `AdminProfile{type, scopes}` + `normalize_admin_profile`).
A GENERAL admin passes every scope check (`admin_profile_has_scope` returns True
for `type==general`), so moderation nav that is *scope-gated* needs a SCOPED
admin carrying the moderation scopes. Seed into `users` (key = normalize_email):

```json
{
  "user_sub": "<normalize_email(username)>",
  "email": "<username>",
  "role": "admin",
  "password_hash": {"hash_b64": "...", "salt_b64": "...", "iterations": 200000},
  "admin_profile": {
    "type": "scoped",
    "scopes": ["content_moderation", "content_moderation_senior"]
  }
}
```

Canonical scopes (`AdminScope`): `auth_support`, `billing_support`,
`content_moderation`, `content_moderation_senior`, `payment_disputes`.
Use `content_moderation` (+ `content_moderation_senior` for the senior-only
final-call / DMCA actions) to drive ModerationBoard / DMCA / video-review.
`/ui/me` now echoes this profile back so the SPA unhides the moderation nav.
