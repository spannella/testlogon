# Contacts hub (Feature 1) — prod hotfix

Backend change: added `GET /ui/contacts/suggestions` ("people you may know") to
`app/routers/contacts.py`. Read-only, own-scoped (`require_ui_session`). Composes
candidates from the social follow graph (followers / following / friend-of-friend
mutuals) + recent DM peers, excluding already-saved contacts, self, and
blocked/blocking users. Returns public profile cards
(`user_id, display_name, profile_photo_url, hint, mutual_count, source`).

No `api_key_route_scope_registry` entry is required: the contacts router is mounted
WITHOUT the `maybe_enforce_api_key_route_policy` dependency (session-only), so the
boot-time drift check never flags it and boot never RuntimeErrors.

## Prod mirror (SSM, instance i-08f937fc705ebea75, us-east-2)

Runbook (byte-identical file swap, keep .bak, self-detaching restart):

1. `prod_inspect_contacts.py`  — snapshot current prod md5 / route / workers.
2. `prod_apply_contacts.py`    — b64-stream the dev `contacts.py` to prod, keep
   `contacts.py.bak_contactshub_latest`, decode + verify md5 == dev
   (`148410fecd6c8e8a3677fe131ea3bc1e`) + `ast.parse` OK.
3. `prod_restart_contacts.py`  — invoke the absolute `/home/ubuntu/restart_backend.sh`
   (it self-detaches via `setsid nohup ... & disown`; do NOT pkill inside the SSM
   shell or it self-kills).
4. `prod_verify_contacts.py`   — poll openapi 200, assert single worker + the new
   `/ui/contacts/suggestions` route present.

Applied result: openapi 200, WORKERS=1, ROUTE_SUGG=1, prod md5 == dev md5.

## Live dev verification

`verify_contacts.sh` — mints HS256 UI cookies for 3 users, builds a follow graph,
and exercises the full round-trip against the dev uvicorn (:8000) over real HTTP:
contacts list/add/favorite/delete, suggestions (mutual/follows-you/you-follow hints,
saved-exclusion, self-exclusion), follow/unfollow/status. All 2xx.
