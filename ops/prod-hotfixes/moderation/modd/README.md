# MOD-D2 hotfix — GET moderation/cases/mine (poster's own cases)

Adds a poster-facing listing endpoint so the app's "My content under review"
screen can enumerate the caller's own moderation cases:

- GET /v1/moderation/cases/mine   (router)
- GET /moderation/cases/mine      (compat_router)

Returns the caller's under_review / hold / awaiting_final cases with the
category set, state, hold_until + days-remaining countdown, and any poster
response. Owner-scoped (FilterExpression owner_user_id == caller) so a case is
visible to its owner even while hidden from the public. Paired with the existing
POST /holds/{case_id}/{respond,close} actions (MOD-A5).

## Apply (idempotent, append-if-absent; runs on dev clone AND prod)
    ROOT=/home/ubuntu/testlogon .venv/bin/python apply_modd_cases.py

py_compile-validated in the script. Anchor-free append (skips if _list_my_cases
already present), so it is safe on the line-offset-diverged prod copy.

## Deployed
- Prod EC2 i-08f937fc705ebea75 via SSM: probe on a copy -> real apply -> restart
  -> openapi 200 -> routes registered on both routers (IMPORT_OK verified).
  Backup: app/routers/moderation.py.bak_modd_<epoch>.
- Dev clone: applied in-place (same script).
