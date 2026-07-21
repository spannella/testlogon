# Contacts Feature 2 — Device contact sync (privacy-safe match) — prod hotfix

Match a user's native Android address book against platform users by EMAIL + PHONE,
privacy-safely (only hashes ever leave the device), and let them add matches to the
Phase-1 Contacts hub.

## Hashing scheme (shared byte-for-byte client<->server)

    id_hash = sha256( APP_CONTACT_MATCH_SALT + ":" + normalized_identifier )   (lowercase hex)

- email: lowercased + trimmed (`app.core.normalize.normalize_email`)
- phone: E.164, default region +1 (`app.core.normalize.normalize_phone`)
- `APP_CONTACT_MATCH_SALT` is a FIXED, NON-SECRET app pepper (default `tl_contact_match_v1`),
  shipped to Android as `BuildConfig.CONTACT_MATCH_SALT`. It is NOT a security boundary — the
  platform already holds every user's email (account PK) and any shared phone, so a matching
  hash reveals nothing new. The salt only raises the bar against precomputed rainbow tables.
  Changing it requires an app rebuild AND a backfill re-run.

## Backend changes

- NEW `app/services/contact_match.py` — hashing + the `ContactMatchIndex` (hash -> user_id)
  read/write helpers. Only HASHES are stored, never raw identifiers.
- NEW table `ContactMatchIndex`, PK `id_hash` (S). Direct get_item lookups (no scan/GSI).
- NEW `POST /ui/contacts/match` on `app/routers/contacts.py` — own-scoped (require_ui_session),
  RATE-LIMITED (`rate_limit_contact_match`, 30/hour), caps hashes/field (413), body is hashes
  only. Excludes self / already-saved / blocked (Phase-1 exclusion logic). Returns match cards
  `{user_id, display_name, profile_photo_url, matched_by}`. No api_key registry entry needed
  (the contacts router carries no api-key policy dependency — boot never RuntimeErrors).
- Registration hook: `create_user_record` indexes the email hash (user_sub IS the email).
- Profile hook: `apply_profile_update` (re)indexes the phone hash when `displayed_telephone_number`
  changes. Both hooks best-effort (never fail the write).
- Settings: `contact_match_salt`, `contact_match_index_table_name`, rate/cap knobs.

## IMPORTANT: prod runs DEV_MODE=1 (DDB-Local at localhost:8001 on the instance)

The running prod uvicorn is launched by `scripts/run_local_mock_backend.sh`, which sources
`.env.local` (DEV_MODE=1, `DDB_ENDPOINT_URL=http://localhost:8001`). So the app's REAL data
store — including `Contacts` (Phase 1) and this feature's `ContactMatchIndex` — lives in the
instance's DDB-Local, NOT real AWS. The EC2 instance role has NO DDB Scan/control-plane perms,
so all table create/verify MUST be done ON the instance against localhost:8001 (source
`.env.local`, use the `.venv` python). Do NOT create the table in real AWS us-east-1.

## Runbook (SSM, instance i-08f937fc705ebea75, us-east-2; runs from the dev host)

1. `prod_inspect_cs.py`          — snapshot prod md5s / route / workers.
2. `prod_apply_cs.py`            — byte-mirror `contacts.py` (md5 == dev
   `f50b07792542db463cc8f84d7e676f0c`) + upload `contact_match.py` + `ops/backfill_contact_match.py`,
   then apply IDEMPOTENT targeted patches to the 5 shared files (settings/tables/registration/
   profile/rate_limit) IN PLACE (those carry prod-only divergence — never byte-clobbered).
   Keeps `.bak_contactsync_*` of every touched file. AST-verifies + marker-checks after.
3. `prod_restart_verify_cs.py`   — restart via absolute `/home/ubuntu/restart_backend.sh`
   (self-detaches; do NOT pkill inside SSM). Polls openapi 200 + single worker + match route.
4. `prod_run_create_backfill.py` — create `ContactMatchIndex` in DDB-Local (localhost:8001,
   sourcing `.env.local`) + run the backfill against the same store.
5. `prod_run_verify.py`          — index count + raw-never-stored inspection + a LIVE match
   over prod HTTP (`POST /ui/contacts/match`).
6. `prod_final_health.py`        — openapi 200 / WORKERS=1 / match + suggestions routes present.

### Applied result (verified)

- Files byte-mirrored/patched, AST OK, markers present. Restart: openapi 200, WORKERS=1,
  `/ui/contacts/match` present.
- Backfill: `users=197 email_hashes=195 phone_hashes=0` (phone is sparsely populated on prod,
  as scoped). `ContactMatchIndex` = 195 items; each item has only `id_hash/user_id/kind/updated_at`
  (no raw email/phone). LIVE match over HTTP returned 200 with the correct matched card.

## Backfill (dev or prod, idempotent + re-runnable)

    # from repo root, with the app env loaded (prod: source .env.local; use .venv python):
    PYTHONPATH=. python ops/backfill_contact_match.py            # apply
    PYTHONPATH=. python ops/backfill_contact_match.py --dry-run  # count only

## Deferred / flagged

- On-device address-book READ is out of the build-gate (Android runtime). The read+hash path is
  covered by the shared client==server hash-vector unit test (proves byte-identical hashes).
- Phone coverage is sparse on prod (0 phone hashes today) because `displayed_telephone_number`
  is optional at signup. New/updated phones index going forward via the profile hook.
- Invite flow: OS share-sheet with a join link (no fake SMS pipeline). A real SMS invite is v2.
