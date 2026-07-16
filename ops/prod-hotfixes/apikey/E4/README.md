# APIK EPIC E4 — Groups parity (#118)

Router-wiring + registry + rollout change. Before E4 the 5 group routers were un-gated,
so under the E0 fail-closed model every key hitting groups (incl. money) got a 401 (the
route never set the `api_key_route_authorized` marker, so the injected principal was
ignored). E4 admits keys on the group routers and models every route so scoped keys work
and money stays gated by distinct high-priv scopes.

## Changes
- **Router wiring (E4-1):** `dependencies=[Depends(maybe_enforce_api_key_route_policy)]`
  added to `user_groups.py`, `group_feed.py` (auth `router` only — `public_group_feed_router`
  stays public), `group_calls.py`, `group_treasury.py`, `group_fundraising.py`
  (`group_fundraising_router` only — `public_*`/`*_internal` webhook routers stay public).
- **Registry (E4-2/E4-3):** 45 rows under `product="groups"`:
  - reads → `groups:read` (list/discover/get/members/pending/feed, call get/participants/
    active/history, treasury balance/ledger/contributors, campaign/fundraiser list/get/stats/donations).
  - mutations → `groups:write` (create group, join/leave/invite/respond/review membership,
    feed post/pin/unpin/delete, call create/join/leave/end/signal/media).
  - settings/role/remove/dissolve → `groups:manage`.
  - **MONEY (SECURITY, E4-3):** treasury contribute/spend/goal → **`groups:treasury`**
    (standalone — `manage` does NOT inherit it); campaign+fundraiser CRUD → **`fundraising:write`**
    (standalone). A plain `groups:write` key CANNOT move money.
  - **confirm-donation is intentionally UNREGISTERED** → stays `require_root_session`; a key
    hitting it 403s `unmapped_route` (fail-closed), a non-root session 403s "root required".
- **Rollout:** `api_key_groups_phase` default **shadow → ga** so scopes actually enforce.

## Drift
46 live group-tagged routes = 45 registered + 1 intentional unregistered (confirm-donation).
0 stale groups rows. App uses UI-session auth (no `X-API-Key` header) → `maybe_enforce`
returns immediately → app behavior unchanged.

## Verify (in-process on PROD DDB, synthetic users/keys, auto-cleaned, 0 residue)
- BEFORE: groups:read→/ui/groups 401, groups:treasury→treasury/spend 401 (fail-closed),
  messager:read→/messaging/conversations 200 (already-keyed).
- AFTER: full positive (write creates group+posts+invites; read lists/gets/feed; manage
  settings/role; treasury contribute/spend/goal past-gate with groups:treasury; fundraiser/
  campaign past-gate with fundraising:write) + negative/security (read!=write, write!=manage,
  **write CANNOT move money**, manage!=treasury, manage!=fundraise, wrong-scope 403,
  confirm-donation fail-closed + root-gated for wildcard/session) + regression (UI session,
  no-cred 401, invalid key 401, admin:all wildcard 200, messager/filemanager keyed intact,
  dak_ delegation intact).

## Apply / verify
    python ops/prod-hotfixes/apikey/E4/apply_apik_e4_patch.py    # idempotent; APIK_ROOT/APIK_REG/... override targets
    APIK_PHASE=AFTER APIK_REPO=<repo> python ops/prod-hotfixes/apikey/E4/verify_apik_e4.py
    python ops/prod-hotfixes/apikey/E4/gen_prod_deploy_e4.py {place|apply|verify_after}  # SSM probes

## .bak
- Prod (kept): `<file>.bak_apik_e4_<ts>` for all 7 patched files.
- Dev working tree: git is source-of-truth (no stray .bak committed).
