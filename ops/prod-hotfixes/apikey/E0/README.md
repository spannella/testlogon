# APIK EPIC E0 — Foundation + CLOSE THE PROD OVER-SCOPE HOLE (#118)

Spec-of-record: dev clone `android-impl`. This epic folds the prod api-key hotfix into dev
source (spec convergence) and CLOSES the P0 production over-scope hole where any valid `ak_`
key acted as full unscoped OWNER on every un-gated router (groups, video, group/syndicate/
delegate feeds) — including money movement (group treasury spend, fundraiser CRUD, video
re-pricing) — under the global `_api_key_principal_middleware`.

## Root cause of the hole
`get_authenticated_user` (app/auth/deps.py) and `require_ui_session` (app/services/sessions.py)
bridge `request.state.api_key_principal` -> owner identity. Scope checks only run inside
`maybe_enforce_api_key_route_policy`, which only ~8 routers wire. On prod the GLOBAL middleware
set the principal on ALL routers, so the two shared identity bridges granted unscoped owner on
routers that have no policy dep + no registry mapping.

## Tickets

- **E0-1 (spec convergence + admin:all).** Folded the prod global `_api_key_principal_middleware`
  into dev `app/main.py` (registered right after `_playback_entitlement_middleware`). Added the
  `admin:all` wildcard to `api_key_capabilities.py` (canonical set + `WILDCARD_API_KEY_CAPABILITY`
  + `expand_api_key_capabilities` -> full canonical set), the ALLOW short-circuit in
  `api_key_authorization.requires_scope`, and the create/set grant-gate
  `_enforce_wildcard_owner_role_or_403` in `api_keys.py` (admin/root owners only;
  `api_key_wildcard_forbidden` 403 otherwise). Plan-check now excludes `admin:all`.

- **E0-2 (capability families).** `api_key_capabilities.py`: added
  `groups:{read,write,manage,treasury}`, `fundraising:write`,
  `video:{read,write,manage,publish,moderate,monetize}`, `newsfeed:tips`. Inheritance:
  `groups:manage>=write>=read`; `video:manage>=write>=read` and `video:manage>=video:publish`;
  `video:moderate>=video:read`. `treasury`/`fundraising:write`/`video:monetize`/`newsfeed:tips`
  are STANDALONE high-privilege money scopes (never folded into a coarse `*:write`). Routes are
  wired in E4 (groups) / E5 (video) / E1-2 (newsfeed money) — scopes are defined ahead of routes
  by design of this foundation epic.

- **E0-3 (rollout products).** `api_key_rollout.py`: `ROLLOUT_PRODUCTS += ("groups","video")`.
  `settings.py`: `api_key_groups*` / `api_key_video*` flags, phase default **shadow** (promote to
  canary->ga in E6). `validate_api_key_rollout_settings()` passes for the new products.

- **E0-4 (THE SECURITY FIX — fail-closed bridge).** `maybe_enforce_api_key_route_policy`
  (`api_key_policy_enforcement.py`) now sets `request.state.api_key_route_authorized = True` on
  every path that ALLOWS the request (enforce-allow + shadow proceed). The two identity bridges
  (`get_authenticated_user`, `require_ui_session`) now honor an api-key principal **only when that
  marker is set**. Router-level `dependencies=[Depends(maybe_enforce_api_key_route_policy)]` run
  BEFORE endpoint deps (FastAPI inserts them at the front), so the marker is set before the bridge
  reads it on gated routers. Un-gated / session-only routers never set the marker -> the injected
  principal is IGNORED -> request falls through to cookie/bearer auth -> 401 (fail-closed). This is
  a single central chokepoint: new routers default CLOSED. `admin:all` is likewise fail-closed on
  un-modeled routers (its wildcard ALLOW lives inside `requires_scope`, which only runs under the
  policy dep) — it regains reach once E4/E5 model those domains.

- **E0-5 (drift cleanup).** Deleted the phantom registry rows `/v1/files*` (4) and `/v1/newsfeed*`
  (3) from `api_key_route_scope_registry.py` -> `stale_route_count` 7 -> 0. Live product phases
  confirmed `ga` (filemanager/newsfeed/tickets/shopping/messager). `filemanager:admin` retained:
  it inherits read/write/share (not a zero-route scope); admin/* fs routes stay session-only by
  design (§4 INTENTIONAL). `unregistered_live_route_count=131` is the domain backlog worked down
  by E1-E5 (not an E0 deliverable).

## Files changed (dev == prod, byte-for-byte)
app/main.py, app/auth/deps.py, app/services/sessions.py,
app/services/api_key_policy_enforcement.py, app/services/api_key_capabilities.py,
app/services/api_key_authorization.py, app/services/api_keys.py, app/services/api_key_rollout.py,
app/services/api_key_route_scope_registry.py, app/core/settings.py.

## Prod apply (LIVE HOTFIX)
Method: the 9 api-key/auth files overwritten byte-for-byte from dev; `settings.py` targeted-patched
(prod == dev-original for that file). All chowned `ubuntu:ubuntu`, byte-compiled OK, then the live
uvicorn (`app.main:app` :8000) was cycled and served `/openapi.json` 200.
- Prod backups: `<file>.bak_apik_e0_1783908867` for all 9 overwritten files + `settings.py.bak_apik_e0_1783908867`.
- Reproduce apply from a clean dev checkout: `python ops/prod-hotfixes/apikey/E0/apply_apik_e0_patch.py <repo> --apply`
  (18 exact-anchor edits). Mirror generator: `gen_prod_deploy.py`. In-process verifier: `verify_apik_e0.py`.

## VERIFY MATRIX (in-process TestClient on PROD DDB, synthetic keys+users, auto-cleaned; 0 residue)

| Check | BEFORE | AFTER |
|---|---|---|
| HOLE  `messager:read` -> GET /ui/groups (un-gated) | **200 owner (HOLE)** | **401 fail-closed** |
| HOLE  `messager:read` -> GET /ui/videos (un-gated) | **200 owner (HOLE)** | **401 fail-closed** |
| KEYED `messager:read` -> GET /messaging/conversations | 200 | 200 (no regression) |
| KEYED `filemanager:read` -> GET /v1/fs/list | 200 | 200 (no regression) |
| NEG   `messager:read` -> GET /v1/fs/list (wrong scope) | 403 | 403 |
| NF    `newsfeed:read` -> GET /feed (phantom/unmapped) | 403 | 403 (E1 re-points) |
| SESSION cookie (no key) -> GET /ui/groups | 200 | 200 (UI session unaffected) |
| DAK   bogus `Bearer dak_` -> GET /ui/delegation-api/v1/conversations | 401 | 401 (delegation intact) |
| WILD  `admin:all` -> GET /messaging/conversations (gated) | n/a | 200 (wildcard works on gated) |
| WILD  `admin:all` -> GET /v1/fs/list (gated cross-product) | n/a | 200 |
| WILD  `admin:all` -> GET /ui/groups (un-modeled) | 200 | **401 (even wildcard fail-closed)** |
| GATE  non-admin owner create `admin:all` | 403 `api_key_wildcard_forbidden` | 403 |
| GATE  admin owner create `admin:all` | n/a | 200 CREATED |
| E0-5  stale_route_count | 7 | **0** |

LIVE-server smoke (running uvicorn, not just in-process): `messager:read` -> GET /ui/groups = **401**,
GET /ui/videos = **401**, GET /messaging/conversations = **200**.

No regression confirmed to: existing keyed messaging/filemanager routes, wrong-scope denial,
UI-session auth, the `dak_` delegation DM system (code untouched; Bearer path never triggers the
api-key middleware), and money-IN/OUT surfaces (untouched). Un-gated money routes are now
fail-closed for ALL keys pending their domain epics (E4/E5).
