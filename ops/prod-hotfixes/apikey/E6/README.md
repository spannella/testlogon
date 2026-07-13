# APIK EPIC E6 — hardening + program-close (#118)

E6 is a **verification + rollout-confirm + Android-alignment** epic. It makes **no backend
source change** (all 7 products were already promoted to `ga`/enforce in E0–E5; the route-scope
registry, capability taxonomy, and rollout module are unchanged). The only shipped code change is
the **Android capability catalog** (`ApiKeyCapabilities.kt`) so the create-key screen offers the
new `groups:*` / `video:*` / money scopes. There is therefore **no prod restart / no SSM deploy**
for E6 — the running prod process from E5 already enforces the final policy.

## Tickets

### APIK-E6-1 — canary→GA promotion + drift/dead-scope gate
`confirm_rollout_and_drift.py` (read-only) asserts the promotion gate:
- All 7 rollout products (`filemanager, newsfeed, tickets, shopping, messager, groups, video`)
  resolve `enforce=True, shadow=False` (phase `ga`). **No silent shadow unscoped pass exists.**
  `dual_credential_mode=prefer_api_key`.
- **`stale_route_count == 0`** — the true green-drift gate: no registry row points at a dead route.
- Gated-but-unregistered routes are **fail-closed (403; exempt == unmapped == deny)**. The
  `unregistered_live_route_count` (~53) is driven entirely by **out-of-program products**
  (`/ui/catalog` 37, `/tickets` 10, `/ui/shop` 4 — the pre-existing E2-5 backlog) plus the
  **intentional** `groups` require_root `confirm-donation` (1) and the **intentional** `video`
  money/moderation/social fail-closed set (19). The registry-drift `status` field reports
  `critical` *only* because that count is > 0 — it is **not** a security exposure: every one of
  those routes denies all keys. The 5 program domains have **0 accidental gated-unregistered
  routes** (newsfeed/messaging/filemanager fully covered; groups only confirm-donation; video only
  the deliberate money/mod deny-list).
- **Dead-scope audit:** every canonical capability is either registry-mapped, a useful grantable
  superset (`filemanager:admin`, `newsfeed:moderate`, `video:manage`), or enforced by a dedicated
  partner subsystem (`ads:*` → `advertiser_api`, `kyc:*` → `kyc_partner_api`). **0 dead scopes** —
  nothing to kill. `admin:all` is the grant-gated wildcard.
- **exempt != allowed** is enforced structurally: policy enforcement reads ONLY the registry, so an
  exempt/omitted route under a gated router is `unmapped_route` 403, identical to unmapped.

### APIK-E6-2 — parity regression suite
`verify_apik_e6.py` — one in-process TestClient run on **PROD DDB** (synthetic keys+users,
auto-cleaned, 0 residue) covering **all 5 domains**. For each domain it proves: a correctly-scoped
key invokes the UI-reachable capability (POS); a wrong-scope/wrong-product key gets 403
`api_key_scope_denied` (NEG); money/moderation routes require their **distinct high-priv scope**
(`newsfeed:tips`, `messager:manage`, `groups:treasury`, `fundraising:write`, `video:monetize`,
`video:publish`, `video:moderate`) and are otherwise fail-closed; and the **E0 over-scope hole
stays shut** (any valid key — incl. `admin:all` — on an un-gated session-only money router
`/ui/billing/*`, `/ui/earnings/*`, `/ui/payouts` returns 401, never injected-owner-200). Plus
no-regression: UI-session cookie unaffected, `dak_` delegation intact, no-key/invalid-key 401,
wildcard cross-product works. **Result: 57/57 GREEN.**

Run (from repo root, prod venv, prod `.env.local` sourced — e.g. via `/tmp/ssm_run.py`):
```
python verify_apik_e6.py         # -> SUITE GREEN, exit 0
python confirm_rollout_and_drift.py   # -> GATE GREEN, exit 0
```

### APIK-E6-3 — Android catalog alignment
`ApiKeyCapabilities.kt` `ALL` + `IMPLICATIONS` now mirror the backend canonical set **exactly
(38/38, 0 missing / 0 extra)**: added `newsfeed:tips`, `groups:{read,write,manage,treasury}`,
`fundraising:write`, `video:{read,write,manage,publish,moderate,monetize}`, and the
groups/video inheritance edges. Money scopes are labelled `(money)` and standalone (no inheritance).
The create-key + detail screens render `GROUPED` chips, so every new scope is a grantable chip.
Build-gate `./gradlew :app:assembleDebug` → **BUILD SUCCESSFUL** (catalog recompiled). The app
still authenticates via UI session, so runtime behavior is unaffected; this only aligns the
grantable-scope catalog.

## dev == prod
The enforcement files (`api_key_route_scope_registry.py`, `api_key_capabilities.py`,
`api_key_rollout.py`, `core/settings.py`) are **unchanged since E5** and remain dev==prod. E6 adds
no divergence.

## Files
- `verify_apik_e6.py` — the durable 5-domain parity regression suite.
- `confirm_rollout_and_drift.py` — rollout-GA + stale-drift + dead-scope promotion gate.
- Android: `android/app/.../feature/apikeys/data/ApiKeyCapabilities.kt` (committed with the epic).
