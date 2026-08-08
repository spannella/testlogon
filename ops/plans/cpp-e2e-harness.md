# cpp-native e2e harness — scope + build plan

**Status:** SCOPED 2026-07-23. Phase F2 (seed harness) in progress. Owner: Claude/Sean.
**Why:** the existing web Playwright suite (429 specs) and Android tests cannot run against the
C++ backend (`testlogon-cpp`, .82) — they are hard-pinned to the *Python* backend. This builds
cpp-native equivalents. See memory `testlogon-cpp-server` for the coupling analysis.

## Why the existing suites don't port (recap)
- Playwright: 288/429 specs hardcode `const API = "http://localhost:8000"`; `auth.setup.ts` mints
  Python-format JWTs (`{sub,sid,iat,exp}` + Python secret) that fail cpp's signature/session model;
  seed is Python (`scripts/e2e_admin_session_setup.py` + DDB-Local single-table schema).
- Android: 92 `androidTest` + 4540 unit tests are ALL fakes (0 hit a backend); no Maestro flows.
  There is nothing to repoint — both Android tracks are greenfield.

## cpp facts grounding the plan (verified 2026-07-23)
- Auth: register `POST /ui/register/start {email,password,full_name}`; dev-login
  `POST /ui/session/start {challenge_context:{username,password}}` -> cookies `ui_session` +
  `ui_access_token` (JWT `{email,sub,iat,exp,jti}`) + `ui_csrf`. Mutations need `X-CSRF-Token` header.
- Schema: `infra/ddb_schema.json` = 406 tables (direct-moto seed source of truth).
- Admin grant: `role:"admin"` on the user's moto item; root = configured `g_root_user_sub`.
  `require_admin` -> 403 unless admin/root.
- No seed/bootstrap endpoint -> seed = API-driven + direct-moto for privileged bits.
- Side-effect assertions: `/internal/dev-tools/{email,sms,billing}`.
- Env: moto :5005, stunnel :5443 (TLS->moto), redis :6379; server `tlccpp.service` (:8080 + :8443).
- Feature-flag-disabled in cpp dev (expect 503, quarantine): orders/CRM/sales/shipping/cognito.
- Unported routes (quarantine or port first): `/ui/contacts/suggestions`, `/ui/contacts/match`.

## Phase F — Shared Foundation (blocks both tracks)
- **F1** dedicated test env on .82: `TLC_TEST=1` scope on a fresh/prefixed moto namespace; reset =
  restart moto + re-seed. Reuses existing systemd-linger + stunnel + redis.
- **F2** seed harness (CRITICAL PATH, ~60% effort): idempotent seeder recreating the fixture world
  (`e2e_bob`, `e2e_alice`, `root` + follows/conversations/posts/products). HYBRID:
  - API-driven for anything with a public route (register, dev-login, follow, conversation, post).
  - Direct-moto writes (against the 406-table golden schema) for privileged fixtures with no public
    route: `role:"admin"`, KYC-verified, wallet balances, entitlements. Mirrors the Python seed +
    the admin-account trick (see memory `android-test-fleet-admin`).
  - Output: named accounts + a cpp cookie `storageState` per user (real login) — consumed by both tracks.
- **F3** reset/isolation contract: per-run clean seed; documented account/fixture manifest.
  Deliverables: `seed_cpp.(ts|py)`, `reset_cpp.sh`, fixture manifest.

## Track W — Web Playwright against cpp
- **W1** de-hardcode API base: codemod the 288 specs to import
  `API = process.env.E2E_API_BASE ?? "http://localhost:8000"` from `e2e/cpp.config.ts`. Repoint via
  the existing vite same-origin proxy (already -> `https://192.168.0.82:8443`, `secure:false`).
- **W2** rewrite `auth.setup.ts`: drop JWT-minting; register-or-login through cpp, save real-cookie
  `storageState` (from F2).
- **W3** triage -> green gate + quarantine (agent-scale): run all 429, categorize failures
  (cpp-route-missing / flag-disabled / seed-gap / behavioral-diff / python-only). Output: cpp green
  subset as the gate + documented quarantine = the honest web<->cpp parity measure.

## Track A — Android against cpp (greenfield)
- **A1** client-contract (highest ROI, deterministic): new `cppE2e` sourceset instantiating the app's
  real `core-network` Retrofit + Moshi against cpp; assert every endpoint deserializes. Catches
  wire-format/DTO drift with no device flakiness. Uses debug variant's cpp SAN-cert trust + F2 seed.
- **A2** black-box on-device (Maestro): greenfield YAML flows driving the real app against cpp
  (login -> message -> post -> tip -> feed) on .238/.101 or an emulator. Maestro reads the
  accessibility tree (FLAG_SECURE blocks screencap, NOT assertions) -> assertions work on secure
  screens; use flow logs + cpp server log as proof.

## Effort & sequencing
| Phase | Effort | Notes |
|---|---|---|
| F2 seed harness | L (~2-4d) | critical path; API + direct-moto hybrid over 406 tables |
| F1/F3 env+reset | S (~0.5d) | reuses systemd/moto |
| W1+W2 | M (~1d) | mechanical codemod + real-login auth |
| W3 triage | M-L (~1-2d) | agent-scale over 429 |
| A1 contract | M (~1-2d) | best Android ROI |
| A2 Maestro | M (~1-2d) | per journey set; device-bound |

Order: F -> W1-W3 -> A1 -> A2. F2 gates everything.

## Risks
- Seed fidelity is the whole ballgame (seed-gap vs behavioral-diff must be separated in triage).
- Flag-disabled subsystems (orders/CRM/sales/shipping = 503) -> quarantine, don't chase.
- 2 unported contacts routes -> quarantine or port first.
- Host limits: .82 stays cpp-only; .249 single Gradle/Node host, no easy power-cycle -> run serially.

## Open decisions
1. Green-gate target: green-subset+quarantine (default) vs 100% portable-passing (bug-fix program).
2. Android emphasis: A1 only vs A1+A2.
3. Privileged-fixture seed: direct-moto (default, fast/brittle) vs API-only (needs admin endpoints).

---

## F2 RESULT — DONE + PROVEN (2026-07-23)
Seeder `e2e/seed_cpp.py` (in the cpp repo on .82; 149 lines, boto3+urllib stdlib, idempotent). Run:
`cd ~/projects/testlogon-cpp && python3 e2e/seed_cpp.py`. **21/21 PASS.** Proves the hybrid seed:
- 3 users (`e2e_bob`/`e2e_alice`/`e2e_admin`, pw `Passw0rd!123`) register (`/ui/register/start`) +
  dev-login (`/ui/session/start {challenge_context}`) via cpp API -> real cookies
  (`ui_session`/`ui_access_token`/`ui_csrf`) + `/ui/me` sub.
- **Privileged fixture via direct-moto:** `tlc_users` key = **`user_sub`** (not email); write `role:"admin"`
  via boto3 `update_item` (moto :5005). **PROVEN EFFECTIVE:** bob=403 vs e2e_admin=200 on real admin routes
  `/ui/admin/ad-platform/accounts`, `/admin/roles/audit`, `/tickets/admin/summary` — the role flips cpp's
  `require_admin` gate, not just sets a field.
- **Fixture data via API:** alice->bob follow = `/ui/social/follow {target_user_id}` -> 200 (follower_count 1);
  bob post = `POST /posts {body,visibility}` -> 200 (NOTE: `/newsfeed` is 404 in cpp; use `/posts`).
- **Outputs** (in `~/projects/testlogon-cpp/e2e/out/` on .82): `{bob,alice,admin}.storageState.json`
  (Playwright format; cookie `domain` defaults to `localhost`, retarget at W2 via `E2E_COOKIE_DOMAIN`) +
  `manifest.json` (accounts/subs/roles/csrf/paths).

### F2 residuals / next
- Seeder currently writes into the SHARED demo moto (not isolated) -> **F1** = dedicated `TLC_TEST` moto
  namespace/prefix + a run that never touches demo data. **F3** = `reset_cpp.sh` (restart moto + re-seed) +
  publish the fixture manifest.
- True `root` (vs admin) needs `g_root_user_sub` env = the root user's sub + cpp restart (admin covers
  `require_admin`; only root-only routes need this).
- storageStates live on .82; W-track must copy them to .249 (or the seeder runs from .249 against cpp:8443
  for API bits — but direct-moto writes need .82 localhost, so seeding stays on .82).
- Broaden fixtures as W3 triage surfaces `seed-gap` failures (conversations, products, KYC-verified, balances).
