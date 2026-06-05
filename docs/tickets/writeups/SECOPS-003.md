# SECOPS-003: Honeypots & Honeytokens (Canaries) — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-003 deploys high-confidence, near-zero-false-positive detection artifacts: bait that legitimate users never touch, so any interaction is immediately classified as malicious. Three categories of bait are needed:

1. **Decoy HTTP routes** — paths that real application traffic never uses (WordPress admin, PHP shells, AWS credential endpoints) whose mere access signals a scanner or exploit attempt.
2. **Honeytoken records** — artificial DynamoDB items (a fake admin user, a canary API key, a canary file, a planted payment method) that are never accessed by normal flows; access signals IDOR enumeration or stolen-credential replay.
3. **Form field traps** — hidden HTML inputs (bot honeypots) that legitimate browsers leave empty; bots that fill them reveal themselves without any CAPTCHA friction.

Every trip fires a `honeypot.hit` or `honeytoken.used` event via SECOPS-001 and feeds SECOPS-002's auto-ban engine (which applies an immediate IP block on any honeypot hit with threshold=1).

- **Type**: security hardening / detection
- **Priority**: Medium-High
- **Status**: Open
- **Attacker class**: 🌐 any-user (route scanners, automated exploiters, IDOR crawlers, credential stuffers)
- **Emits to**: SECOPS-001 (`honeypot.hit`, `honeytoken.used`)
- **Triggers**: SECOPS-002 auto-ban (threshold=1 for honeypot hits)
- **Dependencies**: SECOPS-001 (emitter must exist); SECOPS-007 (dev/prod parity — canary items must be seedable deterministically in dev/test so E2E tests can trip and confirm them without false-positive risk to the full test suite).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Router registration — no existing honeypot routes

`app/main.py` registers 50+ routers. A search of `app/routers/` finds no route for `/wp-login.php`, `/.env`, `/.git/config`, `/phpmyadmin`, `/actuator/env`, or any equivalent path. These paths would today fall through to the React SPA's catch-all `GET /` → `index.html`, which returns 200 with the app shell — not ideal (it's not deceptive, and it silently gives scanners a valid 200 with no detection signal).

The SPA catch-all is registered in `app/main.py` (the `@app.get("/")` route at `main.py:391`). A honeypot router registered **before** the catch-all will intercept decoy paths before they reach the SPA. FastAPI processes `include_router` in registration order for path matching.

### 2.2 FastAPI path matching — SPA catch-all conflict

The SPA catch-all in `main.py:391` is a `GET /` exact match, not a glob. Vite's frontend uses a proxy-based SPA fallback at the Vite dev server layer. The backend's `index.html` fallback is handled by a `StaticFiles` catch-all. Honeypot routes must be registered **before** any `StaticFiles` mount or wildcard route to ensure they match first. FastAPI routes are matched in definition order; `app.include_router(honeypot_router)` near the top of the router registration block in `create_app()` (after `main.py:424`) would work, but since `StaticFiles` is typically mounted as a `Mount` at the ASGI level (outside FastAPI's router), the honeypot routes being in the router is sufficient — the FastAPI router is matched before the ASGI static mount.

### 2.3 API key system — canary key pattern

`app/services/api_keys.py` (not read in full, but referenced in `app/core/tables.py:313` as `api_keys` table). API key validation happens in `app/auth/deps.py`. A canary API key entry seeded into the `api_keys` DDB table with a known `key_hash` value would trigger `honeytoken.used` when that specific hash appears in a Bearer token.

### 2.4 IDOR enumeration — existing profile lookup rate-limiting

`app/services/rate_limit.py:198` — `rate_limit_profile_lookup(requester_user_sub, ip)` limits anonymous profile lookups to 30/min per IP and authenticated to 120/min. This is rate-limiting, not detection. A canary user record (with a non-guessable but seeded `user_sub`) would fire `honeytoken.used` if ever looked up — without needing to break the rate-limit threshold — catching targeted IDOR enumeration.

### 2.5 File manager — canary file

`app/core/tables.py` includes `file_share_links: Any` and a full file manager table (`T.catalog`, `T.file_share_links`, etc.). A canary file node inserted into the file manager (`T.files` table, though not explicitly wired in the viewed portion of `tables.py`) can fire `honeytoken.used` if its `node_id` is ever fetched by anyone other than the seeding system user. The file manager's `get_node` endpoint returns file metadata; wrapping it with a canary check is minimal.

### 2.6 Frontend form — hidden field pattern

The registration and login forms live in `frontend/src/pages/` (e.g., `Register.tsx`, `Login.tsx`). These use React Hook Form + Zod validation. Adding a CSS-hidden `<input name="website" tabIndex={-1} autoComplete="off" />` and including it in the Zod schema with `website: z.string().max(0, "Bot detected")` makes the validation fail silently — the backend receives the extra field and treats a non-empty `website` value as a bot signal. The frontend form change is trivially small; the backend must extract and check this field.

### 2.7 No existing `honeytoken` or `honeypot` infrastructure

A codebase search for `honeypot`, `honeytoken`, `canary` returns no results in `app/`. This is a greenfield build.

---

## 3. Gap / Threat Analysis

### 3.1 Scanners get valid 200 responses today

Any automated scanner hitting `/.env`, `/wp-login.php`, or `/phpmyadmin` receives the full React app shell (200 OK, ~50KB HTML). This:
- Gives no detection signal.
- Wastes compute serving the SPA bundle to bots.
- Provides false comfort (scanners see a 200 and may retry aggressively).

### 3.2 IDOR enumeration is undetectable below the rate-limit threshold

A patient attacker enumerating user IDs one request per minute never trips the rate-limit. If the enumerated range includes a canary user's sub, that single hit fires an alert.

### 3.3 Stolen credentials — canary API key use

If an attacker exfiltrates the database (or internal documentation) and finds a canary API key string, presenting it in production immediately reveals the breach. This provides extremely early warning for database-exfiltration scenarios (SEC-022).

### 3.4 Bot registration / form flooding

Automated account creation bots that fill every field including hidden ones trip the honeypot form trap immediately at registration. Combined with the SECOPS-001 `honeypot.hit` event and SECOPS-002 auto-ban, a bot IP is blocked before completing registration.

### 3.5 Risk: false positives in the E2E test suite

The Playwright E2E suite navigates to many routes and submits many forms. If canary records are not distinguished from test records, or if honeypot routes are hit by valid Playwright test navigations (e.g., testing error pages), tests will fire `honeypot.hit` and trigger auto-bans for the Playwright worker IP. Mitigation: mark all canary seeds with a `is_canary: True` flag and skip auto-ban for IPs in `tests/` CIDR range in dev, OR ensure Playwright test paths never include the honeypot decoy paths (which they shouldn't if those paths are not in the app routing table used by tests).

### 3.6 Deception integrity

Honeypot routes must return plausible but non-functional responses — not immediately reveal they are traps. `/wp-login.php` should return a minimal HTML form body with HTTP 200; `/.env` should return plausible-looking key=value content (fake values only); `/.git/config` should return a `[core]` block. These are commonly called "tarpits" in blue-team parlance. No real credentials or configuration should ever appear in these responses.

---

## 4. Proposed Design / Fix

### 4.1 `app/routers/honeypot.py` — decoy route router

```python
router = APIRouter(tags=["__honeypot__"])  # tag hidden from OpenAPI if desired

DECOY_ROUTES = [
    ("/.env",                  "env",    200, "APP_KEY=base64:...\nDB_PASSWORD=...\n"),
    ("/.git/config",           "git",    200, "[core]\n\trepositoryformatversion = 0\n"),
    ("/wp-login.php",          "wp",     200, "<html><form><!-- WordPress login --></form></html>"),
    ("/wp-admin",              "wp",     302, None),
    ("/phpmyadmin",            "pma",    302, None),
    ("/admin.php",             "php",    200, "<?php // admin panel ?>"),
    ("/actuator/env",          "spring", 200, '{"activeProfiles":[],"propertySources":[]}'),
    ("/api/v1/debug",          "debug",  200, '{"debug":false}'),
    ("/server-status",         "apache", 200, "Apache Server Status"),
    ("/.aws/credentials",      "aws",    200, "[default]\naws_access_key_id=AKIAIOSFODNN7FAKE\n"),
]

@router.get(path)
async def _decoy(request: Request):
    record_security_event("honeypot.hit", "high", request=request,
        detail={"trap": trap_name, "path": path})
    return Response(content=body, status_code=status_code,
        media_type="text/plain" if status_code == 200 else None)
```

Register in `app/main.py` **before** other routers:

```python
app.include_router(honeypot_router)   # ← very first include_router call
app.include_router(ui_session_router)
# ... remaining routers
```

The decoy routes are active in both dev and prod. In dev, they are useful for testing SECOPS-001 instrumentation. In prod, they are the live detection layer.

### 4.2 Honeytoken records — seeding (`scripts/honeytoken_seed.py`)

A script (runnable as `just seed-honeytokens` and called at stack startup) that inserts:

1. **Canary user**: `T.users.put_item(Item={"user_sub": CANARY_USER_SUB, "email": "canary@internal.invalid", "is_canary": True, ...})`. `CANARY_USER_SUB` read from `S.honeytoken_canary_user_sub` (set in `.env.local.example` to a stable test value). Any `GET /ui/profile/{CANARY_USER_SUB}` or `GET /ui/users/{CANARY_USER_SUB}` hit → `honeytoken.used`.

2. **Canary API key**: Insert a row into `T.api_keys` with `key_hash = sha256(CANARY_API_KEY_PLAINTEXT)` where `CANARY_API_KEY_PLAINTEXT` is stored in `S.honeytoken_canary_api_key`. In `app/auth/deps.py`, after successful key hash lookup, check `if item.get("is_canary"): record_security_event("honeytoken.used", "critical", ...)`.

3. **Canary file**: Insert a file node into `T.files` (or equivalent) with `node_id = CANARY_FILE_NODE_ID`. In the file manager's `get_node` / `download` endpoint: `if item.get("is_canary"): record_security_event("honeytoken.used", "critical", ...)`.

4. **Canary payment method**: Insert a `PM#{CANARY_PM_ID}` row in `T.billing`. In the payment method retrieval endpoint, check `is_canary` flag.

All canary items share a consistent `is_canary: True` field so the E2E suite can skip them in list responses (filter client-side) and so the auto-ban system can annotate the ban reason as "canary record accessed."

### 4.3 Canary identifier range

For IDOR enumeration detection, seed a range of `user_sub` values like `canary_0000` through `canary_0099` (100 entries). Normal users have `user_sub` values generated from Cognito UUIDs — non-guessable. An attacker who enumerates sequential/patterned IDs will hit these ranges. Access to any ID in the canary range fires `honeytoken.used` with the accessed canary ID in `detail`.

Implementation: a middleware hook in the profile lookup endpoint (`GET /ui/profile/{user_sub}`) that checks if `user_sub.startswith("canary_")` before the DDB fetch.

### 4.4 Form field trap — frontend + backend

**Frontend** (`frontend/src/pages/Login.tsx`, `Register.tsx`): add a CSS-hidden field:

```tsx
{/* Honeypot field — must remain empty; bots fill it automatically */}
<input
  type="text"
  name="website"
  style={{ display: "none", position: "absolute", left: "-9999px" }}
  tabIndex={-1}
  autoComplete="off"
  aria-hidden="true"
  {...register("website")}
/>
```

**Frontend Zod schema** (add to both Login and Register schemas):

```ts
website: z.string().max(0).optional(),
```

**Backend**: `app/routers/ui_session.py` and `app/routers/register.py` — extract `body.website`; if non-empty, fire `record_security_event("honeypot.hit", "medium", request=request, detail={"trap": "form_field"})` and return 400 `{"code": "invalid_request"}` (not "bot detected" — reveal nothing).

### 4.5 Configurable canary set

Canary values (`CANARY_USER_SUB`, `CANARY_API_KEY`, `CANARY_FILE_NODE_ID`, canary ID ranges) are read from `Settings` / env vars with stable dev defaults documented in `.env.local.example`. Production values must differ from dev defaults. The seeding script is idempotent (uses `ConditionExpression="attribute_not_exists(user_sub)"` to avoid overwriting).

### 4.6 Dev/Prod parity (SECOPS-007)

| Layer | Dev | Prod |
|-------|-----|------|
| Decoy routes | Active — used by E2E tests to verify honeypot.hit emission | Active — live detection |
| Honeytoken records | Seeded by `honeytoken_seed.py` using `S.honeytoken_canary_user_sub` etc. | Same script, different env-var values |
| Form trap | Enabled in both (`S.honeypot_form_trap_enabled`, default True) | Same |
| `is_canary` filter | DDB Local — same code path | DynamoDB |
| SECOPS-001 `record_security_event` | Writes to DDB Local | Writes to DynamoDB |
| Auto-ban on honeypot hit | SECOPS-002 auto-ban with threshold=1 | Same |

In dev, the decoy routes being active is acceptable because Playwright tests never navigate to `/.env` or `/.git/config`. If a test accidentally hits a decoy route, the test will fail with a `403` or unusual response — which is itself a useful signal that something is wrong with the test routing.

### 4.7 OpenAPI visibility

Set `include_in_schema=False` on all honeypot decoy routes so they do not appear in `/docs` or the generated OpenAPI spec. This prevents the traps from being revealed to anyone browsing the API documentation.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_honeypots.py`)

- **Decoy route — event emitted**: `GET /.env` → assert response status is 200, body contains fake content, and `T.security_events` contains one item with `event_type="honeypot.hit"`, `detail.trap="aws_env"`.
- **All decoy routes registered**: iterate `DECOY_ROUTES`, assert each returns expected status code and fires event.
- **Canary user lookup — event emitted**: `GET /ui/profile/{CANARY_USER_SUB}` with a valid session → assert `honeytoken.used` event with `detail.kind="user"`.
- **Canary API key — event emitted**: send `Authorization: Bearer {CANARY_API_KEY_PLAINTEXT}` → assert `honeytoken.used`, `detail.kind="api_key"`.
- **Form trap — empty field passes**: registration with `website=""` or `website` absent → normal flow, no event.
- **Form trap — filled field fires**: registration with `website="filled"` → 400, `honeypot.hit` event with `detail.trap="form_field"`.
- **Canary ID range**: `GET /ui/profile/canary_0042` → `honeytoken.used`.
- **Legitimate users not affected**: standard Alice/Bob profile lookups, API key use, file access → no `honeytoken.used` events.
- **No false positives in full E2E suite**: run all existing tests → assert zero `honeypot.hit` or `honeytoken.used` events originating from test runner IP.

### 5.2 Playwright E2E (`frontend/e2e/honeypots.spec.ts`)

- As Alice (authenticated): navigate to `/.env` via `page.goto` → assert non-200 response (decoy responds with 200 plain text) but definitely not the SPA shell.
- Use `request` fixture (Bearer auth) to fetch `/.git/config` → assert body contains fake `[core]` content and a `honeypot.hit` event is in the security events feed.
- Submit registration form with the hidden `website` field filled (via `page.evaluate` to fill the hidden input) → assert 400 response from the backend.
- Verify that normal registration (website field empty/absent) still works.

### 5.3 Manual QA

1. `just restart` to reset DDB Local.
2. Run `python3 scripts/honeytoken_seed.py` — assert no errors, canary records present in DDB Local.
3. `curl http://localhost:8000/.env` — assert fake env content in response.
4. `curl -H "Authorization: Bearer {CANARY_API_KEY}"  http://localhost:8000/ui/profile` — assert `honeytoken.used` event appears in Dev Tools security panel (SECOPS-004).
5. Verify no canary records appear in the frontend UI (admin → Users, Files, Billing lists should filter `is_canary=True` entries).

### 5.4 Security considerations for decoy content

- Decoy `.env` content must use obviously fake values (`AKIAIOSFODNN7FAKE`, `DB_PASSWORD=not_a_real_password`) that cannot be confused with real credentials. Use a naming convention that is clearly fake to any internal reviewer.
- Canary API key strings must use a prefix that distinguishes them from real API keys (e.g., `hp_canary_...`) and must be in the `.gitignore`-protected env var, never checked into the repo.
- Review decoy route responses with the security team before deploying to prod — ensure no response inadvertently leaks infrastructure information.

### 5.5 Rollout plan

1. Deploy decoy routes first (lowest risk — pure detection, no enforcement side effects).
2. Add form trap to registration/login (monitor for false-positive rate before enabling auto-ban for form hits).
3. Seed honeytoken records (idempotent; runs at stack startup).
4. Add canary ID range check to profile lookup.
5. Wire `honeypot.hit` → SECOPS-002 auto-ban with threshold=1 (only after SECOPS-002 is deployed and tuned).

### 5.6 Effort estimate

**Medium** (~6 days): 1 day for `honeypot.py` router + all decoy routes; 1 day for honeytoken seed script + canary record checks in existing endpoints; 0.5 day for form trap (frontend + backend); 0.5 day for canary ID range middleware; 1.5 days for tests; 1 day for QA/review of decoy content. Sequential on SECOPS-001 (event emitter must exist).

---

## Second-pass verification (2026-06-05)

Verified against current codebase. All cited existing infrastructure confirmed unless noted.

- [Confirmed] No honeypot/honeytoken router in `app/routers/` — `app/routers/security_groups.py` exists but is unrelated (network security groups, not honeypots); no `honeypot.py` router present.
- [Confirmed] No `honeypot`, `honeytoken`, or `is_canary` strings exist anywhere in `app/` (excluding the unrelated `api_key_*_canary_percent` rollout flags in `settings.py`).
- [Confirmed] `app/main.py:391` — SPA catch-all is `@app.get("/")` returning `FileResponse(static_dir / "index.html")` — confirmed at line 391. The write-up's claim that non-matched paths fall through to it is correct for paths not matching any router.
- [Confirmed] The honeypot router must be registered before the SPA index route for path interception — confirmed; `include_router` calls begin at line 424 in `create_app()`; any `app.include_router(honeypot_router)` inserted before line 424 will match first.
- [Confirmed] `app/services/api_keys.py` exists — confirmed at `/home/ubuntu/testlogon/app/services/api_keys.py`; API keys table wired at `app/core/tables.py:313`.
- [Confirmed] `app/auth/deps.py` handles API key validation — no `is_canary` check present in current code; canary check is a new addition.
- [Confirmed] `rate_limit_profile_lookup` at `app/services/rate_limit.py:198` — confirmed at line 198; limits: authenticated 120/min per user_sub (via `_bucket_limit`), anonymous 30/min per IP (via `_ip_user(ip)`).
- [Corrected] Section 2.5 states file manager uses `T.files` — this is wrong. The file manager does NOT use a handle in the `Tables` dataclass. `app/services/filemanager.py:107` calls `ddb.Table(S.filemgr_table_name)` directly on each invocation. No `T.files` handle exists in `app/core/tables.py`. The canary file implementation must use `ddb.Table(S.filemgr_table_name)` or extend `filemanager.py`'s `get_node()` function.
- [Confirmed] `file_share_links: Any` in `app/core/tables.py:302` — confirmed; but this is for shared-link metadata, not file node storage.
- [Confirmed] `frontend/src/pages/Login.tsx` and `frontend/src/pages/Register.tsx` exist — confirmed.
- [Confirmed] `frontend/src/pages/Register.tsx` uses React Hook Form — confirmed by codebase pattern (all forms use RHF + Zod per CLAUDE.md).
- [Confirmed] No `app/routers/honeypot.py` exists — confirmed absent.
- [Confirmed] No `scripts/honeytoken_seed.py` exists — confirmed absent.
- [Confirmed] `security_events` table (SECOPS-001 dependency) does not yet exist — confirmed; honeypot hits cannot be emitted until SECOPS-001 ships.
