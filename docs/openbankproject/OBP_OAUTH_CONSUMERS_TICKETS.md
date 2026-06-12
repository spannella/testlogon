# OBP OAuth2/OIDC Authorization Server + Consumer-App Registry Tickets (prefix `OAU`)

These tickets implement **OBP Tier 1 — making testlogon an OAuth2/OIDC *provider***
(authorization server) for first-party consumer apps, plus the **consumer-app registry**
that backs it. They close the gap-analysis rows
(`docs/openbankproject/OBP_GAP_ANALYSIS.md:72-73`):

- "Consumer-app registration (client_id/secret, redirect URIs, scopes, enable, rotate)" —
  **PARTIAL** ("API-key registry exists; no OAuth consumer-app / secret / redirect / rotation").
- "OAuth2 / OIDC authorization server (authorize/token, OIDC discovery)" — **MISSING**
  ("testlogon is only an OAuth *client*: Cognito/cookie/SAML inbound").

Today testlogon authenticates **inbound** users via cookie sessions (HS256 `ui_access_token`
JWT) + Cognito JWT bearer + API keys, and acts as an OAuth **client** to Google Drive
(`app/services/provider_oauth.py`). What is missing is the **reverse direction**: a way for a
*third-party consumer app* to obtain a delegated, user-consented, scoped access token to call
the testlogon API on a user's behalf via the standard authorization-code + PKCE flow, with an
OIDC identity layer on top.

What OBP provides that these tickets map onto:

1. **Consumer registry** — register an app (`client_id`, hashed `client_secret`, redirect URIs,
   allowed scopes, enabled flag, owner), enable/disable, rotate secret. (OAU-001, OAU-005)
2. **OAuth2 authorization-code + PKCE** — `GET /oauth/authorize` (consent + code issue),
   `POST /oauth/token` (code→token, refresh, PKCE verify) issuing app-scoped access tokens.
   (OAU-002)
3. **OIDC layer** — `/.well-known/openid-configuration`, JWKS at `/oauth/jwks`, signed
   `id_token`, `GET /userinfo`. (OAU-003)
4. **Per-consumer scopes + scope-enforcement** on API calls, reusing the
   `api_key_route_scope_registry` pattern. (OAU-004)
5. Tests. (OAU-006)

DirectLogin (OBP's non-redirect username/password→token grant) is **optional** and folded into
OAU-002 as a flag-gated extra grant, not its own ticket.

---

## Cross-cutting constraints (apply to every OAU ticket)

- **Additive + flag-gated, default-off.** One new master flag `OAUTH_PROVIDER_ENABLED`
  (`S.oauth_provider_enabled`, default `false`). With it off, none of the new routers are
  registered (or every handler 404/503s before any work) and the platform is byte-for-byte
  unchanged. Sub-features gate on their own additive flags that *also* require the master flag:
  `OAUTH_PROVIDER_OIDC_ENABLED` (OAU-003, default off), `OAUTH_PROVIDER_DIRECTLOGIN_ENABLED`
  (OAU-002 DirectLogin extra, default off), `OAUTH_PROVIDER_SCOPE_ENFORCEMENT_ENABLED` (OAU-004,
  default off).
- **Reuse existing primitives — never fork.**
  - **Secret hashing:** reuse the API-key hashing scheme — `client_secret` is a
    `secrets.token_urlsafe(32)` (`app/services/api_keys.py:18`) hashed via
    `sha256_str(secret + "|" + S.api_key_pepper)` (`app/services/api_keys.py:31-34`,
    `app/core/crypto.py:13-14`), stored as `client_secret_hash` — the plaintext is returned
    exactly once at creation/rotation, mirroring `create_api_key`'s `key_secret` return
    (`app/services/api_keys.py:178-185`).
  - **Token signing:** reuse the HS256 JWT helper — access/`id_token` are minted with
    `jwt.encode(payload, S.ui_access_token_secret, algorithm="HS256")`, the exact pattern in
    `mint_access_token` (`app/services/sessions.py:206-228`) and
    `app/auth/deps.py:233-238`. (The OIDC ticket OAU-003 promotes signing to a rotatable key for
    JWKS — see that ticket.) Short signed grant artifacts (auth codes, PKCE state) reuse the
    HMAC `mint_ws_token`/`verify_ws_token` scheme (`app/core/crypto.py:35-61`).
  - **Scope registry:** reuse `API_KEY_ROUTE_SCOPE_REGISTRY` +
    `resolve_required_scopes_for_route` / `get_route_scope_policy` / `is_route_registered_or_exempt`
    (`app/services/api_key_route_scope_registry.py:17-67,275-318`) — OAuth access tokens carry the
    **same** scope strings (`messager:read`, `filemanager:write`, …) so one registry governs both
    API-key and OAuth callers.
  - **Auth integration:** OAuth bearer tokens are recognized in
    `get_authenticated_user` (`app/auth/deps.py:199-305`) as a new branch *before* the Cognito
    branch, returning an `AuthenticatedUser` (`app/auth/deps.py:125-133`) — so every existing
    `Depends(require_ui_session)` / role dep works unchanged for OAuth callers.
  - **Owner auth for the registry UI:** registry CRUD endpoints use
    `Depends(require_ui_session)` + `require_fresh_mfa(ctx)`
    (`app/services/sessions.py:330,699`) exactly like `app/routers/api_keys.py:17-29`, and
    `audit_event(...)` (`app/services/alerts.py`) on every mutation, mirroring
    `app/routers/api_keys.py:21,27`.
  - **Redirect-URI allowlisting** reuses the validation shape of
    `_validate_google_redirect_uri` (`app/services/provider_oauth.py:84-96`) — exact-match against
    a per-consumer stored allowlist, http/https + netloc required.
- **Single-table DDB.** One new `oauth_consumers` table (PK `client_id`, single-table for
  consumer META + auth-code rows + issued-grant rows via `sk`), declared in
  `scripts/local-ddb-init.py` via a `TableDef` (`scripts/local-ddb-init.py:28-60`). An owner GSI
  (`ByOwner`, partition `owner_sub`) mirrors `api_keys`' `ByUser` GSI
  (`scripts/local-ddb-init.py:56-60`). **Any numeric GSI/SK key declares
  `attr_types={"...": "N"}`** (e.g. `issued_at`) per the repo gotcha
  (`scripts/local-ddb-init.py:52-53,84`).
- **`now_ts()` integer Unix seconds** for all timestamps (`app/core/time.py`). TTL rows
  (auth codes, refresh grants) use `with_ttl(item, ttl_epoch=...)` (`app/services/ttl.py`,
  as in `app/services/api_keys.py:174-175`).
- **dev/prod parity (SECOPS-007).** No `if S.dev_mode:` branch in any OAU code path — all DDB
  reads/writes go through `T.*` handles (DynamoDB Local in dev, real DynamoDB in prod); JWT/HMAC
  signing uses the same `UI_ACCESS_TOKEN_SECRET`/`API_KEY_PEPPER` both envs.
- **Hermetic offline tests** (OAU-006): moto in-memory DDB bound to the frozen `T.oauth_consumers`
  handle via `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`, async route
  handlers driven on a fresh `asyncio.new_event_loop()`, no real AWS/network — same recipe as
  `tests/test_gap_0241_0242_google_drive_oauth.py` and `tests/test_gap_0286_0287_kyc_partner_api.py`.

---

### OAU-001: Consumer-app registry — model, table, CRUD, secret hashing

**Type:** Feature | **Priority:** P1 | **Estimate:** 2.5d
**Flags:** `OAUTH_PROVIDER_ENABLED` (new, default off).

#### Description — DDB model + service/router + auth deps + reuse citations

The registry is the foundation: a first-party developer registers a consumer app and receives a
`client_id` + a one-time `client_secret`. Modeled directly on the API-key registry
(`app/services/api_keys.py`) — same secret generation, same pepper-hashing, same owner-scoped
DDB access pattern — but for an OAuth client rather than a raw API key.

**DDB table (new, `oauth_consumers`).** Declared as a `TableDef`
(`scripts/local-ddb-init.py:28-60`): PK `client_id` (S), SK `sk` (S; consumer META row =
`sk="META"`, with auth-code/grant rows added in OAU-002 under `sk="CODE#{code_id}"` /
`sk="GRANT#{grant_id}"` — single-table). GSI `ByOwner` (partition `owner_sub`,
sort `created_at`) mirroring the `api_keys` `ByUser` GSI (`scripts/local-ddb-init.py:56-60`);
`attr_types={"created_at": "N"}` because the sort key is numeric (repo gotcha,
`scripts/local-ddb-init.py:52-53`). Settings: `S.oauth_consumers_table_name`,
`S.oauth_consumers_owner_index` (add to `app/core/settings.py` + `app/core/tables.py` →
`T.oauth_consumers`, mirroring `S.api_keys_table_name`/`T.api_keys`).

**Consumer META item fields:** `client_id` (`secrets.token_hex(16)`, like
`api_keys.py:143`), `client_secret_hash` (`api_key_hash(secret)`, `api_keys.py:31-34`),
`client_secret_prefix` (`oc_{client_id[:8]}` for display, like `api_keys.py:166`), `owner_sub`,
`name`, `description`, `redirect_uris: List[str]` (allowlisted via the
`_validate_google_redirect_uri` shape, `provider_oauth.py:84-96`), `allowed_scopes: List[str]`
(validated against the union of `required_scopes` across `API_KEY_ROUTE_SCOPE_REGISTRY`,
`api_key_route_scope_registry.py:275-283`), `is_confidential: bool` (public PKCE-only clients
have no usable secret), `enabled: bool` (default `True`), `created_at`/`updated_at` (`now_ts()`),
`secret_rotated_at`. **No plaintext secret is ever stored** — returned once at create
(`{"client_secret": f"oc_{client_id}.{secret}"}`), mirroring `create_api_key`
(`api_keys.py:178-185`).

**Service (`app/services/oauth_consumers.py`):** `create_consumer(owner_sub, *, name,
redirect_uris, allowed_scopes, is_confidential)`; `get_consumer(client_id)` →
`{}` or META item; `list_consumers(owner_sub)` (owner GSI query, like
`list_api_keys`, `api_keys.py:349-374`, hiding `client_secret_hash`);
`update_consumer(owner_sub, client_id, *, name?, description?, redirect_uris?, allowed_scopes?)`
(conditional `update_item` `ConditionExpression="owner_sub = :u"`, like
`set_api_key_capabilities`, `api_keys.py:329-341`); `delete_consumer(owner_sub, client_id)`.
`verify_client_secret(client_id, secret)` reuses `api_key_hash` compare
(`api_keys.py:434` style, `hmac.compare_digest` on the stored hash). All scope validation reuses
`get_route_scope_policy` (`api_key_route_scope_registry.py:275-276`).

**Router (`app/routers/oauth_consumers.py`, prefix `/ui/oauth/consumers`):** `GET` (list),
`POST` (create), `GET /{client_id}`, `PATCH /{client_id}`, `DELETE /{client_id}` — all
`Depends(require_ui_session)` + `require_fresh_mfa(ctx)` (`sessions.py:330,699`) + per-mutation
`audit_event("oauth_consumer_create|update|delete", ctx["user_sub"], req, ...)`
exactly as `app/routers/api_keys.py:17-29`. Register in `app/main.py` **only when**
`S.oauth_provider_enabled` (mirror the conditional-router-registration pattern used by other
flag-gated routers).

#### Acceptance Criteria

- New `oauth_consumers` `TableDef` in `scripts/local-ddb-init.py` with PK `client_id` / SK `sk`,
  `ByOwner` GSI, and `attr_types={"created_at": "N"}`; `T.oauth_consumers` wired in
  `app/core/tables.py`.
- `create_consumer` returns the plaintext `client_secret` exactly once; subsequent reads expose
  only `client_secret_prefix`, never the hash or plaintext.
- `client_secret_hash == api_key_hash(plaintext)` (same pepper, same `sha256_str`);
  `verify_client_secret` accepts the correct secret and rejects a wrong one via
  `hmac.compare_digest`.
- `redirect_uris` reject non-http(s)/empty-netloc URIs; `allowed_scopes` reject any scope not
  present in `API_KEY_ROUTE_SCOPE_REGISTRY`'s `required_scopes` union (400 with a clear `code`).
- CRUD endpoints enforce owner ownership (`owner_sub = :u` conditional → 404 for foreign
  `client_id`), require fresh MFA, and emit an `audit_event` per mutation.
- With `OAUTH_PROVIDER_ENABLED` off, the router is not registered (404) and no table reads occur.

#### Dependencies

None (foundation ticket). Reuses existing `api_keys` / `crypto` / `sessions` primitives.

---

### OAU-002: OAuth2 authorization-code + PKCE flow (`GET /oauth/authorize`, `POST /oauth/token`)

**Type:** Feature | **Priority:** P1 | **Estimate:** 4d
**Flags:** `OAUTH_PROVIDER_ENABLED` (OAU-001); `OAUTH_PROVIDER_DIRECTLOGIN_ENABLED` (new, default
off) gates the optional DirectLogin grant.

#### Description — DDB model + service/router + auth deps + reuse citations

Implements the standard authorization-code grant with mandatory PKCE (RFC 7636) for public
clients, issuing an app-scoped access token (+ optional refresh token) that the existing auth
layer recognizes. The logged-in resource owner is identified via the **existing cookie session**
(`Depends(require_ui_session)`, `sessions.py:330`) — the consumer app redirects the user's
browser to `/oauth/authorize`, the user (already authenticated to testlogon) consents, and a
code is issued to the consumer's redirect URI.

**`GET /oauth/authorize`** (`app/routers/oauth_authorize.py`, `Depends(require_ui_session)`):
params `response_type=code`, `client_id`, `redirect_uri`, `scope` (space-delimited),
`state`, `code_challenge`, `code_challenge_method=S256`. Validates: consumer exists + `enabled`
(`get_consumer`, OAU-001); `redirect_uri` ∈ stored `redirect_uris` (exact match,
`provider_oauth.py:84-96` shape); requested `scope` ⊆ consumer `allowed_scopes`; `code_challenge`
present for public clients. On consent it writes an **auth-code row** to `oauth_consumers`
(`sk="CODE#{code_id}"`, fields: `owner_user_sub=ctx["user_sub"]`, `client_id`, `redirect_uri`,
`granted_scopes`, `code_challenge`, `code_challenge_method`, `issued_at`, single-use marker) with
a short TTL (`with_ttl`, ~60s, `ttl.py` as in `api_keys.py:174-175`). The opaque `code` is the
`code_id` wrapped in a signed envelope minted via `mint_ws_token`-style HMAC
(`crypto.py:35-42`) so a tampered code is rejected before any DDB read. 302-redirects to
`{redirect_uri}?code=...&state=...`. (Consent screen UI is out of scope here — the endpoint
auto-consents for first-party apps; a consent page is a follow-up.)

**`POST /oauth/token`** (`app/routers/oauth_token.py`, **no session dep** — client-credential
authenticated): `grant_type=authorization_code` requires `code`, `redirect_uri`,
`client_id`, `code_verifier`, and (confidential clients) `client_secret`. Validates: code
signature (`verify_ws_token`, `crypto.py:44-61`); single-use consume via conditional
`update_item` setting `consumed_at` with `ConditionExpression="attribute_not_exists(consumed_at)"`
(the exact one-time-use pattern from `provider_oauth.py:200-216` / the cart-recovery
`RECOVERY#CONSUMED` scheme); `redirect_uri` + `client_id` match the code row; PKCE
`BASE64URL(SHA256(code_verifier)) == code_challenge` (`crypto.py:b64url` + `hashlib.sha256`);
confidential-client `client_secret` via `verify_client_secret` (OAU-001). Issues an **access
token** = HS256 JWT minted with `jwt.encode(payload, S.ui_access_token_secret, "HS256")`
(`sessions.py:228`) carrying `{sub: owner_user_sub, client_id, scope, token_type:"access",
iss, exp: now+S.oauth_access_token_ttl, iat}`, plus a `refresh_token` (opaque, hashed + stored
as `sk="GRANT#{grant_id}"` with TTL) when `offline_access`/refresh is requested.
`grant_type=refresh_token` rotates the access token off the stored grant.
**DirectLogin extra** (gated `OAUTH_PROVIDER_DIRECTLOGIN_ENABLED`): a
`grant_type=password` branch verifying `username`/`password` via the existing
`_verify_local_password` (`app/auth/deps.py:167-196`) and consumer secret, returning the same
access-token shape — no redirect.

**Auth integration:** add an **OAuth-bearer branch** to `get_authenticated_user`
(`app/auth/deps.py:199-305`), placed before the Cognito branch (`deps.py:254`): if the bearer
token decodes (HS256, `S.ui_access_token_secret`, `verify_exp=True`) with
`token_type=="access"` and `client_id` present, resolve the user's role from `T.users`
(like the api-key principal branch, `deps.py:215-224`), stash `granted_scope` on
`request.state.oauth_scope` for OAU-004 enforcement, and return `AuthenticatedUser(sub=..., role=...)`.
Returns 401 on bad signature/expiry — never falls through to Cognito for an OAuth-shaped token.

#### Acceptance Criteria

- `GET /oauth/authorize` issues a single-use, TTL'd, HMAC-signed code only when client+redirect+
  scope all validate; rejects disabled consumers, foreign redirect URIs, and out-of-allowlist
  scopes (400/403).
- `POST /oauth/token` `authorization_code` grant: verifies the code signature, enforces
  single-use (a replayed code → 400 via the `attribute_not_exists(consumed_at)` conditional),
  enforces PKCE S256, and (confidential) the `client_secret`; returns an HS256 access token whose
  `scope` ⊆ the code's `granted_scopes` and a refresh token when requested.
- A PKCE mismatch, redirect-URI mismatch, or wrong `client_secret` each returns 400 with a
  distinct OAuth `error` code; no token is issued.
- `get_authenticated_user` accepts the issued access token as bearer, resolves the resource
  owner + role, and exposes the granted scope on `request.state` — existing `require_*` deps work
  unchanged for the OAuth caller.
- `refresh_token` grant rotates the access token; `OAUTH_PROVIDER_DIRECTLOGIN_ENABLED`-gated
  `password` grant works only when the flag is on and reuses `_verify_local_password`.
- All artifacts (codes, grants) are DDB rows under the OAU-001 `oauth_consumers` table; no
  `if S.dev_mode:` branch anywhere.

#### Dependencies

OAU-001 (consumer registry + secret verification + table).

---

### OAU-003: OIDC layer — discovery, JWKS, `id_token`, `/userinfo`

**Type:** Feature | **Priority:** P2 | **Estimate:** 3d
**Flags:** `OAUTH_PROVIDER_ENABLED` (OAU-001) + `OAUTH_PROVIDER_OIDC_ENABLED` (new, default off).

#### Description — DDB model + service/router + auth deps + reuse citations

Layers OIDC on top of OAU-002 so consumer apps can use testlogon as an **identity provider**
(sign-in-with-testlogon), not just an API authorizer. Adds the three OIDC surfaces.

**Signing-key promotion.** Pure HS256 (shared `UI_ACCESS_TOKEN_SECRET`) cannot back a public
JWKS (the secret can't be published). So OAU-003 introduces an **RS256 OIDC signing key** for
`id_token`s: a service `app/services/oauth_oidc_keys.py` that lazily generates/stores an RSA
keypair (private key KMS-encrypted at rest via `kms_encrypt`/`kms_decrypt`,
`app/core/crypto.py:16-25` — the same KMS abstraction `provider_oauth.py:312-314` uses; dev mock
KMS vs prod KMS handled transparently, SECOPS-007) under a `KEY#` row in `oauth_consumers`, with
a stable `kid`. The OAU-002 **access** token stays HS256 (internal); only the **`id_token`** is
RS256-signed so its public half can be published. JWKS reuses the JWK-construction path already in
the tree (`jwt.algorithms.RSAAlgorithm.from_jwk` is used inbound at `app/auth/deps.py:72`; we use
the public-key→JWK direction).

**`GET /.well-known/openid-configuration`** (`app/routers/oauth_oidc.py`, no auth): static
discovery doc built from `S.public_base_url` (used the same way in
`app/services/cart_reminders.py` recovery links) advertising `authorization_endpoint`
(`/oauth/authorize`), `token_endpoint` (`/oauth/token`), `jwks_uri` (`/oauth/jwks`),
`userinfo_endpoint` (`/userinfo`), `issuer`, `response_types_supported=["code"]`,
`grant_types_supported`, `scopes_supported` (the registry scope union +
`openid`/`profile`/`email`), `id_token_signing_alg_values_supported=["RS256"]`,
`code_challenge_methods_supported=["S256"]`.

**`GET /oauth/jwks`** (no auth): the public JWKS `{"keys": [<rsa-public-jwk with kid>]}` from
`oauth_oidc_keys`.

**`id_token` issuance.** When `scope` includes `openid`, `POST /oauth/token` (OAU-002) also
returns an RS256 `id_token` (signed via `oauth_oidc_keys`) with OIDC claims `iss`, `sub`
(resource owner), `aud=client_id`, `exp`, `iat`, `nonce` (echoed from the `/authorize` request),
and — when `profile`/`email` scopes are granted — `email`/`name` read from `T.users`.

**`GET /userinfo`** (`Depends(get_authenticated_user)` via the OAU-002 OAuth-bearer branch):
returns `{sub, email?, name?}` filtered by the token's granted scopes (`profile`/`email`),
reading `T.users`.

#### Acceptance Criteria

- `/.well-known/openid-configuration` returns a valid discovery doc with all endpoints derived
  from `S.public_base_url`; `scopes_supported` includes `openid` + the registry scope union.
- `/oauth/jwks` returns a stable RS256 public JWK with a `kid` that matches the `id_token` header
  `kid`; the private key is never exposed and is stored KMS-encrypted.
- When `openid` is in scope, `POST /oauth/token` returns an `id_token` verifiable against the
  published JWKS, with correct `iss`/`aud`/`sub`/`nonce`; `profile`/`email` claims appear only
  when those scopes are granted.
- `GET /userinfo` returns scope-filtered claims for a valid OAuth bearer token and 401 otherwise.
- With `OAUTH_PROVIDER_OIDC_ENABLED` off, the OIDC router is not registered and `POST /oauth/token`
  omits the `id_token` (plain OAuth2 still works).

#### Dependencies

OAU-002 (token endpoint to attach `id_token` to + OAuth-bearer auth branch for `/userinfo`),
OAU-001 (table for the signing-key row).

---

### OAU-004: Per-consumer scope enforcement on API calls

**Type:** Feature | **Priority:** P1 | **Estimate:** 2.5d
**Flags:** `OAUTH_PROVIDER_ENABLED` (OAU-001) + `OAUTH_PROVIDER_SCOPE_ENFORCEMENT_ENABLED`
(new, default off).

#### Description — DDB model + service/router + auth deps + reuse citations

OAU-002 issues scoped tokens but does not yet *enforce* the scope at the route. This ticket wires
OAuth tokens into the **same** route→scope policy the API-key middleware already uses, so one
registry (`API_KEY_ROUTE_SCOPE_REGISTRY`) governs both auth modes — no second scope taxonomy.

**Enforcement service (`app/services/oauth_scope_enforcement.py`):** a helper
`enforce_oauth_scope_for_route(request)` that (a) reads the OAuth grant context that OAU-002
stashed on `request.state.oauth_scope` (only set for OAuth-bearer callers — cookie/Cognito/api-key
callers are untouched and return immediately); (b) builds the `route_id` as
`f"{method}:{path_template}"` from `request.scope["route"].path` (the exact `route` extraction in
`app/auth/policy.py:139-150`); (c) looks up `resolve_required_scopes_for_route(route_id)` and
`is_route_registered_or_exempt(route_id)` (`api_key_route_scope_registry.py:279-318`); (d) if the
route is registered and the token's `granted_scope` set does not cover **all** `required_scopes`,
raises 403 with `{"code": "oauth_insufficient_scope", "required_scopes": [...],
"granted_scopes": [...]}` (shape mirrors `api_key_scopes_out_of_plan`, `api_keys.py:112-122`); an
unregistered/exempt route is allowed (parity with the api-key registry's exemption handling,
`api_key_route_scope_registry.py:316-318`).

**Wiring.** Add this check to the existing request-scope middleware that already runs api-key
scope enforcement (mirror `app/middleware/rate_limit.py` / the api-key middleware that sets
`request.state.api_key_principal`, `deps.py:209-211`) — the OAuth check runs in the same place,
gated by `S.oauth_provider_scope_enforcement_enabled`, and is a no-op for non-OAuth requests. No
per-router changes are required: because OAU-002's auth branch already produces a normal
`AuthenticatedUser`, the *identity* works everywhere; this ticket adds the *scope gate* on top,
exactly as the api-key path layers scope on top of identity.

**Audit.** On a scope denial, emit `audit_event("oauth_scope_denied", user_sub, request,
outcome="error", status_code=403, required_scopes=..., granted_scopes=...)`
(`app/services/alerts.py`), mirroring the `admin_scope_denied` audit in
`app/auth/policy.py:156-165`.

#### Acceptance Criteria

- An OAuth token granted `messager:read` can call `GET /messaging/conversations` (registered as
  `messager:read`, `api_key_route_scope_registry.py:58`) but is 403'd on
  `POST /messaging/conversations/{conversation_id}/messages` (`messager:write`,
  `api_key_route_scope_registry.py:61`).
- The required/granted scopes come from `API_KEY_ROUTE_SCOPE_REGISTRY` — no new scope list is
  introduced; an exempt or unregistered route is allowed.
- Cookie/Cognito/API-key callers are completely unaffected (the helper returns immediately when
  `request.state.oauth_scope` is absent).
- A denial emits `oauth_scope_denied` audit and returns the `oauth_insufficient_scope` 403 shape.
- With `OAUTH_PROVIDER_SCOPE_ENFORCEMENT_ENABLED` off, OAuth tokens authenticate but scope is not
  enforced (identity-only), and the platform is otherwise unchanged.

#### Dependencies

OAU-002 (OAuth-bearer auth branch + `request.state.oauth_scope`), OAU-001 (consumer/scope model).

---

### OAU-005: Consumer enable/disable + client-secret rotation

**Type:** Feature | **Priority:** P2 | **Estimate:** 1.5d
**Flags:** `OAUTH_PROVIDER_ENABLED` (OAU-001).

#### Description — DDB model + service/router + auth deps + reuse citations

Operational lifecycle for a registered consumer: an owner (or admin) can disable a compromised
app and rotate its secret. Modeled on the api-key revoke + capability-update flows
(`app/services/api_keys.py:187-196,329-341`).

**Service (`app/services/oauth_consumers.py`, extends OAU-001):**
`set_consumer_enabled(owner_sub, client_id, enabled: bool)` — conditional `update_item`
`SET enabled=:e, updated_at=:now ConditionExpression="owner_sub = :u"` (the
`revoke_api_key` shape, `api_keys.py:187-196`); when disabling, the issued-grant rows
(`GRANT#` from OAU-002) are no longer accepted (OAU-002's token branch and the OAU-002 token
endpoint both re-check `get_consumer(...).enabled` before honoring a token/grant — a disabled
consumer's existing access tokens are rejected at the auth chokepoint, `deps.py` OAuth branch).
`rotate_client_secret(owner_sub, client_id)` — mints a fresh
`secrets.token_urlsafe(32)` (`api_keys.py:18`), writes the new `client_secret_hash`
(`api_key_hash`, `api_keys.py:31-34`) + `secret_rotated_at=now_ts()`, and returns the new
plaintext `oc_{client_id}.{secret}` **once** (mirrors create, `api_keys.py:178-185`). Old secret
stops verifying immediately (single stored hash).

**Router (`app/routers/oauth_consumers.py`, extends OAU-001):**
`POST /ui/oauth/consumers/{client_id}/enable`, `POST .../disable`,
`POST .../rotate-secret` — all `Depends(require_ui_session)` + `require_fresh_mfa(ctx)`
(`sessions.py:330,699`, like `api_keys.py:19,26`) + `audit_event("oauth_consumer_enable|
disable|secret_rotate", ctx["user_sub"], req, client_id=...)`.

**Disabled-consumer enforcement.** OAU-002's auth-bearer branch (`deps.py`) and the
`/oauth/authorize` + `/oauth/token` handlers all call `get_consumer(client_id)` and reject when
`enabled is False` (401 `oauth_consumer_disabled`) — so disabling instantly kills both new
authorizations and existing tokens without needing to enumerate/revoke individual grants.

#### Acceptance Criteria

- `disable` flips `enabled=False` (owner-scoped conditional) and immediately causes
  `/oauth/authorize`, `/oauth/token`, and OAuth-bearer auth to reject the consumer
  (401 `oauth_consumer_disabled`); `enable` restores it.
- `rotate-secret` returns a new plaintext secret exactly once; the previous secret no longer
  verifies (`verify_client_secret` rejects it); `secret_rotated_at` is updated.
- All three endpoints require fresh MFA, enforce owner ownership (404 for foreign `client_id`),
  and emit an `audit_event`.
- No issued-grant enumeration is required — enforcement is at the `get_consumer().enabled`
  chokepoint, dev/prod identical.

#### Dependencies

OAU-001 (consumer model/service/router), OAU-002 (the auth-bearer + token paths that honor
`enabled`).

---

### OAU-006: Tests — registry, auth-code/PKCE flow, OIDC, scope enforcement, lifecycle

**Type:** Test | **Priority:** P1 | **Estimate:** 3d
**Flags:** tests toggle the OAU flags via `object.__setattr__` on the frozen `S`.

#### Description — what it covers + reuse citations

Hermetic, offline regression coverage for OAU-001..OAU-005, following the established recipe in
`tests/test_gap_0241_0242_google_drive_oauth.py` (OAuth client tests) and
`tests/test_gap_0286_0287_kyc_partner_api.py` (moto-bound frozen-table + in-memory-S3 + direct
async-handler invocation).

**Setup (shared fixture):** a moto in-memory `oauth_consumers` table (PK `client_id`, SK `sk`,
`ByOwner` GSI, numeric `created_at`) bound to the frozen `T.oauth_consumers` handle via
`object.__setattr__` and restored on cleanup; the RS256 OIDC keypair generated once and its KMS
encrypt/decrypt stubbed (no real KMS); frozen `S` flags
(`oauth_provider_enabled`, `oauth_provider_oidc_enabled`,
`oauth_provider_scope_enforcement_enabled`, `oauth_provider_directlogin_enabled`) toggled via
`object.__setattr__`; async route handlers driven on a fresh `asyncio.new_event_loop()`.

**`tests/test_oau_001_consumer_registry.py`:** create→list→get→update→delete; secret returned
once + `client_secret_hash == api_key_hash(plaintext)`; `verify_client_secret` accept/reject;
redirect-URI + scope validation 400s; owner-isolation 404; MFA-required path.

**`tests/test_oau_002_authcode_pkce.py`:** full happy path — `/authorize` issues a signed
single-use code; `/token` exchanges it (PKCE S256 verify) for an HS256 access token; the token is
accepted by `get_authenticated_user` and resolves the owner+role. Negative: replayed code (400
via `attribute_not_exists(consumed_at)`), PKCE mismatch (400), redirect-URI mismatch (400), wrong
`client_secret` (400), out-of-allowlist scope (403). Refresh-token rotation; DirectLogin
`password` grant gated by its flag (reuses a patched `_verify_local_password`).

**`tests/test_oau_003_oidc.py`:** discovery doc shape; JWKS public key; `id_token` issued only
with `openid` scope and verifiable against JWKS (`iss`/`aud`/`sub`/`nonce`); `/userinfo`
scope-filtered claims + 401 without a token; OIDC-flag-off omits `id_token`.

**`tests/test_oau_004_scope_enforcement.py`:** an OAuth token with `messager:read` passes
`GET /messaging/conversations` but is 403'd (`oauth_insufficient_scope`) on the `messager:write`
route, using real `API_KEY_ROUTE_SCOPE_REGISTRY` entries
(`api_key_route_scope_registry.py:58,61`); cookie/api-key callers unaffected; flag-off → no
enforcement; denial emits `oauth_scope_denied`.

**`tests/test_oau_005_lifecycle.py`:** `disable` → `/authorize`/`/token`/bearer-auth all reject
(401 `oauth_consumer_disabled`); `enable` restores; `rotate-secret` returns a new secret once and
the old secret stops verifying; MFA + owner-isolation + audit asserted.

#### Acceptance Criteria

- All five test modules pass offline with no real AWS/network (moto in-memory DDB bound to frozen
  `T.oauth_consumers`; KMS + `_verify_local_password` patched at source).
- Negative-path coverage exists for every reject branch in OAU-002 (replay, PKCE, redirect,
  secret, scope) and OAU-005 (disabled-consumer rejection, old-secret rejection).
- Tests assert dev/prod-parity invariants: no `if S.dev_mode:` branch is exercised; the same code
  path runs under moto as would run against real DynamoDB.
- E2E spec (optional, in this ticket): a Playwright section driving `/oauth/authorize` →
  `/oauth/token` → an authenticated API call against the live local stack with the OAU flags on.

#### Dependencies

OAU-001, OAU-002, OAU-003, OAU-004, OAU-005 (tests cover all of them).

---

## Ticket summary (dependency order)

| Ticket | Title | Type | Priority | Est. | Depends on |
|--------|-------|------|----------|------|-----------|
| OAU-001 | Consumer-app registry (model/table/CRUD/secret hashing) | Feature | P1 | 2.5d | — |
| OAU-002 | OAuth2 authorization-code + PKCE flow | Feature | P1 | 4d | OAU-001 |
| OAU-003 | OIDC layer (discovery/JWKS/id_token/userinfo) | Feature | P2 | 3d | OAU-002, OAU-001 |
| OAU-004 | Per-consumer scope enforcement on API calls | Feature | P1 | 2.5d | OAU-002, OAU-001 |
| OAU-005 | Consumer enable/disable + secret rotation | Feature | P2 | 1.5d | OAU-001, OAU-002 |
| OAU-006 | Tests (registry, flow, OIDC, scope, lifecycle) | Test | P1 | 3d | OAU-001..005 |

**Total: 6 tickets, ~16.5 engineer-days.** All additive + flag-gated default-off, single-table
DDB (`oauth_consumers`) with `attr_types` for the numeric GSI key, reusing the API-key registry /
crypto / sessions / route-scope-registry primitives (never forking), dev/prod parity per
SECOPS-007, hermetic offline tests.
