# OBP Tier-3 — PSD2 Consents + Dynamic Entities/Endpoints + Open-Data (prefix `CSN`)

Derived from `docs/openbankproject/OBP_GAP_ANALYSIS.md` **Tier 3 — open-banking
compliance + extensibility + open-data** (lines 127–134). These are, by the gap
analysis's own assessment, the **lowest-fit OBP features for a creator-economy SaaS** —
PSD2 consents, runtime API generation, and physical-bank open-data have no native home in
testlogon's wallet/ledger/messaging domain. They are authored here as a **fully additive,
flag-gated-default-off** surface so the platform can claim OBP Tier-3 parity *on demand*
without changing one byte of existing behaviour when the flags are off. The **multi-standard
adapters (Berlin Group / UK-OB / STET) are explicitly DE-SCOPED** per the gap analysis
(line 133, "large, bank-regulatory, poor fit").

The five gap rows these tickets close (`OBP_GAP_ANALYSIS.md`):

- **"PSD2 Consents (AIS/PIS) + consent lifecycle + consent-SCA + revoke" — MISSING**
  (`:68`) → CSN-001 (AIS), CSN-002 (SCA + PIS + consent-scoped rate limit).
- **"Dynamic Entities / Dynamic Endpoints (runtime schema → CRUD; register endpoint) —
  MISSING"** (`:87`) → CSN-003 (entities), CSN-004 (endpoints).
- **"Open-data Branches / ATMs — MISSING"** (`:88`) → CSN-005.
- Tests (`:135`-spirit, every OBP ticket file ends with a hermetic test ticket) → CSN-006.

**How these contrast with what already exists.** testlogon is already an OAuth *client*
with a real, tested **delegated-access consent flow** — `app/services/provider_oauth.py`
(`build_google_oauth_start` `:99`, `consume_google_oauth_state` `:168`,
`complete_google_oauth_callback` `:231`, KMS-sealed refresh tokens `:312-314`). A PSD2 AIS/PIS
consent is the *inverse direction* of that flow: instead of testlogon asking Google for scoped
access to a user's Drive, a **third-party consumer app asks the resource owner for scoped,
time-boxed read/initiation access to specific accounts/views inside testlogon**. CSN-001/002
deliberately reuse the same artifact shapes (single-use signed state, KMS where secrets are at
rest, owner-scoped DDB rows, a lifecycle status machine) but model the *grant* rather than the
*client credential*. The OAuth **consumer app** that holds a consent is the **OAU** cluster
(`docs/openbankproject/OBP_OAUTH_CONSUMERS_TICKETS.md`, table `oauth_consumers`, `client_id`);
the **payment** a PIS consent authorizes is a **TXR** transaction-request
(`docs/openbankproject/OBP_TXN_REQUESTS_SCA_TICKETS.md`, table `txn_requests`, `txr_*`); the
**consent-scoped throttle** reuses the **PLT** / `rate_limit.py` bucket limiter
(`docs/openbankproject/OBP_PLATFORM_TICKETS.md`). CSN never forks any of these — it links to them.

This file authors **6 tickets, CSN-001..CSN-006**, in dependency order.

---

## Cross-cutting constraints (apply to every CSN ticket)

- **Additive + flag-gated, default OFF — these are the lowest-fit OBP features, so the
  bar for "zero impact when off" is absolute.** Master flags, each new + default `false`:
  `PSD2_CONSENTS_ENABLED` (`S.psd2_consents_enabled`, CSN-001/002), `DYNAMIC_ENTITIES_ENABLED`
  (`S.dynamic_entities_enabled`, CSN-003), `DYNAMIC_ENDPOINTS_ENABLED`
  (`S.dynamic_endpoints_enabled`, CSN-004), `OPEN_DATA_ENABLED` (`S.open_data_enabled`,
  CSN-005). With a flag off the corresponding router is **not registered in `app/main.py`**
  (mirror the conditional-router-registration the OAU file uses for `oauth_provider_enabled`,
  `OBP_OAUTH_CONSUMERS_TICKETS.md:146`) → 404, and no startup task, middleware, or table read
  runs. The platform is byte-for-byte unchanged.
- **Reuse existing primitives — never fork.**
  - **Consent grant artifact** mirrors the OAuth-client consent shape in
    `provider_oauth.py` (single-use HMAC-signed state, owner-scoped DDB row, KMS at rest) and
    the API-key/registry CRUD shape (`app/routers/api_keys.py:13-29`, owner-scoped conditional
    `update_item`, `audit_event` per mutation).
  - **SCA** reuses the MFA challenge/answer stack verbatim — `sessions.create_action_challenge`
    (`app/services/sessions.py:626`), `load_challenge_or_401` (`:517`), `challenge_done`
    (`:566`), `compute_required_factors` (`:571`), `revoke_challenge` (`:530`), driven by the
    existing `/ui/mfa/{totp,sms,email}/{begin,verify}` routes (`app/routers/ui_mfa.py:51-205`).
    **No new OTP code, send path, or crypto.** This is the exact pattern TXR-003 uses
    (`OBP_TXN_REQUESTS_SCA_TICKETS.md:159-208`).
  - **Consent-scoped rate limit** reuses `rate_limit._bucket_limit`
    (`app/services/rate_limit.py:60`) keyed on `consent:{consent_id}`, modelled on
    `rate_limit_kyc_partner_api` (`rate_limit.py:385`) — same 429 shape (HTTP 429 +
    `detail.code` + `detail.limit` + `detail.window_seconds` + `Retry-After`), same
    `S.*_per_hour` env caps.
  - **Consumer identity** for "list-by-consumer" is the OAU `client_id`
    (`OBP_OAUTH_CONSUMERS_TICKETS.md`, `oauth_consumers` PK). When OAU is not yet built, the
    consumer ref is an opaque string persisted as-is (CSN does not block on OAU — see Deps).
  - **PIS link target** is a TXR `request_id` (`txn_requests` SK `txr_*`,
    `OBP_TXN_REQUESTS_SCA_TICKETS.md:88`). When TXR is not yet built, the link is an opaque ref.
  - **Public open-data endpoints** reuse the **no-auth public-router pattern** already in the
    tree: a separate `APIRouter` with its own prefix, registered in `app/main.py` alongside the
    others (`calendar.public_event_router` prefix `/calendar/public`, `app/routers/calendar.py:89`,
    registered `app/main.py:61`; the booking `public_router` `:88`; `signature_public_router`,
    `file_share_links.public_router`). Public GETs must also be added to the api-key route
    exemptions (`API_KEY_ROUTE_EXEMPTIONS`, `app/services/api_key_route_scope_registry.py:70`)
    so a missing key never 401s an open-data read.
  - **Admin gating** for entity/endpoint/branch/ATM **writes** reuses `Depends(require_root_session)`
    (`app/auth/deps.py:308`, as used at `app/routers/achievements.py:68`) — no new role system.
- **Single-table DDB, numeric-GSI gotcha.** Each ticket adds at most one new `TableDef`
  (`scripts/local-ddb-init.py:28-36`); single-table via `sk`. **Any numeric GSI/SK key declares
  `attr_types={"...": "N"}`** (the repo's #1 gotcha — `scripts/local-ddb-init.py:52-53`, e.g.
  `created_at`/`expires_at`). Settings + `T.*` handles added in `app/core/settings.py` /
  `app/core/tables.py` mirroring `S.api_keys_table_name` / `T.api_keys`.
- **`now_ts()` integer Unix seconds** for all timestamps (`app/core/time.py`); TTL rows use
  `with_ttl(item, ttl_epoch=...)` (`app/services/ttl.py`, as in `sessions.create_action_challenge`
  `:649` and `api_keys.py:174-175`).
- **dev/prod parity (SECOPS-007).** No `if S.dev_mode:` business-logic branch in any CSN path.
  All DDB I/O goes through frozen `T.*` handles (DynamoDB Local in dev, real DynamoDB in prod);
  KMS via the `kms_encrypt`/`kms_decrypt` abstraction (`provider_oauth.py:312-314`, mock KMS dev
  / real KMS prod). The dynamic-entity/endpoint **runtime registration** is the *feature*, not an
  environment shortcut — it runs identically both envs.
- **Audit everything.** Every mutation emits `audit_event(event, user_sub, request, ...)`
  (`app/services/alerts.py`, the helper `app/routers/api_keys.py:22` / `ui_mfa.py` use):
  `consent.created|accepted|revoked|expired`, `dynamic_entity.registered|deleted`,
  `dynamic_endpoint.registered|deleted`, `open_data.branch_upsert|atm_upsert|delete`.
- **Hermetic offline tests** (CSN-006): moto in-memory DDB bound to the frozen `T.*` handle via
  `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`, async route handlers
  driven on a fresh `asyncio.new_event_loop()`, KMS + MFA collaborators patched at source, no
  real AWS/network — the recipe in `tests/test_gap_0241_0242_google_drive_oauth.py` and
  `tests/test_gap_0286_0287_kyc_partner_api.py`.

---

### CSN-001: PSD2 AIS consent — model, table, flag, grant/status/list-by-consumer/revoke

**Type:** Feature | **Priority:** P2 | **Estimate:** 3d
**Flags:** `PSD2_CONSENTS_ENABLED` (new, default off).

#### Description — DDB model + service/router + reuse citations

The foundation: an **Account-Information (AIS) consent** is a durable record in which a
resource owner grants a named consumer app **read** access to **specific accounts/views** for a
**time window**, walking a lifecycle status machine. This is the *inverse* of the existing
OAuth-client consent (`provider_oauth.py:99-231`): there testlogon obtains scoped access to a
user's external resource; here a third party obtains scoped read access to the user's data
*inside* testlogon. The status machine intentionally mirrors PSD2:
`INITIATED → ACCEPTED → {REVOKED, EXPIRED}` (CSN-002 inserts the SCA gate between INITIATED and
ACCEPTED; without SCA wired, CSN-001's create can land directly in INITIATED and a flag-gated
auto-accept path is used for first-party apps — see Acceptance).

**Pydantic models** (`app/models.py`): `ConsentCreateIn{ consumer_ref:str, consent_type:Literal["AIS"]="AIS",
account_refs:List[str], view_refs:List[str]=["owner"], valid_until:int|None, recurring:bool=True,
reason:str|None }` and `ConsentOut{ consent_id, owner_sub, consumer_ref, consent_type, account_refs,
view_refs, status, valid_from, valid_until, sca_challenge_id|None, created_at, updated_at,
revoked_at|None }`. `account_refs`/`view_refs` are opaque strings (a "View" is the OBP
field-level access object built in the **VIEWS** cluster
`docs/openbankproject/OBP_VIEWS_ENTITLEMENTS_TICKETS.md`; until it exists, a view ref is just
`"owner"`/`"accountant"`/`"auditor"`/`"public"` validated against a static set).

**DDB table** `consents` (`TableDef` in `scripts/local-ddb-init.py`): PK `owner_sub` (S), SK
`consent_id` (S, `csn_{uuid4().hex}`). Single-table — CSN-002 adds no second table (the SCA
challenge lives in `T.sessions`, the PIS link is a scalar field). Two GSIs:
`ByConsumer` (partition `consumer_ref` (S), sort `created_at` (N)) for **list-by-consumer**, and
`ByStatusExpiry` (partition `status` (S), sort `valid_until` (N)) for the CSN-001 expiry sweep —
**both numeric sort keys declare `attr_types={"created_at":"N","valid_until":"N"}`** (repo gotcha
`scripts/local-ddb-init.py:52-53`). Settings `S.consents_table_name`,
`S.consents_consumer_index`, `S.consents_status_index` → `T.consents`
(`app/core/tables.py`, mirroring `T.api_keys`).

**Service** (`app/services/psd2_consents.py`):
- `create_consent(owner_sub, body, req)` — validate `account_refs` non-empty, `view_refs` ⊆ the
  static view set, `valid_until` (default `now_ts()+S.psd2_consent_default_ttl_days*86400`,
  capped at `S.psd2_consent_max_ttl_days`); write the item `status="INITIATED"`,
  `valid_from=now_ts()`; return `ConsentOut`.
- `get_consent(owner_sub, consent_id)` — `Key={owner_sub, consent_id}` (foreign id → `None`).
- `list_consents_for_owner(owner_sub, *, status?)` and
  `list_consents_for_consumer(consumer_ref, *, status?)` — the latter queries `ByConsumer`
  (the OBP "consents-by-consumer" surface), cursor-paginated via `app/core/cursor.py`.
- `revoke_consent(owner_sub, consent_id)` — conditional `update_item`
  `SET status='REVOKED', revoked_at=:now ConditionExpression="status IN (:i,:a)"` (only
  INITIATED/ACCEPTED → REVOKED; the conditional-update "status is the lock" pattern from
  `tickets._conditional_update_meta` / `OBP_TXN_REQUESTS_SCA_TICKETS.md:123-129`).
- `is_consent_valid(consent_id) -> (bool, consent|None)` — used by CSN-002's enforcement: a
  consent is usable only when `status=="ACCEPTED"` and `valid_until > now_ts()`.
- **Expiry sweep** `expire_due_consents()` (startup loop `start_consent_expiry_task`, registered
  in `app/main.py` gated on `S.psd2_consents_enabled`, mirroring `start_k8s_ttl_checker_task`):
  query `ByStatusExpiry` for `status="ACCEPTED" AND valid_until < now`, conditional-transition to
  `EXPIRED`, `audit_event("consent.expired", ...)`. (DynamoDB native TTL is *not* relied on for
  the status flip — TTL deletes the row; we want an explicit terminal `EXPIRED` audit, so the
  sweep does the transition and a longer TTL eventually reaps the row.)

**Router** (`app/routers/psd2_consents.py`, prefix `/ui/consents`, `Depends(require_ui_session)`,
CSRF on non-GET per CLAUDE.md): `POST /ui/consents` (owner creates a consent granting
`consumer_ref`), `GET /ui/consents` (owner's consents, `?status=`), `GET /ui/consents/{consent_id}`,
`POST /ui/consents/{consent_id}/revoke`, and an admin/consumer read
`GET /ui/consents/by-consumer/{consumer_ref}` (`Depends(require_root_session)` until OAU client
auth lands). Every mutation `audit_event("consent.created|revoked", ctx["user_sub"], req,
consent_id=...)`. Register in `app/main.py` **only when** `S.psd2_consents_enabled`.

#### Acceptance Criteria
- `POST /ui/consents` persists a `consents` row with `status="INITIATED"`, owner-scoped
  `consent_id`; flag OFF → route 404; no table read when off.
- `account_refs` empty → `400`; `view_refs` outside the static set → `400`;
  `valid_until` beyond `psd2_consent_max_ttl_days` is clamped (or `400`, per security review).
- `GET /ui/consents/by-consumer/{ref}` returns exactly the consents whose `consumer_ref` matches
  (via `ByConsumer` GSI), never another consumer's; `?status=` filters.
- `revoke` flips ACCEPTED/INITIATED → `REVOKED` (owner-scoped conditional); a second revoke or a
  revoke of a terminal consent is a no-op/`409`; `audit_event("consent.revoked", ...)` fired.
- `expire_due_consents()` transitions an ACCEPTED consent past `valid_until` to `EXPIRED` and
  audits `consent.expired`; a still-valid consent is untouched.
- `is_consent_valid` returns `True` only for `ACCEPTED` + unexpired.

#### Dependencies
None hard. **Soft links:** the OAU consumer registry
(`OBP_OAUTH_CONSUMERS_TICKETS.md`, `oauth_consumers.client_id`) is the canonical `consumer_ref`
— until OAU lands, `consumer_ref` is an opaque validated string. The VIEWS cluster
(`OBP_VIEWS_ENTITLEMENTS_TICKETS.md`) is the canonical `view_refs` source — until it lands, the
static `{owner,accountant,auditor,public}` set is used.

---

### CSN-002: Consent SCA gate + PIS consent linked to a TXR + consent-scoped rate limit

**Type:** Feature | **Priority:** P2 | **Estimate:** 3d
**Flags:** `PSD2_CONSENTS_ENABLED` (CSN-001).

#### Description — DDB model + service/router + reuse citations

Three additions over CSN-001, all reusing existing stacks:

**(1) SCA gate before ACCEPTED.** A consent must not become usable until the resource owner
passes a step-up SCA challenge — the PSD2 requirement, satisfied by **reusing the MFA stack
verbatim** (the exact approach TXR-003 takes, `OBP_TXN_REQUESTS_SCA_TICKETS.md:159-208`):
- New `request_consent_sca(owner_sub, consent_id, req)` in `psd2_consents.py`: load the
  INITIATED consent; compute `required_factors = sessions.compute_required_factors(owner_sub)`
  (`sessions.py:571`); mint the challenge via
  `sessions.create_action_challenge(req, owner_sub, purpose="consent_sca",
  send_to=[...], payload={"consent_id": consent_id}, ttl_seconds=300)` (`sessions.py:626`);
  stamp `sca_challenge_id` onto the consent item; return `{challenge_id, required_factors}`.
  The `purpose="consent_sca"` keeps it out of the login-finalize path (`maybe_finalize` returns
  `None` for purposeful challenges, `sessions.py:653-655`). **OTP delivery + answer reuse the
  existing `/ui/mfa/{sms,email}/begin` + `/ui/mfa/{totp,sms,email}/verify` routes
  (`ui_mfa.py:51-205`)** with the returned `challenge_id` — no new OTP code/crypto/send path
  (SECOPS-007: dev mock OTP in `mfa.py`, prod Twilio/SES, inherited unchanged).
- New `accept_consent(owner_sub, consent_id)` endpoint `POST /ui/consents/{id}/accept`: load the
  consent + its `sca_challenge_id`; `chal = sessions.load_challenge_or_401(owner_sub, sca_id)`
  (`sessions.py:517`, auto-rejects expired/revoked); require
  `sessions.challenge_done(chal)` (`sessions.py:566`) → else `403 sca_incomplete`; conditional
  `update_item` `status INITIATED → ACCEPTED` (status-lock); `sessions.revoke_challenge(...)`
  (`sessions.py:530`) so the challenge can't be replayed; `audit_event("consent.accepted",...)`.
- New endpoint `POST /ui/consents/{id}/sca` → `request_consent_sca`, audits
  `consent.sca_required`. Rate-limiting on OTP attempts is inherited from `rate_limit_mfa_verify`
  (`rate_limit.py:177`, used by the MFA verify routes).

**(2) PIS consent linked to a TXR.** Extend `ConsentCreateIn.consent_type` to accept `"PIS"`
(payment-initiation). A PIS consent carries `payment_ref` = a TXR `request_id`
(`txn_requests` SK `txr_*`, `OBP_TXN_REQUESTS_SCA_TICKETS.md:88`) instead of `account_refs`. New
field `payment_ref:str|None` on the model + item. A PIS consent **always** requires SCA
(`_consent_requires_sca(consent) = consent_type=="PIS" or amount>=threshold or sensitive`,
mirroring TXR-003's `_sca_required`, `OBP_TXN_REQUESTS_SCA_TICKETS.md:168`) and, once ACCEPTED,
is the *authorization record* a TXR execution can check: a new helper
`consent_authorizes_payment(payment_ref) -> bool` returns `True` only for an `ACCEPTED`, unexpired
PIS consent whose `payment_ref` matches. **The PIS consent never moves money itself** — money
moves only through the TXR execution engine (`OBP_TXN_REQUESTS_SCA_TICKETS.md:212-282`, one
ledger/refund mechanism, status-as-lock, fraud-gated). When TXR is not yet built, `payment_ref`
is an opaque ref and `consent_authorizes_payment` is exposed for the future TXR wiring but unused.

**(3) Consent-scoped rate limit.** A consumer calling an AIS data read under a consent is
throttled **per consent**, reusing the PLT/`rate_limit` bucket limiter — new
`rate_limit_consent(consent_id, category)` in `app/services/rate_limit.py`, modelled **exactly**
on `rate_limit_kyc_partner_api` (`rate_limit.py:385`): keyed `consent:{consent_id}`,
`sid=f"rl#consent#{category}"`, win `3600`, caps from `S.psd2_consent_rl_{read,refresh}_per_hour`
(defaults 1000/100). Same 429 shape (HTTP 429 + `detail.code="consent_rate_limited"` +
`detail.limit` + `detail.window_seconds` + `Retry-After`). This is the gap-analysis row
"Rate-limit on consent — MISSING" (`OBP_GAP_ANALYSIS.md:81`). Called by any future consent-scoped
AIS read endpoint; the helper ships + is unit-tested here even though the AIS *data* endpoints
(per-account transaction reads) live in the de-scoped/Tier-2 banking-data work — the throttle is
the deliverable, the data surface is not.

#### Acceptance Criteria
- `POST /ui/consents/{id}/sca` mints a `T.sessions` challenge with `purpose="consent_sca"`,
  `passed` seeded false, and returns `{challenge_id, required_factors}`; `audit_event(
  "consent.sca_required", ...)` fired.
- Driving the existing `/ui/mfa/*/verify` routes with that `challenge_id` flips the matching
  `passed.<factor>`; `accept_consent` before `challenge_done` → `403 sca_incomplete`; after all
  required factors pass → consent flips `INITIATED → ACCEPTED`, the challenge is revoked, and a
  replay of `/accept` is idempotent/`409`.
- An expired/revoked challenge is rejected by `load_challenge_or_401` (no separate code).
- A `consent_type="PIS"` consent stores `payment_ref`, **always** requires SCA, and
  `consent_authorizes_payment(payment_ref)` returns `True` only for an ACCEPTED+unexpired PIS
  consent with the matching ref — and **never** itself writes a ledger/wallet row.
- `rate_limit_consent(consent_id, "read")` returns HTTP 429 with `code="consent_rate_limited"`,
  `limit`, `window_seconds`, `Retry-After` once the per-hour cap is exceeded; separate
  `consent_id`s have separate budgets; a `0` cap (env) disables the throttle.

#### Dependencies
CSN-001 (consent model/table/status machine). **Soft link:** TXR
(`OBP_TXN_REQUESTS_SCA_TICKETS.md`, `txn_requests`) is the canonical `payment_ref` target and the
*only* money-mover — CSN-002 ships `consent_authorizes_payment` for TXR to call but does not move
money. SCA reuses the MFA stack (no dependency on a new ticket).

---

### CSN-003: Dynamic Entities — runtime JSON-schema registration → generated CRUD (admin-gated)

**Type:** Feature | **Priority:** P3 | **Estimate:** 3.5d
**Flags:** `DYNAMIC_ENTITIES_ENABLED` (new, default off).

#### Description — DDB model + service/router + reuse citations

OBP's **Dynamic Entity**: an admin registers a JSON-schema-described custom entity at runtime and
testlogon **generates CRUD endpoints** for it, backed by a generic single-table store — no code
deploy. This is genuinely net-new (no analogue in the tree) and the lowest-fit feature in this
file; it is admin-gated and flag-off by default so it can never widen the attack surface unless an
operator explicitly opts in.

**Two tables.** (1) `dynamic_entity_defs` (`TableDef`): PK `entity_name` (S), SK `sk="DEF"` —
the registered definition. Fields: `entity_name` (lowercase, `^[a-z][a-z0-9_]{2,39}$`),
`json_schema` (a stored JSON-Schema dict — `type:object`, `properties`, `required`), `created_by`,
`created_at`/`updated_at` (`now_ts()`), `version`. (2) `dynamic_entity_rows` (`TableDef`): PK
`entity_name` (S), SK `row_id` (S, `dyn_{uuid4().hex}`) — the generic per-entity row store,
single-table across all entities (the partition is the entity name). Each row item carries
`entity_name`, `row_id`, the validated `data` (map), `owner_sub`, `created_at`/`updated_at`. A
GSI `ByOwner` (partition `owner_sub`, sort `created_at` (N), `attr_types={"created_at":"N"}`) so a
user lists their own rows. Settings + `T.dynamic_entity_defs` / `T.dynamic_entity_rows`.

**Service** (`app/services/dynamic_entities.py`):
- `register_entity(admin_sub, entity_name, json_schema)` — validate the name regex; validate the
  schema is a well-formed JSON-Schema object (a bounded subset: `type:object`, scalar/array
  property types, `required` list, a hard cap on property count + nesting depth to prevent abuse);
  reject reserved names colliding with real routes (`{users,billing,messaging,...}` denylist);
  upsert the `DEF` row; `audit_event("dynamic_entity.registered", admin_sub, req, entity=...)`.
- `validate_against_schema(entity_name, data)` — load the `DEF`, validate `data` against the
  stored schema (required-field + type checks; pure-Python, **no external jsonschema dep** unless
  already vendored — same dependency-free posture as `receipts.py`/`_render_audit_pdf`); raise
  `400 schema_validation_failed` with the offending field.
- CRUD: `create_row(entity_name, owner_sub, data)`, `get_row`, `list_rows(entity_name, *, owner_sub?)`
  (owner GSI when scoped), `update_row` (conditional `owner_sub = :u`), `delete_row`,
  `delete_entity(entity_name)` (removes the DEF; rows are TTL-reaped or bulk-deleted per security
  review).

**Router** (`app/routers/dynamic_entities.py`):
- **Admin/definition** (`Depends(require_root_session)`, `app/auth/deps.py:308`): `POST /ui/dynamic-entities`
  (register), `GET /ui/dynamic-entities` (list defs), `GET /ui/dynamic-entities/{name}` (get def),
  `DELETE /ui/dynamic-entities/{name}`.
- **Generated CRUD** (`Depends(require_ui_session)`, one *parameterized* route set that dispatches
  on the `{entity_name}` path param — NOT FastAPI route objects minted at runtime, which can't be
  added to a running app cleanly; instead a single static route family `…/{entity_name}/…` whose
  handler loads the DEF, validates, and reads/writes `dynamic_entity_rows`):
  `POST /ui/dynamic/{entity_name}`, `GET /ui/dynamic/{entity_name}`,
  `GET /ui/dynamic/{entity_name}/{row_id}`, `PUT /ui/dynamic/{entity_name}/{row_id}`,
  `DELETE /ui/dynamic/{entity_name}/{row_id}`. An unknown `entity_name` → `404 entity_not_found`.
  Every write validates `data` against the stored schema first. Register the router in
  `app/main.py` **only when** `S.dynamic_entities_enabled`.

#### Acceptance Criteria
- `POST /ui/dynamic-entities` (root) registers a schema; flag OFF → all dynamic routes 404; a
  non-root caller → `403`.
- A registered entity exposes working CRUD under `/ui/dynamic/{entity_name}`; `data` that violates
  the stored JSON-Schema (missing required field / wrong type) → `400 schema_validation_failed`
  naming the field; a valid `data` persists to `dynamic_entity_rows`.
- An entity name failing the regex, hitting the reserved denylist, or exceeding the property/depth
  caps → `400`; an unknown entity in a CRUD call → `404 entity_not_found`.
- `list`/`update`/`delete` are owner-scoped (foreign `owner_sub` → 404 on read, conditional-fail
  on write); each definition mutation emits `dynamic_entity.registered|deleted` audit.
- No `if S.dev_mode:` branch; the same handler path runs against DynamoDB Local and real DynamoDB.

#### Dependencies
None (self-contained). Independent of CSN-001/002.

---

### CSN-004: Dynamic Endpoints — register a custom OpenAPI path mapped to a handler/connector

**Type:** Feature | **Priority:** P3 | **Estimate:** 3d
**Flags:** `DYNAMIC_ENDPOINTS_ENABLED` (new, default off).

#### Description — DDB model + service/router + reuse citations

OBP's **Dynamic Endpoint**: an admin registers a custom OpenAPI path at runtime and maps it to a
handler/connector, so a partner-specific endpoint can be stood up without a deploy. Like CSN-003
this is net-new, admin-gated, flag-off, and deliberately constrained: rather than executing
arbitrary uploaded code (a non-starter security-wise), a dynamic endpoint maps an OpenAPI
`{method, path}` to a small allowlisted **connector kind** + config, dispatched by a single static
gateway route. The two safe connector kinds shipped here:
1. `static_response` — return a stored JSON body + status (the OBP "mock dynamic endpoint" mode).
2. `dynamic_entity_proxy` — proxy to a CSN-003 entity's CRUD (e.g. map `GET /custom/widgets` →
   `list_rows("widget")`), reusing `dynamic_entities` service calls (no new data path).
(A `connector` kind that calls a registered internal service is left as an explicit follow-up,
not shipped — arbitrary handler binding is out of scope.)

**DDB table** `dynamic_endpoints` (`TableDef`): PK `endpoint_id` (S, `dye_{uuid4().hex}`),
SK `sk="DEF"`. Fields: `method` (GET/POST/PUT/DELETE), `path` (must start `/custom/`,
validated to a safe charset, uniqueness enforced via a `ByMethodPath` GSI partition
`method_path` = `f"{method} {path}"`), `connector_kind` (`static_response|dynamic_entity_proxy`),
`connector_config` (map — `{status, body}` for static; `{entity_name, op}` for proxy),
`openapi_spec` (the stored path-item dict surfaced in CSN-004's spec endpoint), `created_by`,
`created_at` (N). `attr_types={"created_at":"N"}`. Settings + `T.dynamic_endpoints`.

**Service** (`app/services/dynamic_endpoints.py`): `register_endpoint(admin_sub, method, path,
connector_kind, connector_config)` (validate path prefix/charset, method, connector kind +
config shape, uniqueness on `method_path`); `get_endpoint(method, path)`;
`list_endpoints()`; `delete_endpoint(endpoint_id)`;
`invoke_endpoint(method, path, request) -> Response` — dispatch on `connector_kind`:
`static_response` returns `JSONResponse(body, status)`; `dynamic_entity_proxy` calls the
CSN-003 `dynamic_entities` op. All mutations `audit_event("dynamic_endpoint.registered|deleted",
...)`.

**Router** (`app/routers/dynamic_endpoints.py`):
- **Admin** (`Depends(require_root_session)`): `POST /ui/dynamic-endpoints`, `GET /ui/dynamic-endpoints`,
  `GET /ui/dynamic-endpoints/{endpoint_id}`, `DELETE /ui/dynamic-endpoints/{endpoint_id}`, plus
  `GET /ui/dynamic-endpoints/openapi` returning the merged path-items (the runtime OpenAPI surface).
- **Gateway** (one static catch-all per method, `Depends(require_ui_session)`):
  `… /custom/{path:path}` for each of GET/POST/PUT/DELETE → looks up `get_endpoint(method,
  "/custom/"+path)` (404 if unregistered) → `invoke_endpoint(...)`. Register **only when**
  `S.dynamic_endpoints_enabled`.

#### Acceptance Criteria
- `POST /ui/dynamic-endpoints` (root) registers a `static_response` endpoint; calling
  `GET /custom/<path>` returns the stored body + status; flag OFF → gateway + admin routes 404.
- A `dynamic_entity_proxy` endpoint mapped to a CSN-003 entity returns that entity's rows via the
  `dynamic_entities` service (no second data path); an unregistered `/custom/...` → `404`.
- Path validation rejects a path not under `/custom/` or with an unsafe charset (`400`); a
  duplicate `method+path` → `409`; an unknown `connector_kind` or malformed `connector_config` →
  `400`.
- `GET /ui/dynamic-endpoints/openapi` lists the registered path-items; non-root admin calls → 403.
- Mutations emit `dynamic_endpoint.registered|deleted` audit; no `dev_mode` branch.

#### Dependencies
CSN-003 (the `dynamic_entity_proxy` connector kind calls the dynamic-entity service; the
`static_response` kind is independent, so CSN-004 can ship its static path without CSN-003 but the
proxy connector requires it).

---

### CSN-005: Open-data Branches + ATMs — CRUD + public GET endpoints

**Type:** Feature | **Priority:** P3 | **Estimate:** 2.5d
**Flags:** `OPEN_DATA_ENABLED` (new, default off).

#### Description — DDB model + service/router + reuse citations

OBP's open-data surface: **Branches** (location / opening hours / accessibility) and **ATMs**
(location) are admin-managed and **publicly readable** (no auth) so anyone can discover physical
locations. Lowest fit for a creator-economy SaaS (no physical branches), shipped purely for OBP
parity behind `OPEN_DATA_ENABLED`. The public reads reuse the **no-auth public-router pattern**
already in the tree.

**DDB table** `open_data` (`TableDef`, single-table for both resource kinds): PK `kind` (S,
`"BRANCH"`|`"ATM"`), SK `resource_id` (S, `brn_*`/`atm_*`). Fields (Pydantic in `app/models.py`):
- `BranchOut/BranchIn{ branch_id, name, address{line1,line2,city,region,country,postcode},
  location{lat,lng}, opening_hours:List[{day,opens,closes}], accessibility:List[str],
  phone|None, is_active }`.
- `AtmOut/AtmIn{ atm_id, name, address{...}, location{lat,lng}, is_active, has_deposit:bool,
  is_accessible:bool }`.
A GSI `ByActive` (partition `is_active` (S, `"1"`/`"0"`), sort `name`) so public lists return only
active resources. Settings + `T.open_data`.

**Service** (`app/services/open_data.py`): `upsert_branch(admin_sub, body)`,
`upsert_atm(admin_sub, body)`, `get_branch(branch_id)`, `get_atm(atm_id)`,
`list_branches(*, active_only=True)`, `list_atms(*, active_only=True)`,
`delete_resource(kind, resource_id)` — owner/admin writes audit
`open_data.branch_upsert|atm_upsert|delete`.

**Routers** (`app/routers/open_data.py`): **two** routers, mirroring `calendar.py`'s
admin/public split (`calendar.py:87-89`):
- **Admin write** (`router`, prefix `/ui/open-data`, `Depends(require_root_session)`):
  `POST /ui/open-data/branches`, `PUT /ui/open-data/branches/{id}`,
  `DELETE /ui/open-data/branches/{id}`, and the ATM equivalents. Plus admin lists incl. inactive.
- **Public read** (`public_router`, prefix `/open-data`, **no auth dependency** —
  the `calendar.public_event_router` shape, `calendar.py:89` / `app/main.py:61`):
  `GET /open-data/branches`, `GET /open-data/branches/{id}`, `GET /open-data/atms`,
  `GET /open-data/atms/{id}` — return active resources only. Register **both** in `app/main.py`
  **only when** `S.open_data_enabled` (the public router beside `calendar_public_event_router`).
  Add the four public GET route ids to `API_KEY_ROUTE_EXEMPTIONS`
  (`app/services/api_key_route_scope_registry.py:70`) so a request with no API key is not 401'd on
  an open-data read (parity with the other public reads).

#### Acceptance Criteria
- `POST /ui/open-data/branches` (root) upserts a branch; `GET /open-data/branches` returns it with
  **no auth** (cookie/bearer/key all absent → 200); flag OFF → both admin and public routes 404.
- Public lists return only `is_active=true` resources (via `ByActive`); an inactive branch is
  hidden from the public GET but visible to the admin list.
- ATM CRUD mirrors branch CRUD; `DELETE` removes the resource; non-root admin writes → 403.
- The public GET route ids are in `API_KEY_ROUTE_EXEMPTIONS` (no 401 without a key); mutations
  emit `open_data.branch_upsert|atm_upsert|delete` audit.
- No `dev_mode` branch; the same handler runs against DynamoDB Local and real DynamoDB.

#### Dependencies
None (self-contained). Independent of CSN-001..004.

---

### CSN-006: Tests — consents (AIS/SCA/PIS/rate-limit), dynamic entities/endpoints, open-data

**Type:** Test | **Priority:** P2 | **Estimate:** 3d
**Flags:** tests toggle the CSN flags via `object.__setattr__` on the frozen `S`.

#### Description — what it covers + reuse citations

Hermetic, offline regression coverage for CSN-001..CSN-005, following the established recipe in
`tests/test_gap_0241_0242_google_drive_oauth.py` (consent-flow tests) and
`tests/test_gap_0286_0287_kyc_partner_api.py` (moto-bound frozen-table + direct async-handler
invocation). Shared setup: moto in-memory tables (`consents`, `dynamic_entity_defs`,
`dynamic_entity_rows`, `dynamic_endpoints`, `open_data`) bound to the frozen `T.*` handles via
`object.__setattr__` and restored on cleanup (numeric GSI keys declared); frozen `S` flags
(`psd2_consents_enabled`, `dynamic_entities_enabled`, `dynamic_endpoints_enabled`,
`open_data_enabled`) toggled via `object.__setattr__`; `now_ts` patched; the MFA collaborators
(`sessions.create_action_challenge`/`load_challenge_or_401`/`challenge_done`/`compute_required_factors`)
either run against the moto `T.sessions` or are patched at source; async handlers driven on a fresh
`asyncio.new_event_loop()`; no real AWS/network.

- **`tests/test_csn_001_002_psd2_consents.py`:** create → INITIATED; `account_refs` empty / bad
  `view_refs` → 400; `ByConsumer` list returns only the matching consumer's consents; revoke
  INITIATED/ACCEPTED → REVOKED, second revoke → 409/no-op; `expire_due_consents` flips an
  expired ACCEPTED → EXPIRED + audits. SCA: `/sca` mints a `purpose="consent_sca"` challenge;
  `/accept` before `challenge_done` → 403; after marking the required factors passed → ACCEPTED +
  challenge revoked; replay of `/accept` idempotent. PIS: `consent_type="PIS"` stores `payment_ref`,
  always requires SCA, `consent_authorizes_payment` True only for ACCEPTED+unexpired+matching, and
  asserts **no ledger/wallet write** occurs. Rate limit: `rate_limit_consent(id,"read")` 429s at the
  cap with the `consent_rate_limited` shape; distinct ids → distinct budgets.
- **`tests/test_csn_003_dynamic_entities.py`:** root registers a schema; non-root → 403; flag-off →
  routes 404; valid `data` persists; schema-violating `data` → 400 naming the field; bad
  entity-name/reserved/over-cap → 400; unknown entity CRUD → 404; owner-scoped list/update/delete.
- **`tests/test_csn_004_dynamic_endpoints.py`:** register a `static_response` endpoint → `GET
  /custom/...` returns the stored body/status; `dynamic_entity_proxy` returns a CSN-003 entity's
  rows; duplicate method+path → 409; unsafe path / bad connector → 400; unregistered `/custom/...`
  → 404; flag-off → 404.
- **`tests/test_csn_005_open_data.py`:** root upserts a branch + ATM; public GET returns active
  resources with **no auth**; inactive hidden from public but in admin list; non-root write → 403;
  public route ids present in `API_KEY_ROUTE_EXEMPTIONS`; flag-off → 404.

#### Acceptance Criteria
- All four test modules pass offline with no real AWS/network (moto in-memory DDB bound to the
  frozen `T.*` handles; MFA/KMS collaborators run on moto or patched at source).
- Negative-path coverage exists for every reject branch: consent SCA-incomplete/replay, PIS
  no-money-move, consent rate-limit 429; schema-validation/reserved-name/unknown-entity;
  duplicate/unsafe dynamic-endpoint; non-root admin 403; flag-off 404 for every router.
- Tests assert dev/prod-parity invariants: no `if S.dev_mode:` branch is exercised; the same code
  path runs under moto as would run against real DynamoDB.
- (Optional, in this ticket) Playwright specs driving the consent lifecycle + a public open-data
  GET against the live local stack with the CSN flags on.

#### Dependencies
CSN-001, CSN-002, CSN-003, CSN-004, CSN-005 (tests cover all of them).

---

## Ticket summary (dependency order)

| Ticket | Title | Type | Priority | Est. | Depends on |
|--------|-------|------|----------|------|-----------|
| CSN-001 | PSD2 AIS consent — model/table/flag/grant/status/list-by-consumer/revoke | Feature | P2 | 3d | — (soft: OAU, VIEWS) |
| CSN-002 | Consent SCA gate + PIS↔TXR link + consent-scoped rate limit | Feature | P2 | 3d | CSN-001 (soft: TXR) |
| CSN-003 | Dynamic Entities — runtime JSON-schema → generated CRUD (admin) | Feature | P3 | 3.5d | — |
| CSN-004 | Dynamic Endpoints — register custom OpenAPI path → connector | Feature | P3 | 3d | CSN-003 (proxy kind) |
| CSN-005 | Open-data Branches + ATMs — CRUD + public GETs | Feature | P3 | 2.5d | — |
| CSN-006 | Tests — consents / dynamic entities+endpoints / open-data | Test | P2 | 3d | CSN-001..005 |

**Total: 6 tickets, ~18 engineer-days.** All additive + flag-gated default-off, single-table DDB
with `attr_types` for numeric GSI keys, reusing the OAuth-consent shape (`provider_oauth.py`), the
MFA/SCA stack (`sessions.py`/`ui_mfa.py`), the `rate_limit._bucket_limit` throttle, the api-key /
root-session auth + audit primitives, the webhook taxonomy, and the public-router/no-auth pattern
(`calendar.public_event_router`) — never forking. Honestly the **lowest-fit OBP features**
(PSD2 consents, runtime API generation, physical-branch open-data); multi-standard adapters
remain DE-SCOPED. dev/prod parity per SECOPS-007; hermetic offline tests.
