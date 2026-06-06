---
id: AND-359
title: Delegates / delegation API
milestone: M7
epic: E46
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-359 — Delegates / delegation API

## 1. Overview & Goal

This ticket ports the web reference module `frontend/src/api/endpoints/delegates.ts`
to the Android client and implements **manage-as-creator mode**: the ability for an
authenticated principal who has been granted a delegation (e.g. an agency manager,
an assistant, an org operator) to act *on behalf of* a creator account, with every
subsequent API call and UI surface scoped to that creator.

The deliverable is three layers, all under `com.testlogon.android`:

1. A typed Retrofit transport `DelegatesApi` covering the delegation lifecycle:
   listing delegations the current user holds, entering a delegated ("manage-as")
   context, querying the active context, and exiting it.
2. A `DelegationRepository` in `:core:data` that wraps those endpoints in
   `ApiResult<T>` and owns the **`managingCreator`** auth-store flag — a durable,
   observable record of which creator (if any) the session is currently acting as.
3. A `DelegateScopeInterceptor` that, while a delegation is active, attaches the
   acting-as identity to outgoing requests so that downstream feature areas
   (feed, messaging, earnings, files, etc.) automatically operate against the
   delegated creator without per-call changes.

Scope, verbatim from the backlog: *`delegates.ts`/delegation API; manage-as-creator
mode (auth store `managingCreator`).* Acceptance, verbatim: *Enter delegate mode;
scoped actions apply.*

This ticket owns the **delegation transport, repository, the `managingCreator`
state, and the scoping seam**. It does **not** own the delegation management *screen*
(picker UI, delegate-mode banner — a downstream feature-orgs ticket), nor any
specific scoped feature behaviour beyond proving the scope header is applied.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Transport lands in `:core:network`
  (`com.testlogon.android.core.network.delegates`); DTOs in `:core:model`
  (`com.testlogon.android.core.model.delegates`); repository, `managingCreator`
  store, and interceptor in `:core:data`
  (`com.testlogon.android.core.data.delegates`).
- **Canonical package / applicationId base:** `com.testlogon.android` everywhere.
- **Stack pins:** Kotlin 2.0.21, Retrofit 2.11.0, OkHttp 4.12.0, Moshi 1.15.x
  (KSP codegen), Hilt (KSP), Coroutines/Flow, DataStore (prefs), JDK 17,
  minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. No `feature-*`/`app` symbols
  leak into `:core:network`/`:core:data`.
- **Upstream — AND-027 (AuthApi / session endpoints):** establishes the
  cookie-based session this ticket layers on. Delegation is a *property of an
  already-authenticated session*: the user logs in normally, then enters a
  delegated context. `DelegatesApi` reuses the same shared Retrofit/OkHttp stack
  (cookie jar AND-011, CSRF interceptor AND-012, 401-refresh Authenticator
  AND-013, `ApiResult` AND-018, backoff AND-016).
- **Related — AND-029 (getMe / auth state store):** defines `AuthStateStore`
  exposing `StateFlow<AuthState>`. This ticket *extends* that store with the
  `managingCreator` field rather than introducing a parallel store.
- **Web reference:** `frontend/src/api/endpoints/delegates.ts`; shared types
  `frontend/src/api/types.ts`. Endpoint paths/shapes below are mirrored from that
  module and `/openapi.json`; confirm against live `/openapi.json` at integration.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable): ~20s timeouts, bounded backoff for idempotent
  GETs only (owned by AND-009/AND-016), offline/stale UI states.

## 3. Functional Requirements

FR-1. Declare a Retrofit interface `DelegatesApi` covering exactly:
`listDelegations`, `enterDelegation`, `currentDelegation`, `exitDelegation`.

FR-2. `DelegationRepository.delegations()` returns the set of creators the current
principal may manage (`ApiResult<List<Delegation>>`), each carrying the creator
identity, display name, and the scopes/permissions granted to the delegate.

FR-3. `DelegationRepository.enter(creatorSub)` calls the enter endpoint; on success
it writes `managingCreator = ManagingCreator(creatorSub, displayName, scopes)` to
the auth store and returns `ApiResult.Success(ActiveDelegation)`. The active
delegation is **session-scoped + durable across process death** (DataStore) so the
banner/scoping survives a cold start while the cookie remains valid.

FR-4. While `managingCreator != null`, all outbound API requests carry the
acting-as identity (see §4.3) so downstream reads/writes apply to the delegated
creator. This is the operational meaning of "scoped actions apply."

FR-5. `DelegationRepository.exit()` calls the exit endpoint and clears
`managingCreator` back to `null`, returning the session to acting as self. Exit
MUST be attempted even when the network call fails (local clear is unconditional;
see §7) so a user is never trapped in a stale delegate context.

FR-6. `managingCreator` is exposed as `StateFlow<ManagingCreator?>` so navigation,
the delegate-mode banner (downstream), and feature ViewModels can react without
re-hitting the network.

FR-7. On a hard auth reset — logout (AND-032) or a 401 that exhausts refresh
(AND-013/AND-029) — `managingCreator` MUST be cleared along with `AuthState`. A
delegation never outlives the underlying session.

FR-8. `currentDelegation()` reconciles server truth with local state at cold start:
if the server reports no active delegation but local state has one (or vice-versa),
server wins and the local store is corrected.

## 4. Technical Design

### 4.1 DTOs (`:core:model`)

```kotlin
@JsonClass(generateAdapter = true)
data class DelegationDto(
    @Json(name = "creator_sub") val creatorSub: String,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "username") val username: String?,
    @Json(name = "avatar_url") val avatarUrl: String?,
    @Json(name = "scopes") val scopes: List<String> = emptyList(),
    @Json(name = "granted_at") val grantedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class EnterDelegationReq(@Json(name = "creator_sub") val creatorSub: String)

@JsonClass(generateAdapter = true)
data class ActiveDelegationDto(
    @Json(name = "active") val active: Boolean,
    @Json(name = "creator_sub") val creatorSub: String?,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "scopes") val scopes: List<String> = emptyList(),
)
```

Domain models (mapped from DTOs, no Moshi annotations):

```kotlin
data class Delegation(
    val creatorSub: String,
    val displayName: String,
    val username: String?,
    val avatarUrl: String?,
    val scopes: Set<DelegateScope>,
)

data class ManagingCreator(
    val creatorSub: String,
    val displayName: String,
    val scopes: Set<DelegateScope>,
)

enum class DelegateScope { MESSAGING, FEED, EARNINGS, BILLING, FILES, CALENDAR, UNKNOWN }
```

`DelegateScope.from(raw: String)` maps unknown strings to `UNKNOWN` (forward-compat).

### 4.2 Transport (`:core:network`)

```kotlin
interface DelegatesApi {
    @GET("ui/delegates")
    suspend fun listDelegations(): Response<List<DelegationDto>>

    @POST("ui/delegates/enter")
    suspend fun enterDelegation(@Body body: EnterDelegationReq): Response<ActiveDelegationDto>

    @GET("ui/delegates/current")
    suspend fun currentDelegation(): Response<ActiveDelegationDto>

    @POST("ui/delegates/exit")
    suspend fun exitDelegation(): Response<ActiveDelegationDto>
}
```

Hilt provider in the existing network module:

```kotlin
@Provides @Singleton
fun provideDelegatesApi(retrofit: Retrofit): DelegatesApi =
    retrofit.create(DelegatesApi::class.java)
```

### 4.3 The scoping seam — `DelegateScopeInterceptor`

The interceptor reads `managingCreator` (a non-suspending snapshot via
`StateFlow.value`) and, when present, adds the acting-as header to every request:

```kotlin
class DelegateScopeInterceptor @Inject constructor(
    private val store: AuthStateStore,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val mc = store.managingCreator.value
        val req = if (mc != null) {
            chain.request().newBuilder()
                .header("X-Manage-As", mc.creatorSub)
                .build()
        } else chain.request()
        return chain.proceed(req)
    }
}
```

It is registered as an **application interceptor** on the shared `OkHttpClient`
(ordered after the CSRF interceptor, before logging) so it covers all feature
traffic uniformly. The header name (`X-Manage-As`) mirrors the cookie/header
convention used by the web `delegates.ts`; confirm exact name against the backend
before merge and centralise it in a `DelegateHeaders` constant.

> If the backend instead scopes via a server-side cookie set by `enter`/`exit`
> (rather than a per-request header), the interceptor becomes a no-op and the
> persistent cookie jar (AND-011) already carries scope. The repository contract,
> `managingCreator` state, and ACs are unchanged either way; only §4.3 flips. This
> is called out as Open Question OQ-1.

### 4.4 Repository (`:core:data`)

```kotlin
interface DelegationRepository {
    suspend fun delegations(): ApiResult<List<Delegation>>
    suspend fun enter(creatorSub: String): ApiResult<ManagingCreator>
    suspend fun current(): ApiResult<ManagingCreator?>
    suspend fun exit(): ApiResult<Unit>
}

class DefaultDelegationRepository @Inject constructor(
    private val api: DelegatesApi,
    private val authStore: AuthStateStore,
    private val errorMapper: ApiErrorMapper,        // AND-015
) : DelegationRepository {

    override suspend fun enter(creatorSub: String): ApiResult<ManagingCreator> =
        runCatchingApi(errorMapper) {
            val dto = api.enterDelegation(EnterDelegationReq(creatorSub)).bodyOrThrow()
            val mc = dto.toManagingCreator()
            authStore.setManagingCreator(mc)        // durable + StateFlow emit
            mc
        }

    override suspend fun exit(): ApiResult<Unit> =
        try {
            runCatchingApi(errorMapper) { api.exitDelegation().bodyOrThrow(); Unit }
        } finally {
            authStore.setManagingCreator(null)      // FR-5: unconditional local clear
        }
    // delegations() / current() analogous; current() reconciles per FR-8
}
```

### 4.5 Auth store extension (`:core:data`, extends AND-029)

`AuthStateStore` gains:

```kotlin
val managingCreator: StateFlow<ManagingCreator?>
suspend fun setManagingCreator(mc: ManagingCreator?)
```

Backed by DataStore Preferences keys `managing_creator_sub`,
`managing_creator_name`, `managing_creator_scopes` (CSV). `clear()` (AND-029/032)
also removes these keys, satisfying FR-7.

## 5. API Contract

Base URL (dev): `http://18.222.237.167:8000/`. All calls ride the cookie session +
`X-CSRF-Token` for mutating verbs (handled by AND-012). Paths below mirror
`frontend/src/api/endpoints/delegates.ts`; verify against `/openapi.json`.

**`GET /ui/delegates`** → `200`
```json
[
  { "creator_sub": "u_creator_42", "display_name": "Nova Star",
    "username": "novastar", "avatar_url": "https://.../a.jpg",
    "scopes": ["messaging", "feed", "earnings"], "granted_at": "2026-05-01T12:00:00Z" }
]
```

**`POST /ui/delegates/enter`** — body `{ "creator_sub": "u_creator_42" }` → `200`
```json
{ "active": true, "creator_sub": "u_creator_42",
  "display_name": "Nova Star", "scopes": ["messaging", "feed", "earnings"] }
```
Errors: `403` (delegate not authorised for that creator), `404` (unknown creator),
`409` (delegation revoked) — all surfaced via the FastAPI `detail` mapping (AND-015).

**`GET /ui/delegates/current`** → `200` `{ "active": false, "creator_sub": null, "scopes": [] }`
when acting as self, else the active-delegation shape above.

**`POST /ui/delegates/exit`** → `200` `{ "active": false, "creator_sub": null, "scopes": [] }`.

**Scoped traffic:** while a delegation is active, every request carries
`X-Manage-As: <creator_sub>` (§4.3). Acceptance for "scoped actions apply" is
proven by asserting this header on a representative downstream call.

`detail` shapes handled by AND-015's mapper: `string`, `[{msg}]`, `{code, ...}`.

## 6. Data & State Management

- **Single source of truth:** `AuthStateStore.managingCreator: StateFlow<ManagingCreator?>`.
  `null` = acting as self; non-null = manage-as-creator mode.
- **Durability:** persisted to DataStore so the delegate context survives process
  death while the cookie session is valid. First emission derives from DataStore.
- **Reconciliation (cold start):** if `authState` is `Authenticated`, call
  `current()` in the background; server response overwrites local `managingCreator`
  (FR-8). Mismatch → server wins.
- **Lifecycle coupling:** `managingCreator` is strictly subordinate to `AuthState`.
  Transition to `Unauthenticated` (logout, exhausted-refresh 401) clears it (FR-7).
- **No Room cache:** delegation lists are small and authorisation-sensitive; fetch
  on demand. The active context is the only persisted datum.
- **Consumers (downstream):** delegate picker screen + delegate-mode banner read
  `managingCreator`; feature ViewModels may read it to label "you are managing X".

## 7. Error Handling & Resilience

- **Transport:** all calls wrapped in `ApiResult<T>` via `runCatchingApi` (AND-018);
  FastAPI `detail` mapped by AND-015. ~20s timeouts (AND-009).
- **Idempotent GETs** (`listDelegations`, `currentDelegation`) are eligible for the
  bounded backoff retry (AND-016). `enter`/`exit` are **POST and not retried**
  automatically.
- **Enter failures:** `403/404/409` return `ApiResult.Error` with a user-readable
  message; `managingCreator` is **not** mutated (stay as self).
- **Exit resilience (FR-5):** `setManagingCreator(null)` runs in a `finally` block
  so a network failure on `exitDelegation` still drops local delegate scope —
  the user is never trapped. A best-effort retry of the server exit may be enqueued.
- **Offline:** `delegations()`/`current()` return `ApiResult.Error(Offline)` →
  consumers render the offline state (AND-021). Entering a delegation while offline
  is disallowed (requires server confirmation).
- **Revoked mid-session:** a scoped call returning `403` with a revocation code
  signals the repository to clear `managingCreator` and emit so the UI exits
  delegate mode and informs the user.

## 8. Security & Privacy

- **Authorisation is server-enforced.** The client never assumes a delegation is
  valid; `enter` must succeed server-side before `managingCreator` is set. The
  `X-Manage-As` header is an *assertion*, validated by the backend against the
  delegate's grants — the client cannot escalate by forging it.
- **No secrets in the header:** `X-Manage-As` carries only the opaque creator
  `sub`, not credentials. Auth remains cookie + CSRF (AND-011/AND-012).
- **PII minimisation in DataStore:** persist only `creator_sub`, display name, and
  scope strings — no creator credentials, tokens, or financial data. Consistent
  with AND-029's stance on plaintext DataStore.
- **Audit clarity:** because the header rides every scoped request, the backend can
  audit delegate actions; the client must never silently mix self + delegated
  traffic (the interceptor reads one atomic snapshot per request).
- **Plaintext dev host:** dev backend is HTTP; treat all delegation traffic as
  observable in dev. Production must be HTTPS (platform default).

## 9. Accessibility & i18n

- This ticket is data/transport-layer; no screens. All user-facing strings it
  *produces* (error messages, "Now managing {name}" / "Exited delegate mode")
  are `string` resources with placeholders, routed through the i18n plumbing
  (AND-111) — no hardcoded literals in `:core:data`.
- Scope names (`messaging`, `earnings`, …) shown to users must be mapped to
  localised labels by the consuming screen, not surfaced raw.
- The delegate-mode banner's a11y semantics (role, live-region announcement on
  enter/exit) are owned by the downstream banner ticket; this ticket exposes the
  `StateFlow` it needs.

## 10. Telemetry & Logging

- Emit structured events (existing telemetry façade, cf. AND-052 redaction rules):
  `delegate_enter_attempt`, `delegate_enter_success`, `delegate_enter_failure`
  (with mapped error code), `delegate_exit`. Include `creator_sub` (opaque id) but
  **never** display name or PII in logs.
- Log the active-delegation reconciliation outcome at `DEBUG` (`local`, `server`,
  `corrected`).
- OkHttp logging (AND-009) must **redact** the `X-Manage-As` value to a hashed/short
  form at `BASIC`+ levels to avoid leaking creator ids into shared logcat.

## 11. Testing Strategy

**Unit — repository (`:core:data`, MockWebServer via AND-046 harness):**
- `enter()` 200 → `ApiResult.Success`, `managingCreator` emits non-null with mapped
  scopes.
- `enter()` 403/404/409 → `ApiResult.Error` with mapped detail; `managingCreator`
  stays `null`.
- `exit()` 200 → `managingCreator` cleared.
- `exit()` network failure → `managingCreator` **still** cleared (FR-5 `finally`).
- `current()` reconciliation: local non-null + server `active:false` → store
  corrected to `null` (FR-8).
- `delegations()` decodes the list DTO; unknown scope string → `DelegateScope.UNKNOWN`.

**Unit — `DelegateScopeInterceptor`:**
- `managingCreator == null` → no `X-Manage-As` header.
- `managingCreator != null` → header equals `creator_sub` on the outbound request.

**Integration — scoping proof (acceptance):** with a delegation active, fire a
representative downstream GET through the real OkHttp stack against MockWebServer
and assert the recorded request carried `X-Manage-As: u_creator_42`. This is the
testable form of "Enter delegate mode; scoped actions apply."

**Lifecycle:** simulate logout / exhausted-refresh 401 → assert `managingCreator`
cleared alongside `AuthState` (FR-7).

CI: unit on every build (AND-050); instrumented not required (no UI here).

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) — the authenticated session
  delegation rides on. Transitively: AND-009/010/011/012/013/015/016/018 (shared
  network stack + error/result plumbing) and **AND-029** (`AuthStateStore`, which
  this ticket extends with `managingCreator`).
- **Blocks:** the downstream delegate-mode UI (picker screen + banner) and any
  feature area that surfaces "managing X" labelling, within epic E46 / M7. No
  blocked ids are listed in the source backlog, so `blocks: []` until the UI
  ticket is filed.
- **Implementation order:** (1) DTOs + domain mappers in `:core:model`;
  (2) `DelegatesApi` + Hilt provider in `:core:network`; (3) `AuthStateStore`
  `managingCreator` extension + DataStore keys; (4) `DefaultDelegationRepository`;
  (5) `DelegateScopeInterceptor` registration on shared OkHttp; (6) tests.

## 13. Risks & Open Questions

- **OQ-1 (scope mechanism):** Does the backend scope delegated traffic via a
  per-request header (`X-Manage-As`) or via a cookie set by `enter`/`exit`?
  Resolve against `/openapi.json` + `delegates.ts` before merge; §4.3 design covers
  both, only the interceptor body changes.
- **OQ-2 (exact paths/header name):** `ui/delegates{,/enter,/current,/exit}` and
  `X-Manage-As` are mirrored from the web reference; confirm casing/prefix.
- **OQ-3 (CSRF on scoped POSTs):** confirm the `ui_csrf` cookie/header remains valid
  and unchanged while delegated (expected yes — same session).
- **Risk:** stale delegate context leaking self-actions as delegate (or vice-versa)
  if the interceptor reads an inconsistent snapshot. Mitigated by one atomic
  `StateFlow.value` read per request and the cold-start reconciliation (FR-8).
- **Risk:** unreliable dev host causing `enter` to time out after the server
  actually granted scope → local/server divergence. Mitigated by `current()`
  reconciliation and unconditional-clear exit.

## 14. Acceptance Criteria

AC-1. `DelegatesApi` exposes `listDelegations`/`enterDelegation`/`currentDelegation`/
`exitDelegation` with the exact verbs and paths in §5; each is callable and decodes
its response (MockWebServer). *(unit, tested)*

AC-2. `DelegationRepository.enter(creatorSub)` on 200 sets
`managingCreator` to the mapped `ManagingCreator` and the `StateFlow` emits it.
*(unit, tested)*

AC-3. **Enter delegate mode; scoped actions apply** — with a delegation active, a
downstream request carries `X-Manage-As: <creator_sub>`; with no delegation, it
does not. *(integration, tested)*

AC-4. `exit()` clears `managingCreator` even when the server call fails. *(unit, tested)*

AC-5. Logout / exhausted-refresh 401 clears `managingCreator` alongside `AuthState`.
*(unit, tested)*

AC-6. `current()` reconciles divergent local vs. server state with server winning.
*(unit, tested)*

AC-7. Enter failures (403/404/409) surface mapped `detail` errors and leave
`managingCreator` unchanged. *(unit, tested)*

## 15. Definition of Done

- All ACs met; code under `com.testlogon.android` in `:core:model` / `:core:network`
  / `:core:data` as laid out in §4; graph compiles (KSP) with no missing bindings.
- `DelegateScopeInterceptor` registered on the shared `OkHttpClient`; `X-Manage-As`
  redacted in OkHttp logs.
- `AuthStateStore` extended with `managingCreator` + DataStore keys; `clear()`
  removes them.
- Unit + integration tests above pass in CI (AND-050); MockWebServer fixtures added
  to the AND-046 harness.
- No hardcoded user-facing strings in `:core:data`; telemetry events emitted with
  PII redacted per AND-052.
- KDoc on `DelegationRepository`, `DelegateScope`, and the `managingCreator` store
  surface; PR notes OQ-1/OQ-2/OQ-3 resolution and the downstream delegate-mode UI
  consumer.
