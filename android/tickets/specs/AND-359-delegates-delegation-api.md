---
id: AND-359
title: Delegates / delegation API
milestone: M7
epic: E46
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> **REVIEWER CORRECTION (AND-359 review, 2026-06-06):** The original draft assumed an
> *enter/exit/current* delegation lifecycle backed by `POST /ui/delegates/enter`,
> `POST /ui/delegates/exit`, and `GET /ui/delegates/current`. **None of those
> endpoints exist** in the backend OpenAPI, and the web reference (`stores/authStore.ts`,
> `pages/messages/DelegateBanner.tsx`) implements "manage-as-creator" as **pure
> client-side state**: `setManagingCreator(creatorId, name)` / `setManagingCreator(null)`.
> There is **no network round-trip** to enter or exit delegate mode. Additionally,
> scoping is **path-based** — delegated actions hit dedicated
> `/{area}/delegate/{creator_id}/...` endpoints — not a blanket `X-Manage-As` header.
> The sections below are corrected to match; see §16 for the full audit.

The deliverable is three layers, all under `com.testlogon.android`:

1. A typed Retrofit transport `DelegatesApi` covering the delegation surface that
   **actually exists**: `GET /ui/delegates/managed` (creators the current principal
   may manage) plus the delegate-management endpoints (`GET/POST /ui/delegates`,
   `GET /ui/delegates/invites`, `POST /ui/delegates/invites/{creator_id}/respond`,
   etc.). **There is no enter/exit/current endpoint** (corrected).
2. A `DelegationRepository` in `:core:data` that wraps those endpoints in
   `ApiResult<T>` and owns the **`managingCreator`** auth-store flag — an
   observable record of which creator (if any) the session is currently acting as.
   Entering/exiting delegate mode is a **local state mutation**, mirroring the web
   reference (`authStore.setManagingCreator`).
3. Scoped feature traffic operates by calling the **path-scoped delegate endpoints**
   (`/messaging/delegate/{creator_id}/...`, `/ui/newsfeed/delegate/{creator_id}/...`,
   `/ui/broadcast/delegate/{creator_id}/...`) using `managingCreator.creatorId` as
   the `{creator_id}` path segment. (The original draft's blanket
   `DelegateScopeInterceptor` adding `X-Manage-As` to all traffic does not match the
   backend; see §4.3 and §16-OQ-1.)

Scope, verbatim from the backlog: *`delegates.ts`/delegation API; manage-as-creator
mode (auth store `managingCreator`).* Acceptance, verbatim: *Enter delegate mode;
scoped actions apply.*

This ticket owns the **delegation transport, repository, the `managingCreator`
state, and the path-scoping seam** (resolving the active `creator_id` for delegate
endpoints). It does **not** own the delegation management *screen* (picker UI,
delegate-mode banner — a downstream feature-orgs ticket), nor any specific scoped
feature behaviour beyond proving the active `creator_id` is correctly threaded into
a representative delegate endpoint call.

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
  authenticated session this ticket layers on. **CORRECTION:** the web client
  (`src/api/client.ts`) authenticates with an `Authorization: Bearer <accessToken>`
  header (token from the auth store), plus a `X-CSRF-Token` header read from the
  `ui_csrf` cookie on mutating verbs, and a `X-SESSION-ID` header (present as a
  param on every delegate endpoint in the OpenAPI index). It is **not** a pure
  cookie session — though `credentials: "include"` is also sent. Delegation is a
  *property of an already-authenticated session*: the user logs in normally, then
  enters a delegated context **locally**. `DelegatesApi` reuses the same shared
  Retrofit/OkHttp stack (cookie jar AND-011, CSRF interceptor AND-012, 401-refresh
  Authenticator AND-013, `ApiResult` AND-018, backoff AND-016). Note the web 401
  handler refreshes via `POST /ui/session/refresh`.
- **Related — AND-029 (getMe / auth state store):** defines `AuthStateStore`
  exposing `StateFlow<AuthState>`. This ticket *extends* that store with the
  `managingCreator` field rather than introducing a parallel store.
- **Web reference (verified):** `src/api/endpoints/delegates.ts`; shared types
  `src/api/types.ts`; state in `src/stores/authStore.ts`; banner UX in
  `src/pages/messages/DelegateBanner.tsx`; transport in `src/api/client.ts`.
  Endpoint paths/shapes below have been **verified against the OpenAPI index/spec
  and the web source** during this review (§16). Note the web app's
  `X-IMPERSONATION-TOKEN` header (`src/stores/impersonationStore.ts`) is a
  **separate admin-impersonation feature**, NOT the delegate-scoping mechanism.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable): ~20s timeouts, bounded backoff for idempotent
  GETs only (owned by AND-009/AND-016), offline/stale UI states.

## 3. Functional Requirements

FR-1. **(CORRECTED)** Declare a Retrofit interface `DelegatesApi` covering the
endpoints that exist in the backend. At minimum for "manage-as":
`GET /ui/delegates/managed` (creators I may manage → `List<ManagedCreatorDto>`).
The fuller delegate-management surface (`GET/POST /ui/delegates`,
`GET /ui/delegates/invites`, `POST /ui/delegates/invites/{creator_id}/respond`,
`GET/PUT /ui/delegates/settings`, `GET /ui/delegates/presets`,
`GET /ui/delegates/audit`, `GET/DELETE/PUT /ui/delegates/{delegate_id}[/permissions]`)
mirrors `src/api/endpoints/delegates.ts` and MAY be split into a downstream UI
ticket — for AND-359 the *required* call is `listManagedCreators`. There is **no**
`enterDelegation`/`currentDelegation`/`exitDelegation` endpoint (removed).

FR-2. `DelegationRepository.managedCreators()` returns the set of creators the
current principal may manage (`ApiResult<List<ManagedCreator>>`), each carrying the
`creator_id`, the granted `permissions`, `preset`, `status`, `label`, and
`accepted_at`. **CORRECTION:** the DTO is `ManagedCreatorOut` (no `display_name`,
`username`, `avatar_url`, `scopes`, or `granted_at`; the human label is `label` and
permissions are in `permissions`).

FR-3. **(CORRECTED — no network call)** `DelegationRepository.enter(creatorId, label)`
writes `managingCreator = ManagingCreator(creatorId, label, permissions)` to the
auth store **locally** and returns `ApiResult.Success(ManagingCreator)`. Mirrors
web `setManagingCreator(creatorId, name)`. There is no enter endpoint to call.
**Persistence:** the web reference does **NOT** persist `managingCreator` across
reloads (`authStore.ts` `partialize` omits it). Persisting it on Android via
DataStore (so the banner survives process death) is a **deliberate, allowed
divergence**, flagged as an assumption in §16 (OQ-2); if parity is required, keep
it in-memory only.

FR-4. While `managingCreator != null`, downstream feature areas issue their
requests against the **path-scoped delegate endpoints** using
`managingCreator.creatorId` as the `{creator_id}` path segment (e.g.
`GET /messaging/delegate/{creator_id}/conversations`). This is the operational
meaning of "scoped actions apply." **CORRECTION:** there is no per-request
`X-Manage-As` header.

FR-5. **(CORRECTED — no network call)** `DelegationRepository.exit()` clears
`managingCreator` back to `null` locally (web `setManagingCreator(null)`),
returning the session to acting as self. Because it is purely local, it cannot
fail on the network and the user can never be trapped in a stale delegate context.

FR-6. `managingCreator` is exposed as `StateFlow<ManagingCreator?>` so navigation,
the delegate-mode banner (downstream), and feature ViewModels can react.

FR-7. On a hard auth reset — logout (AND-032) or a 401 that exhausts refresh
(AND-013/AND-029) — `managingCreator` MUST be cleared along with `AuthState`. A
delegation never outlives the underlying session. (Verified parity: web `logout()`
resets `managingCreatorId`/`managingCreatorName` to `null`.)

FR-8. **(CORRECTED)** There is no `current()` server endpoint to reconcile against.
Instead, at cold start (if persisted per FR-3) the repository SHOULD validate the
persisted `managingCreator.creatorId` against a fresh `listManagedCreators()`: if
that creator is no longer in the managed set (or its `status != "active"`), clear
`managingCreator`. This replaces the original "server `current()` wins" claim,
which referenced a non-existent endpoint.

## 4. Technical Design

### 4.1 DTOs (`:core:model`)

**CORRECTED to match `components.schemas.ManagedCreatorOut` and `src/api/types.ts`.**
There is no `creator_sub`/`display_name`/`username`/`avatar_url`/`scopes`/`granted_at`
and no `EnterDelegationReq`/`ActiveDelegationDto` (those endpoints don't exist).

```kotlin
@JsonClass(generateAdapter = true)
data class ManagedCreatorDto(
    @Json(name = "creator_id") val creatorId: String,          // required
    @Json(name = "permissions") val permissions: List<String> = emptyList(),
    @Json(name = "preset") val preset: String? = null,
    @Json(name = "status") val status: String = "",            // e.g. "active" / "pending"
    @Json(name = "label") val label: String = "",
    @Json(name = "accepted_at") val acceptedAt: Long = 0,      // epoch seconds (integer)
)
```

Domain models (mapped from DTOs, no Moshi annotations):

```kotlin
data class ManagedCreator(
    val creatorId: String,
    val label: String,                 // falls back to creatorId when blank (web behaviour)
    val permissions: Set<DelegatePermission>,
    val preset: String?,
    val status: String,
)

data class ManagingCreator(
    val creatorId: String,
    val label: String,                 // display label for the banner
    val permissions: Set<DelegatePermission>,
)

// CORRECTED: real permission vocabulary from DelegatesPage.tsx ALL_PERMISSIONS.
enum class DelegatePermission {
    CHAT_READ, CHAT_RESPOND, FEED_READ, FEED_POST, FEED_MODERATE,
    BROADCAST_MODERATE, BROADCAST_CONTROL, UNKNOWN
}
```

`DelegatePermission.from(raw: String)` maps unknown strings to `UNKNOWN`
(forward-compat). NOTE: the original `DelegateScope` set
(`MESSAGING/EARNINGS/BILLING/FILES/CALENDAR`) was invented and does not match the
backend; `EARNINGS`/`BILLING`/`FILES`/`CALENDAR` delegate permissions are not in the
verified vocabulary.

### 4.2 Transport (`:core:network`)

**CORRECTED:** `enter`/`current`/`exit` removed (no such endpoints). The required
call for manage-as is `listManagedCreators` (`GET /ui/delegates/managed`). Note
`GET /ui/delegates` lists delegates *you have granted to others* (`DelegateOut[]`),
which is a different concept from creators you may manage.

```kotlin
interface DelegatesApi {
    // Creators the current principal may manage (the "manage-as" source list).
    @GET("ui/delegates/managed")
    suspend fun listManagedCreators(): Response<List<ManagedCreatorDto>>

    // --- Delegate-management surface (mirrors delegates.ts; may move to a UI ticket) ---
    @GET("ui/delegates")
    suspend fun listDelegates(): Response<List<DelegateDto>>

    @POST("ui/delegates")
    suspend fun addDelegate(@Body body: DelegateAddDto): Response<DelegateDto>

    @GET("ui/delegates/invites")
    suspend fun listInvites(): Response<List<DelegateDto>>

    @POST("ui/delegates/invites/{creatorId}/respond")
    suspend fun respondToInvite(
        @Path("creatorId") creatorId: String,
        @Body body: DelegateInviteRespondDto,
    ): Response<Unit>
    // getDelegateSettings / updateDelegateSettings / getDelegateAudit / listPresets /
    // getDelegate / updateDelegatePermissions / revokeDelegate analogous — see delegates.ts.
}
```

Hilt provider in the existing network module:

```kotlin
@Provides @Singleton
fun provideDelegatesApi(retrofit: Retrofit): DelegatesApi =
    retrofit.create(DelegatesApi::class.java)
```

### 4.3 The scoping seam — path-based `{creator_id}` resolution

**CORRECTED.** The original `DelegateScopeInterceptor` that injected an
`X-Manage-As` header on *all* traffic does **not** match the backend. Verified
against the OpenAPI index and the web source, delegated actions are scoped by
**dedicated path-templated endpoints** carrying the creator id as a path segment:

- Messaging: `GET/POST /messaging/delegate/{creator_id}/conversations[/...]`,
  `GET /messaging/delegate/{creator_id}/audit`
- Feed: `GET/POST/PUT/DELETE /ui/newsfeed/delegate/{creator_id}/posts[/...]`,
  drafts, settings, analytics, audit
- Broadcast: `POST /ui/broadcast/delegate/{creator_id}/sessions/...` (start/stop/
  schedule, moderation, bans, mutes)

There is no `X-Manage-As` header anywhere in the backend or web client. (The
`X-IMPERSONATION-TOKEN` header that *does* appear as a param on these endpoints is
the **admin-impersonation** feature driven by `src/stores/impersonationStore.ts` —
a separate concern, not delegation. Do not conflate them.)

The "scoping seam" this ticket owns is therefore a small, non-network helper, not an
interceptor: a way for downstream feature ViewModels/repositories to obtain the
active `creator_id` to substitute into their delegate-endpoint paths.

```kotlin
/** Single source of the active managed creator's id for delegate-scoped calls. */
class DelegateScope @Inject constructor(private val store: AuthStateStore) {
    /** Non-null when in manage-as mode; the value to use as {creator_id}. */
    fun activeCreatorId(): String? = store.managingCreator.value?.creatorId

    /** Convenience for downstream repos that must be scoped. */
    fun requireCreatorId(): String =
        activeCreatorId() ?: error("Not in delegate mode")
}
```

> **OQ-1 (RESOLVED by this review):** scoping is path-based (`{creator_id}` in the
> URL), not header- or cookie-based. The downstream feature tickets must call the
> `/.../delegate/{creator_id}/...` variants when `managingCreator != null` and the
> self variants otherwise. No shared-OkHttp interceptor is registered for
> delegation.

### 4.4 Repository (`:core:data`)

**CORRECTED:** `enter`/`exit` are **local-only** state mutations (no network);
`current()` is replaced by `validateActive()` against `listManagedCreators()`.

```kotlin
interface DelegationRepository {
    suspend fun managedCreators(): ApiResult<List<ManagedCreator>>
    /** Local: web parity with authStore.setManagingCreator(creatorId, name). */
    fun enter(creator: ManagedCreator)
    /** Local: web parity with authStore.setManagingCreator(null). */
    fun exit()
    /** Cold-start FR-8: drop managingCreator if it is no longer a managed creator. */
    suspend fun validateActive(): ApiResult<Unit>
}

class DefaultDelegationRepository @Inject constructor(
    private val api: DelegatesApi,
    private val authStore: AuthStateStore,
    private val errorMapper: ApiErrorMapper,        // AND-015
) : DelegationRepository {

    override suspend fun managedCreators(): ApiResult<List<ManagedCreator>> =
        runCatchingApi(errorMapper) {
            api.listManagedCreators().bodyOrThrow().map { it.toManagedCreator() }
        }

    override fun enter(creator: ManagedCreator) =
        authStore.setManagingCreator(             // local; StateFlow emit (+ DataStore, see FR-3)
            ManagingCreator(creator.creatorId, creator.label, creator.permissions)
        )

    override fun exit() = authStore.setManagingCreator(null)   // local; cannot fail

    override suspend fun validateActive(): ApiResult<Unit> =
        runCatchingApi(errorMapper) {
            val active = authStore.managingCreator.value ?: return@runCatchingApi Unit
            val managed = api.listManagedCreators().bodyOrThrow()
            val ok = managed.any { it.creatorId == active.creatorId && it.status == "active" }
            if (!ok) authStore.setManagingCreator(null)        // FR-8 corrected
            Unit
        }
}
```

### 4.5 Auth store extension (`:core:data`, extends AND-029)

`AuthStateStore` gains:

```kotlin
val managingCreator: StateFlow<ManagingCreator?>
suspend fun setManagingCreator(mc: ManagingCreator?)
```

Backed by DataStore Preferences keys `managing_creator_id`,
`managing_creator_label`, `managing_creator_permissions` (CSV). `clear()`
(AND-029/032) also removes these keys, satisfying FR-7. **CORRECTION:** the web
reference keeps `managingCreatorId`/`managingCreatorName` **in-memory only** (its
`partialize` omits them); DataStore persistence here is a deliberate Android
divergence (FR-3 / §16 OQ-2). The `mc.creatorSub`→`mc.creatorId` rename applies in
the §4.3 interceptor sketch removed above.

## 5. API Contract

**CORRECTED to verified backend contract.** Base URL (dev):
`http://18.222.237.167:8000/`. Verified headers (from `src/api/client.ts` +
OpenAPI params): `Authorization: Bearer <accessToken>`, `X-SESSION-ID`,
`X-CSRF-Token` (from `ui_csrf` cookie) on mutating verbs, plus `credentials:
include`. All delegate endpoints also list `user_sub` and `X-IMPERSONATION-TOKEN`
as params (the latter only set when admin impersonation is active — not delegation).
On `401`, the web client refreshes via `POST /ui/session/refresh` and retries once.

**`GET /ui/delegates/managed`** → `200` `List<ManagedCreatorOut>` — the
"manage-as" source list (creators I may act for):
```json
[
  { "creator_id": "u_creator_42", "permissions": ["chat_read", "chat_respond", "feed_post"],
    "preset": "social_manager", "status": "active",
    "label": "Nova Star", "accepted_at": 1746100800 }
]
```
(`creator_id` is the only required field; `accepted_at` is integer epoch seconds.)

**`GET /ui/delegates`** → `200` `List<DelegateOut>` — delegates *I have granted to
others* (different concept; `delegate_id`, `creator_id`, `permissions[]`, `preset?`,
`status`, `label`, `show_delegate_tag`, `delegate_tag_format`, `invited_at`,
`accepted_at`, `updated_at`). **`POST /ui/delegates`** body `DelegateAddIn`
(`delegate_id`, `permissions[]`, `preset?`, `label?`) → `200 DelegateOut`.

**`POST /ui/delegates/invites/{creator_id}/respond`** — body `{ "accept": true }`
(`DelegateInviteRespondIn`) → `200`.

**Other verified delegate-management endpoints:** `GET /ui/delegates/invites`,
`GET/PUT /ui/delegates/settings` (`DelegateSettingsOut`/`In`),
`GET /ui/delegates/presets`, `GET /ui/delegates/audit`,
`GET/DELETE /ui/delegates/{delegate_id}`,
`PUT /ui/delegates/{delegate_id}/permissions`.

**ENTERING/EXITING delegate mode: no endpoint.** Done purely client-side
(`setManagingCreator(creatorId, label)` / `setManagingCreator(null)`). The original
`/ui/delegates/enter`, `/ui/delegates/current`, `/ui/delegates/exit` **do not
exist** and have been removed.

**Scoped traffic (CORRECTED):** while a delegation is active, downstream features
call **path-scoped delegate endpoints** with `{creator_id} = managingCreator.creatorId`,
e.g. `GET /messaging/delegate/{creator_id}/conversations`,
`POST /ui/newsfeed/delegate/{creator_id}/posts`. Acceptance for "scoped actions
apply" is proven by asserting a representative call targets the delegate path with
the correct `creator_id`. **No `X-Manage-As` header is sent.**

**Errors:** all delegate endpoints document `422 HTTPValidationError` (FastAPI
validation: `detail` is `[{loc, msg, type}]`). Authorization failures surface as
`403` with a `detail` object carrying a `code` (e.g. `role_required`,
`role_required_scope`) — see `mapAuthorizationError` in `src/api/client.ts`.
`detail` shapes handled by AND-015's mapper: `string`, `[{msg}]`, `{code, ...}`.

## 6. Data & State Management

- **Single source of truth:** `AuthStateStore.managingCreator: StateFlow<ManagingCreator?>`.
  `null` = acting as self; non-null = manage-as-creator mode.
- **Durability (DIVERGENCE):** the web reference does NOT persist `managingCreator`
  (`authStore.ts partialize` omits it). This spec persists it to DataStore on
  Android so the banner survives process death; if web parity is mandated, keep it
  in-memory only (§16 OQ-2). First emission derives from DataStore (or `null`).
- **Reconciliation (cold start, CORRECTED):** there is no `current()` endpoint. If
  `authState` is `Authenticated` and a persisted `managingCreator` exists, call
  `listManagedCreators()` in the background and clear `managingCreator` if its
  `creatorId` is absent or not `status == "active"` (FR-8). Otherwise keep local.
- **Lifecycle coupling:** `managingCreator` is strictly subordinate to `AuthState`.
  Transition to `Unauthenticated` (logout, exhausted-refresh 401) clears it (FR-7).
- **No Room cache:** delegation lists are small and authorisation-sensitive; fetch
  on demand. The active context is the only persisted datum.
- **Consumers (downstream):** delegate picker screen + delegate-mode banner read
  `managingCreator`; feature ViewModels may read it to label "you are managing X".

## 7. Error Handling & Resilience

- **Transport:** all calls wrapped in `ApiResult<T>` via `runCatchingApi` (AND-018);
  FastAPI `detail` mapped by AND-015. ~20s timeouts (AND-009).
- **Idempotent GETs** (`listManagedCreators`, `listDelegates`, `listInvites`,
  settings/presets/audit GETs) are eligible for the bounded backoff retry (AND-016).
- **Enter/exit (CORRECTED):** these are **local-only** state writes with no network
  call, so they cannot return `403/404/409` and never block on the network. The
  validation/authorization failures instead surface when a **scoped delegate
  endpoint** is later called (downstream feature ticket).
- **Exit resilience (FR-5):** `exit()` = `setManagingCreator(null)`; purely local
  and synchronous, so the user is never trapped in a stale context.
- **Offline:** `listManagedCreators()`/`validateActive()` return
  `ApiResult.Error(Offline)` → consumers render the offline state (AND-021).
  Entering a delegation while offline is **allowed** (it is local state); only the
  picker list and cold-start validation need the network. (CORRECTED: original said
  entering requires server confirmation — it does not.)
- **Revoked mid-session:** a scoped delegate call returning `403` (e.g.
  `role_required`/`role_required_scope`, per `mapAuthorizationError`) signals the
  repository to clear `managingCreator` and emit so the UI exits delegate mode and
  informs the user.

## 8. Security & Privacy

- **Authorisation is server-enforced.** The client never assumes a delegation is
  valid; entering delegate mode is a local UI convenience only. **CORRECTED:**
  authorisation is enforced by the backend on each **path-scoped delegate endpoint**
  (`/.../delegate/{creator_id}/...`) against the delegate's grants; the client
  cannot escalate by setting `managingCreator` locally — an unauthorised
  `creator_id` simply yields `403` on the scoped call.
- **No forging:** there is no `X-Manage-As` header to forge. The `creator_id` is an
  opaque id in the URL path; the backend validates the caller's delegate grant.
  Auth remains Bearer token + `X-SESSION-ID` + CSRF (AND-011/AND-012).
- **PII minimisation in DataStore:** persist only `creator_id`, `label`, and
  permission strings — no creator credentials, tokens, or financial data.
  Consistent with AND-029's stance on plaintext DataStore.
- **Audit clarity:** the backend exposes delegate audit logs
  (`GET /ui/delegates/audit`, `/messaging/delegate/{creator_id}/audit`,
  `/ui/newsfeed/delegate/{creator_id}/audit`); the client must never silently mix
  self + delegated traffic (downstream features pick the self vs. delegate endpoint
  from one atomic `managingCreator` snapshot).
- **Plaintext dev host:** dev backend is HTTP; treat all delegation traffic as
  observable in dev. Production must be HTTPS (platform default).

## 9. Accessibility & i18n

- This ticket is data/transport-layer; no screens. All user-facing strings it
  *produces* (error messages, "Now managing {name}" / "Exited delegate mode")
  are `string` resources with placeholders, routed through the i18n plumbing
  (AND-111) — no hardcoded literals in `:core:data`.
- Permission names (`chat_read`, `feed_post`, `broadcast_moderate`, …) shown to
  users must be mapped to localised labels by the consuming screen, not surfaced
  raw. (CORRECTED: real vocabulary is the `permissions` list, not `messaging`/
  `earnings`.)
- The delegate-mode banner's a11y semantics (role, live-region announcement on
  enter/exit) are owned by the downstream banner ticket; this ticket exposes the
  `StateFlow` it needs.

## 10. Telemetry & Logging

- Emit structured events (existing telemetry façade, cf. AND-052 redaction rules):
  `delegate_enter` (local), `delegate_exit` (local),
  `delegate_managed_list_success`/`_failure` (with mapped error code on failure).
  Include `creator_id` (opaque id) but **never** the `label`/display name or PII in
  logs. (CORRECTED: enter/exit have no network attempt/failure events since there
  is no enter/exit endpoint.)
- Log the cold-start `validateActive()` outcome at `DEBUG` (`kept`, `cleared`,
  `offline`).
- OkHttp logging (AND-009): the delegate `creator_id` appears in **request URLs**
  for path-scoped delegate endpoints; redact/short-hash the `{creator_id}` segment
  at `BASIC`+ levels to avoid leaking creator ids into shared logcat. (CORRECTED:
  there is no `X-Manage-As` header to redact.)

## 11. Testing Strategy

**(CORRECTED to the real local-state + path-scoping model.)**

**Unit — repository (`:core:data`, MockWebServer via AND-046 harness):**
- `enter(creator)` → `managingCreator` emits non-null with mapped permissions/label
  (no network call performed).
- `exit()` → `managingCreator` cleared (no network call performed).
- `managedCreators()` 200 → decodes `ManagedCreatorOut[]`; unknown permission string
  → `DelegatePermission.UNKNOWN`; blank `label` falls back to `creatorId`.
- `managedCreators()` 422/403 → `ApiResult.Error` with mapped `detail`.
- `validateActive()`: local non-null + creator absent from `managed` (or
  `status != active`) → store corrected to `null` (FR-8); creator present+active →
  kept.

**Unit — `DelegateScope` helper:**
- `managingCreator == null` → `activeCreatorId() == null`, `requireCreatorId()` throws.
- `managingCreator != null` → `activeCreatorId() == creatorId`.

**Integration — scoping proof (acceptance):** with a delegation active, fire a
representative downstream delegate GET (e.g.
`GET /messaging/delegate/{creator_id}/conversations`) through the real OkHttp stack
against MockWebServer and assert the recorded request **path** carried the active
`creator_id` (e.g. `/messaging/delegate/u_creator_42/conversations`); with no
delegation, the self-path is used. This is the testable form of "Enter delegate
mode; scoped actions apply." (CORRECTED: assert path, not an `X-Manage-As` header.)

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
  (5) `DelegateScope` helper for path-scoped `creator_id` resolution + cold-start
  `validateActive()`; (6) tests. (CORRECTED: no shared-OkHttp interceptor.)

## 13. Risks & Open Questions

- **OQ-1 (scope mechanism) — RESOLVED:** delegated traffic is scoped by
  **path templates** (`/.../delegate/{creator_id}/...`), not a header or
  enter/exit cookie. Verified against the OpenAPI index and `delegates.ts`.
- **OQ-2 (DataStore persistence of `managingCreator`) — OPEN:** the web reference
  keeps it in-memory only. This spec persists it on Android (survives process
  death). Confirm product expectation; trivially revertible to in-memory.
- **OQ-3 (CSRF on scoped POSTs) — likely yes:** `src/api/client.ts` sends
  `X-CSRF-Token` (from `ui_csrf` cookie) on all mutating verbs uniformly; scoped
  POSTs are no different. Confirm at integration.
- **OQ-4 (`X-IMPERSONATION-TOKEN` interplay) — OPEN:** every delegate endpoint
  lists `X-IMPERSONATION-TOKEN` as a param. In the web app this is set only by the
  admin-impersonation store, independent of delegation. Confirm the Android client
  does not need to set it for ordinary delegate flows (expected: no).
- **Risk:** stale delegate context leaking self-actions as delegate (or vice-versa)
  if the interceptor reads an inconsistent snapshot. Mitigated by one atomic
  `StateFlow.value` read per request and the cold-start reconciliation (FR-8).
- **Risk:** unreliable dev host causing `enter` to time out after the server
  actually granted scope → local/server divergence. Mitigated by `current()`
  reconciliation and unconditional-clear exit.

## 14. Acceptance Criteria

AC-1. **(CORRECTED)** `DelegatesApi` exposes `listManagedCreators` →
`GET /ui/delegates/managed` (plus the delegate-management endpoints) with the exact
verbs/paths in §5; each is callable and decodes its response (MockWebServer). No
`enter`/`current`/`exit` endpoints are declared. *(unit, tested)*

AC-2. **(CORRECTED)** `DelegationRepository.enter(creator)` sets `managingCreator`
to the mapped `ManagingCreator` (creatorId, label, permissions) **locally** and the
`StateFlow` emits it (no network call). *(unit, tested)*

AC-3. **Enter delegate mode; scoped actions apply (CORRECTED)** — with a delegation
active, a representative downstream delegate request targets the path-scoped
endpoint carrying the active `creator_id` (e.g.
`/messaging/delegate/<creator_id>/conversations`); with no delegation, the self
endpoint is used. No `X-Manage-As` header is sent. *(integration, tested)*

AC-4. `exit()` clears `managingCreator` (local, cannot fail on network). *(unit, tested)*

AC-5. Logout / exhausted-refresh 401 clears `managingCreator` alongside `AuthState`.
*(unit, tested)*

AC-6. **(CORRECTED)** `validateActive()` reconciles a persisted `managingCreator`
against `listManagedCreators()`: if the creator is absent or not `active`, the local
store is cleared; otherwise kept. (No server `current()` endpoint.) *(unit, tested)*

AC-7. **(CORRECTED)** Failures on `listManagedCreators` / scoped delegate calls
(`422`, `403` with mapped `detail.code`) surface mapped `detail` errors; a `403` on
a scoped call clears `managingCreator`, while a `managedCreators()` error leaves it
unchanged. *(unit, tested)*

## 15. Definition of Done

- All ACs met; code under `com.testlogon.android` in `:core:model` / `:core:network`
  / `:core:data` as laid out in §4; graph compiles (KSP) with no missing bindings.
- `DelegateScope` helper exposes the active `creator_id` for path-scoped delegate
  calls (no shared-OkHttp interceptor); the `{creator_id}` URL segment is
  redacted/short-hashed in OkHttp logs. (CORRECTED: no `DelegateScopeInterceptor`,
  no `X-Manage-As`.)
- `AuthStateStore` extended with `managingCreator` + DataStore keys; `clear()`
  removes them.
- Unit + integration tests above pass in CI (AND-050); MockWebServer fixtures added
  to the AND-046 harness.
- No hardcoded user-facing strings in `:core:data`; telemetry events emitted with
  PII redacted per AND-052.
- KDoc on `DelegationRepository`, `DelegateScope`, and the `managingCreator` store
  surface; PR notes OQ-1/OQ-2/OQ-3/OQ-4 resolution and the downstream delegate-mode
  UI consumer.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources:
OpenAPI index `reference/openapi.index.txt`, OpenAPI spec
`reference/openapi.pretty.json` (`components.schemas.*`), and frontend
`reference/src/...`.

1. **"manage-as is entered/exited via `POST /ui/delegates/enter` and
   `/ui/delegates/exit`."** — **Corrected.** No such endpoints exist. Entering/
   exiting is local state. Source: `openapi.index.txt` (no `/ui/delegates/enter|exit`
   lines); `src/stores/authStore.ts: setManagingCreator`;
   `src/pages/messages/DelegateBanner.tsx` (Exit button calls
   `setManagingCreator(null)`).
2. **"`GET /ui/delegates/current` returns the active delegation."** — **Corrected.**
   No `current` endpoint. Source: `openapi.index.txt` (no `/ui/delegates/current`).
3. **"Listing managed creators = `GET /ui/delegates`."** — **Corrected.** That
   endpoint lists delegates *you granted* (`DelegateOut[]`). Managed creators =
   `GET /ui/delegates/managed` → `ManagedCreatorOut[]`. Source:
   `openapi.index.txt: GET /ui/delegates` (`op=list_delegates`) and
   `GET /ui/delegates/managed` (`op=list_managed`); `src/api/endpoints/delegates.ts:
   listManagedCreators` (`/managed`).
4. **`ManagedCreatorOut` shape = `{creator_id, permissions[], preset?, status,
   label, accepted_at}`.** — **Verified / Corrected** (replaces invented
   `creator_sub/display_name/username/avatar_url/scopes/granted_at`). Source:
   `openapi.pretty.json: components.schemas.ManagedCreatorOut` (line ~48807);
   `src/api/types.ts: ManagedCreatorOut`.
5. **`accepted_at` is integer epoch seconds.** — **Verified.** Source:
   `openapi.pretty.json: ManagedCreatorOut.accepted_at type=integer`;
   `src/api/types.ts: accepted_at: number`.
6. **Scoped delegated actions go to path-templated endpoints
   `/.../delegate/{creator_id}/...`, not a blanket header.** — **Corrected**
   (removes `X-Manage-As`). Source: `openapi.index.txt`
   `GET /messaging/delegate/{creator_id}/conversations`,
   `POST /ui/newsfeed/delegate/{creator_id}/posts`,
   `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/start`, etc.;
   `src/api/endpoints/delegates.ts: MSG_BASE = "/messaging/delegate"`.
7. **No `X-Manage-As` header exists anywhere.** — **Verified (absence).** Source:
   grep of `reference/src/` and `openapi.index.txt` — no occurrences.
8. **Real permission vocabulary = `chat_read, chat_respond, feed_read, feed_post,
   feed_moderate, broadcast_moderate, broadcast_control`** (replaces invented
   `MESSAGING/EARNINGS/BILLING/FILES/CALENDAR`). — **Corrected.** Source:
   `src/pages/delegates/DelegatesPage.tsx: ALL_PERMISSIONS`;
   `src/pages/messages/DelegateBanner.tsx` filters `permissions.includes("chat_read")`.
9. **Auth is Bearer token + `X-SESSION-ID` + `X-CSRF-Token` (from `ui_csrf`
   cookie), not a pure cookie session.** — **Corrected.** Source:
   `src/api/client.ts` (sets `Authorization: Bearer`, `X-CSRF-Token`,
   `credentials: include`); `openapi.index.txt` delegate lines list
   `X-SESSION-ID` + `authorization` params.
10. **401 handling: refresh once via `POST /ui/session/refresh`, then retry; on
    failure logout(`session_expired`).** — **Verified.** Source:
    `src/api/client.ts: refreshSession()` and 401 branch.
11. **`X-IMPERSONATION-TOKEN` is admin impersonation, separate from delegation.** —
    **Verified.** Source: `src/stores/impersonationStore.ts`; `src/api/client.ts`
    sets it only when `impersonationStore.isActive()`. It appears as a param on the
    delegate endpoints but is driven by a different store.
12. **Web does NOT persist `managingCreator` across reloads.** — **Verified.**
    Source: `src/stores/authStore.ts` `partialize` omits `managingCreatorId`/
    `managingCreatorName`. (Android DataStore persistence is a divergence — OQ-2.)
13. **Logout clears `managingCreator` with `AuthState` (FR-7).** — **Verified.**
    Source: `src/stores/authStore.ts: logout()` resets `managingCreatorId` and
    `managingCreatorName` to `null`.
14. **FastAPI validation error shape = `422 HTTPValidationError`
    (`detail: [{loc, msg, type}]`); auth errors = `403` with `detail.code`
    (`role_required`, `role_required_scope`, …).** — **Verified.** Source:
    `openapi.index.txt` (`resp=...;422:HTTPValidationError` on delegate lines);
    `src/api/client.ts: mapAuthorizationError` + `normalizeErrorDetail`.
15. **`DelegateOut` shape and `DelegateAddIn` body** (for the delegate-management
    surface). — **Verified.** Source:
    `openapi.pretty.json: components.schemas.DelegateOut` (~25647),
    `DelegateAddIn` (~25539); `src/api/types.ts: DelegateOut`, `DelegateAddReq`.
16. **`POST /ui/delegates/invites/{creator_id}/respond` body `{accept: bool}`.** —
    **Verified.** Source: `openapi.index.txt` (`req=DelegateInviteRespondIn`);
    `src/api/endpoints/delegates.ts: respondToInvite`; `src/api/types.ts:
    DelegateInviteRespondReq`.
17. **Banner UX: shows "Managing @{name}", creator switcher when >1 chat-capable
    creator, Exit clears state.** — **Verified** (informs downstream UI ticket).
    Source: `src/pages/messages/DelegateBanner.tsx`.
18. **Persisting `managingCreator` in plaintext DataStore (only `creator_id`,
    `label`, permissions).** — **Unverified-assumption** (Android design choice;
    consistent with AND-029 stance). Framework ref: Android Jetpack DataStore
    (Preferences) — https://developer.android.com/topic/libraries/architecture/datastore
19. **Retrofit/OkHttp/Moshi/Hilt transport choices and `ApiResult` wrapping.** —
    **Unverified-assumption** (Android stack pins from §2; not derivable from web
    source). Framework ref: Retrofit — https://square.github.io/retrofit/ ;
    OkHttp — https://square.github.io/okhttp/ .

### Corrections made

- Removed the non-existent `enterDelegation`/`currentDelegation`/`exitDelegation`
  endpoints and the `EnterDelegationReq`/`ActiveDelegationDto` DTOs (§1, §3 FR-1/3/5/8,
  §4.1, §4.2, §5, §14 AC-1/2/6/7).
- Replaced the `DelegationDto` shape with the verified `ManagedCreatorDto`
  (`creator_id/permissions/preset/status/label/accepted_at`) and corrected the list
  source to `GET /ui/delegates/managed` (§4.1, §4.4, §5).
- Replaced `DelegateScope` enum (`MESSAGING/EARNINGS/BILLING/FILES/CALENDAR`) with
  the real `DelegatePermission` vocabulary (§4.1, §9).
- Removed the blanket `DelegateScopeInterceptor` + `X-Manage-As` header; scoping is
  path-based via `{creator_id}` (§1, §4.3, §5, §7, §8, §10, §12, §13, §14 AC-3, §15).
- Corrected auth from "cookie-based" to Bearer + `X-SESSION-ID` + CSRF (§2, §5, §8).
- Corrected enter/exit to local-only (no network, no failure modes) (§3, §7).
- Corrected cold-start reconciliation from server `current()` to validation against
  `listManagedCreators()` (§3 FR-8, §4.4, §6, §14 AC-6).
- Flagged DataStore persistence of `managingCreator` as a divergence from web (§4.5,
  §6, OQ-2).

### Open assumptions

- **OQ-2 (persistence):** whether `managingCreator` should survive process death on
  Android (this spec says yes; web says no). Unverifiable from sources — product call.
- **OQ-4 (`X-IMPERSONATION-TOKEN`):** whether ordinary Android delegate flows must
  send this header. Web sets it only for admin impersonation; assumed not required
  for delegation, but the OpenAPI lists it as a param on delegate endpoints.
- **Android stack (Retrofit/OkHttp/Moshi/Hilt/DataStore/ApiResult):** framework
  choices, not derivable from the web reference; taken from §2 stack pins.
- **CSRF on scoped POSTs (OQ-3):** expected valid (same session) but not explicitly
  confirmed for the `/delegate/{creator_id}/...` POSTs.

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1..AC-7). Test targets:
**JVM** = JVM unit/Robolectric (local, no device); **emulator** = headless AVD
`test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U,
API 34, arm64-v8a). This ticket is data/transport only (no UI it owns), so most
cases are JVM unit + MockWebServer contract; a couple instrumented cases verify the
shared OkHttp stack + DataStore on a real Android runtime.

- **TC-AND-359-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues `200` with a `ManagedCreatorOut[]` body
  (one active creator, mixed known + unknown permission). Steps: call
  `DelegatesApi.listManagedCreators()` and map to domain. Expected:
  `ApiResult.Success`; `creator_id/label/preset/status/accepted_at` decode
  correctly; unknown permission → `DelegatePermission.UNKNOWN`; blank `label` falls
  back to `creatorId`. Traces: AC-1, AC-2 (DTO mapping).
- **TC-AND-359-02** — Type: unit. Target: JVM. Preconditions: repository with a
  fake `AuthStateStore`. Steps: `enter(creator)` then read
  `authStore.managingCreator.value`/first emission. Expected: emits non-null
  `ManagingCreator(creatorId, label, permissions)`; **no** HTTP request issued
  (MockWebServer `takeRequest` times out). Traces: AC-2, AC-3.
- **TC-AND-359-03** — Type: integration/contract (MockWebServer, real OkHttp).
  Target: JVM (or emulator for the instrumented variant). Preconditions:
  `managingCreator = u_creator_42`; a representative downstream delegate call wired
  to the shared client. Steps: invoke the delegate messaging GET; capture the
  recorded request. Expected: request path ==
  `/messaging/delegate/u_creator_42/conversations`; **no** `X-Manage-As` header
  present. With `managingCreator = null`, the self path is used instead. Traces:
  AC-3.
- **TC-AND-359-04** — Type: unit. Target: JVM. Preconditions: `managingCreator`
  set. Steps: call `exit()`. Expected: `managingCreator` becomes `null`
  synchronously; no HTTP request issued; cannot fail on network. Traces: AC-4.
- **TC-AND-359-05** — Type: unit. Target: JVM. Preconditions: `AuthStateStore`
  with `managingCreator` set and an `AuthState = Authenticated`. Steps: trigger
  `clear()` / logout and a separate exhausted-refresh `401` path. Expected: both
  reset `managingCreator` to `null` together with `AuthState → Unauthenticated`.
  Traces: AC-5.
- **TC-AND-359-06** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: persisted `managingCreator = u_gone`; MockWebServer returns a
  `managed` list NOT containing `u_gone`. Steps: `validateActive()`. Expected:
  `managingCreator` cleared to `null` (`cleared` outcome). Traces: AC-6.
- **TC-AND-359-07** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: persisted `managingCreator = u_creator_42`; `managed` list
  contains it with `status:"active"`. Steps: `validateActive()`. Expected:
  `managingCreator` kept unchanged (`kept`). Variant: same creator with
  `status:"pending"` → cleared. Traces: AC-6.
- **TC-AND-359-08** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer returns `422` with
  `detail:[{loc,msg,type}]` then a separate `403` with `detail:{code:"role_required_scope",
  required_scope:"chat_respond"}`. Steps: call `listManagedCreators()` (422) and a
  scoped delegate call (403). Expected: both → `ApiResult.Error` with mapped
  human-readable message; the `managedCreators()` error leaves `managingCreator`
  unchanged, while the scoped-call `403` clears `managingCreator`. Traces: AC-7.
- **TC-AND-359-09** — Type: unit. Target: JVM. Preconditions: `DelegateScope`
  helper over fake store. Steps: query `activeCreatorId()`/`requireCreatorId()` with
  and without an active creator. Expected: `null` + thrown error when none; correct
  `creatorId` when present. Traces: AC-3.
- **TC-AND-359-10** — Type: integration (flaky-dev-host/offline). Target: JVM
  (MockWebServer with throttle/`SocketPolicy.NO_RESPONSE_AND_FAIL` and ~20s
  timeout). Preconditions: simulate the unreliable dev host. Steps: call
  `listManagedCreators()` (timeout) and then `enter(creator)` while "offline".
  Expected: `listManagedCreators()` → `ApiResult.Error(Offline/Timeout)`;
  `enter()` still succeeds locally (it is offline-safe, no network). Traces: AC-2,
  AC-4 (offline resilience), AC-1.
- **TC-AND-359-11** — Type: instrumented/e2e. Target: **device** (physical A15,
  API 34, arm64-v8a). Preconditions: app installed; auth session valid; DataStore
  empty. Steps: enter delegate mode, force-stop the process, relaunch, run
  cold-start `validateActive()`. Expected: persisted `managingCreator` is restored
  from DataStore on relaunch and survives, confirming real on-device DataStore
  durability (the divergence from web in §4.5/OQ-2). MUST run on the physical
  device to validate arm64/API-34 DataStore behavior distinct from the x86 emulator.
  Traces: AC-6 (persistence + reconciliation).
- **TC-AND-359-12** — Type: instrumented (security). Target: emulator (`test35`).
  Preconditions: real shared OkHttp stack; `managingCreator` set. Steps: issue a
  scoped delegate POST and inspect the on-wire request (MockWebServer). Expected:
  `Authorization: Bearer`, `X-CSRF-Token`, `X-SESSION-ID` present; the `creator_id`
  rides only in the URL path; no credentials or `label`/PII leak into headers; the
  OkHttp `BASIC` log line redacts/short-hashes the `{creator_id}` segment. Traces:
  AC-3 (security of scoping).
- **TC-AND-359-13** — Type: manual. Target: device. Preconditions: a creator whose
  delegation is revoked server-side mid-session. Steps: while in delegate mode for
  that creator, trigger a scoped action. Expected: backend `403`
  (`role_required`/revoked); repository clears `managingCreator` and emits so the UI
  exits delegate mode and informs the user. Traces: AC-7.

### Coverage matrix

| AC (§14) | Covered by |
|----------|------------|
| AC-1 (DelegatesApi paths/decode, no enter/current/exit) | TC-01, TC-10 |
| AC-2 (enter sets managingCreator locally, StateFlow emits) | TC-01, TC-02, TC-10 |
| AC-3 (scoped path carries creator_id; no X-Manage-As) | TC-02, TC-03, TC-09, TC-12 |
| AC-4 (exit clears locally, network-independent) | TC-04, TC-10 |
| AC-5 (logout / exhausted-refresh 401 clears managingCreator) | TC-05 |
| AC-6 (validateActive reconciles vs managed list) | TC-06, TC-07, TC-11 |
| AC-7 (mapped 422/403 errors; revocation clears mode) | TC-08, TC-13 |
