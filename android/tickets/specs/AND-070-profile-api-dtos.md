---
id: AND-070
title: Profile API + DTOs
milestone: M2
epic: E10
priority: P0
size: M
status: draft
depends_on:
  - AND-027
blocks:
  - AND-071
  - AND-072
---

# AND-070 — Profile API + DTOs

## 1. Overview & Goal

This ticket delivers the network and data-transfer layer for user profiles in the
TestLogon native Android app: a Retrofit service interface (`ProfileApi`) plus the
Moshi-backed DTOs and domain models that back it. It is the data foundation for the
profile feature surfaces (own-profile screen, public-profile-by-identifier screen)
that downstream feature tickets consume. The functional goal is narrow and precise:
every endpoint the web reference's `profile.ts` exercises must be callable from
Kotlin with byte-compatible request/response shapes, must deserialize the dev
backend's real payloads without loss, and must map cleanly into immutable domain
models in `core-model`.

The scope is the API + DTO + mapper code only. No Compose UI, no ViewModel, no
Room cache, and no Paging are part of this ticket — those belong to the profile
feature tickets (E10 follow-ups). The acceptance bar is mechanical and testable:
the own-profile payload (`GET /ui/me` is owned by AND-027; here we own the richer
`GET /ui/profile/meta/{identifier}`) and the public-profile payload both load and
map under MockWebServer, with full coverage of nullable and FastAPI-error branches.

This work lives in `core-network` (the `ProfileApi` interface and DTOs) and
`core-model` (domain models + mappers), consistent with the module layering
`app -> feature-* -> core-*`. It introduces no new dependencies beyond the already-
established Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15 stack configured in AND-026.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/profile.ts` and shared types in
  `frontend/src/api/types.ts` (repo `spannella/testlogon`, branch `android-port`).
  `profile.ts` is the authoritative enumeration of profile endpoints, query params,
  and response field names. Where this spec and the TypeScript diverge, the
  TypeScript (and the live `/openapi.json`) wins; mismatches become Open Questions
  in §13.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI schema at `/openapi.json` — use it to confirm field
  nullability and the `profile/meta` response model before freezing DTOs.
- **Auth dependency (AND-027):** `AuthApi` already supplies cookie-based session,
  the persistent cookie jar, the `X-CSRF-Token` echo, and the single-shot 401 →
  `POST /ui/session/refresh` → retry interceptor. `ProfileApi` reuses the same
  OkHttp `Retrofit` instance and shares that auth/CSRF/refresh plumbing; this ticket
  adds no auth logic of its own.
- **Networking foundation (AND-026):** the shared `Retrofit`/`Moshi`/`OkHttpClient`
  Hilt module, the `ApiResult<T>` type, and the FastAPI `detail` error mapper.
- **Module layering & conventions:** ViewModels (out of scope here) expose
  `StateFlow<UiState>`; the network layer returns `ApiResult<T>`; domain models are
  immutable Kotlin `data class`es in `core-model`.

## 3. Functional Requirements

FR-1. Provide a Retrofit interface `ProfileApi` exposing every profile read used by
`profile.ts`. Minimum surface (final list reconciled against `/openapi.json`):

- `getProfileMeta(identifier)` → `GET /ui/profile/meta/{identifier}` — the public
  profile-by-identifier endpoint (identifier = username or user id).
- `getMyProfileMeta()` → `GET /ui/profile/meta/me` (or the `/ui/me`-adjacent self
  variant exposed by `profile.ts`; see §5) — the own-profile payload.
- Any additional read endpoints present in `profile.ts` (e.g. profile-by-handle
  lookups) added as suspend functions following the same shape.

FR-2. All `ProfileApi` functions are `suspend` and return either the raw DTO
(`ProfileMetaDto`) or `ApiResult<ProfileMetaDto>` via the shared call adapter from
AND-026. Functions never block the calling thread and never throw for HTTP error
statuses — errors surface through `ApiResult.Error`.

FR-3. Define DTOs that deserialize the live payloads losslessly: `ProfileMetaDto`
and nested DTOs (`ProfileStatsDto`, `ProfileLinkDto`, `ProfileAvatarDto` as the
payload dictates). Unknown JSON fields must not crash deserialization (Moshi
ignores unknown keys by default — verified, not relied on by accident).

FR-4. Provide pure mapper functions converting each DTO to an immutable `core-model`
domain type (`ProfileMeta`, `ProfileStats`, …). Mappers apply defaulting for
nullable fields, normalize identifiers, and never emit nullable collections (empty
list instead of null).

FR-5. Distinguish own-profile from public-profile mapping where the payload carries
viewer-scoped fields (e.g. `is_self`, `email`, edit-permission flags present only on
the owner's payload). The domain model exposes these as nullable/optional so a
public profile maps without fabricating owner-only data.

FR-6. Identifier handling: `getProfileMeta` accepts a raw identifier string and
URL-encodes it via Retrofit's `@Path(encoded = false)` default so usernames with
reserved characters resolve to the correct path segment.

## 4. Technical Design

**Placement.** `ProfileApi` and DTOs go in
`core-network` under
`com.testlogon.android.core.network.profile`; domain models and mappers go in
`core-model` under `com.testlogon.android.core.model.profile`. `core-model` must not
depend on Retrofit/Moshi annotations leaking outward — DTOs stay in `core-network`,
domain types stay annotation-free.

**Service interface (`core-network`):**

```kotlin
package com.testlogon.android.core.network.profile

import com.testlogon.android.core.network.ApiResult
import retrofit2.http.GET
import retrofit2.http.Path

interface ProfileApi {

    /** Public profile by username or user id. GET /ui/profile/meta/{identifier} */
    @GET("ui/profile/meta/{identifier}")
    suspend fun getProfileMeta(
        @Path("identifier") identifier: String,
    ): ApiResult<ProfileMetaDto>

    /** Own profile (viewer-scoped fields populated). GET /ui/profile/meta/me */
    @GET("ui/profile/meta/me")
    suspend fun getMyProfileMeta(): ApiResult<ProfileMetaDto>
}
```

**DTOs (`core-network`):**

```kotlin
@JsonClass(generateAdapter = true)
data class ProfileMetaDto(
    @Json(name = "identifier") val identifier: String,
    @Json(name = "username") val username: String,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "bio") val bio: String?,
    @Json(name = "avatar_url") val avatarUrl: String?,
    @Json(name = "created_at") val createdAt: String?,      // ISO-8601
    @Json(name = "is_self") val isSelf: Boolean?,           // owner-only
    @Json(name = "email") val email: String?,               // owner-only
    @Json(name = "can_edit") val canEdit: Boolean?,         // owner-only
    @Json(name = "stats") val stats: ProfileStatsDto?,
    @Json(name = "links") val links: List<ProfileLinkDto>?,
)

@JsonClass(generateAdapter = true)
data class ProfileStatsDto(
    @Json(name = "followers") val followers: Int?,
    @Json(name = "following") val following: Int?,
    @Json(name = "posts") val posts: Int?,
)

@JsonClass(generateAdapter = true)
data class ProfileLinkDto(
    @Json(name = "label") val label: String?,
    @Json(name = "url") val url: String,
)
```

> Field names above are the working set; before merge they are reconciled
> one-to-one against `frontend/src/api/types.ts` and `/openapi.json`. Any field that
> exists there but is missing here is a merge blocker, not a follow-up.

**Domain models (`core-model`):**

```kotlin
package com.testlogon.android.core.model.profile

data class ProfileMeta(
    val identifier: String,
    val username: String,
    val displayName: String,        // falls back to username if null
    val bio: String?,
    val avatarUrl: String?,
    val createdAt: Instant?,        // parsed; null if unparseable/absent
    val viewer: ViewerScope,        // owner-only data, null-safe
    val stats: ProfileStats,
    val links: List<ProfileLink>,   // never null
)

data class ViewerScope(
    val isSelf: Boolean,
    val email: String?,
    val canEdit: Boolean,
)

data class ProfileStats(val followers: Int, val following: Int, val posts: Int)
data class ProfileLink(val label: String, val url: String)
```

**Mappers (`core-model`, pure functions):**

```kotlin
fun ProfileMetaDto.toDomain(): ProfileMeta = ProfileMeta(
    identifier = identifier,
    username = username,
    displayName = displayName?.takeIf { it.isNotBlank() } ?: username,
    bio = bio?.trim()?.takeIf { it.isNotBlank() },
    avatarUrl = avatarUrl?.takeIf { it.isNotBlank() },
    createdAt = createdAt?.let { runCatching { Instant.parse(it) }.getOrNull() },
    viewer = ViewerScope(
        isSelf = isSelf ?: false,
        email = email,
        canEdit = canEdit ?: false,
    ),
    stats = stats?.toDomain() ?: ProfileStats(0, 0, 0),
    links = links.orEmpty().mapNotNull { it.toDomainOrNull() },
)
```

Mappers are exhaustively unit-tested (§11) and contain no I/O. The `ProfileApi` is
provided through a Hilt `@Provides` in the existing `core-network` Retrofit module
(`retrofit.create(ProfileApi::class.java)`), reusing the shared OkHttp client so the
cookie jar, CSRF header, timeouts, and refresh interceptor from AND-026/AND-027
apply automatically.

## 5. API Contract

Base URL from AND-026 config (dev: `http://18.222.237.167:8000`). All requests
carry the session cookies and `X-CSRF-Token` header automatically via the shared
OkHttp interceptors; this ticket adds no per-call headers.

**Public profile**

```
GET /ui/profile/meta/{identifier}
Path: identifier — username or user id (URL-encoded path segment)
200 OK  application/json
```

Example response (public viewer — owner-only fields absent or null):

```json
{
  "identifier": "ada",
  "username": "ada",
  "display_name": "Ada Lovelace",
  "bio": "Analytical engines.",
  "avatar_url": "http://18.222.237.167:8000/media/ada.png",
  "created_at": "2025-11-02T09:15:00Z",
  "is_self": false,
  "stats": { "followers": 42, "following": 7, "posts": 3 },
  "links": [ { "label": "site", "url": "https://example.org" } ]
}
```

**Own profile**

```
GET /ui/profile/meta/me
200 OK  application/json
```

Example response (owner viewer — viewer-scoped fields populated):

```json
{
  "identifier": "spannella",
  "username": "spannella",
  "display_name": "Sean",
  "bio": null,
  "avatar_url": null,
  "created_at": "2025-10-01T00:00:00Z",
  "is_self": true,
  "email": "spannella@gmail.com",
  "can_edit": true,
  "stats": { "followers": 0, "following": 1, "posts": 0 },
  "links": []
}
```

> The exact self path (`/ui/profile/meta/me` vs. a query-flagged variant) is taken
> verbatim from `profile.ts`; §13 flags this as the one item to confirm against the
> reference before freezing the interface.

**Error responses** follow the FastAPI `detail` convention handled by the AND-026
mapper. The three observed shapes:

```json
{ "detail": "Profile not found" }                         // string
{ "detail": [ { "msg": "value is not a valid identifier" } ] }  // 422 list
{ "detail": { "code": "FORBIDDEN", "message": "..." } }   // object
```

Status mapping: `200` → `ApiResult.Success`; `401` → handled upstream (refresh +
single retry) before reaching `ProfileApi` callers; `404` → `ApiResult.Error` with
not-found detail; `422` → validation error; `5xx`/timeout → network/server error.

## 6. Data & State Management

This ticket produces **stateless** data-access code: an interface, DTOs, domain
models, and pure mappers. There is no in-memory cache, no DataStore write, and no
Room entity here. Repository orchestration, `StateFlow<UiState>` exposure, Room
caching of `ProfileMeta`, and stale/offline rendering are owned by the downstream
profile-repository and profile-screen tickets (E10). The domain models defined here
are deliberately UI- and storage-agnostic so those consumers can adapt them without
re-shaping.

The only state concern internal to this ticket is the contract that mappers are
**total**: every well-formed payload (including all-nullable-optional payloads)
produces a valid, non-throwing `ProfileMeta` with non-null collections and a sane
`displayName` fallback. This invariant is what downstream state holders rely on.

## 7. Error Handling & Resilience

- **Transport.** Inherits AND-026 settings: ~20s timeouts against the unreliable
  dev host, and bounded exponential backoff retry applied to idempotent GETs only.
  Both `ProfileApi` calls are GETs, so they are eligible for retry; the retry policy
  is configured centrally in OkHttp and not duplicated here.
- **Auth.** A `401` triggers the AND-027 single-shot `POST /ui/session/refresh` then
  one retry, transparently to `ProfileApi`. If refresh fails, the original `401`
  surfaces as `ApiResult.Error` and the caller routes to re-auth.
- **Deserialization.** Unknown fields are ignored. A missing **required** field
  (`identifier`, `username`, or a link `url`) is a hard parse failure surfaced as an
  `ApiResult.Error` (malformed-response), never a silent default — required fields
  are non-nullable in the DTO precisely so Moshi fails loudly.
- **Mapping.** Optional/nullable fields are defaulted (empty list, `false`, username
  fallback). Unparseable `created_at` yields `null`, not an exception. Malformed
  individual `links` entries are dropped (`mapNotNull`) rather than failing the whole
  profile.
- **Error detail.** All non-2xx bodies pass through the shared FastAPI `detail`
  mapper (string | list-of-`{msg}` | `{code,...}`) so callers get a typed reason.

## 8. Security & Privacy

- Authentication is entirely cookie-based and owned by AND-027; `ProfileApi` carries
  no tokens in URLs or bodies. The persistent cookie jar and `X-CSRF-Token` header
  are applied by the shared client.
- **Owner-only PII** (`email`) appears only on the self payload. The domain model
  isolates it inside `ViewerScope`, so public-profile mappings cannot leak or
  fabricate an email. Mappers must never copy owner-only fields onto a profile whose
  `is_self` is false.
- The dev backend is **plaintext HTTP**, so profile payloads (including the owner's
  email) traverse the network unencrypted in dev. This is a known dev-host
  limitation; production must use HTTPS. A cleartext-traffic allowance for the dev
  host is configured at the app level (AND-026), not here. Do not log full profile
  payloads (see §10).
- DTOs and domain models are not persisted by this ticket, so no at-rest concern is
  introduced here.

## 9. Accessibility & i18n

No UI is produced by this ticket, so screen-reader, focus, and contrast concerns are
N/A and owned by the downstream profile-screen ticket (E10). Two data-layer
obligations support later i18n:

- `created_at` is mapped to a locale-agnostic `Instant`; all human-readable date
  formatting is deferred to the UI layer so it can be localized.
- No user-facing strings are hard-coded in this layer; error reasons are codes/detail
  passed upward, not pre-translated sentences. `displayName` fallback uses the raw
  `username` rather than an English literal like "Unknown".

## 10. Telemetry & Logging

- Reuse the `core-network` OkHttp logging interceptor (BODY level in debug builds
  only, NONE in release) from AND-026. Because profile payloads carry PII (`email`),
  ensure release builds never log bodies, and add `email` to the redaction list if a
  redacting interceptor is present.
- Log a single structured warning when a mapper drops a malformed `links` entry or
  fails to parse `created_at`, at DEBUG level, including the field name but **not**
  the full payload.
- Emit no analytics events from this layer; profile-view analytics belong to the
  feature/UI ticket. Surface deserialization failures as `ApiResult.Error` so the
  consuming ViewModel can decide whether to report them.

## 11. Testing Strategy

All tests run on the JVM (`core-network`/`core-model` unit tests) with MockWebServer;
no instrumented tests are required for this ticket.

- **T-1 `ProfileApi` path/verb (MockWebServer).** Enqueue a 200 and assert the
  recorded request line is `GET /ui/profile/meta/ada` for `getProfileMeta("ada")`
  and the self path for `getMyProfileMeta()`. Assert no body and that session/CSRF
  headers are present (proving shared-client wiring).
- **T-2 Identifier encoding.** `getProfileMeta("a b/c")` produces a correctly
  percent-encoded single path segment.
- **T-3 Public payload deserialize + map.** Feed the §5 public fixture; assert
  `ProfileMetaDto` parses and `toDomain()` yields `viewer.isSelf == false`,
  `viewer.email == null`, populated stats, and non-null links.
- **T-4 Own payload deserialize + map.** Feed the §5 self fixture; assert
  `viewer.isSelf == true`, `viewer.email == "spannella@gmail.com"`,
  `viewer.canEdit == true`.
- **T-5 Nullable/empty branches.** All-nulls payload (`display_name`, `bio`,
  `avatar_url`, `stats`, `links` null) maps to `displayName == username`,
  `bio == null`, `stats == ProfileStats(0,0,0)`, `links == emptyList()`.
- **T-6 Malformed branches.** (a) Missing required `username` → `ApiResult.Error`
  (malformed). (b) Bad `created_at` → `createdAt == null`, no throw. (c) A `links`
  entry missing `url` is dropped; valid entries retained.
- **T-7 Error mapping.** Enqueue 404 string-detail, 422 list-detail, and
  object-detail bodies; assert each yields `ApiResult.Error` with the correctly
  parsed reason via the shared FastAPI mapper.
- **T-8 Unknown-field tolerance.** Payload with extra unknown keys parses without
  error.

Coverage gate: 100% of mapper branches exercised; both endpoints have a happy-path
and an error-path test.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) — supplies the shared
  Retrofit instance, cookie jar, CSRF header, and 401-refresh interceptor that
  `ProfileApi` reuses. Transitively depends on AND-026 (networking foundation:
  `Retrofit`/`Moshi`/`OkHttp` Hilt module, `ApiResult<T>`, FastAPI error mapper).
- **Blocks** the downstream E10 profile tickets: the profile repository + Room cache
  ticket and the own/public profile screen + ViewModel tickets (referenced here as
  AND-071 / AND-072; reconcile exact ids with the E10 backlog). Those cannot begin
  until `ProfileApi`, the DTOs, and the domain models exist.
- Sequencing: implement DTOs and mappers first (fully unit-testable in isolation),
  then wire `ProfileApi` and add MockWebServer tests. No backend changes required.

## 13. Risks & Open Questions

- **Self-profile path shape.** The exact own-profile route (`/ui/profile/meta/me`
  vs. a query-flagged or `/ui/me`-derived variant) must be confirmed against
  `profile.ts` and `/openapi.json` before freezing the interface. **Owner: confirm
  before merge.**
- **Field-name drift.** DTO field names are a working approximation; the live
  `/openapi.json` `ProfileMeta` schema is authoritative. Any extra/renamed field is a
  merge blocker, not a follow-up.
- **Owner-only field set.** Which fields are owner-only (`email`, `can_edit`,
  `is_self`) versus always-present needs verification; misclassifying could leak PII
  or drop needed data. Mitigated by `ViewerScope` isolation and T-3/T-4.
- **Unreliable dev host.** Flaky `5xx`/timeouts from `18.222.237.167:8000` can make
  manual verification noisy; tests use MockWebServer to stay deterministic.
- **Identifier ambiguity.** Whether `{identifier}` accepts both username and user id
  in all cases is unconfirmed; if not, downstream lookup logic may need a second
  endpoint.

## 14. Acceptance Criteria

- AC-1. `ProfileApi` exists in `core-network` with suspend functions for the public
  (`GET /ui/profile/meta/{identifier}`) and own profile endpoints; paths, verbs, and
  the empty GET bodies match the contract, verified by MockWebServer (T-1, T-2).
- AC-2. The own-profile payload loads and maps to a `ProfileMeta` with populated
  `ViewerScope` (`isSelf`, `email`, `canEdit`), proven by an automated test (T-4).
- AC-3. The public-profile payload loads and maps to a `ProfileMeta` with no
  owner-only data leaked (`isSelf == false`, `email == null`), proven by an
  automated test (T-3).
- AC-4. Nullable/empty and malformed payloads map without throwing per §7
  (defaults applied, malformed required-field → `ApiResult.Error`), proven by T-5
  and T-6.
- AC-5. All three FastAPI `detail` error shapes map to typed `ApiResult.Error`
  reasons (T-7); unknown fields are tolerated (T-8).
- AC-6. `core-model` domain types are free of Retrofit/Moshi annotations; DTOs stay
  in `core-network`. No new third-party dependencies are added.

## 15. Definition of Done

- Code merged to branch `android-port` under `android/core-network` and
  `android/core-model` with package base `com.testlogon.android`.
- `ProfileApi`, all DTOs, all domain models, and all mappers implemented as specified
  and provided via the existing Hilt Retrofit module.
- All tests T-1 through T-8 pass in CI; mapper branch coverage at 100%; no MockWebServer
  test is flaky.
- DTO field names reconciled against `frontend/src/api/types.ts` and `/openapi.json`;
  the self-path Open Question (§13) resolved and reflected in the interface.
- KSP (Moshi codegen, Hilt) builds clean with no warnings introduced; `ktlint`/detekt
  pass.
- No PII logged in release builds; debug body logging gated to debug variants.
- Spec Open Questions either resolved or re-filed as follow-up tickets against E10;
  downstream tickets (AND-071/AND-072) unblocked.
