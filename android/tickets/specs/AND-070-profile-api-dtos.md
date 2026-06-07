---
id: AND-070
title: Profile API + DTOs
milestone: M2
epic: E10
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
the own-profile payload (`GET /ui/profile`, returning `{ profile: Profile }`) and the
cross-user / public-profile payload (`GET /ui/profiles/{identifier}`, returning
`CrossUserProfileResp`) both load and map under MockWebServer, with full coverage of
nullable and FastAPI-error branches.

> REVIEW CORRECTION: The ticket scope line names `/ui/profile/meta/{identifier}`, but
> the web reference `profile.ts` never calls that path. In the live OpenAPI it is
> `profile_meta_tags_…` ("Profile Meta Tags") with an **untyped (`{}`) 200 body** — an
> OG/SEO meta-tags endpoint, not the profile data endpoint. The data reads the web
> client actually uses are `GET /ui/profile` (own) and `GET /ui/profiles/{identifier}`
> (cross-user). This spec is corrected throughout to those endpoints; the meta-tags
> endpoint is documented but treated as out-of-scope unless explicitly required (see
> §13 / §16). The original DTO field set (`username`, `bio`, `avatar_url`, `stats`,
> `links`, `is_self`, `email`, `can_edit`) was invented and is replaced below with the
> real `Profile` / `CrossUserProfileResp` shapes from `src/api/types.ts`.

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
- **Auth dependency (AND-027):** `AuthApi` already supplies the session transport that
  `ProfileApi` reuses. Per the web reference (`src/api/client.ts`), auth is a **hybrid**,
  not "cookie-only": every request sends (a) cookies via `credentials: "include"`,
  (b) an `Authorization: Bearer <accessToken>` header when an access token is present in
  the auth store, and (c) an `X-CSRF-Token` header whose value is read from the
  `ui_csrf` cookie. An optional `X-IMPERSONATION-TOKEN` header is added when impersonation
  is active. The 401 path is a single-shot `POST /ui/session/refresh` (deduplicated via a
  shared in-flight `refreshPromise`) followed by one retry; a failed refresh logs the user
  out. `ProfileApi` reuses the same OkHttp `Retrofit` instance and shares that
  auth/CSRF/refresh plumbing; this ticket adds no auth logic of its own.
  (VERIFIED: `src/api/client.ts:140-237`; refresh path `POST /ui/session/refresh` at
  `src/api/client.ts:122` and `src/api/endpoints/auth.ts:60`.)
- **Networking foundation (AND-026):** the shared `Retrofit`/`Moshi`/`OkHttpClient`
  Hilt module, the `ApiResult<T>` type, and the FastAPI `detail` error mapper.
- **Module layering & conventions:** ViewModels (out of scope here) expose
  `StateFlow<UiState>`; the network layer returns `ApiResult<T>`; domain models are
  immutable Kotlin `data class`es in `core-model`.

## 3. Functional Requirements

FR-1. Provide a Retrofit interface `ProfileApi` exposing every profile read used by
`profile.ts` (verified against `src/api/endpoints/profile.ts`). Surface, reconciled
against the OpenAPI index:

- `getMyProfile()` → `GET /ui/profile` — the own-profile read. Response is wrapped:
  `{ "profile": Profile }` (web: `getProfile()`, `profile.ts:8-9`).
- `getProfileByIdentifier(identifier)` → `GET /ui/profiles/{identifier}` — the
  cross-user read. Response is `CrossUserProfileResp` `{ identifier, canonical_identifier?,
  user_sub, audience, profile }` where `audience ∈ {owner|member|public}` is inferred by
  the backend from the session (web: `getProfileByIdentifier()`, `profile.ts:137-245`).
  Note: this is `/ui/profiles/{identifier}` (plural), NOT `/ui/profile/meta/{identifier}`.
- `getPublicProfile(identifier)` → `GET /ui/profile/public/{identifier}` — the
  storefront public profile, response `PublicProfileData` (web: `getPublicProfile()`,
  `profile.ts:249-250`). Include if the public storefront screen is in E10 scope.
- (Optional, only if explicitly required) `getProfileMetaTags(identifier)` →
  `GET /ui/profile/meta/{identifier}` — the OG/SEO meta-tags endpoint named in the ticket
  scope line; untyped (`{}`) body, parse as `Map<String, Any?>`. Not used by `profile.ts`.

FR-2. All `ProfileApi` functions are `suspend` and return `ApiResult<T>` via the shared
call adapter from AND-026 (e.g. `ApiResult<ProfileEnvelopeDto>`,
`ApiResult<CrossUserProfileDto>`). Functions never block the calling thread and never
throw for HTTP error statuses — errors surface through `ApiResult.Error`.

FR-3. Define DTOs that deserialize the live payloads losslessly, mirroring
`src/api/types.ts`: `ProfileEnvelopeDto` (`{ profile }`), `ProfileDto` (the `Profile`
shape: `display_name?`, `first_name?`, `middle_name?`, `last_name?`, `title?`,
`description?`, `birthday?`, `gender?`, `location?`, `displayed_email?`,
`displayed_telephone_number?`, `mailing_address?`, `languages?`, `profile_photo_url?`,
`cover_photo_url?` — ALL optional), `CrossUserProfileDto`
(`identifier`, `canonical_identifier?`, `user_sub`, `audience`, `profile`), and (if used)
`PublicProfileDataDto`. Unknown JSON fields must not crash deserialization (Moshi ignores
unknown keys by default).

FR-4. Provide pure mapper functions converting each DTO to an immutable `core-model`
domain type (`Profile`, `CrossUserProfile`, …). Mappers apply defaulting for nullable
fields, normalize identifiers, and never emit nullable collections (empty list instead of
null, e.g. `languages`).

FR-5. Distinguish own vs. cross-user reads via the `audience` discriminator on
`CrossUserProfileResp` (`owner | member | public`), NOT via invented owner-only boolean
flags. The backend decides audience server-side from the session/auth context; the domain
model surfaces `audience` so the UI can gate owner-only affordances. There is no
`is_self`/`email`/`can_edit` field on these payloads — owner-private contact data is
`Profile.displayed_email` / `displayed_telephone_number`, which are user-curated display
fields, not session-PII.

FR-6. Identifier handling: `getProfileByIdentifier` accepts a raw identifier string and
URL-encodes it as a single path segment (the web client uses `encodeURIComponent`,
`profile.ts:161`). In Retrofit, use `@Path("identifier")` (encoded = false default) so
reserved characters are percent-encoded into one segment.

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

    /** Own profile. GET /ui/profile -> { "profile": Profile }. */
    @GET("ui/profile")
    suspend fun getMyProfile(): ApiResult<ProfileEnvelopeDto>

    /** Cross-user profile by identifier (plural path). GET /ui/profiles/{identifier}. */
    @GET("ui/profiles/{identifier}")
    suspend fun getProfileByIdentifier(
        @Path("identifier") identifier: String,
    ): ApiResult<CrossUserProfileDto>

    /** Storefront public profile. GET /ui/profile/public/{identifier}. */
    @GET("ui/profile/public/{identifier}")
    suspend fun getPublicProfile(
        @Path("identifier") identifier: String,
    ): ApiResult<PublicProfileDataDto>
}
```

> Path note: `getProfileByIdentifier` is `ui/profiles/{identifier}` (plural `profiles`),
> per `profile.ts:161`. The singular `ui/profile/meta/{identifier}` in the ticket scope
> line is the OG meta-tags endpoint and is intentionally NOT modeled here (untyped body,
> unused by the web client).

**DTOs (`core-network`):**

```kotlin
/** GET /ui/profile -> { "profile": Profile }. */
@JsonClass(generateAdapter = true)
data class ProfileEnvelopeDto(
    @Json(name = "profile") val profile: ProfileDto,
)

/** The `Profile` shape from src/api/types.ts. Every field is optional in the contract. */
@JsonClass(generateAdapter = true)
data class ProfileDto(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "first_name") val firstName: String? = null,
    @Json(name = "middle_name") val middleName: String? = null,
    @Json(name = "last_name") val lastName: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "birthday") val birthday: String? = null,
    @Json(name = "gender") val gender: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "displayed_email") val displayedEmail: String? = null,
    @Json(name = "displayed_telephone_number") val displayedTelephoneNumber: String? = null,
    @Json(name = "mailing_address") val mailingAddress: MailingAddressDto? = null,
    @Json(name = "languages") val languages: List<LanguageDto>? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "cover_photo_url") val coverPhotoUrl: String? = null,
)

/** CrossUserProfileResp from src/api/types.ts (GET /ui/profiles/{identifier}). */
@JsonClass(generateAdapter = true)
data class CrossUserProfileDto(
    @Json(name = "identifier") val identifier: String,
    @Json(name = "canonical_identifier") val canonicalIdentifier: String? = null,
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "audience") val audience: String,          // owner | member | public
    @Json(name = "profile") val profile: ProfileDto,
)

/** PublicProfileData from src/api/types.ts (GET /ui/profile/public/{identifier}). */
@JsonClass(generateAdapter = true)
data class PublicProfileDataDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "identifier") val identifier: String,
    @Json(name = "canonical_identifier") val canonicalIdentifier: String? = null,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "cover_photo_url") val coverPhotoUrl: String? = null,
    @Json(name = "follower_count") val followerCount: Int,
    @Json(name = "following_count") val followingCount: Int,
    @Json(name = "post_count") val postCount: Int,
    @Json(name = "is_following") val isFollowing: Boolean,
    @Json(name = "is_followed_by") val isFollowedBy: Boolean,
    @Json(name = "is_mutual") val isMutual: Boolean,
    @Json(name = "has_subscription_plans") val hasSubscriptionPlans: Boolean,
    @Json(name = "created_at") val createdAt: Long? = null,  // epoch seconds, NOT ISO-8601
    @Json(name = "discoverability") val discoverability: String? = null,
)
```

> Field names above are taken one-to-one from `src/api/types.ts` (`Profile`,
> `CrossUserProfileResp`, `PublicProfileData`). `MailingAddressDto`/`LanguageDto` mirror
> the `MailingAddress`/`Language` types in the same file (model their fields when those
> sub-screens land). Note `PublicProfileData.created_at` is a **numeric epoch**, not an
> ISO string — do NOT `Instant.parse` it.

**Domain models (`core-model`):**

```kotlin
package com.testlogon.android.core.model.profile

/** Audience inferred server-side; replaces the invented is_self/can_edit flags. */
enum class ProfileAudience { OWNER, MEMBER, PUBLIC, UNKNOWN }

data class Profile(
    val displayName: String?,
    val firstName: String?,
    val lastName: String?,
    val title: String?,
    val description: String?,
    val location: String?,
    val displayedEmail: String?,
    val displayedTelephoneNumber: String?,
    val profilePhotoUrl: String?,
    val coverPhotoUrl: String?,
    val languages: List<String>,   // never null
)

data class CrossUserProfile(
    val identifier: String,
    val canonicalIdentifier: String?,
    val userSub: String,
    val audience: ProfileAudience,
    val profile: Profile,
)

data class PublicProfile(
    val userId: String,
    val identifier: String,
    val canonicalIdentifier: String?,
    val displayName: String,
    val title: String?,
    val description: String?,
    val location: String?,
    val profilePhotoUrl: String?,
    val coverPhotoUrl: String?,
    val followerCount: Int,
    val followingCount: Int,
    val postCount: Int,
    val isFollowing: Boolean,
    val isFollowedBy: Boolean,
    val isMutual: Boolean,
    val hasSubscriptionPlans: Boolean,
    val createdAt: Instant?,        // from epoch seconds; null if absent
    val discoverability: String?,
)
```

**Mappers (`core-model`, pure functions):**

```kotlin
fun ProfileDto.toDomain(): Profile = Profile(
    displayName = displayName?.takeIf { it.isNotBlank() },
    firstName = firstName?.takeIf { it.isNotBlank() },
    lastName = lastName?.takeIf { it.isNotBlank() },
    title = title?.takeIf { it.isNotBlank() },
    description = description?.trim()?.takeIf { it.isNotBlank() },
    location = location?.takeIf { it.isNotBlank() },
    displayedEmail = displayedEmail?.takeIf { it.isNotBlank() },
    displayedTelephoneNumber = displayedTelephoneNumber?.takeIf { it.isNotBlank() },
    profilePhotoUrl = profilePhotoUrl?.takeIf { it.isNotBlank() },
    coverPhotoUrl = coverPhotoUrl?.takeIf { it.isNotBlank() },
    languages = languages.orEmpty().mapNotNull { it.toDomainOrNull() },
)

fun CrossUserProfileDto.toDomain(): CrossUserProfile = CrossUserProfile(
    identifier = identifier,
    canonicalIdentifier = canonicalIdentifier,
    userSub = userSub,
    audience = when (audience.lowercase()) {
        "owner" -> ProfileAudience.OWNER
        "member" -> ProfileAudience.MEMBER
        "public" -> ProfileAudience.PUBLIC
        else -> ProfileAudience.UNKNOWN          // tolerate new server values
    },
    profile = profile.toDomain(),
)

fun PublicProfileDataDto.toDomain(): PublicProfile = PublicProfile(
    userId = userId,
    identifier = identifier,
    canonicalIdentifier = canonicalIdentifier,
    displayName = displayName,
    title = title, description = description, location = location,
    profilePhotoUrl = profilePhotoUrl, coverPhotoUrl = coverPhotoUrl,
    followerCount = followerCount, followingCount = followingCount, postCount = postCount,
    isFollowing = isFollowing, isFollowedBy = isFollowedBy, isMutual = isMutual,
    hasSubscriptionPlans = hasSubscriptionPlans,
    createdAt = createdAt?.let { runCatching { Instant.ofEpochSecond(it) }.getOrNull() },
    discoverability = discoverability,
)
```

Mappers are exhaustively unit-tested (§11) and contain no I/O. The `ProfileApi` is
provided through a Hilt `@Provides` in the existing `core-network` Retrofit module
(`retrofit.create(ProfileApi::class.java)`), reusing the shared OkHttp client so the
cookie jar, CSRF header, timeouts, and refresh interceptor from AND-026/AND-027
apply automatically.

## 5. API Contract

Base URL from AND-026 config (dev: `http://18.222.237.167:8000`). All requests carry
session cookies (`credentials: include`), an `Authorization: Bearer` header when an
access token exists, and an `X-CSRF-Token` header sourced from the `ui_csrf` cookie,
applied by the shared OkHttp interceptors (matching `src/api/client.ts`); this ticket
adds no per-call headers.

**Own profile**

```
GET /ui/profile
200 OK  application/json
```

Example response (the body is an ENVELOPE — note the `profile` wrapper; all `Profile`
fields are optional):

```json
{
  "profile": {
    "display_name": "Sean",
    "first_name": "Sean",
    "last_name": "Pannella",
    "title": null,
    "description": null,
    "location": "Pittsburgh, PA",
    "displayed_email": "spannella@gmail.com",
    "displayed_telephone_number": null,
    "languages": [],
    "profile_photo_url": null,
    "cover_photo_url": null
  }
}
```

**Cross-user profile by identifier**

```
GET /ui/profiles/{identifier}
Path: identifier — username or user id (single URL-encoded path segment)
200 OK  application/json
```

Example response (`CrossUserProfileResp`; `audience` is server-inferred — owner/member/public):

```json
{
  "identifier": "ada",
  "canonical_identifier": "ada",
  "user_sub": "auth0|abc123",
  "audience": "public",
  "profile": {
    "display_name": "Ada Lovelace",
    "description": "Analytical engines.",
    "profile_photo_url": "http://18.222.237.167:8000/media/ada.png",
    "languages": ["en"]
  }
}
```

> Supporting behaviors of the web `getProfileByIdentifier` (see §7/§13 for which the
> Android client adopts): ETag / `If-None-Match` conditional GET with a 304 path, a
> bespoke 404 → `not_found_or_suppressed` and 429 → `rate_limited` error normalization
> (with `Retry-After` header or `detail.retry_after_seconds` parsing), and an
> `X-IMPERSONATION-TOKEN` header when impersonation is active. (`profile.ts:137-245`.)

**Storefront public profile** (optional, if in scope)

```
GET /ui/profile/public/{identifier}
200 OK  application/json   -> PublicProfileData
```
`created_at` here is a numeric epoch (seconds), not an ISO-8601 string.

**Error responses** follow the FastAPI `detail` convention handled by the AND-026
mapper. Verified shapes:

```json
{ "detail": "Profile not available" }                                  // string (e.g. 404)
{ "detail": [ { "loc": ["path","identifier"], "msg": "...", "type": "..." } ] }  // 422 (ValidationError[])
```

The 422 list element is the FastAPI `ValidationError` object with required `loc`, `msg`,
`type` (verified: `components.schemas.ValidationError`; wrapper `HTTPValidationError`).
A 429 rate-limit body carries `{ "detail": { "retry_after_seconds": N } }` and/or a
`Retry-After` header (verified: `profile.ts:107-130, 189-225`). The previously-claimed
`{ "detail": { "code": "FORBIDDEN", "message": "..." } }` object shape is NOT present in
the sources for these endpoints and is removed.

Status mapping: `200` → `ApiResult.Success`; `304` → reuse cached body (if conditional
GET is adopted); `401` → handled upstream (refresh + single retry) before reaching
`ProfileApi` callers; `404` → `ApiResult.Error` (not-found / suppressed); `422` →
validation error; `429` → rate-limited (honor `Retry-After`); `5xx`/timeout →
network/server error.

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
- **Auth.** A `401` triggers the AND-027 single-shot `POST /ui/session/refresh`
  (deduplicated via a shared in-flight promise) then one retry, transparently to
  `ProfileApi`. If refresh fails, the caller is logged out / routed to re-auth
  (verified: `src/api/client.ts:194-237`).
- **Rate limiting.** `GET /ui/profiles/{identifier}` can return `429`; honor the
  `Retry-After` header (or `detail.retry_after_seconds`) and surface a typed
  rate-limited error rather than a generic failure (verified: `profile.ts:107-130,
  189-225`).
- **Deserialization.** Unknown fields are ignored. Missing **required** fields are a
  hard parse failure surfaced as `ApiResult.Error` (malformed-response): on
  `CrossUserProfileResp` the required fields are `identifier`, `user_sub`, `audience`,
  and `profile`; on `{ profile: Profile }` the `profile` wrapper is required (every
  field INSIDE `Profile` is optional); on `PublicProfileData` the non-`?` fields
  (`user_id`, `identifier`, `display_name`, the counts, the boolean flags) are required.
- **Mapping.** Optional/nullable fields are defaulted (empty list for `languages`,
  blank-to-null normalization). Unparseable/absent `created_at` (epoch) yields `null`,
  not an exception. An unknown `audience` string maps to `ProfileAudience.UNKNOWN`
  rather than throwing.
- **Error detail.** All non-2xx bodies pass through the shared FastAPI `detail` mapper.
  Real shapes: a string detail, or a 422 list of `ValidationError` `{loc,msg,type}`
  objects (verified `components.schemas.ValidationError`). The earlier `{code,message}`
  object shape is not used by these endpoints.

## 8. Security & Privacy

- Authentication is owned by AND-027 and is a **hybrid** (session cookies + optional
  `Authorization: Bearer` + `X-CSRF-Token` from the `ui_csrf` cookie); `ProfileApi`
  carries no tokens in URLs. The cookie jar, bearer header, and CSRF header are applied
  by the shared client (verified: `src/api/client.ts:154-184`).
- **Audience gating.** The server decides what a viewer may see via the `audience`
  discriminator (`owner|member|public`) it returns on `CrossUserProfileResp`; the client
  must NOT fabricate or widen audience. The domain preserves `audience` so the UI gates
  owner-only affordances, but the client trusts the server's payload shaping for PII.
  (There is no client-side `is_self`/`email`/`can_edit` flag to leak — those fields were
  invented in the prior draft and removed.) Contact fields `displayed_email` /
  `displayed_telephone_number` are user-curated display data, returned only when the
  server includes them for that audience.
- The dev backend is **plaintext HTTP**, so profile payloads (including any
  `displayed_email`) traverse the network unencrypted in dev. This is a known dev-host
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
  only, NONE in release) from AND-026. Because profile payloads can carry PII
  (`displayed_email`, `displayed_telephone_number`, `mailing_address`), ensure release
  builds never log bodies, and add those fields to the redaction list if a redacting
  interceptor is present.
- Log a single structured warning when a mapper fails to parse `created_at` (epoch) or
  encounters an unknown `audience`, at DEBUG level, including the field name but **not**
  the full payload.
- Emit no analytics events from this layer; profile-view analytics belong to the
  feature/UI ticket. Surface deserialization failures as `ApiResult.Error` so the
  consuming ViewModel can decide whether to report them.

## 11. Testing Strategy

All tests run on the JVM (`core-network`/`core-model` unit tests) with MockWebServer;
no instrumented tests are required for this ticket.

- **T-1 `ProfileApi` path/verb (MockWebServer).** Enqueue a 200 and assert the recorded
  request line is `GET /ui/profile` for `getMyProfile()` and `GET /ui/profiles/ada` for
  `getProfileByIdentifier("ada")`. Assert no body and that the bearer + CSRF headers are
  present (proving shared-client wiring).
- **T-2 Identifier encoding.** `getProfileByIdentifier("a b/c")` produces a correctly
  percent-encoded single path segment (`a%20b%2Fc`).
- **T-3 Cross-user payload deserialize + map.** Feed the §5 `CrossUserProfileResp`
  fixture; assert `CrossUserProfileDto` parses and `toDomain()` yields
  `audience == ProfileAudience.PUBLIC`, populated `profile`, and non-null `languages`.
- **T-4 Own payload (envelope) deserialize + map.** Feed the §5 `{ profile: ... }`
  fixture; assert the envelope unwraps and `profile.displayedEmail == "spannella@gmail.com"`,
  `profile.languages == emptyList()`.
- **T-5 Nullable/empty branches.** A `{ "profile": {} }` body (all `Profile` fields
  absent) maps to a `Profile` with all-null scalar fields and `languages == emptyList()`,
  no throw.
- **T-6 Malformed / edge branches.** (a) `CrossUserProfileResp` missing required
  `user_sub` → `ApiResult.Error` (malformed). (b) Unknown `audience` value
  (e.g. `"vip"`) → `ProfileAudience.UNKNOWN`, no throw. (c) `PublicProfileData.created_at`
  absent → `createdAt == null`, no throw (epoch path).
- **T-7 Error mapping.** Enqueue 404 string-detail and 422 `ValidationError[]`
  (`{loc,msg,type}`) bodies; assert each yields `ApiResult.Error` with the correctly
  parsed reason via the shared FastAPI mapper. Add a 429 case asserting the rate-limited
  reason and `Retry-After` extraction.
- **T-8 Unknown-field tolerance.** Payload with extra unknown keys parses without error.

Coverage gate: 100% of mapper branches exercised; both data endpoints have a happy-path
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

- **Self-profile path (RESOLVED in review).** Own profile is `GET /ui/profile`
  returning `{ "profile": Profile }`. There is no `/ui/profile/meta/me`. Verified:
  `profile.ts:8-9`, OpenAPI `GET /ui/profile`.
- **`/ui/profile/meta/{identifier}` scope (RESOLVED in review).** This is the OG/SEO
  "Profile Meta Tags" endpoint with an untyped (`{}`) 200 body and is NOT called by
  `profile.ts`. The ticket scope line names it, but the real data reads are
  `GET /ui/profile` and `GET /ui/profiles/{identifier}`. **Open decision:** confirm with
  the ticket owner whether the meta-tags endpoint is genuinely required for this ticket;
  default is to exclude it. Verified: OpenAPI `profile_meta_tags_…` (untyped 200).
- **Field-name drift (RESOLVED in review).** DTO fields now mirror `src/api/types.ts`
  (`Profile`, `CrossUserProfileResp`, `PublicProfileData`) exactly. The endpoint 200
  bodies are untyped (`{}`) in OpenAPI, so `src/api/types.ts` is the authoritative shape.
- **Conditional-GET / caching adoption (OPEN).** The web `getProfileByIdentifier`
  implements ETag/`If-None-Match` + 304 reuse and bespoke 404/429 normalization. Decide
  whether the Android data layer replicates conditional GET now or defers it to the
  repository ticket (E10). Verified behavior: `profile.ts:137-245`.
- **`MailingAddress`/`Language` sub-shapes (OPEN).** Modeled as nested DTOs; their exact
  fields must be lifted from `src/api/types.ts` when the address/language sub-screens land.
- **Unreliable dev host.** Flaky `5xx`/timeouts from `18.222.237.167:8000` make manual
  verification noisy; tests use MockWebServer to stay deterministic.
- **Identifier ambiguity.** Whether `{identifier}` accepts both username and user id in
  all cases is unconfirmed from the static sources (the web passes either through
  `encodeURIComponent`); if not, downstream lookup logic may need adjustment.

## 14. Acceptance Criteria

- AC-1. `ProfileApi` exists in `core-network` with suspend functions for the own
  (`GET /ui/profile`) and cross-user (`GET /ui/profiles/{identifier}`) profile endpoints;
  paths (note plural `profiles`), verbs, and the empty GET bodies match the contract,
  verified by MockWebServer (T-1, T-2).
- AC-2. The own-profile payload (`{ "profile": Profile }`) loads, unwraps the envelope,
  and maps to a domain `Profile` with optional fields preserved (e.g. `displayedEmail`),
  proven by an automated test (T-4).
- AC-3. The cross-user payload (`CrossUserProfileResp`) loads and maps to a
  `CrossUserProfile` with the server-supplied `audience` preserved and no fabricated
  owner-only data, proven by an automated test (T-3).
- AC-4. Nullable/empty and malformed payloads map without throwing per §7 (defaults
  applied, unknown `audience` → `UNKNOWN`, missing required field → `ApiResult.Error`),
  proven by T-5 and T-6.
- AC-5. The real FastAPI `detail` error shapes (string detail; 422
  `ValidationError[]` with `loc/msg/type`) and the 429 rate-limited path map to typed
  `ApiResult.Error` reasons (T-7); unknown fields are tolerated (T-8).
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
  the self-path and `/ui/profile/meta` scope Open Questions (§13) resolved and reflected
  in the interface (own = `GET /ui/profile` envelope; cross-user = `GET /ui/profiles/{identifier}`).
- KSP (Moshi codegen, Hilt) builds clean with no warnings introduced; `ktlint`/detekt
  pass.
- No PII logged in release builds; debug body logging gated to debug variants.
- Spec Open Questions either resolved or re-filed as follow-up tickets against E10;
  downstream tickets (AND-071/AND-072) unblocked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Own-profile endpoint is `GET /ui/profile` returning `{ profile: Profile }`.**
   VERDICT: Corrected (was `GET /ui/profile/meta/me`). SOURCE: `src/api/endpoints/profile.ts: getProfile` (`api.get<{ profile: Profile }>("/ui/profile")`); OpenAPI `GET /ui/profile` (op `ui_get_profile_ui_profile_get`).
2. **Cross-user read is `GET /ui/profiles/{identifier}` (plural) returning `CrossUserProfileResp`.**
   VERDICT: Corrected (was `GET /ui/profile/meta/{identifier}` singular). SOURCE: `src/api/endpoints/profile.ts: getProfileByIdentifier` (path `/ui/profiles/${encodeURIComponent(...)}`); OpenAPI `GET /ui/profiles/{identifier}` (op `ui_get_profile_by_identifier_…`); `src/api/types.ts: CrossUserProfileResp`.
3. **`GET /ui/profile/meta/{identifier}` is an OG/SEO "Profile Meta Tags" endpoint with an untyped (`{}`) 200 body, NOT the data endpoint, and is unused by `profile.ts`.**
   VERDICT: Corrected/Verified. SOURCE: OpenAPI `GET /ui/profile/meta/{identifier}` (op `profile_meta_tags_…`, summary "Profile Meta Tags", `responses.200.content.application/json.schema = {}`); absence in `src/api/endpoints/profile.ts`.
4. **Storefront public profile is `GET /ui/profile/public/{identifier}` returning `PublicProfileData`.**
   VERDICT: Verified. SOURCE: `src/api/endpoints/profile.ts: getPublicProfile`; OpenAPI `GET /ui/profile/public/{identifier}`; `src/api/types.ts: PublicProfileData`.
5. **`Profile` DTO field set (display_name/first_name/.../cover_photo_url, ALL optional).**
   VERDICT: Corrected (replaces invented username/bio/avatar_url/stats/links). SOURCE: `src/api/types.ts: Profile` (lines 473-489).
6. **`CrossUserProfileResp` fields = identifier, canonical_identifier?, user_sub, audience, profile; `audience ∈ owner|member|public`.**
   VERDICT: Corrected (replaces is_self/email/can_edit `ViewerScope`). SOURCE: `src/api/types.ts: CrossUserProfileResp` + `ProfileViewAudience` (lines 491-499).
7. **`PublicProfileData.created_at` is a numeric epoch (seconds), not ISO-8601.**
   VERDICT: Corrected (prior draft parsed `created_at` as an ISO string). SOURCE: `src/api/types.ts: PublicProfileData.created_at?: number` (line 520).
8. **Auth transport is hybrid: cookies (`credentials: include`) + optional `Authorization: Bearer` + `X-CSRF-Token` from the `ui_csrf` cookie (+ optional `X-IMPERSONATION-TOKEN`).**
   VERDICT: Corrected (prior draft said "entirely cookie-based"). SOURCE: `src/api/client.ts:154-184`; `src/api/endpoints/profile.ts:149-160`.
9. **401 handling = single-shot `POST /ui/session/refresh` (deduped via shared promise) + one retry; failed refresh logs out.**
   VERDICT: Verified. SOURCE: `src/api/client.ts:121-128, 194-237`; `src/api/endpoints/auth.ts: refreshSession` (`api.post<StatusResp>("/ui/session/refresh")`).
10. **422 error body = `{ detail: ValidationError[] }` where each element has required `loc`, `msg`, `type`.**
    VERDICT: Corrected (prior draft used `{msg}`-only and an invented `{code,message}` shape). SOURCE: OpenAPI `components.schemas.ValidationError` (required loc/msg/type) and `components.schemas.HTTPValidationError`; all profile ops list `422:HTTPValidationError`.
11. **404 normalizes to `not_found_or_suppressed`; 429 normalizes to `rate_limited` with `Retry-After` / `detail.retry_after_seconds`.**
    VERDICT: Verified. SOURCE: `src/api/endpoints/profile.ts:86-130, 189-225` (`ProfileLookupError`, `parseRetryAfterSeconds`).
12. **`getProfileByIdentifier` uses ETag / `If-None-Match` conditional GET with a 304 reuse path.**
    VERDICT: Verified (adoption deferred — see Open assumptions). SOURCE: `src/api/endpoints/profile.ts:144-245`.
13. **Identifier is URL-encoded as a single path segment.**
    VERDICT: Verified. SOURCE: `src/api/endpoints/profile.ts:161` (`encodeURIComponent(normalized)`).
14. **Moshi ignores unknown JSON keys by default.**
    VERDICT: Verified (framework ref). SOURCE: Moshi docs — https://github.com/square/moshi#unknown-keys (unknown names are skipped unless `@JsonClass(... ignoreUnknown=false)`/`failOnUnknown` is set).
15. **Retrofit `@Path` percent-encodes path values by default (`encoded = false`).**
    VERDICT: Verified (framework ref). SOURCE: Retrofit docs — https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Path.html
16. **Dev backend is plaintext HTTP at `http://18.222.237.167:8000`.**
    VERDICT: Unverified-assumption (carried from spec/AND-026; not derivable from the static API sources, which use a configurable `VITE_API_BASE_URL`). SOURCE: `src/api/endpoints/profile.ts:63` (`VITE_API_BASE_URL`); host value asserted by spec.

### Corrections made

- Own-profile endpoint `/ui/profile/meta/me` → `GET /ui/profile` returning a `{ profile }` envelope (claims 1).
- Public/cross-user endpoint `/ui/profile/meta/{identifier}` → `GET /ui/profiles/{identifier}` returning `CrossUserProfileResp`; clarified the singular `/ui/profile/meta/{identifier}` is an unused OG meta-tags endpoint (claims 2, 3).
- Replaced the invented DTO/domain fields (`username`, `bio`, `avatar_url`, `stats`, `links`, `is_self`, `email`, `can_edit`, `ViewerScope`) with the real `Profile`/`CrossUserProfileResp`/`PublicProfileData` shapes; introduced an `audience` discriminator and `ProfileAudience.UNKNOWN` fallback (claims 5, 6).
- Fixed `created_at` handling on `PublicProfileData` from ISO-8601 to epoch seconds (claim 7).
- Auth corrected from "entirely cookie-based" to the hybrid cookie + bearer + CSRF transport; added impersonation header and 429 rate-limit handling (claims 8, 11).
- Error shapes corrected to string-detail + `ValidationError[]` (`loc/msg/type`); removed the fictitious `{code,message}` object detail (claim 10).
- Updated §3, §4, §5, §7, §8, §10, §11, §13, §14, §15 inline accordingly.

### Open assumptions

- **Dev host plaintext / IP** (`http://18.222.237.167:8000`): not provable from the static sources (web uses a build-time `VITE_API_BASE_URL`); inherited from AND-026/spec. Confirm against the actual Android build config.
- **`/ui/profile/meta/{identifier}` in-scope?** The ticket scope line names it but the web client never calls it and its body is untyped. Defaulting to exclude; needs a product/owner decision.
- **Conditional-GET (ETag/304) adoption** for the Android data layer: verified in web but its placement (this ticket vs. the E10 repository ticket) is undecided.
- **`MailingAddress` / `Language` sub-DTO fields**: declared but not fully modeled here; exact fields live in `src/api/types.ts` and must be lifted when those sub-screens land.
- **Whether `{identifier}` accepts both username and user id** in every case: not provable from static sources (web forwards either string verbatim).
- **`StatusResp` body of `/ui/session/refresh`**: AND-027's concern; not modeled here.

## 17. Test Plan

All cases are JVM/Robolectric-local except where noted. This ticket is a pure data/network
layer (no UI, no device features), so the JVM unit + MockWebServer target covers the bulk;
two cases use the headless emulator and one uses the physical device only to validate ABI /
API-level parity, since nothing here touches camera/biometrics/WebRTC/FCM.

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** = headless
emulator AVD `test35` (x86_64, API 35); **DEVICE** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, arm64-v8a, API 34).

- **TC-AND-070-01** — Type: contract/MockWebServer (JVM). Target: `ProfileApi` request line.
  Preconditions: MockWebServer enqueues `200 { "profile": {} }`. Steps: call `getMyProfile()`.
  Expected: recorded request is `GET /ui/profile`, empty body, and the `Authorization: Bearer`
  + `X-CSRF-Token` headers are present (shared-client wiring). Traces: AC-1.
- **TC-AND-070-02** — Type: contract/MockWebServer (JVM). Target: cross-user path.
  Preconditions: enqueue a valid `CrossUserProfileResp`. Steps: call
  `getProfileByIdentifier("ada")`. Expected: recorded request is `GET /ui/profiles/ada`
  (plural), empty body. Traces: AC-1.
- **TC-AND-070-03** — Type: unit (JVM). Target: identifier encoding. Preconditions: none.
  Steps: call `getProfileByIdentifier("a b/c")` against MockWebServer. Expected: request path
  is a single segment `a%20b%2Fc` (no extra `/`). Traces: AC-1.
- **TC-AND-070-04** — Type: contract/MockWebServer + unit mapper (JVM). Target:
  cross-user deserialize + `toDomain()`. Preconditions: enqueue the §5 `CrossUserProfileResp`
  fixture (`audience:"public"`). Steps: call + map. Expected: `CrossUserProfileDto` parses;
  domain `audience == PUBLIC`, `profile.description` populated, `profile.languages` non-null.
  Traces: AC-3.
- **TC-AND-070-05** — Type: contract/MockWebServer + unit mapper (JVM). Target: own-profile
  envelope. Preconditions: enqueue the §5 `{ "profile": { ... displayed_email ... } }` fixture.
  Steps: call `getMyProfile()` + map. Expected: envelope unwraps; `profile.displayedEmail ==
  "spannella@gmail.com"`, `profile.languages == emptyList()`. Traces: AC-2.
- **TC-AND-070-06** — Type: unit mapper (JVM). Target: nullable/empty defaulting.
  Preconditions: body `{ "profile": {} }`. Steps: parse + map. Expected: all scalar `Profile`
  fields null, `languages == emptyList()`, no throw. Traces: AC-4.
- **TC-AND-070-07** — Type: unit mapper (JVM). Target: malformed + edge branches.
  Preconditions: (a) `CrossUserProfileResp` missing `user_sub`; (b) `audience:"vip"`;
  (c) `PublicProfileData` with `created_at` absent and with `created_at: 1730538900`.
  Steps: parse/map each. Expected: (a) `ApiResult.Error` (malformed), no crash; (b)
  `audience == UNKNOWN`; (c) `createdAt == null` for absent, and a valid `Instant` from epoch.
  Traces: AC-4.
- **TC-AND-070-08** — Type: contract/MockWebServer (JVM). Target: FastAPI error mapping.
  Preconditions: enqueue `404 { "detail": "Profile not available" }` and `422 { "detail":
  [ { "loc":["path","identifier"], "msg":"...", "type":"..." } ] }`. Steps: call
  `getProfileByIdentifier` for each. Expected: each yields `ApiResult.Error` with the parsed
  reason; 404 maps to a not-found reason, 422 to a validation reason. Traces: AC-5.
- **TC-AND-070-09** — Type: contract/MockWebServer (JVM). Target: 429 rate-limit path.
  Preconditions: enqueue `429` with `Retry-After: 30` and `{ "detail": { "retry_after_seconds":
  30 } }`. Steps: call `getProfileByIdentifier`. Expected: `ApiResult.Error` typed as
  rate-limited with retry-after = 30s extracted. Traces: AC-5.
- **TC-AND-070-10** — Type: unit (JVM). Target: unknown-field tolerance. Preconditions: a
  `CrossUserProfileResp` body with extra unknown keys. Steps: parse. Expected: parses without
  error; known fields populated. Traces: AC-5.
- **TC-AND-070-11** — Type: integration/MockWebServer (JVM). Target: 401 → refresh → retry.
  Preconditions: enqueue `401`, then a `200` for `POST /ui/session/refresh`, then a `200`
  profile body; auth store reports authenticated. Steps: call `getMyProfile()`. Expected: the
  client issues `POST /ui/session/refresh` once and retries the GET once, returning
  `ApiResult.Success`; a second `401` after refresh surfaces as Error/logout. Traces: AC-1,
  AC-2 (transport reuse).
- **TC-AND-070-12** — Type: integration/MockWebServer (JVM). Target: offline / flaky-dev-host.
  Preconditions: MockWebServer set to `SocketPolicy.NO_RESPONSE` (timeout) then a recovered
  `200`. Steps: call `getProfileByIdentifier` with the AND-026 retry policy active. Expected:
  timeout surfaces as a network `ApiResult.Error` (no throw to caller); a subsequent call after
  recovery succeeds. Traces: AC-4 (resilience), AC-1.
- **TC-AND-070-13** — Type: instrumented (EMU, AVD test35 / API 35). Target: Moshi KSP-generated
  adapters + Hilt provision of `ProfileApi` on a real ART runtime. Preconditions: app/test APK
  installed on emulator; MockWebServer reachable from the instrumented process. Steps: resolve
  `ProfileApi` from the Hilt graph, call both reads against MockWebServer. Expected: generated
  adapters parse identically to JVM; no `R8`/codegen runtime issues. Note: MUST run on emulator
  (or device) because it validates the packaged KSP adapters + DI on-device, not on the JVM.
  Traces: AC-1, AC-6.
- **TC-AND-070-14** — Type: instrumented/e2e (DEVICE, SM-A156U / arm64-v8a / API 34). Target:
  arm64 vs x86_64 and API-34 vs API-35 parity for DTO parse + mapping. Preconditions: device
  connected via adb; instrumented test APK installed. Steps: run the parse/map suite (cases
  04-07) on the physical device against MockWebServer. Expected: results byte-identical to the
  emulator/JVM runs. Note: MUST run on the PHYSICAL DEVICE — it is the only arm64-v8a / API-34
  target available; it catches ABI- or API-level deserialization differences the x86_64/API-35
  emulator cannot. (No camera/biometric/WebRTC/FCM behavior is exercised — none is in scope.)
  Traces: AC-2, AC-3, AC-4.

Security/permission note: this layer adds no runtime permissions and no device capabilities;
the only security-relevant assertions are header wiring (TC-01), audience non-fabrication
(TC-04), and no-PII-in-logs (covered by the §10 release-build logging gate, validated in the
AND-026 logging test rather than re-asserted here). Accessibility: N/A — no UI is produced by
this ticket (deferred to the E10 profile-screen ticket).

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (endpoints/paths/verbs, empty GET, header wiring) | TC-01, TC-02, TC-03, TC-11, TC-12, TC-13 |
| AC-2 (own-profile envelope loads + maps) | TC-05, TC-11, TC-14 |
| AC-3 (cross-user loads + maps, audience preserved, no leak) | TC-04, TC-14 |
| AC-4 (nullable/empty + malformed map without throwing; resilience) | TC-06, TC-07, TC-12, TC-14 |
| AC-5 (FastAPI error shapes + 429 typed; unknown fields tolerated) | TC-08, TC-09, TC-10 |
| AC-6 (domain annotation-free; DTOs in core-network; no new deps) | TC-13 (DI/codegen on-device), enforced by build/lint |
