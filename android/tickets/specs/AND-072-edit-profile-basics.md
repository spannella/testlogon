---
id: AND-072
title: Edit profile (basics)
milestone: M2
epic: E10
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-071]
blocks: [AND-073]
---

# AND-072 — Edit profile (basics)

## 1. Overview & Goal

Provide an authenticated user the ability to edit the core fields of their own
profile — display name, bio, and external links — with client-side validation,
optimistic-but-safe persistence to the backend, and immediate reflection of the
saved values across the app on reload. This ticket builds directly on the
read-only own-profile view delivered by **AND-071** (`feature-profile`), adding
the write path (`PATCH /ui/profile`) and an `EditProfileScreen`.

The success condition is narrow and testable: a user opens edit, mutates the
editable basics (display name, description/"bio", location, title, name parts),
saves, and on returning to (or reloading) their own profile the new values are
shown — both from the in-memory `StateFlow` and after a cold process restart
that re-fetches the own profile.

> **CORRECTED (review 2026-06-06):** Cold-start re-fetch is `GET /ui/profile`
> (returns `{ "profile": Profile }`), **not** `GET /ui/me`. `GET /ui/me` returns
> only `{ user_sub, session_id, ip }` (`MeResp`) and carries no profile fields —
> see §16. Avatar/photo upload is explicitly out of scope (owned by a later media
> ticket via `POST /ui/profile/photos/{kind}/upload`); this ticket edits text
> fields only.
>
> **CORRECTED (review 2026-06-06):** The backend `Profile` schema has **no
> `links` field** and **no `bio` field**. The web "bio" maps to `description`.
> The links feature described throughout the original draft has **no backend
> support** and is treated below as an unverified/blocked sub-feature (see §13
> OQ-1 and §16 Open assumptions). The verifiable editable basics are
> `display_name`, `description`, `first_name`, `middle_name`, `last_name`,
> `title`, `location`, `displayed_email`, `displayed_telephone_number`,
> `gender`, and `birthday`.

## 2. Context & References

- **Module:** `feature-profile` (consumer of `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). Package root
  `com.testlogon.android.feature.profile`.
- **Depends on AND-071** for `ProfileRepository`, `Profile` domain model,
  `ProfileViewModel`, `ProfileRoute`, and the `profile/own` navigation
  destination. This ticket extends those rather than re-creating them.
- **Blocks AND-073** (public profile) only insofar as both share the `Profile`
  model and `core-model` `ProfileLink` type; no behavioral coupling.
- **Web reference:** `src/api/endpoints/profile.ts` (the `patchProfile` call —
  the web export is named `patchProfile`, **not** `updateProfile`) and shared
  types in `src/api/types.ts` (the `Profile` interface). **CORRECTED:** there is
  no `ProfileLink` or `ProfileUpdateRequest` type in the web app; the web client
  sends `Partial<Profile>` directly to `PATCH /ui/profile`. Mirror field names
  (snake_case, e.g. `display_name`, `description`) and validation rules from the
  web app and the OpenAPI `ProfilePatchReq` schema.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Canonical contract at `/openapi.json`. Cookie +
  `X-CSRF-Token` auth as described in project context; profile edit is a
  non-idempotent `PATCH` and therefore **must not** be auto-retried.

## 3. Functional Requirements

FR-1. From the own-profile screen (AND-071) an "Edit profile" action navigates
to `EditProfileScreen` and pre-populates fields from the currently loaded
`Profile`. If no profile is cached, the screen loads it first (reusing the
repository) and shows a loading state.

FR-2. Editable fields (wire names are snake_case per `ProfilePatchReq`):
- **Display name** (`display_name`): required (client rule), 1–50 chars after
  trim, no leading/trailing whitespace persisted, control characters rejected.
- **Bio / description** (`description`): optional, 0–280 chars, multi-line,
  newlines allowed. **CORRECTED:** the backend field is `description`, not `bio`;
  there is no `bio` field in `Profile`/`ProfilePatchReq`.
- **Location** (`location`): optional free-text, ≤100 chars (client cap;
  server cap unverified — see §16 Open assumptions).
- **Title** (`title`): optional free-text, ≤100 chars (client cap; server cap
  unverified).

> **CORRECTED:** The original draft listed a **Links** field (ordered list of
> `{label, url}`). The backend `Profile`/`ProfilePatchReq` schemas contain **no
> `links` field**, and the web `Profile` type has none either. Links are
> therefore **descoped** from this ticket unless/until the backend adds support
> (carried as OQ-1). All links UI, validation, DTOs, and persistence below are
> retained only as conditional/future design and MUST NOT ship against the
> current contract. `first_name`/`middle_name`/`last_name`/`gender`/`birthday`
> are additional supported basics that MAY be added to the form; they are
> validated as optional free-text/date strings.

FR-3. Validation runs live (per keystroke, debounced for the URL field) and on
save. The **Save** action is disabled while any field is invalid or while no
field differs from the loaded baseline (dirty-tracking).

FR-4. Save issues `PATCH /ui/profile` with only the changed fields (partial
update). On success the screen updates the shared profile state and navigates
back; the own-profile screen reflects the new values without a manual refresh.

FR-5. Field-level server validation errors (FastAPI 422 `detail` array) are
mapped back onto the corresponding field; non-field errors surface as a snackbar
with retry.

FR-6. Unsaved-changes guard: if the user attempts to leave (system back, up
button) with a dirty form, a confirmation dialog ("Discard changes?") is shown.

FR-7. Add/remove link rows; reorder is **not** required for this ticket (links
persist in display order as entered).

## 4. Technical Design

New/changed files under
`feature-profile/src/main/java/com/testlogon/android/feature/profile/edit/`:

```kotlin
// EditProfileUiState.kt
data class LinkFormItem(
    val id: String = UUID.randomUUID().toString(), // stable Compose key
    val label: String = "",
    val url: String = "",
    val urlError: Int? = null,   // string resource id, null = valid
    val labelError: Int? = null,
)

data class EditProfileForm(
    val displayName: String = "",
    val bio: String = "",
    val links: List<LinkFormItem> = emptyList(),
    val displayNameError: Int? = null,
    val bioError: Int? = null,
)

sealed interface EditProfileUiState {
    data object Loading : EditProfileUiState
    data class Error(val message: UiText) : EditProfileUiState
    data class Editing(
        val form: EditProfileForm,
        val baseline: EditProfileForm, // immutable snapshot for dirty-check
        val isSaving: Boolean = false,
        val saveError: UiText? = null,
    ) : EditProfileUiState {
        val isDirty: Boolean get() = form.normalized() != baseline.normalized()
        val isValid: Boolean get() = form.displayNameError == null &&
            form.bioError == null && form.links.all { it.urlError == null && it.labelError == null }
        val canSave: Boolean get() = isDirty && isValid && !isSaving
    }
}
```

```kotlin
@HiltViewModel
class EditProfileViewModel @Inject constructor(
    private val repository: ProfileRepository,
    private val validator: ProfileValidator,
) : ViewModel() {
    val uiState: StateFlow<EditProfileUiState>

    fun onDisplayNameChange(value: String)
    fun onBioChange(value: String)
    fun onLinkLabelChange(itemId: String, value: String)
    fun onLinkUrlChange(itemId: String, value: String)
    fun onAddLink()
    fun onRemoveLink(itemId: String)
    fun onSave()                       // builds ProfileUpdateRequest of dirty fields
    fun consumeSaveError()
}
```

```kotlin
// ProfileValidator.kt (core-model or feature-local; pure, unit-tested)
class ProfileValidator {
    fun validateDisplayName(raw: String): ValidationResult
    fun validateBio(raw: String): ValidationResult
    fun validateUrl(raw: String): ValidationResult
    fun validateLabel(raw: String): ValidationResult
}
sealed interface ValidationResult { data object Ok : ValidationResult; data class Invalid(val msgRes: Int) : ValidationResult }
```

`ProfileRepository` (from AND-071) gains:

```kotlin
suspend fun updateProfile(request: ProfileUpdateRequest): ApiResult<Profile>
```

The repository performs the `PATCH`, and on success updates its single
source-of-truth cache (Room `ProfileEntity` row keyed by the authenticated user
id) and emits the updated `Profile` on the shared `profileFlow` consumed by
AND-071's `ProfileViewModel`. This is how FR-4 reflection happens without manual
refresh.

UI: `EditProfileScreen(onNavigateBack: () -> Unit)` is a stateless composable
driven by `EditProfileViewModel`. Uses Material 3 `OutlinedTextField`,
`Scaffold` + `TopAppBar` with a save `TextButton`/check action, and a
`LazyColumn` of link rows (each with label/url fields and a delete icon) plus an
"Add link" row enabled while `links.size < 5`. The discard dialog uses
`BackHandler(enabled = state.isDirty)`. Navigation destination
`profile/edit` is registered in the existing profile nav graph; only the
authenticated owner can reach it.

## 5. API Contract

**Endpoint:** `PATCH /ui/profile` (op `ui_patch_profile_ui_profile_patch`,
req schema `ProfilePatchReq`) — **VERIFIED** against the OpenAPI index.
**Auth:** the web client sends `Authorization: Bearer <accessToken>` **and**
`X-CSRF-Token` (value from `ui_csrf` cookie) **and** session cookies
(`credentials: include`). On Android these are injected by the existing OkHttp
auth/CSRF interceptors from `core-network`. On `401` (and only when already
authenticated), the client calls `POST /ui/session/refresh` once and retries
the original request exactly once (the refresh is the only retry — the mutation
itself is never blindly re-issued; **VERIFIED** by `src/api/client.ts` lines
194–237; see §7).

> **CORRECTED:** The original draft described auth as cookie + CSRF only. The
> web reference also attaches an `Authorization: Bearer` header from the auth
> store; Android must mirror whichever transport M1 adopted (cookie session
> and/or bearer). The CSRF header name/source (`X-CSRF-Token` from `ui_csrf`)
> is VERIFIED.

**Request body** (partial; only changed fields sent — all `ProfilePatchReq`
properties are nullable/optional, so a true partial update is supported.
Moshi `@JsonClass(generateAdapter = true)`, null fields omitted):

```json
{
  "display_name": "Sean P.",
  "description": "Building things.",
  "location": "Austin, TX"
}
```

```kotlin
// CORRECTED: field is `description` (not `bio`); no `links` field exists in
// ProfilePatchReq. Add only fields confirmed in the schema.
@JsonClass(generateAdapter = true)
data class ProfileUpdateRequest(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "first_name") val firstName: String? = null,
    @Json(name = "middle_name") val middleName: String? = null,
    @Json(name = "last_name") val lastName: String? = null,
)
```

**Success `200`** — **CORRECTED:** the response is **wrapped** in a `profile`
key (`{ "profile": Profile }`), per `src/api/endpoints/profile.ts`
(`api.patch<{ profile: Profile }>(...)`). The `Profile` object uses snake_case
fields and has **no** `id`, `username`, `avatar_url`, or `stats` fields (those
in the original draft were fabricated). Avatar is `profile_photo_url` /
`cover_photo_url`. Verified shape (`src/api/types.ts: Profile`):

```json
{
  "profile": {
    "display_name": "Sean P.",
    "first_name": "Sean",
    "last_name": "P.",
    "title": "Builder",
    "description": "Building things.",
    "location": "Austin, TX",
    "profile_photo_url": "https://.../a.jpg",
    "cover_photo_url": "https://.../c.jpg"
  }
}
```

**Error `422`** (FastAPI `HTTPValidationError`, **VERIFIED** as the documented
error response for `PATCH /ui/profile`): `detail` is an array of
`{ "loc": ["body", "display_name"], "msg": "...", "type": "..." }`. The
`ApiResult` error mapper in `core-network` handles `detail` as
`string | [{msg}] | {code,...}` (the web `normalizeErrorDetail` in
`src/api/client.ts` confirms `detail` may be a string, an object with `msg`, or
an authorization-error object); this ticket adds a field-mapping step that reads
the last `loc` element (e.g. `display_name`, `description`, `location`) to route
the message to the right field. **CORRECTED:** `bio`/`links` loc values do not
apply (no such fields). `400` surfaces as a save snackbar; `403` is handled by
the shared interceptor (permission/geo). `429` (rate limit) is plausible on
read paths but unverified for `PATCH /ui/profile`.

Retrofit interface (extends AND-071's `ProfileApi`) — note the **wrapped**
response envelope:

```kotlin
// CORRECTED: response is { "profile": ProfileDto }, not a bare ProfileDto.
@JsonClass(generateAdapter = true)
data class ProfileEnvelope(@Json(name = "profile") val profile: ProfileDto)

@PATCH("ui/profile")
suspend fun updateProfile(@Body body: ProfileUpdateRequest): Response<ProfileEnvelope>
```

## 6. Data & State Management

- **Single source of truth:** Room `ProfileEntity` (own profile row), introduced
  in AND-071. `updateProfile` writes through to Room on `200`, and the shared
  `Flow<Profile>` re-emits, so AND-071's screen recomposes with new values —
  satisfying "reflect on reload" both in-session and after cold start.
  **CORRECTED:** cold start re-fetches `GET /ui/profile` (returns
  `{ profile: Profile }` with persisted values), **not** `GET /ui/me` (which
  returns only `{ user_sub, session_id, ip }`).
- **Form state** lives only in `EditProfileViewModel` (not persisted to Room).
  It is retained across configuration changes via the ViewModel and additionally
  survives process death via `SavedStateHandle` for the primitive form fields
  (display name, description, location, title, name parts) so an unexpected kill
  does not silently drop edits. (Links removed — see §3 FR-2 correction.)
- **Dirty tracking** compares a normalized form (trimmed, empty links dropped)
  against the `baseline` snapshot captured at load. Save sends only fields whose
  normalized value differs from baseline.
- **No DataStore** changes required; profile is cache data, not a preference.

## 7. Error Handling & Resilience

- **Timeouts:** rely on `core-network`'s ~20s OkHttp call timeout for the dev
  host. A timeout on `PATCH` yields `ApiResult.Error.Network`, shown as a
  retryable snackbar; the form remains intact and dirty.
- **No automatic retry of the mutation.** `PATCH /ui/profile` is
  non-idempotent; the bounded-backoff retry policy applies to idempotent GETs
  only. The single permitted re-issue is after a `401 → /ui/session/refresh`
  success, performed once by the auth interceptor.
- **Concurrency:** `isSaving` disables Save and field edits during the in-flight
  request to prevent double submission.
- **Server validation (422):** mapped to field-level errors; the form stays open
  so the user can correct and resubmit.
- **Refresh failure:** if `/ui/session/refresh` fails, the request returns
  `ApiResult.Error.Unauthorized`; the user is routed to re-auth (handled by the
  global auth gate from M1), form state preserved via `SavedStateHandle`.
- **Offline:** if `core-data` reports no connectivity, Save is blocked with an
  inline "You're offline" message rather than firing a doomed request.

## 8. Security & Privacy

- Edit is restricted to the authenticated owner; there is no userId parameter —
  the backend derives identity from the session cookie. The `profile/edit`
  destination is reachable only from the own-profile screen.
- CSRF protection is mandatory on this state-changing `PATCH`: the
  `X-CSRF-Token` header (mirrored from the `ui_csrf` cookie) is attached by the
  shared interceptor; requests missing it are rejected server-side.
- Cookies live in the persistent encrypted cookie jar from M1; no tokens are
  logged. Bio/links are user content — never logged at value level (see §10).
- URL validation rejects non-`http(s)` schemes (e.g. `javascript:`,
  `file:`, `intent:`) to avoid persisting hostile links that a public profile
  (AND-073) might later render or make tappable.
- Input length caps are enforced client-side and re-enforced server-side; client
  caps are a UX nicety, not a trust boundary.

## 9. Accessibility & i18n

- All fields have visible labels and programmatic `contentDescription`/
  `semantics`; error text is associated with its field and announced via
  `Modifier.semantics { error(msg) }` for TalkBack.
- Character counters (bio 280, name 50) are exposed as supporting text and read
  by screen readers; the disabled Save state has an explanatory
  `stateDescription` ("Save, disabled, no changes" / "fix errors").
- Touch targets (add/remove link, save) ≥ 48dp; full keyboard/D-pad traversal
  with logical focus order; `imeAction` Next/Done wired across fields.
- All user-facing strings (labels, errors, dialog, counters) live in
  `feature-profile/src/main/res/values/strings.xml` with no hardcoded text;
  counters use plurals/`Formatter` and are RTL-safe. Layout uses
  start/end (not left/right) padding.

## 10. Telemetry & Logging

- Emit structured analytics events via the existing `Analytics` abstraction
  (M1): `profile_edit_opened`, `profile_edit_saved`
  (props: `fields_changed` = list of changed field names, `links_count`),
  `profile_edit_save_failed` (props: `error_type`, `http_status`), and
  `profile_edit_discarded`. **No field values** are included — only field names
  and counts.
- Debug logging via `Timber` is tag-scoped (`EditProfile`) and logs request
  outcome and mapped error type at `DEBUG`, never request/response bodies. No PII
  (bio/link/name content) in logs at any level.

## 11. Testing Strategy

- **Unit (`ProfileValidator`):** boundary tests for name (0/1/50/51 chars,
  whitespace-only, control chars), bio (280/281), url (valid http/https,
  missing scheme, `javascript:`, >200 chars, relative), label (30/31), link
  count (5/6). Pure functions, JVM tests.
- **ViewModel (`core-testing` + Turbine):** dirty/valid/canSave transitions;
  partial-request construction sends only changed fields; 422 maps to correct
  field; 401→refresh→retry success path; save error surfaces and is consumable;
  `SavedStateHandle` restore reconstitutes form. Use a fake `ProfileRepository`.
- **Repository:** MockWebServer asserts `PATCH /ui/profile`, body shape,
  `X-CSRF-Token` header presence, Room write-through, and `profileFlow`
  re-emission on success.
- **Compose UI tests:** Save disabled until dirty+valid; discard dialog on back
  when dirty; error text rendered against the right field; add/remove link rows;
  link cap at 5.
- **Acceptance (instrumented end-to-end against MockWebServer):** edit
  name/bio/link → save → navigate back → own-profile (AND-071) shows new values;
  simulate process recreation (ViewModel/SavedState restore + re-fetch
  `GET /ui/me` returning the updated profile) and assert values persist — this
  directly verifies the ticket's "Edits persist and reflect on reload" criterion.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-071** — requires `ProfileRepository`, `Profile`/`ProfileLink`
  models, `ProfileEntity` Room cache, shared `profileFlow`, and the profile nav
  graph. Cannot start until AND-071's read path merges.
- Relies on M1 infrastructure: `core-network` cookie jar + CSRF/auth
  interceptors + `ApiResult` mapper, `Analytics`, connectivity from `core-data`.
- **Blocks AND-073** loosely (shared `ProfileLink` model and URL validation are
  reused by the public profile renderer); no runtime dependency.
- Sequencing: extend `ProfileApi`/`ProfileRepository` (write) → `ProfileValidator`
  → `EditProfileViewModel`/state → `EditProfileScreen` + nav → tests.

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED, review 2026-06-06):** Field names confirmed against
  `ProfilePatchReq` and `src/api/types.ts: Profile`. The wire fields are
  `display_name` and `description` (the web "bio"); **there is no `links` field
  and no `bio` field**. `PATCH` accepts true partial updates (all properties
  optional). The links sub-feature is **descoped / blocked** pending a backend
  schema change — carry forward with backend owner sign-off before any links UI
  ships.
- **OQ-2:** Server `description`/`display_name` length limits are **not
  expressed** in `ProfilePatchReq` (no `maxLength` in the schema); the 280/50
  client caps are an unverified assumption. Confirm with backend to avoid
  client/server divergence (see §16 Open assumptions).
- **OQ-3:** Does the backend normalize/validate URLs (add scheme, reject
  schemes)? Align client rules to avoid double-rejection or silent rewriting.
- **Risk:** unreliable dev host may make the acceptance "reflect on reload" flaky
  if `GET /ui/profile` returns stale data; mitigated by write-through cache so
  in-app reflection does not depend on the network round-trip.
- **OQ-4:** Whether link reorder is needed soon (deferred here) — if yes, the
  stable `LinkFormItem.id` already supports it.

## 14. Acceptance Criteria

AC-1. Opening edit pre-fills the editable basics (display name, description,
location, title, name parts) from the loaded profile. (CORRECTED: "links"
removed.)
AC-2. Save is disabled when the form is pristine or invalid, enabled only when
dirty **and** valid.
AC-3. Validation enforces: display name 1–50 (trimmed, required),
description ("bio") ≤280, location/title ≤100; violations show field-level
errors. (CORRECTED: links/label/url rules removed — no backend `links` field.
If links are later added via a backend schema change, the deferred url/label
rules apply.)
AC-4. Save sends `PATCH /ui/profile` with only changed fields and the
`X-CSRF-Token` header; a `200` updates the cache and navigates back.
AC-5. After save, the own-profile screen (AND-071) shows the new values without a
manual refresh.
AC-6. **After app reload/cold restart, the edited values persist** (verified via
`GET /ui/profile` re-fetch in the acceptance test — CORRECTED from `GET /ui/me`)
— the ticket's core criterion.
AC-7. Server 422 errors map to the correct fields; network/other errors show a
retryable snackbar with the form preserved.
AC-8. Leaving with unsaved changes prompts a discard confirmation.
AC-9. The mutation is never auto-retried except the single post-`session/refresh`
re-issue.

## 15. Definition of Done

- All AC met and demonstrated by the automated acceptance test.
- Unit, ViewModel, repository (MockWebServer), and Compose UI tests added and
  green in CI; no decrease in `feature-profile` coverage.
- No hardcoded strings; TalkBack pass on `EditProfileScreen`; ktlint/detekt clean.
- No PII in logs/analytics (field names/counts only); CSRF header verified by test.
- Package names under `com.testlogon.android.feature.profile.edit`; builds with
  Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9, minSdk 24 / target 35.
- Code reviewed and merged to `android-port`; OQ-1..OQ-4 resolved against
  `/openapi.json` or explicitly carried forward with backend owner sign-off.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **`PATCH /ui/profile` is the edit endpoint.** VERDICT: Verified.
   SOURCE: OpenAPI `PATCH /ui/profile` (op `ui_patch_profile_ui_profile_patch`,
   req `ProfilePatchReq`, resp `200`; `422:HTTPValidationError`); frontend
   `src/api/endpoints/profile.ts: patchProfile`.
2. **The web export is `patchProfile`, not `updateProfile`.** VERDICT: Corrected
   (draft said `updateProfile`). SOURCE: `src/api/endpoints/profile.ts:
   patchProfile`.
3. **HTTP method is PATCH and accepts true partial updates.** VERDICT: Verified.
   SOURCE: OpenAPI `ProfilePatchReq` — every property is `anyOf [type, null]`
   (all optional); `src/api/endpoints/profile.ts` types body as
   `Partial<Profile>`. (A `PUT /ui/profile` full-replace also exists,
   `ProfilePutReq`, but is not used here.)
4. **Bio is the `description` field; there is no `bio` field.** VERDICT:
   Corrected (draft used `bio`). SOURCE: OpenAPI `ProfilePatchReq.description`;
   `src/api/types.ts: Profile.description`.
5. **There is no `links` field (no `{label,url}` list) in the contract.**
   VERDICT: Corrected (draft added a `links` array + `ProfileLinkDto`). SOURCE:
   OpenAPI `ProfilePatchReq` (properties: birthday, cover_photo_url,
   description, display_name, displayed_email, displayed_telephone_number,
   first_name, gender, languages, last_name, locale, location, mailing_address,
   middle_name, profile_photo_url, title — no `links`); `src/api/types.ts:
   Profile` (no `links`).
6. **Field names are snake_case (`display_name`, `description`, `location`,
   `title`, `first_name`, etc.).** VERDICT: Verified. SOURCE: OpenAPI
   `ProfilePatchReq`; `src/api/types.ts: Profile`.
7. **Success `200` response is wrapped: `{ "profile": Profile }`.** VERDICT:
   Corrected (draft showed a bare profile object). SOURCE:
   `src/api/endpoints/profile.ts` — `api.patch<{ profile: Profile }>(...)`;
   `getProfile` is `api.get<{ profile: Profile }>("/ui/profile")`.
8. **`Profile` has no `id`, `username`, `avatar_url`, or `stats`; avatar is
   `profile_photo_url` / `cover_photo_url`.** VERDICT: Corrected (draft invented
   those fields). SOURCE: `src/api/types.ts: Profile` (fields:
   display_name, first_name, middle_name, last_name, title, description,
   birthday, gender, location, displayed_email, displayed_telephone_number,
   mailing_address, languages, profile_photo_url, cover_photo_url).
9. **Own-profile read / cold-start re-fetch is `GET /ui/profile`, NOT
   `GET /ui/me`.** VERDICT: Corrected (draft said `GET /ui/me`). SOURCE:
   `src/api/endpoints/profile.ts: getProfile`; OpenAPI `GET /ui/me`
   (op `ui_me_ui_me_get`) + `src/api/types.ts: MeResp = { user_sub, session_id,
   ip }` (no profile fields).
10. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie on
    state-changing requests.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (lines ~168–171: `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", ...)`);
    same pattern in `src/api/endpoints/profile.ts: getProfileByIdentifier`.
11. **Auth also sends `Authorization: Bearer <accessToken>` plus session cookies
    (`credentials: include`).** VERDICT: Corrected/expanded (draft described
    cookie+CSRF only). SOURCE: `src/api/client.ts` lines ~157–159, 183.
12. **On `401`, exactly one `POST /ui/session/refresh` then one retry of the
    original request; refresh failure → logout/re-auth.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` lines ~194–237 (`refreshSession` →
    `POST /ui/session/refresh`, single retry, `logout("session_expired")` on
    failure); OpenAPI `POST /ui/session/refresh`
    (op `ui_session_refresh_ui_session_refresh_post`).
13. **Errors: `422` = FastAPI `HTTPValidationError` (`detail[]` of
    `{loc,msg,type}`); `detail` may also be a string or `{msg}`/auth object.**
    VERDICT: Verified. SOURCE: OpenAPI `PATCH /ui/profile`
    `resp 422:HTTPValidationError`; `src/api/client.ts: normalizeErrorDetail`
    (handles string | `{msg}` | authorization object).
14. **`403` (permission / geo-block) handled by shared transport.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` lines ~239–255.
15. **Compose / Material 3 / Hilt / Moshi / Room stack and `BackHandler` for the
    discard guard.** VERDICT: Unverified-assumption (framework choices, not in
    the API sources). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/develop/ui/compose/components/scaffold ,
    https://developer.android.com/jetpack/androidx/releases/activity (BackHandler),
    https://dagger.dev/hilt/ , https://github.com/square/moshi ,
    https://developer.android.com/training/data-storage/room . Consistent with
    M1/AND-071 conventions but not independently verifiable from this ticket's
    reference set.

### Corrections made

- `updateProfile` → `patchProfile` (web export name). [claim 2]
- Bio field `bio` → `description`. [claim 4]
- Removed the `links` array / `ProfileLinkDto` and all link-list validation
  (no backend `links` field); descoped pending backend change. [claim 5,
  §3 FR-2, §3 FR-7, §14 AC-1/AC-3]
- Success response corrected to wrapped `{ "profile": Profile }`. [claim 7]
- Removed fabricated `id`/`username`/`avatar_url`/`stats`; avatar is
  `profile_photo_url`/`cover_photo_url`. [claim 8]
- Cold-start / reflect-on-reload re-fetch `GET /ui/me` → `GET /ui/profile`.
  [claim 9; §1, §6, §13, §14 AC-6]
- Auth expanded to include `Authorization: Bearer` + cookies alongside CSRF.
  [claim 11]
- Retrofit `Response<ProfileDto>` → `Response<ProfileEnvelope>`. [claim 7]

### Open assumptions

- **Server length limits** for `display_name` (50) and `description` (280),
  and `location`/`title` (100): `ProfilePatchReq` declares no `maxLength`, so
  these caps are client-side guesses. Why unverifiable: the schema carries no
  validation constraints and no separate validation doc is in the reference set.
  (OQ-2.)
- **URL validation / link rendering**: moot for now since `links` does not
  exist in the contract; the `javascript:`/`file:`/`intent:` scheme-rejection
  rationale only applies if links are later added. (OQ-1/OQ-3.)
- **Offline detection** via `core-data` connectivity and **~20s OkHttp call
  timeout**: M1 infra assumptions, not in this ticket's reference sources.
- **Framework stack** (Compose/Hilt/Moshi/Room/BackHandler): see claim 15.

## 17. Test Plan

Test target legend — JVM = JVM unit/Robolectric (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35) on CI; DEV = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a).

- **TC-AND-072-01** — Validator boundaries (display name). Type: unit.
  Target: JVM. Preconditions: `ProfileValidator` instantiated. Steps: validate
  "", "a", a 50-char string, a 51-char string, "   " (whitespace-only), and a
  string containing a control char (``). Expected: empty/whitespace-only/
  51-char/control → `Invalid(msgRes)`; 1- and 50-char → `Ok`. Traces: AC-2,
  AC-3.
- **TC-AND-072-02** — Validator boundaries (description "bio"). Type: unit.
  Target: JVM. Preconditions: validator ready. Steps: validate 0-, 280-, and
  281-char strings, plus a multi-line string with `\n`. Expected: 0 and 280 →
  `Ok`; 281 → `Invalid`; newlines allowed. Traces: AC-3.
- **TC-AND-072-03** — ViewModel dirty/valid/canSave transitions. Type: unit
  (Turbine + fake `ProfileRepository`). Target: JVM. Preconditions: VM loaded
  with a baseline profile. Steps: emit no change (pristine); change
  `display_name` to a valid value; change it to invalid (empty); revert to
  baseline. Expected: `canSave` = false (pristine), true (dirty+valid), false
  (invalid), false (reverted/pristine). Traces: AC-2.
- **TC-AND-072-04** — Partial request builds only changed snake_case fields.
  Type: unit. Target: JVM. Preconditions: VM loaded; only `description` edited.
  Steps: call `onSave()`; capture the `ProfileUpdateRequest` passed to the fake
  repo. Expected: body contains `description` only; `display_name`/others are
  null/omitted; Moshi serializes key as `description`. Traces: AC-4.
- **TC-AND-072-05** — Contract: PATCH path, method, CSRF header, wrapped
  response. Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer enqueues `200` with body `{"profile":{"display_name":"X",...}}`.
  Steps: call `repository.updateProfile(...)`. Expected: recorded request is
  `PATCH /ui/profile`, carries `X-CSRF-Token`, `Content-Type: application/json`;
  parser unwraps `profile` and returns `ApiResult.Success(Profile)`; Room
  write-through occurs and `profileFlow` re-emits. Traces: AC-4, AC-5.
- **TC-AND-072-06** — 422 field mapping from real FastAPI shape. Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `422` with
  `{"detail":[{"loc":["body","display_name"],"msg":"...","type":"..."}]}`.
  Steps: edit + save. Expected: error routed to the display-name field
  (`displayNameError != null`); form stays open; no navigation. Traces: AC-7.
- **TC-AND-072-07** — 401 → single session refresh → single retry success.
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then
  a `200` for `POST /ui/session/refresh`, then a `200` for the retried `PATCH`.
  Steps: save once. Expected: exactly one `/ui/session/refresh`, exactly one
  retry of the `PATCH`, success surfaced; MockWebServer shows no third PATCH.
  Traces: AC-4, AC-9.
- **TC-AND-072-08** — Mutation never blind-retried; refresh failure → re-auth.
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401` then a
  failing `/ui/session/refresh` (`401`). Steps: save. Expected: result is
  `ApiResult.Error.Unauthorized`; the original `PATCH` is issued only once
  (pre-refresh); user routed to re-auth; `SavedStateHandle` retains form values.
  Traces: AC-9, AC-7.
- **TC-AND-072-09** — Offline path: save blocked, no request fired. Type:
  unit/integration (fake connectivity). Target: JVM. Preconditions:
  connectivity reports offline. Steps: form dirty+valid, tap Save. Expected:
  inline "You're offline" shown; no MockWebServer request; form stays dirty.
  Traces: AC-7.
- **TC-AND-072-10** — Flaky dev-host: PATCH timeout yields retryable snackbar,
  form preserved. Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer set to no-response / socket delay beyond call timeout. Steps:
  save. Expected: `ApiResult.Error.Network`; retryable snackbar; form remains
  intact and dirty; no auto-retry. Traces: AC-7, AC-9.
- **TC-AND-072-11** — Compose UI: Save enabled only when dirty+valid; discard
  dialog on back. Type: Compose-UI. Target: EMU. Preconditions: screen loaded
  with baseline. Steps: assert Save disabled; type a valid display name (assert
  enabled); clear it (assert disabled); with dirty form press system back.
  Expected: enable/disable transitions correct; "Discard changes?" dialog
  appears. Traces: AC-2, AC-8.
- **TC-AND-072-12** — Accessibility: TalkBack semantics, error association,
  touch targets. Type: instrumented/accessibility. Target: DEV (run on the
  physical device for a real TalkBack pass; EMU acceptable for the automated
  semantics assertions). Preconditions: invalid display name set. Steps: assert
  each field has a label + `contentDescription`; error text is associated via
  `semantics { error(...) }`; Save's disabled `stateDescription` is present;
  all actionable targets ≥ 48dp. Expected: all assertions pass; TalkBack
  announces field + error. Traces: AC-3, AC-2.
- **TC-AND-072-13** — End-to-end acceptance: edit → save → reflect → persist
  across cold restart via `GET /ui/profile`. Type: instrumented/e2e
  (MockWebServer or staged dev host). Target: EMU (DEV optional for a real
  device pass). Preconditions: own profile loaded. Steps: edit display name +
  description, save, navigate back, assert AND-071 shows new values; simulate
  process recreation; on relaunch the app re-fetches `GET /ui/profile`
  returning the updated `{ profile: ... }`. Expected: new values visible
  immediately (write-through) and after restart from the re-fetch. Traces:
  AC-5, AC-6.
- **TC-AND-072-14** — Security: CSRF required + owner-only destination. Type:
  contract + manual. Target: JVM (CSRF assertion) / DEV (navigation). Steps:
  (a) assert the `PATCH` always carries `X-CSRF-Token`; (b) confirm
  `profile/edit` is reachable only from the authenticated own-profile screen and
  sends no user-id param (server derives identity from session). Expected: CSRF
  header present on every mutation; no user-id in path/body/query. Traces: AC-4.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (pre-fill basics) | TC-AND-072-13 (and implied by VM load in -03) |
| AC-2 (Save dirty+valid only) | TC-AND-072-01, -03, -11, -12 |
| AC-3 (field validation) | TC-AND-072-01, -02, -06, -12 |
| AC-4 (PATCH changed-fields + CSRF, 200) | TC-AND-072-04, -05, -07, -14 |
| AC-5 (reflect without refresh) | TC-AND-072-05, -13 |
| AC-6 (persist across cold restart) | TC-AND-072-13 |
| AC-7 (422 field map / network errors) | TC-AND-072-06, -08, -09, -10 |
| AC-8 (discard confirmation) | TC-AND-072-11 |
| AC-9 (no auto-retry except post-refresh) | TC-AND-072-07, -08, -10 |
