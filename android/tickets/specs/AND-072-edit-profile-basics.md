---
id: AND-072
title: Edit profile (basics)
milestone: M2
epic: E10
priority: P1
size: M
status: draft
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

The success condition is narrow and testable: a user opens edit, mutates
name/bio/links, saves, and on returning to (or reloading) their own profile the
new values are shown — both from the in-memory `StateFlow` and after a cold
process restart that re-fetches `GET /ui/me`. Avatar/photo upload is explicitly
out of scope (owned by a later media ticket); this ticket edits text fields and
link entries only.

## 2. Context & References

- **Module:** `feature-profile` (consumer of `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`). Package root
  `com.testlogon.android.feature.profile`.
- **Depends on AND-071** for `ProfileRepository`, `Profile` domain model,
  `ProfileViewModel`, `ProfileRoute`, and the `profile/own` navigation
  destination. This ticket extends those rather than re-creating them.
- **Blocks AND-073** (public profile) only insofar as both share the `Profile`
  model and `core-model` `ProfileLink` type; no behavioral coupling.
- **Web reference:** `frontend/src/api/endpoints/profile.ts` (the
  `updateProfile` call) and shared types in `frontend/src/api/types.ts`
  (`Profile`, `ProfileLink`, `ProfileUpdateRequest`). Mirror field names and
  validation rules from the web app.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Canonical contract at `/openapi.json`. Cookie +
  `X-CSRF-Token` auth as described in project context; profile edit is a
  non-idempotent `PATCH` and therefore **must not** be auto-retried.

## 3. Functional Requirements

FR-1. From the own-profile screen (AND-071) an "Edit profile" action navigates
to `EditProfileScreen` and pre-populates fields from the currently loaded
`Profile`. If no profile is cached, the screen loads it first (reusing the
repository) and shows a loading state.

FR-2. Editable fields:
- **Display name** (`displayName`): required, 1–50 chars after trim, no leading/
  trailing whitespace persisted, control characters rejected.
- **Bio** (`bio`): optional, 0–280 chars, multi-line, newlines allowed.
- **Links** (`links`): ordered list, 0–5 entries. Each entry has an optional
  `label` (0–30 chars) and a required `url` (valid `http`/`https` absolute URL,
  ≤200 chars). Empty trailing rows are dropped on save.

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

**Endpoint:** `PATCH /ui/profile`
**Auth:** session cookies + `X-CSRF-Token` header (value from `ui_csrf`
cookie), injected by the existing OkHttp auth/CSRF interceptors from
`core-network`. On `401`, the interceptor calls `POST /ui/session/refresh` once
and retries the original `PATCH` exactly once (the refresh is the only retry —
the mutation itself is never blindly re-issued; see §7).

**Request body** (partial; only changed fields sent — Moshi
`@JsonClass(generateAdapter = true)`, nullable omission via
`@Json` + non-null only):

```json
{
  "display_name": "Sean P.",
  "bio": "Building things.",
  "links": [
    { "label": "Site", "url": "https://example.com" },
    { "label": "", "url": "https://github.com/spannella" }
  ]
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class ProfileUpdateRequest(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "bio") val bio: String? = null,
    @Json(name = "links") val links: List<ProfileLinkDto>? = null,
)
@JsonClass(generateAdapter = true)
data class ProfileLinkDto(val label: String?, val url: String)
```

**Success `200`** returns the full updated profile (same shape as
`GET /ui/me`'s profile object):

```json
{
  "id": "usr_123",
  "username": "spannella",
  "display_name": "Sean P.",
  "bio": "Building things.",
  "avatar_url": "https://.../a.jpg",
  "links": [ { "label": "Site", "url": "https://example.com" } ],
  "stats": { "followers": 12, "following": 8, "posts": 3 }
}
```

**Error `422`** (FastAPI validation): `detail` is an array of
`{ "loc": ["body", "display_name"], "msg": "...", "type": "..." }`. The
`ApiResult` error mapper in `core-network` already handles `detail` as
`string | [{msg}] | {code,...}`; this ticket adds a field-mapping step that reads
the last `loc` element (`display_name`, `bio`, `links`, or `links[i].url`) to
route the message to the right field. `409`/`400` surface as a save snackbar.

Retrofit interface (extends AND-071's `ProfileApi`):

```kotlin
@PATCH("ui/profile")
suspend fun updateProfile(@Body body: ProfileUpdateRequest): Response<ProfileDto>
```

## 6. Data & State Management

- **Single source of truth:** Room `ProfileEntity` (own profile row), introduced
  in AND-071. `updateProfile` writes through to Room on `200`, and the shared
  `Flow<Profile>` re-emits, so AND-071's screen recomposes with new values —
  satisfying "reflect on reload" both in-session and after cold start (cold start
  re-fetches `GET /ui/me`, which the backend now returns with persisted values).
- **Form state** lives only in `EditProfileViewModel` (not persisted to Room).
  It is retained across configuration changes via the ViewModel and additionally
  survives process death via `SavedStateHandle` for the three primitive form
  fields (display name, bio, serialized links JSON) so an unexpected kill does
  not silently drop edits.
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

- **OQ-1:** Exact `/ui/profile` request/response field names and the link object
  shape must be confirmed against `/openapi.json` and `frontend/src/api/types.ts`;
  this spec assumes snake_case `display_name`/`bio`/`links[{label,url}]`. Confirm
  whether `PATCH` accepts true partial updates or requires the full object.
- **OQ-2:** Server bio/name length limits — confirm 280/50 match the backend to
  avoid client/server divergence.
- **OQ-3:** Does the backend normalize/validate URLs (add scheme, reject
  schemes)? Align client rules to avoid double-rejection or silent rewriting.
- **Risk:** unreliable dev host may make the acceptance "reflect on reload" flaky
  if `GET /ui/me` returns stale data; mitigated by write-through cache so in-app
  reflection does not depend on the network round-trip.
- **OQ-4:** Whether link reorder is needed soon (deferred here) — if yes, the
  stable `LinkFormItem.id` already supports it.

## 14. Acceptance Criteria

AC-1. Opening edit pre-fills name, bio, and links from the loaded profile.
AC-2. Save is disabled when the form is pristine or invalid, enabled only when
dirty **and** valid.
AC-3. Validation enforces: name 1–50 (trimmed, required), bio ≤280, ≤5 links,
each url a valid absolute http/https ≤200 chars, label ≤30; violations show
field-level errors.
AC-4. Save sends `PATCH /ui/profile` with only changed fields and the
`X-CSRF-Token` header; a `200` updates the cache and navigates back.
AC-5. After save, the own-profile screen (AND-071) shows the new values without a
manual refresh.
AC-6. **After app reload/cold restart, the edited values persist** (verified via
`GET /ui/me` re-fetch in the acceptance test) — the ticket's core criterion.
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
