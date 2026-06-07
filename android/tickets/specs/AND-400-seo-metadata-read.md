---
id: AND-400
title: SEO metadata (read)
milestone: M8
epic: E52
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-400 — SEO metadata (read)

## 1. Overview & Goal

This ticket delivers a **read-only** SEO metadata view inside the TestLogon
experience for the native Android port (`com.testlogon.android`). The web reference
implements this surface in `seoMetadata.ts`: for a given **public** resource identified by
a `type` (`profile` | `event` | `post` | `video` | `live`) and `id` (or by a URL `path`),
the app fetches the server-computed SEO metadata — the `<title>`/`og:title`, meta
description, canonical URL, site name, locale, Open Graph tags, Twitter card tags, the
single JSON-LD (`json_ld`) block, and the resolved share/preview image — and renders them
in a scrollable, copy-friendly inspector.

> CORRECTION (review AND-400): the web client comment in `seoMetadata.ts` states these
> endpoints are **public (no auth)** and return generic default metadata for private/locked
> content. This is therefore **not** a "creator-owned / owner-enforced" surface; there is no
> `403`-on-not-owner behavior. The earlier draft's "creator scope" framing and the
> `channel|video|playlist` asset types were not supported by the sources and have been
> corrected throughout. JSON-LD is a **single** `json_ld` object, not a list of blocks. There
> is no `robots` field in the response. See §16.

The goal is parity with the web SEO inspector: a user can open the SEO panel for a
public resource and **see exactly what crawlers and social cards will see**. This is a
diagnostic/preview surface. There is **no editing** in this ticket; mutating SEO fields
(overriding title/description, regenerating Open Graph images) is explicitly out of scope
and is owned by a future write ticket. The deliverable is a `feature-seo` Compose screen,
its `ViewModel`, the Retrofit endpoint, Moshi DTOs/domain models, and tests proving the
metadata renders for a valid asset and degrades cleanly when the field set is empty or the
dev backend is unreachable.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/seoMetadata.ts` (`getSeoMetadata`,
  `getSeoMetadataForPath`) and `frontend/src/hooks/useSeoMeta.ts` (the React-Query hook the
  pages consume), plus the shared `SeoMetadata` type in `frontend/src/api/types.ts`. The
  Android contract must mirror the web request/response shapes. VERIFIED against these files.
- **OpenAPI:** authoritative schema at `http://18.222.237.167:8000/openapi.json`. VERIFIED:
  the operation is `GET /seo/metadata` (operationId `get_seo_metadata_seo_metadata_get`),
  with **query** parameters `type`, `id`, `secondary_id`, `path` (all optional strings) and
  responses **`200`** (free-form JSON; no named response schema) and **`422` HTTPValidationError**.
  The OpenAPI `200` schema is `{}` (untyped), so the response field shape below is taken from
  the frontend `SeoMetadata` type, which is authoritative for the client contract.
- **Dependency AND-027 (AuthApi / session endpoints):** CORRECTION — the `/seo/metadata`
  endpoint is **public (no auth required)** and carries **no `security` block** in OpenAPI, so
  this feature does **not** depend on an authenticated session to function. The shared
  `core-network` OkHttp/Retrofit pipeline from AND-027 still applies globally (it attaches
  session cookies and the `X-CSRF-Token` header echoed from the `ui_csrf` cookie on every
  request — VERIFIED in `src/api/client.ts`), and reuse of that pipeline is why AND-027 is kept
  as a soft dependency, but cookies/CSRF/401-refresh are **not** semantically meaningful for
  this read. This ticket does **not** re-implement auth.
- **Module layering:** `app -> feature-seo -> core-network, core-model, core-ui,
  core-data, core-testing`. ViewModels expose `StateFlow<UiState>`; the network layer
  returns the typed `ApiResult<T>`; FastAPI `detail` is mapped per the project-wide convention
  (string | `[{msg}]` | `{code,...}`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit
  2.11 / OkHttp 4.12 / Moshi 1.15, Coil for the preview image. minSdk 24, compileSdk 35.

## 3. Functional Requirements

FR-1. Given a public resource identified by `resourceType` (`profile` | `event` | `post` |
`video` | `live`) and `id` (with optional `secondaryId` — used for events — or a URL
`path`), the screen fetches and displays its SEO metadata via the query-parameterized
`GET /seo/metadata`.

FR-2. The screen renders, when present, the following grouped sections (field names per the
`SeoMetadata` type in `src/api/types.ts`):
- **Primary:** `title`, `description`, `canonical_url`, `site_name`, `locale`. (CORRECTION:
  there is **no** `robots` field in the response shape; removed.)
- **Open Graph (`og`):** a flat map of `og:*` string entries —
  `og:title`, `og:description`, `og:type`, `og:site_name`, `og:locale`, `og:url`, `og:image`,
  plus any additional `og:*` keys (the map is open-ended). `og:image` is a **string URL**
  (rendered via Coil); there is no width/height/alt object in the contract.
- **Twitter card (`twitter`):** a flat map of `twitter:*` string entries —
  `twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`, plus any
  additional `twitter:*` keys. (CORRECTION: `twitter:site`/`twitter:creator` are not in the
  typed shape; they may appear via the open-ended map but are not guaranteed.)
- **Structured data:** the **single** `json_ld` object (nullable), shown as formatted,
  monospaced, scrollable text. (CORRECTION: it is one object, not a list of blocks.)
- A top-level resolved preview `image` (nullable string URL) is also rendered via Coil.

FR-3. Each scalar metadata row exposes a **copy-to-clipboard** affordance (long-press or a
trailing copy icon). Copying a value shows a transient confirmation (snackbar). The preview
image section shows the resolved image URL and lets the user copy it.

FR-4. The screen is **read-only**. No fields are editable; there are no save/regenerate
controls. A short caption states "Read-only preview" near the header.

FR-5. Empty handling: any field that is absent/blank is omitted from its section. A section
with zero populated fields is hidden. If the response carries `available == false`, or the
entire payload yields no renderable fields, an empty state ("No SEO metadata available for
this resource yet") is shown. (NOTE: the response includes an `available` boolean that
signals private/locked/unknown resources returning generic defaults; prefer it as the
primary empty signal, falling back to a derived "no renderable fields" check.)

FR-6. Loading and error states are first-class (see §7). A pull-to-refresh / retry control
re-issues the GET.

FR-7. Navigation: reachable from the resource's detail surface via route
`seo/{resourceType}/{id}` (with optional `secondaryId` arg for events). Back navigation
returns to the originating screen.

## 4. Technical Design

New Gradle module `:feature-seo` depending on `:core-network`, `:core-model`, `:core-ui`,
`:core-data`, `:core-testing`. Package root `com.testlogon.android.feature.seo`.

**Retrofit API** (`com.testlogon.android.feature.seo.data.SeoApi`):

CORRECTION: the path is `GET /seo/metadata` with **query** parameters, not a path-templated
`/ui/seo/{assetType}/{assetId}`.

```kotlin
interface SeoApi {
    @GET("seo/metadata")
    suspend fun getSeoMetadata(
        @Query("type") type: String,
        @Query("id") id: String,
        @Query("secondary_id") secondaryId: String? = null,
    ): Response<SeoMetadataDto>

    // Path-based variant (mirrors getSeoMetadataForPath in the web client):
    @GET("seo/metadata")
    suspend fun getSeoMetadataForPath(
        @Query("path") path: String,
    ): Response<SeoMetadataDto>
}
```

**Repository** wraps the call into `ApiResult<SeoMetadata>` using the shared
`apiCall { }` adapter from `core-network` (which performs `detail` mapping, the 401 refresh
retry, ~20s timeout, and — because this is an idempotent GET — bounded exponential backoff
for transient transport/5xx failures):

```kotlin
class SeoRepository @Inject constructor(
    private val api: SeoApi,
    private val mapper: SeoMetadataMapper,
) {
    suspend fun metadata(
        type: ResourceType,
        id: String,
        secondaryId: String? = null,
    ): ApiResult<SeoMetadata> =
        apiCall(retryIdempotent = true) { api.getSeoMetadata(type.wire, id, secondaryId) }
            .map(mapper::toDomain)
}
```

**ViewModel** (`SeoViewModel`) reads `assetType`/`assetId` from
`SavedStateHandle` (Navigation args), exposes immutable UI state, and supports refresh:

```kotlin
@HiltViewModel
class SeoViewModel @Inject constructor(
    private val repo: SeoRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val type = ResourceType.from(savedState["resourceType"]!!)
    private val id: String = savedState["id"]!!
    private val secondaryId: String? = savedState["secondaryId"]

    private val _state = MutableStateFlow<SeoUiState>(SeoUiState.Loading)
    val state: StateFlow<SeoUiState> = _state.asStateFlow()

    init { load() }

    fun load() { viewModelScope.launch {
        _state.value = SeoUiState.Loading
        _state.value = when (val r = repo.metadata(type, id, secondaryId)) {
            is ApiResult.Success ->
                if (r.data.isEmpty) SeoUiState.Empty
                else SeoUiState.Content(r.data)
            is ApiResult.Error -> SeoUiState.Error(r.message, r.isRetryable)
        }
    } }
}
```

**UI state:**

```kotlin
sealed interface SeoUiState {
    data object Loading : SeoUiState
    data object Empty : SeoUiState
    data class Content(val metadata: SeoMetadata) : SeoUiState
    data class Error(val message: String, val retryable: Boolean) : SeoUiState
}
```

**Composables** (in `com.testlogon.android.feature.seo.ui`):

```kotlin
@Composable fun SeoScreen(onBack: () -> Unit, vm: SeoViewModel = hiltViewModel())
@Composable private fun SeoContent(metadata: SeoMetadata, onCopy: (String) -> Unit)
@Composable private fun SeoSection(title: String, rows: List<SeoRow>, onCopy: (String) -> Unit)
@Composable private fun MetaRow(label: String, value: String, onCopy: (String) -> Unit)
@Composable private fun OgImageCard(image: SeoImage, onCopyUrl: (String) -> Unit)
@Composable private fun JsonLdBlock(json: String, onCopy: (String) -> Unit)
```

`SeoScreen` collects state with `collectAsStateWithLifecycle()`, hosts a `Scaffold` with a
`TopAppBar` ("SEO preview" + back), wraps the body in a pull-to-refresh container bound to
`vm.load()`, and renders `Loading`/`Empty`/`Error`/`Content` accordingly. Copy uses
`LocalClipboardManager`; confirmation via `SnackbarHostState`. The OG/preview image is loaded
with Coil `AsyncImage` with a placeholder and an error fallback (broken-image icon + URL).

**Navigation:** registered in the app nav graph:

```kotlin
composable(
    route = "seo/{resourceType}/{id}?secondaryId={secondaryId}",
    arguments = listOf(
        navArgument("resourceType") { type = NavType.StringType },
        navArgument("id") { type = NavType.StringType },
        navArgument("secondaryId") { type = NavType.StringType; nullable = true; defaultValue = null },
    ),
) { SeoScreen(onBack = navController::popBackStack) }
```

**Hilt:** `SeoApi` is provided in a `@Module @InstallIn(SingletonComponent::class)` via the
shared authenticated `Retrofit` from `core-network`; `SeoRepository`/`SeoMetadataMapper` are
constructor-injected.

## 5. API Contract

CORRECTION: this section previously described a path-templated, cookie-authenticated,
owner-enforced endpoint with a nested response. All of that was wrong; corrected below.

**Request:** `GET /seo/metadata?type={type}&id={id}[&secondary_id={secondaryId}]`, or the
path variant `GET /seo/metadata?path={path}`. `type ∈ {profile, event, post, video, live}`.
**Public endpoint — no auth required** (no `security` block in OpenAPI; the web client comment
explicitly states "public (no auth)"). No request body. The shared `core-network` interceptor
still attaches session cookies + `X-CSRF-Token` globally, but they are not required here.
Idempotent → eligible for bounded backoff retry on transient failures. Param length limits per
OpenAPI: `type` ≤ 32, `id`/`secondary_id` ≤ 256, `path` ≤ 512.

**Response 200 (`SeoMetadataDto`)** — OpenAPI declares the `200` body as untyped (`{}`); the
authoritative client shape is the `SeoMetadata` interface in `frontend/src/api/types.ts`:

```json
{
  "resource_type": "profile",
  "resource_id": "abc123",
  "available": true,
  "title": "My Profile — TestLogon",
  "description": "Latest content from My Profile.",
  "canonical_url": "https://testlogon.example/u/alice",
  "site_name": "TestLogon",
  "locale": "en_US",
  "og": {
    "og:title": "My Profile",
    "og:description": "Latest content from My Profile.",
    "og:type": "profile",
    "og:site_name": "TestLogon",
    "og:locale": "en_US",
    "og:url": "https://testlogon.example/u/alice",
    "og:image": "https://.../og.png"
  },
  "twitter": {
    "twitter:card": "summary_large_image",
    "twitter:title": "My Profile",
    "twitter:description": "Latest content from My Profile.",
    "twitter:image": "https://.../og.png"
  },
  "image": "https://.../og.png",
  "json_ld": { "@context": "https://schema.org", "@type": "ProfilePage" }
}
```

Notes on the corrected shape: `og` and `twitter` are **flat maps** of prefixed string keys
(`og:*` / `twitter:*`), not nested objects with bare keys; `og:image`/`image` are **string
URLs**, not objects with width/height/alt; `json_ld` is a **single nullable object**, not a
list; there is **no** `robots` field; `available` is a boolean flag for empty/locked handling.

**Moshi DTOs** (`@JsonClass(generateAdapter = true)`):

```kotlin
@JsonClass(generateAdapter = true)
data class SeoMetadataDto(
    @Json(name = "resource_type") val resourceType: String?,
    @Json(name = "resource_id") val resourceId: String?,
    val available: Boolean = false,
    val title: String?,
    val description: String?,
    @Json(name = "canonical_url") val canonicalUrl: String?,
    @Json(name = "site_name") val siteName: String?,
    val locale: String?,
    val og: Map<String, String?>?,          // flat og:* tag map
    val twitter: Map<String, String?>?,     // flat twitter:* tag map
    val image: String?,
    @Json(name = "json_ld") val jsonLd: Map<String, Any?>?,  // single JSON-LD object, nullable
)
```

`og`/`twitter` deserialize as `Map<String,String?>`; `json_ld` uses a Moshi
`Map<String,Any?>` adapter and is serialized back to a pretty-printed JSON string for display.

**Error responses:** the endpoint declares only **`200`** and **`422`** (`HTTPValidationError`)
in OpenAPI — there is **no documented `401`/`403`/`404`** for this public read. `422` →
FastAPI `detail` (array of `{loc, msg, type}` per the `ValidationError` schema) parsed via the
project union mapper (`string | [{msg}] | {code,...}`); `5xx`/timeouts → retryable transport
error. The shared `401`→refresh interceptor remains wired globally but is not expected to fire
for this endpoint. Private/locked resources return **`200` with `available: false`** and
generic defaults (per the web client comment) rather than an error.

**N/A note:** no mutation endpoints are consumed here; the write/regenerate SEO contract is
owned by a future SEO-write ticket (not in this milestone's backlog).

## 6. Data & State Management

**Domain model** (`core-model` or feature-local), the mapper target:

```kotlin
data class SeoMetadata(
    val resourceType: String?,
    val resourceId: String?,
    val available: Boolean,
    val title: String?,
    val description: String?,
    val canonicalUrl: String?,
    val siteName: String?,
    val locale: String?,
    val og: Map<String, String>,        // og:* tags, blanks dropped
    val twitter: Map<String, String>,   // twitter:* tags, blanks dropped
    val image: String?,
    val jsonLd: String?,                 // single pretty-printed JSON-LD block, or null
) {
    val isEmpty: Boolean
        get() = !available || (
            title.isNullOrBlank() && description.isNullOrBlank() &&
            canonicalUrl.isNullOrBlank() && siteName.isNullOrBlank() &&
            locale.isNullOrBlank() && og.isEmpty() && twitter.isEmpty() &&
            image.isNullOrBlank() && jsonLd.isNullOrBlank())
}

enum class ResourceType(val wire: String) {
    PROFILE("profile"), EVENT("event"), POST("post"), VIDEO("video"), LIVE("live");
    companion object {
        fun from(s: String) = entries.first { it.wire == s }
        val String.toResourceType get() = from(this)
    }
}
```

`SeoMetadataMapper.toDomain(dto)` normalizes blank strings to null, drops blank entries from
the `og`/`twitter` maps, and renders the `json_ld` object to an indented JSON string (null if
absent). The screen derives ordered `List<SeoSection>` from the domain object, dropping
null/blank rows and empty sections.

**State scope & persistence:** this is read-only, ephemeral diagnostic data. It is **not**
persisted to Room or DataStore — no caching ticket applies here; state lives only in the
`ViewModel` for the screen's lifetime. Process death restores `resourceType`/`id`/`secondaryId`
from `SavedStateHandle`; the view re-fetches on recreation (acceptable: cheap GET, always fresh).
The image is cached transparently by Coil's disk/memory cache (no app-managed cache).

## 7. Error Handling & Resilience

- **Loading:** centered progress + skeleton section placeholders.
- **Empty (`200` with `available == false`, or no renderable fields):** `SeoUiState.Empty` →
  "No SEO metadata available for this resource yet." (Private/locked resources return `200`
  with `available: false` and generic defaults — treat as empty, not as an error.)
- **Retryable errors (timeout, transport, 5xx):** `SeoUiState.Error(retryable = true)` with a
  message and a **Retry** button bound to `vm.load()`. The dev host
  (`http://18.222.237.167:8000`) is plaintext and unreliable, so the GET uses a ~20s timeout
  and bounded exponential backoff (e.g. 2 attempts after the first, capped) in the shared
  idempotent-GET path before surfacing the error.
- **Auth (401):** CORRECTION — not expected for this **public** endpoint (no `security` block,
  no documented `401`). The global OkHttp interceptor's `POST /ui/session/refresh`-once-retry
  remains wired but should not fire here; if a `401` ever occurs it falls through to the generic
  retryable transport-error path.
- **Validation (422):** the only documented non-200 (`HTTPValidationError`, an array of
  `{loc, msg, type}` items) — surfaces as a non-retryable error with the parsed `detail`
  message (e.g. when neither `type+id` nor `path` is supplied). CORRECTION: there are no
  documented `403`/`404` responses for this endpoint; the prior "not the asset owner / asset
  missing" handling has been removed.
- **Image load failure:** Coil error fallback (broken-image icon + the raw URL still shown
  and copyable) so the rest of the metadata remains usable.
- **Malformed JSON-LD:** if the `json_ld` object can't be re-serialized, it is skipped and
  a single inline note ("Structured data could not be displayed") is shown rather than
  crashing.

## 8. Security & Privacy

- CORRECTION: the `/seo/metadata` endpoint is **public** and requires no authentication. The
  shared `core-network` interceptor still attaches the cookie-based session from AND-027 and the
  `X-CSRF-Token` header echoed from the `ui_csrf` cookie on every outbound request, but these
  are not required for this read. This feature adds no new auth surface and stores no credentials.
- The endpoint is **not** creator/owner-scoped: there is no `403`/ownership enforcement. Private
  or locked resources are protected server-side by returning `200` with `available: false` and
  **generic default metadata** (never private content). The client renders that as the empty
  state; it does not attempt to access or display non-public data.
- Copy-to-clipboard places only already-displayed, non-secret metadata onto the clipboard.
  Metadata values are display-only; no value is rendered as live HTML/markup (canonical/OG
  URLs are shown as text, never auto-opened or injected into a WebView), preventing any
  injection from server-controlled strings.
- Dev backend is plaintext HTTP; no PII or secrets are introduced by this view. Production
  builds continue to require HTTPS per the app network-security config (owned elsewhere).

## 9. Accessibility & i18n

- All section headers, row labels, copy buttons, retry, and the back action have Compose
  `contentDescription`/`semantics`. Copy icons announce "Copy {label}".
- The OG/preview image's `alt` (from `og:image.alt`) is used as its `contentDescription`,
  falling back to "SEO preview image" when absent.
- JSON-LD blocks are exposed as scrollable text regions with a description ("Structured data,
  JSON-LD") rather than as raw unlabeled code.
- Layout reflows for font scaling up to 200% and supports landscape; long URLs wrap or
  horizontally scroll without truncating silently.
- All user-facing strings live in `res/values/strings.xml` (no hardcoded literals);
  server-provided metadata values are shown verbatim and are not translated. Touch targets
  for copy/retry are ≥48dp.

## 10. Telemetry & Logging

- Screen-view event `seo_view_opened` with params `asset_type`, `asset_id` (hashed/opaque),
  and the load outcome (`success` | `empty` | `error`).
- `seo_value_copied` with `field` (e.g. `canonical_url`, `og_image`) — no value contents
  logged.
- `seo_load_failed` with `http_status`/`error_kind` and `retried` (whether backoff fired);
  retry taps emit `seo_retry_tapped`.
- Logging uses the project logger; **no metadata values, URLs, or session/cookie data** are
  written to logs. On debug builds, OkHttp logging is body-level per the shared interceptor
  config; release strips it.

## 11. Testing Strategy

- **API/contract (MockWebServer, `core-testing`):** assert `SeoApi.getSeoMetadata` issues
  `GET /seo/metadata?type=..&id=..` (query params, with `secondary_id` when supplied); parse a
  full fixture into `SeoMetadataDto`; verify flat `og`/`twitter` map deserialization, single
  `json_ld` object handling, and `@Json` name mapping (`canonical_url`, `site_name`,
  `resource_type`, `resource_id`, `json_ld`).
- **Mapper unit tests:** blank→null normalization; blank-entry drop from og/twitter maps;
  `isEmpty` true for `available:false` and for an all-null payload, false when any field is set;
  `json_ld` object → pretty JSON string; section derivation drops empty sections.
- **ViewModel tests (Turbine + coroutine test rule):** `Loading→Content` on success;
  `Loading→Empty` on `available:false`/empty payload; `Loading→Error(retryable=true)` on
  timeout/5xx and `retryable=false` on `422`; `load()` re-fetch transitions back through `Loading`.
- **Compose UI tests (`createAndroidComposeRule`):** content state renders all sections and
  populated rows; empty/loading/error states render their respective controls; tapping copy
  invokes the clipboard and shows the snackbar (acceptance: **SEO metadata renders**); Retry
  calls `load()`.
- **Accessibility checks:** semantics assertions for labels and copy descriptions.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) for the authenticated, cookie- and
  CSRF-aware Retrofit/OkHttp pipeline and the 401-refresh interceptor. Cannot integration-test
  against the live creator endpoint without it.
- Transitively relies on the established `core-network` `ApiResult`/`apiCall` adapter,
  `core-ui` theme/components, and `core-testing` MockWebServer harness (foundational modules
  assumed present from M1).
- **Blocks:** none in the current backlog. A future SEO-write/regenerate ticket would build on
  this view but is not enumerated as dependent here.
- Sequencing within M8/E52: implementable independently once M1 networking + AND-027 land;
  no other M8 ticket is a hard prerequisite.

## 13. Risks & Open Questions

- **Endpoint path & field names — RESOLVED during review** (see §16): the route is
  `GET /seo/metadata` with query params `type`/`id`/`secondary_id`/`path`; `json_ld` is a single
  object (not a list); `og`/`twitter` are flat prefixed-key maps; there is no `robots` field.
  Remaining minor risk: the OpenAPI `200` body is untyped (`{}`), so the field shape relies on
  the frontend `SeoMetadata` type — additional/optional fields could appear at runtime; the
  generic map/nullable rendering absorbs this.
- **Per-resource-type response variance:** profile vs event vs post vs video vs live may return
  different OG `type`/`json_ld` schemas; the generic `Map`/string rendering absorbs this, but UI
  grouping labels should be verified per type. (Events also take a `secondary_id`.)
- **JSON-LD size:** large structured-data blocks could be long; mitigated by scrollable
  monospaced blocks, but consider collapse/expand if blocks exceed a threshold.
- **Dev-host flakiness** may make manual verification intermittent; rely on MockWebServer for
  deterministic CI and treat live 5xx as the retryable path.
- Open question: should copied values include a trailing newline or be raw? Default to raw.

## 14. Acceptance Criteria

1. Opening `seo/{resourceType}/{id}` for a public resource issues
   `GET /seo/metadata?type={resourceType}&id={id}` (with `secondary_id` for events) and, on
   `200`, **SEO metadata renders**: title, description, canonical URL, site name, locale, Open
   Graph (incl. image via Coil), Twitter card, and the JSON-LD block each appear when present.
2. Absent/blank fields are omitted and fully empty sections are hidden; a payload with
   `available:false` or no renderable fields shows the empty state.
3. The screen is read-only (no editable fields, no save controls) and labels itself as a
   preview.
4. Each scalar row and the OG/preview image URL can be copied to the clipboard with a confirmation.
5. Loading shows a progress/skeleton; transient/5xx/timeout failures show a retryable error
   with a working Retry; `422` shows a non-retryable validation message. (No `403`/`404`/`401`
   are expected for this public endpoint.)
6. MockWebServer test confirms correct path/verb and query params; ViewModel tests cover
   Loading→Content/Empty/Error; Compose test confirms metadata renders and copy works.

## 15. Definition of Done

- `:feature-seo` module created under package `com.testlogon.android.feature.seo` with
  `SeoApi`, `SeoRepository`, `SeoMetadataMapper`, DTOs, domain models, `SeoViewModel`,
  `SeoUiState`, and `SeoScreen` + child composables implemented per §4.
- Navigation route `seo/{resourceType}/{id}` (optional `secondaryId`) wired into the app graph;
  reachable from the resource detail surface.
- All acceptance criteria in §14 met and demonstrated by passing unit, ViewModel, contract
  (MockWebServer), and Compose UI tests in CI.
- No hardcoded user-facing strings; accessibility semantics present; telemetry events emitted;
  no metadata/URL/session data logged.
- Lint/detekt/ktlint clean; module builds on JDK 17 / AGP 8.7.3 / Gradle 8.9; merged to
  `android-port` with code review approved.

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and SOURCE pointer.

1. **Endpoint is `GET /seo/metadata`** (not `GET /ui/seo/{assetType}/{assetId}`).
   VERDICT: **Corrected.** SOURCE: OpenAPI `GET /seo/metadata`
   (operationId `get_seo_metadata_seo_metadata_get`); `src/api/endpoints/seoMetadata.ts:
   getSeoMetadata` (`api.get("/seo/metadata", ...)`).
2. **Parameters are query params `type`, `id`, `secondary_id`, `path`** (not path segments).
   VERDICT: **Corrected.** SOURCE: OpenAPI `GET /seo/metadata` params (`type` ≤32, `id` ≤256,
   `secondary_id` ≤256, `path` ≤512, all optional); `src/api/endpoints/seoMetadata.ts`
   (`params: { type, id, secondary_id }` and `getSeoMetadataForPath` → `params: { path }`).
3. **Resource types are `profile | event | post | video | live`** (not `channel | video |
   playlist`). VERDICT: **Corrected.** SOURCE: `src/api/endpoints/seoMetadata.ts:
   SeoResourceType`.
4. **Endpoint is public — no authentication / no `security` block.**
   VERDICT: **Corrected** (spec asserted creator-scoped, cookie-authenticated).
   SOURCE: OpenAPI `GET /seo/metadata` has no `security` member; `src/api/endpoints/
   seoMetadata.ts` header comment "These endpoints are public (no auth)...".
5. **No `403`/`404`/`401` responses; documented responses are `200` and `422`
   (`HTTPValidationError`).** VERDICT: **Corrected** (spec described 401/403/404 handling).
   SOURCE: OpenAPI `GET /seo/metadata` responses; index line
   `resp=200:;422:HTTPValidationError`.
6. **Private/locked resources return `200` with generic defaults (signaled by `available`),
   not an error.** VERDICT: **Verified.** SOURCE: `src/api/endpoints/seoMetadata.ts` comment
   ("private / locked content yields generic default metadata"); `available` field in
   `src/api/types.ts: SeoMetadata`.
7. **Response shape is flat: `resource_type`, `resource_id`, `available`, `title`,
   `description`, `canonical_url`, `site_name`, `locale`, `og`, `twitter`, `image`,
   `json_ld`.** VERDICT: **Corrected** (spec used nested `open_graph`/`twitter`/
   `structured_data`). SOURCE: `src/api/types.ts: SeoMetadata`. NOTE: OpenAPI `200` schema is
   untyped (`{}`), so the frontend type is the authoritative client contract here.
8. **`og` and `twitter` are flat maps of prefixed string keys (`og:*` / `twitter:*`).**
   VERDICT: **Corrected** (spec used nested objects with bare keys). SOURCE: `src/api/types.ts:
   SeoOpenGraphTags` (keys `og:title`, `og:image`, …, plus index signature) and
   `SeoTwitterTags` (keys `twitter:card`, `twitter:image`, …, plus index signature).
9. **`og:image` / top-level `image` are string URLs (no width/height/alt object).**
   VERDICT: **Corrected.** SOURCE: `src/api/types.ts: SeoOpenGraphTags["og:image"]: string`,
   `SeoMetadata.image: string | null`.
10. **`json_ld` is a single nullable object, not a list of `structured_data` blocks.**
    VERDICT: **Corrected.** SOURCE: `src/api/types.ts: SeoMetadata.json_ld:
    Record<string, unknown> | null`.
11. **There is no `robots` field in the response.** VERDICT: **Corrected** (spec listed
    `robots`). SOURCE: `src/api/types.ts: SeoMetadata` (no `robots` member).
12. **CSRF is sent as `X-CSRF-Token` echoed from the `ui_csrf` cookie; session refresh is
    `POST /ui/session/refresh`; requests use `credentials: include`.** VERDICT: **Verified**
    as *global* client transport behavior (but not required by this public endpoint).
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `fetch(withApiBase("/ui/session/refresh"), { credentials: "include" })`).
13. **Web client consumes the endpoint via a React-Query hook `useSeoMeta` /
    `useSeoMetaForPath`.** VERDICT: **Verified.** SOURCE: `src/hooks/useSeoMeta.ts`.
14. **`422` body is `HTTPValidationError` = `{ detail: ValidationError[] }`, each item
    `{ loc, msg, type }`.** VERDICT: **Verified.** SOURCE: OpenAPI
    `components.schemas.HTTPValidationError` and `components.schemas.ValidationError`.
15. **Android framework choices** (Compose + Material 3, Hilt/KSP, Retrofit 2.11/OkHttp 4.12/
    Moshi 1.15, Coil, `collectAsStateWithLifecycle`, `LocalClipboardManager`,
    `SavedStateHandle`). VERDICT: **Unverified-assumption** (project-stack conventions; not
    derivable from backend/frontend sources). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose and
    https://square.github.io/retrofit/ (stack choices owned by the M1 networking/UI tickets).

### Corrections made

- §1, §3, §4, §5, §6, §7, §8, §11, §13, §14, §15: endpoint changed from path-templated
  `GET /ui/seo/{assetType}/{assetId}` to query-parameterized `GET /seo/metadata`
  (`type`/`id`/`secondary_id`/`path`).
- Asset taxonomy corrected from `channel|video|playlist` to resource types
  `profile|event|post|video|live`; `AssetType` enum renamed to `ResourceType`; nav route and
  SavedStateHandle keys updated (`resourceType`/`id`/`secondaryId`).
- "Creator-scoped, cookie-authenticated, owner-enforced (`403`)" reframed as a **public,
  no-auth** endpoint; removed `401`/`403`/`404` handling; added `available:false` empty path
  and `422` validation error handling.
- Response DTO/domain reshaped: flat fields, flat `og`/`twitter` string maps, string image
  URLs, single `json_ld` object (was a `structured_data` list), removed `robots`, added
  `resource_type`/`resource_id`/`site_name`/`locale`/`available`.
- §13 endpoint-shape open question marked RESOLVED.

### Open assumptions

- **Untyped `200` body:** OpenAPI declares the success body as `{}` (no schema), so the exact
  runtime field set is taken from the frontend `SeoMetadata` type. Extra/optional fields could
  appear; mitigated by tolerant Moshi maps and nullable fields. (Why unverifiable: backend does
  not publish a named response schema.)
- **Android stack/library versions and Compose APIs:** assumed from project conventions / M1
  foundation, not verifiable against the provided sources (framework ref only).
- **Navigation entry point** ("reachable from the resource detail surface") and **telemetry
  event names** are product/app conventions, not present in the backend/frontend sources.
- **`secondary_id` semantics** ("for events") are taken from the OpenAPI endpoint description
  and the web client; the precise per-type usage beyond events is not enumerated in sources.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD
`test35` (x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). Most cases here are non-hardware and run on JVM or EMU; the physical device is only
required for the real-network/offline and accessibility-on-real-hardware cases noted below.

- **TC-AND-400-01 — Happy path: metadata renders (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues `200` with a
  full `SeoMetadata` fixture (title, description, canonical_url, site_name, locale, populated
  `og`/`twitter` maps, image URL, `json_ld` object). Steps: call
  `SeoApi.getSeoMetadata("profile","abc123")`; map to domain; drive `SeoViewModel`.
  Expected: request is `GET /seo/metadata?type=profile&id=abc123`; DTO parses; state →
  `Content` with all sections populated. Traces: AC-1, AC-6.

- **TC-AND-400-02 — Query param + `@Json` mapping correctness (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: fixture with snake_case keys
  (`canonical_url`, `site_name`, `resource_type`, `resource_id`, `json_ld`) and `secondary_id`
  supplied. Steps: call `getSeoMetadata("event","cal1","evt9")`; inspect `RecordedRequest`.
  Expected: path `= /seo/metadata`, query `type=event&id=cal1&secondary_id=evt9`; fields map to
  camelCase domain props; `og`/`twitter` deserialize as flat maps; single `json_ld` object
  parsed. Traces: AC-1, AC-6.

- **TC-AND-400-03 — Path-variant request (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer `200`. Steps: call
  `SeoApi.getSeoMetadataForPath("/u/alice")`. Expected: request is
  `GET /seo/metadata?path=%2Fu%2Falice`; no `type`/`id` query params present. Traces: AC-1.

- **TC-AND-400-04 — Empty state via `available:false` (unit/ViewModel).**
  Type: unit + ViewModel (Turbine). Target: JVM. Preconditions: `200` fixture with
  `available:false` and otherwise-default fields. Steps: `load()`. Expected: emits
  `Loading → Empty`; UI shows "No SEO metadata available for this resource yet." Traces: AC-2.

- **TC-AND-400-05 — Empty state via no renderable fields (unit/mapper).**
  Type: unit. Target: JVM. Preconditions: payload with `available:true` but all scalars
  blank/null and empty `og`/`twitter`/`json_ld`. Steps: map → `SeoMetadata.isEmpty`. Expected:
  `isEmpty == true`; blank entries dropped from `og`/`twitter`; ViewModel → `Empty`.
  Traces: AC-2.

- **TC-AND-400-06 — Mapper: blank→null, map cleanup, JSON-LD pretty-print (unit).**
  Type: unit. Target: JVM. Preconditions: DTO with blank `title`, blank `og:locale`, populated
  `json_ld`. Steps: `SeoMetadataMapper.toDomain`. Expected: blank title→null; blank map entries
  removed; `json_ld` object rendered to indented JSON string; section derivation drops empty
  sections. Traces: AC-1, AC-2.

- **TC-AND-400-07 — `422` validation error is non-retryable (contract + ViewModel).**
  Type: contract/MockWebServer + ViewModel. Target: JVM. Preconditions: MockWebServer enqueues
  `422` with `{ "detail": [ { "loc": ["query","type"], "msg": "field required", "type":
  "missing" } ] }`. Steps: `load()`. Expected: union mapper extracts `msg`; state →
  `Error(retryable=false)`; Retry hidden. Traces: AC-5.

- **TC-AND-400-08 — Retryable transient/5xx with bounded backoff (contract + ViewModel).**
  Type: contract/MockWebServer + ViewModel. Target: JVM. Preconditions: MockWebServer returns
  `503` then `200` (idempotent-GET backoff path). Steps: `load()`. Expected: shared backoff
  retries the GET; final state → `Content` (or `Error(retryable=true)` with working Retry if all
  attempts fail). Traces: AC-5.

- **TC-AND-400-09 — Flaky-dev-host / offline path (integration).**
  Type: integration (real network). Target: **DEVICE (required)** — exercises real
  arm64/API-34 networking against the plaintext dev host `http://18.222.237.167:8000`, including
  airplane-mode toggling for the offline branch. Preconditions: app installed on the A15;
  network togglable. Steps: open SEO screen online (expect render); enable airplane mode and
  trigger Retry. Expected: online → `Content`; offline → `Error(retryable=true)` with a working
  Retry that succeeds once connectivity returns; no crash. Traces: AC-5. (Run on the physical
  device because emulator NAT masks real radio/connectivity transitions.)

- **TC-AND-400-10 — Content renders all sections (Compose-UI).**
  Type: Compose-UI. Target: EMU. Preconditions: ViewModel seeded with a full `Content` state
  (fake repo). Steps: launch `SeoScreen` via `createAndroidComposeRule`. Expected: Primary, Open
  Graph (incl. Coil image slot), Twitter, and Structured-data sections render with their
  populated rows; "Read-only preview" caption present; no edit/save controls. Traces: AC-1,
  AC-3.

- **TC-AND-400-11 — Copy-to-clipboard with confirmation (Compose-UI).**
  Type: Compose-UI. Target: EMU. Preconditions: `Content` state with a `canonical_url` row and
  an OG image URL. Steps: tap the copy affordance on a scalar row and on the image URL.
  Expected: `LocalClipboardManager` receives the exact value (raw, no trailing newline); a
  snackbar confirmation appears. Traces: AC-4.

- **TC-AND-400-12 — Loading and Retry controls (Compose-UI).**
  Type: Compose-UI. Target: EMU. Preconditions: ViewModel in `Loading`, then
  `Error(retryable=true)`. Steps: assert progress/skeleton in Loading; in Error, tap Retry.
  Expected: skeleton shown while Loading; Retry button visible only when `retryable`, and tapping
  invokes `vm.load()`. Traces: AC-5, AC-6.

- **TC-AND-400-13 — Image load failure fallback (Compose-UI).**
  Type: Compose-UI. Target: EMU. Preconditions: `Content` with an unreachable `og:image` URL
  (Coil error). Steps: render screen. Expected: broken-image fallback shown, the raw URL remains
  visible and copyable, and the rest of the metadata still renders. Traces: AC-1, AC-4.

- **TC-AND-400-14 — Accessibility semantics & font scaling (instrumented/e2e).**
  Type: instrumented/e2e + accessibility checks. Target: **DEVICE (preferred)** with TalkBack and
  200% font scale enabled (real assistive-tech behavior); EMU acceptable for semantics-only
  assertions. Preconditions: `Content` state. Steps: enable TalkBack + max font scale; traverse
  the screen. Expected: section headers, row labels, copy buttons ("Copy {label}"), Retry, and
  back action expose `contentDescription`/semantics; OG image uses `alt` (fallback "SEO preview
  image"); JSON-LD region labeled "Structured data, JSON-LD"; layout reflows at 200% without
  silent truncation; touch targets ≥48dp. Traces: AC-1, AC-3, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (issues `GET /seo/metadata`, renders metadata) | TC-01, TC-02, TC-03, TC-06, TC-10, TC-13, TC-14 |
| AC-2 (empty fields/sections hidden; empty state) | TC-04, TC-05, TC-06 |
| AC-3 (read-only, labeled preview) | TC-10, TC-14 |
| AC-4 (copy scalar rows + image URL w/ confirmation) | TC-11, TC-13, TC-14 |
| AC-5 (loading; retryable vs non-retryable errors; Retry; no 401/403/404) | TC-07, TC-08, TC-09, TC-12 |
| AC-6 (MockWebServer path/verb/params; ViewModel states; Compose render+copy) | TC-01, TC-02, TC-08, TC-12 |
