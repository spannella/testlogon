---
id: AND-400
title: SEO metadata (read)
milestone: M8
epic: E52
priority: P2
size: S
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-400 — SEO metadata (read)

## 1. Overview & Goal

This ticket delivers a **read-only** SEO metadata view inside the TestLogon creator
experience for the native Android port (`com.testlogon.android`). The web reference
implements this surface in `seoMetadata.ts` (creator scope): for a given creator-owned
entity (channel, video, or playlist) the app fetches the server-computed SEO metadata —
the `<title>`/`og:title`, meta description, canonical URL, Open Graph tags, Twitter card
tags, structured-data (JSON-LD) blocks, robots directives, and the resolved share/preview
image — and renders them in a scrollable, copy-friendly inspector.

The goal is parity with the web SEO inspector: a creator can open the SEO panel for an
asset they own and **see exactly what crawlers and social cards will see**. This is a
diagnostic/preview surface. There is **no editing** in this ticket; mutating SEO fields
(overriding title/description, regenerating Open Graph images) is explicitly out of scope
and is owned by a future write ticket. The deliverable is a `feature-seo` Compose screen,
its `ViewModel`, the Retrofit endpoint, Moshi DTOs/domain models, and tests proving the
metadata renders for a valid asset and degrades cleanly when the field set is empty or the
dev backend is unreachable.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/seoMetadata.ts` (creator view) plus the
  shared types in `frontend/src/api/types.ts`. The Android contract must mirror the web
  request/response shapes.
- **OpenAPI:** authoritative schema at `http://18.222.237.167:8000/openapi.json`. The
  SEO read path and its response model are derived from there; field names below follow the
  web reference and must be reconciled against OpenAPI during implementation.
- **Dependency AND-027 (AuthApi / session endpoints):** SEO metadata for creator-owned
  assets requires an authenticated, cookie-backed session. AND-027 provides the cookie jar,
  CSRF header injection, and the 401→`POST /ui/session/refresh`→retry interceptor that this
  feature reuses. This ticket does **not** re-implement auth; it consumes the established
  OkHttp/Retrofit pipeline from `core-network`.
- **Module layering:** `app -> feature-seo -> core-network, core-model, core-ui,
  core-data, core-testing`. ViewModels expose `StateFlow<UiState>`; the network layer
  returns the typed `ApiResult<T>`; FastAPI `detail` is mapped per the project-wide convention
  (string | `[{msg}]` | `{code,...}`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit
  2.11 / OkHttp 4.12 / Moshi 1.15, Coil for the preview image. minSdk 24, compileSdk 35.

## 3. Functional Requirements

FR-1. Given a creator-owned asset identified by `assetType` (`channel` | `video` |
`playlist`) and `assetId`, the screen fetches and displays its SEO metadata.

FR-2. The screen renders, when present, the following grouped sections:
- **Primary:** page title, meta description, canonical URL, robots directive.
- **Open Graph:** `og:title`, `og:description`, `og:type`, `og:url`, `og:site_name`,
  `og:image` (rendered via Coil, with width/height/alt shown as caption).
- **Twitter card:** `twitter:card`, `twitter:title`, `twitter:description`,
  `twitter:image`, `twitter:site`/`twitter:creator`.
- **Structured data:** any JSON-LD blocks, shown as formatted, monospaced, scrollable text.

FR-3. Each scalar metadata row exposes a **copy-to-clipboard** affordance (long-press or a
trailing copy icon). Copying a value shows a transient confirmation (snackbar). The preview
image section shows the resolved image URL and lets the user copy it.

FR-4. The screen is **read-only**. No fields are editable; there are no save/regenerate
controls. A short caption states "Read-only preview" near the header.

FR-5. Empty handling: any field that is absent/blank is omitted from its section. A section
with zero populated fields is hidden. If the entire payload yields no renderable fields, an
empty state ("No SEO metadata available for this asset yet") is shown.

FR-6. Loading and error states are first-class (see §7). A pull-to-refresh / retry control
re-issues the GET.

FR-7. Navigation: reachable from the asset's creator detail surface via route
`seo/{assetType}/{assetId}`. Back navigation returns to the originating screen.

## 4. Technical Design

New Gradle module `:feature-seo` depending on `:core-network`, `:core-model`, `:core-ui`,
`:core-data`, `:core-testing`. Package root `com.testlogon.android.feature.seo`.

**Retrofit API** (`com.testlogon.android.feature.seo.data.SeoApi`):

```kotlin
interface SeoApi {
    @GET("ui/seo/{assetType}/{assetId}")
    suspend fun getSeoMetadata(
        @Path("assetType") assetType: String,
        @Path("assetId") assetId: String,
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
    suspend fun metadata(assetType: AssetType, assetId: String): ApiResult<SeoMetadata> =
        apiCall(retryIdempotent = true) { api.getSeoMetadata(assetType.wire, assetId) }
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
    private val assetType = AssetType.from(savedState["assetType"]!!)
    private val assetId: String = savedState["assetId"]!!

    private val _state = MutableStateFlow<SeoUiState>(SeoUiState.Loading)
    val state: StateFlow<SeoUiState> = _state.asStateFlow()

    init { load() }

    fun load() { viewModelScope.launch {
        _state.value = SeoUiState.Loading
        _state.value = when (val r = repo.metadata(assetType, assetId)) {
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
    route = "seo/{assetType}/{assetId}",
    arguments = listOf(
        navArgument("assetType") { type = NavType.StringType },
        navArgument("assetId") { type = NavType.StringType },
    ),
) { SeoScreen(onBack = navController::popBackStack) }
```

**Hilt:** `SeoApi` is provided in a `@Module @InstallIn(SingletonComponent::class)` via the
shared authenticated `Retrofit` from `core-network`; `SeoRepository`/`SeoMetadataMapper` are
constructor-injected.

## 5. API Contract

**Request:** `GET /ui/seo/{assetType}/{assetId}` — `assetType ∈ {channel, video, playlist}`.
Cookie-authenticated; the `core-network` interceptors attach session cookies and the
`X-CSRF-Token` header (echoed from `ui_csrf`). No request body. Idempotent → eligible for
bounded backoff retry on transient failures.

**Response 200 (`SeoMetadataDto`)** — field set mirrors `frontend/src/api/types.ts`; reconcile
exact names against `/openapi.json` during implementation:

```json
{
  "title": "My Channel — TestLogon",
  "description": "Latest videos from My Channel.",
  "canonical_url": "https://testlogon.example/c/abc123",
  "robots": "index,follow",
  "open_graph": {
    "title": "My Channel",
    "description": "Latest videos from My Channel.",
    "type": "profile",
    "url": "https://testlogon.example/c/abc123",
    "site_name": "TestLogon",
    "image": { "url": "https://.../og.png", "width": 1200, "height": 630, "alt": "My Channel" }
  },
  "twitter": {
    "card": "summary_large_image",
    "title": "My Channel",
    "description": "Latest videos from My Channel.",
    "image": "https://.../og.png",
    "site": "@testlogon",
    "creator": "@creator"
  },
  "structured_data": [ { "@context": "https://schema.org", "@type": "ProfilePage" } ]
}
```

**Moshi DTOs** (`@JsonClass(generateAdapter = true)`):

```kotlin
@JsonClass(generateAdapter = true)
data class SeoMetadataDto(
    val title: String?,
    val description: String?,
    @Json(name = "canonical_url") val canonicalUrl: String?,
    val robots: String?,
    @Json(name = "open_graph") val openGraph: OpenGraphDto?,
    val twitter: TwitterCardDto?,
    @Json(name = "structured_data") val structuredData: List<Map<String, Any?>>?,
)
```

`OpenGraphDto`, `TwitterCardDto`, and `OgImageDto` follow the nested shapes above.
`structured_data` entries are serialized back to pretty-printed JSON strings for display via a
Moshi `Map<String,Any?>` adapter.

**Error responses:** `401` → handled by the shared refresh-once-then-retry interceptor;
`403` (not the asset owner) → mapped to a non-retryable "You don't have access to this asset"
message; `404` (asset missing) → "Asset not found"; `422` → FastAPI `detail` parsed via the
union mapper (`string | [{msg}] | {code,...}`); `5xx`/timeouts → retryable transport error.

**N/A note:** no mutation endpoints are consumed here; the write/regenerate SEO contract is
owned by a future SEO-write ticket (not in this milestone's backlog).

## 6. Data & State Management

**Domain model** (`core-model` or feature-local), the mapper target:

```kotlin
data class SeoMetadata(
    val title: String?,
    val description: String?,
    val canonicalUrl: String?,
    val robots: String?,
    val openGraph: OpenGraph?,
    val twitter: TwitterCard?,
    val structuredData: List<String>,   // pretty-printed JSON-LD blocks
) {
    val isEmpty: Boolean
        get() = title.isNullOrBlank() && description.isNullOrBlank() &&
            canonicalUrl.isNullOrBlank() && robots.isNullOrBlank() &&
            openGraph == null && twitter == null && structuredData.isEmpty()
}

enum class AssetType(val wire: String) {
    CHANNEL("channel"), VIDEO("video"), PLAYLIST("playlist");
    companion object {
        fun from(s: String) = entries.first { it.wire == s }
        val String.toAssetType get() = from(this)
    }
}
```

`SeoMetadataMapper.toDomain(dto)` normalizes blank strings to null and renders each
`structured_data` map to an indented JSON string. The screen derives ordered
`List<SeoSection>` from the domain object, dropping null/blank rows and empty sections.

**State scope & persistence:** this is read-only, ephemeral diagnostic data. It is **not**
persisted to Room or DataStore — no caching ticket applies here; state lives only in the
`ViewModel` for the screen's lifetime. Process death restores `assetType`/`assetId` from
`SavedStateHandle`; the view re-fetches on recreation (acceptable: cheap GET, always fresh).
The image is cached transparently by Coil's disk/memory cache (no app-managed cache).

## 7. Error Handling & Resilience

- **Loading:** centered progress + skeleton section placeholders.
- **Empty (`200` with no renderable fields):** `SeoUiState.Empty` → "No SEO metadata
  available for this asset yet."
- **Retryable errors (timeout, transport, 5xx):** `SeoUiState.Error(retryable = true)` with a
  message and a **Retry** button bound to `vm.load()`. The dev host
  (`http://18.222.237.167:8000`) is plaintext and unreliable, so the GET uses a ~20s timeout
  and bounded exponential backoff (e.g. 2 attempts after the first, capped) in the shared
  idempotent-GET path before surfacing the error.
- **Auth (401):** transparent — the OkHttp interceptor calls `POST /ui/session/refresh` once
  and retries; only a persistent failure surfaces as a non-retryable "Session expired" state.
- **Authorization (403) / not found (404):** non-retryable, specific copy; Retry hidden.
- **Image load failure:** Coil error fallback (broken-image icon + the raw URL still shown
  and copyable) so the rest of the metadata remains usable.
- **Malformed JSON-LD:** if a structured-data entry can't be re-serialized, it is skipped and
  a single inline note ("1 structured-data block could not be displayed") is shown rather
  than crashing.

## 8. Security & Privacy

- All requests ride the existing **cookie-based session** from AND-027 (persistent cookie
  jar) with the `X-CSRF-Token` header echoed from the `ui_csrf` cookie. This feature adds no
  new auth surface and stores no credentials.
- The endpoint is creator-scoped; the backend enforces ownership and returns `403` for
  assets the caller doesn't own. The client never assumes access — it renders the `403` state.
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
  `GET /ui/seo/{assetType}/{assetId}` with the CSRF header present; parse a full fixture into
  `SeoMetadataDto`; verify nested OG/Twitter/structured-data deserialization and
  `@Json` name mapping.
- **Mapper unit tests:** blank→null normalization; `isEmpty` true for an all-null payload and
  false when any field is set; JSON-LD map → pretty JSON string; section derivation drops
  empty sections.
- **ViewModel tests (Turbine + coroutine test rule):** `Loading→Content` on success;
  `Loading→Empty` on empty payload; `Loading→Error(retryable=true)` on timeout/5xx and
  `retryable=false` on 403/404; `load()` re-fetch transitions back through `Loading`.
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

- **Exact endpoint path & field names** are inferred from `seoMetadata.ts` and the web types;
  must be confirmed against `/openapi.json` (e.g. whether the route is `/ui/seo/...` vs a
  per-asset sub-resource like `/ui/{assetType}/{assetId}/seo`, and whether `structured_data`
  is a list vs a single object). Resolve before coding the `SeoApi` path.
- **Per-asset-type response variance:** channel vs video vs playlist may return different OG
  `type`/structured-data schemas; the generic `Map`/string rendering absorbs this, but UI
  grouping labels should be verified per type.
- **JSON-LD size:** large structured-data blocks could be long; mitigated by scrollable
  monospaced blocks, but consider collapse/expand if blocks exceed a threshold.
- **Dev-host flakiness** may make manual verification intermittent; rely on MockWebServer for
  deterministic CI and treat live 5xx as the retryable path.
- Open question: should copied values include a trailing newline or be raw? Default to raw.

## 14. Acceptance Criteria

1. Opening `seo/{assetType}/{assetId}` for a creator-owned asset issues
   `GET /ui/seo/{assetType}/{assetId}` and, on `200`, **SEO metadata renders**: title,
   description, canonical URL, robots, Open Graph (incl. image via Coil), Twitter card, and
   any JSON-LD blocks each appear when present.
2. Absent/blank fields are omitted and fully empty sections are hidden; a payload with no
   renderable fields shows the empty state.
3. The screen is read-only (no editable fields, no save controls) and labels itself as a
   preview.
4. Each scalar row and the OG image URL can be copied to the clipboard with a confirmation.
5. Loading shows a progress/skeleton; transient/5xx/timeout failures show a retryable error
   with a working Retry; `403`/`404` show non-retryable messages; `401` is transparently
   refreshed-and-retried.
6. MockWebServer test confirms correct path/verb and CSRF header; ViewModel tests cover
   Loading→Content/Empty/Error; Compose test confirms metadata renders and copy works.

## 15. Definition of Done

- `:feature-seo` module created under package `com.testlogon.android.feature.seo` with
  `SeoApi`, `SeoRepository`, `SeoMetadataMapper`, DTOs, domain models, `SeoViewModel`,
  `SeoUiState`, and `SeoScreen` + child composables implemented per §4.
- Navigation route `seo/{assetType}/{assetId}` wired into the app graph; reachable from the
  creator asset surface.
- All acceptance criteria in §14 met and demonstrated by passing unit, ViewModel, contract
  (MockWebServer), and Compose UI tests in CI.
- No hardcoded user-facing strings; accessibility semantics present; telemetry events emitted;
  no metadata/URL/session data logged.
- Lint/detekt/ktlint clean; module builds on JDK 17 / AGP 8.7.3 / Gradle 8.9; merged to
  `android-port` with code review approved.
