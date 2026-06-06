---
id: AND-392
title: "Public download (`/share/:linkId`)"
milestone: M8
epic: E51
priority: P2
size: M
status: draft
depends_on: [AND-335]
blocks: []
---

# AND-392 — Public download

## 1. Overview & Goal

This ticket delivers the **public download screen** for TestLogon Android: a deep-linkable, unauthenticated landing page that resolves a shared file by its opaque `linkId` and lets the visitor download (or stream-preview where appropriate) the shared file content. It is the recipient-facing counterpart to the share-link **creation/revocation** flow delivered by AND-335 (`fileShareLinks.ts`). Where AND-335 owns the API client (`FileShareApi`/`fileShareLinks.ts`), the create/revoke screens, and the public-page contract definition, **AND-392 owns the native public-download screen, its deep-link wiring, and the download/preview/error UX** that the recipient experiences when they tap a `https://<host>/share/<linkId>` URL.

The canonical behaviour is set by the web reference route `/share/:linkId`: it fetches share metadata by `linkId`, renders file name / size / type, and exposes a download action that resolves to the actual file bytes. The native screen must reproduce this against the unreliable plaintext dev backend, handling the full set of terminal and transient states: resolved (downloadable), **not-found** (no such link), **revoked/expired** (link existed but is no longer valid), **password-required** (gated links), loading, offline, and generic error.

The screen is reachable two ways: (a) an Android **App Link** mapping `https://<verified-host>/share/<linkId>` onto the native screen, and (b) in-app navigation from the share-sheet/created-link confirmation in AND-335. Download itself is delegated to the platform `DownloadManager` so that large files, notification progress, and resumability are handled by the OS rather than re-implemented in-process.

Out of scope: link **creation**, **revocation**, listing a user's own share links, and any owner-side management UI — all owned by AND-335. This ticket renders the **public recipient projection** only and never requires the visitor to be authenticated.

## 2. Context & References

- **Module**: lives in `feature-files` under `android/feature/feature-files/`, namespace `com.testlogon.android.feature.files`, subpackage `...feature.files.share.publicdownload`. Layering: `app -> feature-files -> core-network, core-model, core-ui, core-data, core-testing`.
- **Upstream dep — AND-335 (Share links + public download)**: provides `FileShareApi` (the `fileShareLinks.ts` binding), the share DTOs/domain models, and the repository entry point used here. AND-335 also defines the public-page **contract**; this ticket implements the native rendering of that contract. If AND-335's repository does not yet expose a public-resolve method, this ticket adds `resolvePublicShare(linkId)` to the shared `FileShareRepository` interface (see §5/§6) and AND-335 implements it.
- **Transitive deps**: AND-331 (Files API + DTOs) supplies the base file DTO shapes; AND-022 (Navigation host) supplies the `NavHost` + typed-route/deep-link mechanism; AND-015 (error mapper), AND-016 (idempotent-GET retry), AND-018 (`ApiResult`), AND-011 (cookie jar), AND-012 (CSRF interceptor) supply network plumbing.
- **Web reference**: `frontend/src/api/endpoints/fileShareLinks.ts` (endpoint shapes), `frontend/src/api/types.ts` (shared `PublicShare`/share-link types), and the web router route `/share/:linkId`. OpenAPI: `GET http://18.222.237.167:8000/openapi.json` — inspect paths under `/ui/files/share/*` for the authoritative public-resolve and download paths.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Coil (image preview), Media3/ExoPlayer 1.4 (audio/video preview, optional). minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend reality**: dev host `18.222.237.167:8000` is **plaintext HTTP** and unreliable — design for ~20s OkHttp timeouts, bounded backoff retry on idempotent GETs only, and offline/stale states. App Links require HTTPS verification, so the App Link host is the production HTTPS host, not the dev IP (see §8).

## 3. Functional Requirements

FR-1 **Route**: registered as a typed route `PublicDownloadRoute(linkId: String)` rendering at in-app path `share/{linkId}`.

FR-2 **App Link**: tapping `https://<verified-host>/share/<linkId>` opens the app directly on this screen with `linkId` extracted from the path. Custom-scheme fallback `testlogon://share/<linkId>` is accepted for share flows on all builds. App Link `autoVerify` is enabled on `release` only (§8).

FR-3 **Resolve**: on entry, fetch share metadata by `linkId` via `GET /ui/files/share/{linkId}` and show a loading state until resolved.

FR-4 **Resolved state**: render file display name, human-readable size, MIME/type icon, optional owner display name, optional expiry/“downloads remaining” hint, and a primary **Download** action. For previewable images, show an inline Coil thumbnail; previewing is best-effort and never blocks download.

FR-5 **Download action**: tapping **Download** enqueues the file via Android `DownloadManager` to the public `Downloads/` collection using the backend download URL (`GET /ui/files/share/{linkId}/download`), with the cookie jar + CSRF header attached when present. While enqueued, show a non-blocking “Download started” confirmation; rely on the system notification for progress/completion.

FR-6 **Password-gated links**: if resolve returns `requires_password == true` (or HTTP 401/403 classified as password-required), render a password entry field; on submit, re-resolve/download with the supplied password (passed per §5). Wrong password shows an inline field error and allows retry without leaving the screen.

FR-7 **Not-found state**: HTTP 404 (or `detail` indicating no such link) renders a terminal “This link doesn’t exist” state with Back and **no** Retry.

FR-8 **Revoked/expired state**: HTTP 410 Gone, or a payload marked `revoked`/`expired`/`download_limit_reached`, renders a terminal “This link is no longer available” state explaining the reason, with Back and no Retry.

FR-9 **Offline/stale**: if resolve fails on connectivity and a cached metadata copy exists, render the cached metadata with a “Showing saved info — connect to download” banner; the Download action is **disabled** while offline (bytes cannot be fetched). With no cache, show an offline error state with Retry.

FR-10 **Retry**: transient errors (timeout/5xx/network) show an error state with a Retry that re-issues the idempotent resolve GET.

FR-11 **Back**: system Back and the up affordance pop the screen; if entered via deep link onto an empty back stack, Back routes to the app start destination, not app exit.

FR-12 **Identifier passthrough**: `linkId` is opaque; URL-decoded once on extraction and passed verbatim. No client normalization beyond non-empty.

## 4. Technical Design

### Module & files

```
feature-files/
  src/main/kotlin/com/testlogon/android/feature/files/share/publicdownload/
    PublicDownloadScreen.kt
    PublicDownloadViewModel.kt
    PublicDownloadUiState.kt
    PublicDownloadNav.kt
    ShareDownloadEnqueuer.kt
  src/main/res/values/strings.xml
  src/main/AndroidManifest.xml   // intent-filter merged into app manifest
```

### Route registration (consumes AND-022)

```kotlin
// PublicDownloadNav.kt
@Serializable
data class PublicDownloadRoute(val linkId: String)

fun NavGraphBuilder.publicDownloadScreen(onBack: () -> Unit) {
    composable<PublicDownloadRoute>(
        deepLinks = listOf(
            navDeepLink<PublicDownloadRoute>(
                basePath = "https://${'$'}{BuildConfig.APP_LINK_HOST}/share"
            ),
            navDeepLink<PublicDownloadRoute>(basePath = "testlogon://share"),
        ),
    ) { PublicDownloadScreen(onBack = onBack) }
}

fun NavController.navigateToPublicDownload(linkId: String) =
    navigate(PublicDownloadRoute(linkId))
```

`{linkId}` maps onto the route field via type-safe Navigation-Compose deep linking. `APP_LINK_HOST` is a per-build-type `BuildConfig` field (§8).

### ViewModel

```kotlin
@HiltViewModel
class PublicDownloadViewModel @Inject constructor(
    private val shareRepository: FileShareRepository,   // from AND-335 / core-data
    private val enqueuer: ShareDownloadEnqueuer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val args = savedStateHandle.toRoute<PublicDownloadRoute>()
    val linkId: String = args.linkId

    private val _uiState = MutableStateFlow<PublicDownloadUiState>(PublicDownloadUiState.Loading)
    val uiState: StateFlow<PublicDownloadUiState> = _uiState.asStateFlow()

    private val _events = Channel<DownloadEvent>(Channel.BUFFERED)
    val events: Flow<DownloadEvent> = _events.receiveAsFlow()

    init { resolve() }

    fun resolve(password: String? = null) {
        if (linkId.isBlank()) { _uiState.value = PublicDownloadUiState.NotFound; return }
        viewModelScope.launch {
            _uiState.value = PublicDownloadUiState.Loading
            _uiState.value = when (val r = shareRepository.resolvePublicShare(linkId, password)) {
                is ApiResult.Success -> PublicDownloadUiState.Resolved(r.data, stale = false)
                is ApiResult.Stale   -> PublicDownloadUiState.Resolved(r.data, stale = true)
                is ApiResult.Error   -> r.toPublicDownloadUiState()  // maps 404/410/401/403/transient
            }
        }
    }

    fun onDownload() {
        val s = _uiState.value as? PublicDownloadUiState.Resolved ?: return
        if (s.stale) { _events.trySend(DownloadEvent.OfflineNoDownload); return }
        val req = enqueuer.enqueue(linkId, s.share)
        _events.trySend(DownloadEvent.Started(req))
    }

    fun submitPassword(pw: String) = resolve(password = pw)
    fun retry() = resolve()
}

sealed interface DownloadEvent {
    data class Started(val downloadId: Long) : DownloadEvent
    data object OfflineNoDownload : DownloadEvent
}
```

`FileShareRepository.resolvePublicShare(linkId, password): ApiResult<PublicShare>` and the `PublicShare` domain model are owned by **AND-335**; this ticket consumes them (and adds the method signature to the shared interface if absent). If AND-335 lacks an `ApiResult.Stale` variant, map a cache hit to `Success(stale=true)` via a repository flag.

### UI state

```kotlin
sealed interface PublicDownloadUiState {
    data object Loading : PublicDownloadUiState
    data class Resolved(val share: PublicShare, val stale: Boolean) : PublicDownloadUiState
    data class PasswordRequired(val error: String? = null) : PublicDownloadUiState
    data object NotFound : PublicDownloadUiState
    data class Unavailable(val reason: UnavailableReason) : PublicDownloadUiState  // revoked/expired/limit
    data class Error(val message: String, val retryable: Boolean) : PublicDownloadUiState
}

enum class UnavailableReason { REVOKED, EXPIRED, LIMIT_REACHED, UNKNOWN }
```

### Download enqueuer

```kotlin
class ShareDownloadEnqueuer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cookieJar: PersistentCookieJar,   // AND-011, to forward session/CSRF cookies
) {
    fun enqueue(linkId: String, share: PublicShare): Long {
        val url = "${'$'}{BuildConfig.API_BASE_URL}/ui/files/share/$linkId/download"
        val req = DownloadManager.Request(Uri.parse(url)).apply {
            setTitle(share.fileName)
            setMimeType(share.contentType)
            setNotificationVisibility(VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            setDestinationInExternalPublicDir(DIRECTORY_DOWNLOADS, share.fileName.sanitized())
            cookieHeader(linkId)?.let { addRequestHeader("Cookie", it) }
        }
        return context.downloadManager.enqueue(req)
    }
}
```

### Composable

```kotlin
@Composable
fun PublicDownloadScreen(
    onBack: () -> Unit,
    viewModel: PublicDownloadViewModel = hiltViewModel(),
)
```

A single `Scaffold` with a `TopAppBar` (title = file name once known, up icon → `onBack`) hosts a `when (state)` dispatch into `LoadingSkeleton`, `ResolvedContent` (file card + Download button + optional Coil thumbnail + stale banner), `PasswordPrompt`, `NotFoundState`, `UnavailableState`, and `ErrorState`. `events` are collected with `collectAsStateWithLifecycle`-friendly `LaunchedEffect` to show a snackbar (“Download started” / “Connect to download”). State is collected via `collectAsStateWithLifecycle()`.

## 5. API Contract

Endpoints owned by AND-335 (`fileShareLinks.ts`), consumed here. Confirm exact paths against `/openapi.json` (`/ui/files/share/*`).

**Resolve metadata — request**
```
GET /ui/files/share/{linkId}
Headers: X-CSRF-Token: <ui_csrf cookie>   (attached opportunistically; public resolve works unauthenticated)
Query (gated links): ?password=<pw>        (or header X-Share-Password: <pw> — match the web client)
```

**200 — resolvable**
```json
{
  "link_id": "9fK3xQ",
  "file_name": "quarterly-report.pdf",
  "content_type": "application/pdf",
  "size_bytes": 4823311,
  "owner_display_name": "Ada Lovelace",
  "requires_password": false,
  "expires_at": "2026-07-01T00:00:00Z",
  "downloads_remaining": 17,
  "preview_url": null,
  "revoked": false
}
```

**200/401/403 — password required**
```json
{ "link_id": "9fK3xQ", "requires_password": true, "file_name": null }
```
Treat `requires_password == true` **or** a 401/403 classified as password-gated as `PasswordRequired`. A wrong-password retry yields the same shape with an error `detail`; surface it as the inline field error.

**404 — not found**
```json
{ "detail": "Share link not found" }
```

**410 — revoked/expired/limit reached**
```json
{ "detail": { "code": "link_revoked" } }
```
Map `code` → `UnavailableReason` (`link_revoked`→REVOKED, `link_expired`→EXPIRED, `download_limit_reached`→LIMIT_REACHED, else UNKNOWN). A 200 payload with `revoked==true` or `expires_at` in the past or `downloads_remaining==0` is also `Unavailable`.

**Download bytes — request**
```
GET /ui/files/share/{linkId}/download   (+ password param/header if gated)
→ 200 binary stream (Content-Disposition: attachment; filename=...)
```
This is enqueued to `DownloadManager`, not consumed via Retrofit, so the OkHttp body-size and timeout limits do not apply to the byte transfer.

**FastAPI `detail` mapping** (`string | [{msg}] | {code,...}`) is normalized by core-network’s mapper (AND-015); 404/410/401/403 are classified by status before message extraction. The resolve GET is **idempotent** → eligible for bounded backoff retry on transient failures (AND-016); 404/410 are never retried.

## 6. Data & State Management

- **Source of truth**: `FileShareRepository` (core-data, AND-335) performs the resolve GET, maps DTO→`PublicShare`, and optionally caches metadata in Room keyed by `linkId`. This ticket adds the `resolvePublicShare(linkId, password)` entry point if absent and adds **no new persistence** beyond that optional metadata cache.
- **Cache key**: `linkId`. Only **non-gated, non-sensitive metadata** is cached (file name/size/type) to enable the offline “Showing saved info” banner; password-required state and the file **bytes** are never cached. TTL/eviction are AND-335’s concern.
- **UI state holder**: `PublicDownloadViewModel` exposes a single immutable `StateFlow<PublicDownloadUiState>` plus a one-shot `events` channel for snackbars (download started / offline).
- **Process death**: `linkId` recovered from `SavedStateHandle.toRoute()`; the screen re-resolves in `init`. The entered password is **not** persisted across process death (security); the user re-enters it.
- **Download lifecycle**: ownership of the byte transfer is handed to `DownloadManager`; the screen does not track progress in its `UiState`. Completion/failure is the OS notification’s responsibility.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| 404 / `detail` not-found | terminal | `NotFound`, no retry |
| 410 / `revoked`/`expired`/`limit` | terminal | `Unavailable(reason)`, no retry |
| 401/403 password-gated, or `requires_password==true` | recoverable | `PasswordRequired`; wrong pw → inline field error |
| Timeout (~20s), 5xx, conn reset | transient | `Error(retryable=true)`, or `Resolved(stale=true)` if cache hit |
| Offline, no cache | transient | `Error(retryable=true)` |
| Offline, metadata cached | degraded | `Resolved(stale=true)` + banner; Download disabled |
| Malformed body / parse error | terminal | `Error("Couldn't load this link", retryable=true)` (allow one retry) |
| Download enqueue while stale/offline | guard | `DownloadEvent.OfflineNoDownload` snackbar; no enqueue |

- Honour the **~20s** OkHttp timeout and **bounded backoff** retry for the idempotent resolve GET (AND-016 policy); the screen adds only the user-driven Retry and password re-submit on top.
- On 401 the network layer performs the single `POST /ui/session/refresh` + retry transparently (AND-013); however, for **public** links a 401 is more likely a password gate — classify by the resolve payload/`code` before treating it as a session refresh case.
- Retry and password-submit are debounced (ignored while `Loading`).
- `DownloadManager` failures (e.g., storage full, byte-level network error) are surfaced by the system notification; the app does not duplicate that error UI in M8.

## 8. Security & Privacy

- **App Link host split**: App Links require HTTPS + Digital Asset Links verification; the plaintext dev host (`18.222.237.167:8000`) **cannot** be an autoVerified App Link host. `APP_LINK_HOST` is a per-build-type `BuildConfig`/string: production verified host on `release` (`autoVerify="true"`); `debug`/`internal` rely on `testlogon://share/<linkId>` and set `autoVerify="false"`. Cleartext stays restricted to the dev API host via the existing network-security-config; the App Link host is always HTTPS. `/.well-known/assetlinks.json` publishing on the production host is a release-ops prerequisite (release/CI ticket, not here).
- Intent-filter (release):
```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https" android:host="@string/app_link_host" android:pathPrefix="/share/"/>
</intent-filter>
```
- **Password handling**: the share password is held only in transient Compose/VM state, sent over the request, and **never** logged, cached, or persisted across process death. Prefer the header form (`X-Share-Password`) over a query param if the backend supports it, to keep it out of any URL/access logs.
- **No sensitive logging**: log only `linkId` (already in the URL) and HTTP status; never log file bytes, owner PII payloads, passwords, cookies, or CSRF tokens.
- **Cookie forwarding to DownloadManager**: only the session/CSRF cookies for the API host are forwarded as a `Cookie` header on the download request; do not attach them to any other host. Public resolve/download work unauthenticated, so cookies are attached opportunistically, not required.
- **Filename sanitization**: sanitize `file_name` before passing to `setDestinationInExternalPublicDir` to prevent path traversal (`../`) and reserved characters; fall back to `download-<linkId>` if empty.

## 9. Accessibility & i18n

- All strings in `feature-files/src/main/res/values/strings.xml`; no hardcoded text. Keys: `share_dl_title`, `share_dl_download_button`, `share_dl_not_found_title`, `share_dl_unavailable_revoked`, `share_dl_unavailable_expired`, `share_dl_unavailable_limit`, `share_dl_password_label`, `share_dl_password_error`, `share_dl_stale_banner`, `share_dl_started_snackbar`, `share_dl_offline_snackbar`, `share_dl_error_retry`.
- File size formatted with `android.text.format.Formatter.formatShortFileSize(context, size_bytes)`; `expires_at` rendered with `DateTimeFormatter` in device locale/zone.
- File-type icon `Icon`/thumbnail `AsyncImage` has a `contentDescription` (“<file name>, <type>”); decorative dividers `contentDescription = null`.
- Download button and Retry ≥ 48dp touch targets; password field uses `KeyboardType.Password` + `PasswordVisualTransformation` with an accessible reveal toggle.
- TalkBack reading order: title → stale banner (if any) → file name → size/type → expiry/downloads-remaining → Download. Error/empty/unavailable states announced via `liveRegion = Polite`.
- Dynamic type + dark theme via Material 3 tokens from `core-ui`; no fixed font sizes.

## 10. Telemetry & Logging

- Events (core analytics facade): `public_download_viewed { source: "applink"|"in_app"|"deep_scheme", result: "resolved"|"password_required"|"not_found"|"unavailable"|"error", stale: Boolean }` — `source` derived from the launching intent.
- `public_download_started { content_type: String, size_bucket: String }` on enqueue (size bucketed, not exact, to avoid fingerprinting).
- `public_download_password_submitted { success: Boolean }`; `public_download_retry_tapped {}`.
- Logging at `DEBUG` only: `tag=PublicDownload`, fields `linkId`, `httpStatus`, `elapsedMs`. Errors at `WARN` with classification (`transient`/`terminal`/`password`). No payload bodies, passwords, tokens, or cookies.

## 11. Testing Strategy

**Unit (core-testing: JUnit + Turbine + coroutines-test)** — `PublicDownloadViewModelTest`, fake `FileShareRepository` + fake `ShareDownloadEnqueuer`:
- 200 resolvable → `Resolved(stale=false)`.
- 200 `requires_password=true` / 401 / 403 → `PasswordRequired`.
- wrong password re-submit → `PasswordRequired(error=…)`.
- 404 → `NotFound` (no retry).
- 410 `link_revoked`/`link_expired`/`download_limit_reached` → `Unavailable(reason)` with correct mapping; 200 with `revoked==true`/past `expires_at`/`downloads_remaining==0` → `Unavailable`.
- timeout/5xx → `Error(retryable=true)`.
- cache hit on network failure → `Resolved(stale=true)`.
- blank `linkId` → `NotFound` with no repository call.
- `onDownload()` on `Resolved(stale=false)` → enqueuer invoked once + `DownloadEvent.Started`.
- `onDownload()` on `Resolved(stale=true)` → no enqueue + `DownloadEvent.OfflineNoDownload`.
- `retry()` re-invokes repository: `Error → Loading → Resolved`.

**Compose UI (createAndroidComposeRule)**:
- Each state renders its hallmark node (Download button only when resolved & not stale; password field when gated; not-found/unavailable titles; stale banner iff stale; Retry only when `retryable`).
- Download click emits the event/snackbar (assert via test event collector).
- Password submit invokes `submitPassword`; reveal toggle works; field error shown.
- contentDescription assertions for file icon and Back.

**Deep-link / instrumentation**:
- `adb shell am start -W -a android.intent.action.VIEW -d "https://<host>/share/9fK3xQ"` opens `PublicDownloadScreen` with `linkId == "9fK3xQ"`.
- `testlogon://share/9fK3xQ` resolves the same route on all builds.
- URL-encoded `linkId` (`/share/a%20b`) decodes to `"a b"`.
- Back from deep-link cold start routes to home, not exit.
- `DownloadManager` enqueue smoke test against a MockWebServer-served binary (AND-046 harness) verifying a request is created with the correct URL and forwarded `Cookie` header.

**Acceptance mapping**: the deep-link + enqueue tests cover “public download works”; not-found/revoked/password unit+UI tests cover the terminal/gated branches.

## 12. Dependencies & Sequencing

- **Blocked by AND-335 (Share links + public download)**: must land first — provides `FileShareApi`/`fileShareLinks.ts`, share DTOs/`PublicShare` model, the `FileShareRepository`, and the public-page contract. If AND-335 slips, this screen can be built against a fake repository and wired on merge; the `resolvePublicShare(linkId, password)` signature is the integration seam to agree on early.
- **Transitively depends on**: AND-331 (file DTOs), AND-022 (NavHost + deep links), AND-015/016/018 (error mapping, idempotent retry, `ApiResult`), AND-011/012/013 (cookie jar, CSRF, refresh-authenticator), AND-046 (MockWebServer harness for tests).
- **Sibling**: AND-391 (Public event) is the parallel M8/E51 public-link screen; share the App Link host-split pattern and the deep-link cold-start Back behaviour.
- **Blocks**: none recorded in backlog. Keep `navigateToPublicDownload(linkId)` and `PublicDownloadRoute` stable as public API for the AND-335 share-sheet/created-link confirmation to navigate into.
- **External prerequisite**: production `/.well-known/assetlinks.json` for App Link autoVerify (release/CI ticket).

## 13. Risks & Open Questions

- **R1 — Exact endpoint paths**: `/ui/files/share/{linkId}` and `.../download` are inferred from `fileShareLinks.ts`/web route; confirm against `/openapi.json` before wiring. *Open.*
- **R2 — Password transport**: query param vs `X-Share-Password` header. Prefer header to keep secrets out of logs; confirm backend support and match the web client. *Open.*
- **R3 — App Link verification on plaintext dev host**: cannot autoVerify HTTP. Mitigated by per-build `APP_LINK_HOST` + custom scheme on non-release; confirm production HTTPS host and assetlinks owner. *Open.*
- **R4 — Revoked vs not-found ambiguity**: backend may return 404 for revoked links to avoid leaking existence. Both states are handled; confirm whether 410+`code` or 404 is returned. *Open.*
- **R5 — DownloadManager auth**: if the download endpoint requires the same cookie/CSRF session and the cookie expires mid-flight, the OS download fails without an in-app refresh. Mitigation: resolve immediately before enqueue; treat enqueue as best-effort. Confirm whether download requires auth at all (public links may be tokenized in the URL).
- **R6 — Preview scope**: inline image preview is best-effort this ticket; Media3 audio/video preview is deferred. Confirm M8 scope for previews vs download-only.

## 14. Acceptance Criteria

- AC-1 Tapping a verified `https://<host>/share/<linkId>` (release) opens the app on `PublicDownloadScreen` with the correct `linkId`; `testlogon://share/<linkId>` does the same on all builds. *(Source: public `/share/:linkId` page.)*
- AC-2 A valid, non-gated link resolves and renders file name, size, type, and a working **Download** action that enqueues the file to the device `Downloads/` via `DownloadManager`. *(Source: “Public download works.”)*
- AC-3 A password-gated link renders the password prompt; a correct password resolves/downloads; a wrong password shows an inline error and allows retry.
- AC-4 A non-existent link (404) renders `NotFound` with no Retry; a revoked/expired/limit-reached link (410 or payload flags) renders `Unavailable` with the correct reason and no Retry.
- AC-5 Transient failures render an `Error` state with a working Retry; an offline cache hit renders the stale-info banner with the Download action disabled.
- AC-6 Back from a deep-link cold start navigates to home, not app exit.
- AC-7 No password, cookie, token, or file-body content is logged or persisted; filename is sanitized before write.
- AC-8 All listed unit, Compose, and deep-link/instrumentation tests pass in CI.

## 15. Definition of Done

- `feature-files` extended with `PublicDownloadScreen`, `PublicDownloadViewModel`, `PublicDownloadUiState`, `ShareDownloadEnqueuer`, and route/deep-link registration under `com.testlogon.android.feature.files.share.publicdownload`.
- Route registered in the AND-022 `NavHost`; `navigateToPublicDownload(linkId)` exposed as stable public API.
- `FileShareRepository.resolvePublicShare(linkId, password)` integrated (added to the shared interface if AND-335 had not yet exposed it).
- App Link intent-filter merged (autoVerify on release host, custom scheme on all builds); `APP_LINK_HOST` `BuildConfig`/string per build type.
- All UI states (loading / resolved / password / not-found / unavailable / error / offline-stale) implemented, accessible (TalkBack-verified), and fully externalized strings.
- Download delegated to `DownloadManager` with sanitized filename and opportunistic cookie/CSRF forwarding scoped to the API host.
- Unit + Compose + deep-link/instrumentation tests written and green; all §11 branches covered.
- Telemetry emitted with no PII/password/token/payload logging.
- Code review approved; merged to `android-port`; CI (build + lint + tests) green.
- Open questions R1–R5 resolved or explicitly deferred with owners before release tagging.
