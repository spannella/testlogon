---
id: AND-392
title: "Public download (`/share/:linkId`)"
milestone: M8
epic: E51
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference**: `src/api/endpoints/fileShareLinks.ts` (`getShareLinkInfo`, `downloadShareLink`), `src/api/types.ts: ShareLinkPublicInfo` (the public DTO; note the web type is `ShareLinkPublicInfo`, not `PublicShare`), and the web page `src/pages/files/PublicDownloadPage.tsx` (route `/share/:linkId`). OpenAPI: the authoritative public paths are under **`/public/files/share/*`** (tag `public-file-share`): `GET /public/files/share/{link_id}/info`, `GET|POST /public/files/share/{link_id}/download`. (CORRECTED: `/ui/files/share-links*` are the **owner-side** management endpoints owned by AND-335, not the public-recipient paths.)
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Coil (image preview), Media3/ExoPlayer 1.4 (audio/video preview, optional). minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend reality**: dev host `18.222.237.167:8000` is **plaintext HTTP** and unreliable — design for ~20s OkHttp timeouts, bounded backoff retry on idempotent GETs only, and offline/stale states. App Links require HTTPS verification, so the App Link host is the production HTTPS host, not the dev IP (see §8).

## 3. Functional Requirements

FR-1 **Route**: registered as a typed route `PublicDownloadRoute(linkId: String)` rendering at in-app path `share/{linkId}`.

FR-2 **App Link**: tapping `https://<verified-host>/share/<linkId>` opens the app directly on this screen with `linkId` extracted from the path. Custom-scheme fallback `testlogon://share/<linkId>` is accepted for share flows on all builds. App Link `autoVerify` is enabled on `release` only (§8).

FR-3 **Resolve**: on entry, fetch share metadata by `linkId` via `GET /public/files/share/{linkId}/info` (verified — `op=get_share_link_info_endpoint...`; response `ShareLinkPublicInfoOut`) and show a loading state until resolved. (CORRECTED: the spec previously claimed `GET /ui/files/share/{linkId}`; `/ui/files/share-links*` are the **owner-side** management endpoints owned by AND-335, not the public-recipient path.)

FR-4 **Resolved state**: render file display name (`file_name`), human-readable size (`file_size_bytes`), MIME/type icon (`content_type`), an optional “downloads remaining” hint (`remaining_downloads`), and a primary **Download** action. For previewable images, show an inline Coil thumbnail; previewing is best-effort and never blocks download. (CORRECTED: `ShareLinkPublicInfoOut` exposes **no** `owner_display_name` and **no** `expires_at`; "owner display name" and "expiry hint" are NOT available from the public-info payload — do not render them. Expiry is surfaced only as the boolean `is_expired`.)

FR-5 **Download action**: tapping **Download** enqueues the file via Android `DownloadManager` to the public `Downloads/` collection using the backend download URL `GET /public/files/share/{linkId}/download` (CORRECTED path; verified `op=download_share_link_get_endpoint...`). The GET form is required because `DownloadManager` only issues GET; for gated links the password is supplied as the `?password=` query parameter (the GET download endpoint declares an optional `password` query param). NOTE: these public endpoints take **no auth** — the web client calls them via raw `fetch` with neither `credentials` nor a CSRF header (`src/api/endpoints/fileShareLinks.ts`), so cookie/CSRF forwarding to `DownloadManager` is NOT required by the contract (see §8 correction). While enqueued, show a non-blocking “Download started” confirmation; rely on the system notification for progress/completion. (The web client instead uses **POST** `/public/files/share/{linkId}/download` with a JSON `{password}` body via `downloadShareLink`, then triggers a browser blob download — the native client uses the GET+query form purely because `DownloadManager` cannot POST.)

FR-6 **Password-gated links**: if resolve returns `requires_password == true`, render a password entry field; on submit, download with the supplied password as the `?password=` query param. A wrong password yields HTTP 403 on the **download** call (web maps 403 → "Invalid password."); surface it as an inline field error and allow retry without leaving the screen. (CORRECTED: the password gate is detected from the `requires_password` flag on the 200 info payload, not from a 401/403 on resolve — the info endpoint documents only 200/422. 403 occurs on the download attempt.)

FR-7 **Not-found state**: a failed info fetch (web treats any non-OK info response as not-found: `getShareLinkInfo` throws on `!resp.ok`; the page renders "Share link not found.") renders a terminal “This link doesn’t exist” state with Back and **no** Retry. (UNVERIFIED: the OpenAPI documents only 200/422 for the info endpoint, so the exact not-found status — e.g. 404 — is not specified by the contract; classify any non-2xx/non-422 info failure as not-found, mirroring the web client which does not branch on status for info.)

FR-8 **Revoked/expired state**: unavailability is signaled by **boolean flags on the 200 info payload** — `is_revoked`, `is_expired`, `is_used` — and renders a terminal “This link is no longer available” state explaining the reason (web `unavailableMessage()`: revoked → "revoked by the owner", expired → "has expired", used → "already been used"), with Back and no Retry. On the **download** call, HTTP 410 is mapped to "This link is no longer available." (web). (CORRECTED: there is no `revoked`/`expired`/`download_limit_reached` field; the real fields are `is_revoked`/`is_expired`/`is_used`. There is no `download_limit_reached` / `LIMIT_REACHED` concept in the public payload — `remaining_downloads` is informational only and `is_used` covers the consumed/limit case. Revoked/expired are NOT primarily an HTTP 410 on info; they are 200-payload flags.)

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

// CORRECTED: payload flags are is_revoked / is_expired / is_used. No download_limit_reached concept.
enum class UnavailableReason { REVOKED, EXPIRED, USED, UNKNOWN }
```

### Download enqueuer

```kotlin
// CORRECTED: no cookie jar — public download endpoint is unauthenticated (no cookie/CSRF).
class ShareDownloadEnqueuer @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    fun enqueue(linkId: String, share: PublicShare, password: String? = null): Long {
        // CORRECTED path: /public/files/share/{linkId}/download (GET form for DownloadManager).
        // Password (if any) goes as the ?password= query param; no cookie/CSRF needed (public endpoint).
        val base = "${'$'}{BuildConfig.API_BASE_URL}/public/files/share/$linkId/download"
        val url = password?.let { "$base?password=${'$'}{Uri.encode(it)}" } ?: base
        val req = DownloadManager.Request(Uri.parse(url)).apply {
            setTitle(share.fileName)
            setMimeType(share.contentType)
            setNotificationVisibility(VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            setDestinationInExternalPublicDir(DIRECTORY_DOWNLOADS, share.fileName.sanitized())
            // No Cookie/CSRF header: public endpoint is unauthenticated (CORRECTED).
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

Public-recipient endpoints (web binding in `src/api/endpoints/fileShareLinks.ts`; verified against OpenAPI tag `public-file-share`). NOTE the owner-side management endpoints (`GET/POST /ui/files/share-links`, `DELETE /ui/files/share-links/{link_id}`) are AND-335's and are NOT used here. The public endpoints take **no auth, no cookies, no CSRF** (web calls them with raw `fetch`).

**Resolve metadata — request** (CORRECTED path)
```
GET /public/files/share/{linkId}/info
Accept: application/json
(no auth / no CSRF / no credentials — public endpoint)
```
op `get_share_link_info_endpoint_public_files_share__link_id__info_get`; documented responses: `200:ShareLinkPublicInfoOut`, `422:HTTPValidationError`.

**200 — `ShareLinkPublicInfoOut`** (CORRECTED field set — verified against `components.schemas.ShareLinkPublicInfoOut` and `src/api/types.ts: ShareLinkPublicInfo`)
```json
{
  "file_name": "quarterly-report.pdf",
  "file_size_bytes": 4823311,
  "content_type": "application/pdf",
  "requires_password": false,
  "is_expired": false,
  "is_revoked": false,
  "is_used": false,
  "remaining_downloads": 17
}
```
Required fields: `file_name`, `file_size_bytes`, `content_type`. Booleans default `false`; `remaining_downloads` defaults `0`. There is **no** `link_id`, `owner_display_name`, `expires_at`, `downloads_remaining`, `preview_url`, or `revoked` field — earlier spec drafts invented these.

**Password required** — detected from the 200 info payload flag `requires_password == true` (the info endpoint returns 200 with the metadata and this flag; it does NOT 401/403). The file metadata (`file_name` etc.) is still present and required. Render `PasswordRequired` / the inline password field when this flag is set.

**Unavailable (revoked / expired / used)** — signaled by 200-payload booleans, not by an HTTP status: `is_revoked`, `is_expired`, `is_used`. Map → `UnavailableReason` (`is_revoked`→REVOKED, `is_expired`→EXPIRED, `is_used`→USED/consumed). There is no `download_limit_reached` code and no `LIMIT_REACHED`; `is_used` is the consumed/limit-reached case and `remaining_downloads` is informational.

**Not found** — `getShareLinkInfo` throws on any `!resp.ok` info response (`{ status, detail }`) and the web page renders "Share link not found." (UNVERIFIED status: OpenAPI documents only 200/422 for info, so the exact not-found code is unspecified; treat any non-2xx/non-422 info failure as `NotFound`.)

**Download bytes — request** (CORRECTED path; GET form used by the native `DownloadManager`)
```
GET /public/files/share/{linkId}/download?password=<pw>   (password query param only if gated)
→ 200 binary stream (Content-Disposition: attachment; filename="...")
```
op `download_share_link_get_endpoint...`; documented responses `200:` (binary), `422:HTTPValidationError`. The GET endpoint declares an optional `password` **query** parameter (no header form exists — earlier `X-Share-Password` claim is unverified/invented). The web client uses the **POST** variant `download_share_link_endpoint...` with JSON body `ShareLinkDownloadIn { password?: string (maxLength 128) }`; the native client uses GET because `DownloadManager` cannot POST. On download, the web client maps **403 → "Invalid password."** and **410 → "This link is no longer available."** (`PublicDownloadPage.tsx`); these are the only download error statuses the web client branches on. This transfer is enqueued to `DownloadManager`, not consumed via Retrofit, so OkHttp body-size/timeout limits do not apply.

**FastAPI `detail` mapping** (`string | [{msg}] | {code,...}`) is normalized by core-network's mapper (AND-015). The resolve/info GET is **idempotent** → eligible for bounded backoff retry on transient failures (AND-016); a not-found classification is never retried. NOTE: because revoked/expired/used are 200-payload flags, they are detected after a *successful* HTTP response, not via status classification.

## 6. Data & State Management

- **Source of truth**: `FileShareRepository` (core-data, AND-335) performs the resolve GET, maps DTO→`PublicShare`, and optionally caches metadata in Room keyed by `linkId`. This ticket adds the `resolvePublicShare(linkId, password)` entry point if absent and adds **no new persistence** beyond that optional metadata cache.
- **Cache key**: `linkId`. Only **non-gated, non-sensitive metadata** is cached (file name/size/type) to enable the offline “Showing saved info” banner; password-required state and the file **bytes** are never cached. TTL/eviction are AND-335’s concern.
- **UI state holder**: `PublicDownloadViewModel` exposes a single immutable `StateFlow<PublicDownloadUiState>` plus a one-shot `events` channel for snackbars (download started / offline).
- **Process death**: `linkId` recovered from `SavedStateHandle.toRoute()`; the screen re-resolves in `init`. The entered password is **not** persisted across process death (security); the user re-enters it.
- **Download lifecycle**: ownership of the byte transfer is handed to `DownloadManager`; the screen does not track progress in its `UiState`. Completion/failure is the OS notification’s responsibility.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| info fetch non-OK (not-found) | terminal | `NotFound`, no retry |
| 200 payload `is_revoked`/`is_expired`/`is_used` (or download 410) | terminal | `Unavailable(reason)`, no retry |
| 200 payload `requires_password==true` (gate); wrong pw → download **403** | recoverable | `PasswordRequired`; wrong pw → inline "Invalid password." field error |
| Timeout (~20s), 5xx, conn reset | transient | `Error(retryable=true)`, or `Resolved(stale=true)` if cache hit |
| Offline, no cache | transient | `Error(retryable=true)` |
| Offline, metadata cached | degraded | `Resolved(stale=true)` + banner; Download disabled |
| Malformed body / parse error | terminal | `Error("Couldn't load this link", retryable=true)` (allow one retry) |
| Download enqueue while stale/offline | guard | `DownloadEvent.OfflineNoDownload` snackbar; no enqueue |

- Honour the **~20s** OkHttp timeout and **bounded backoff** retry for the idempotent resolve GET (AND-016 policy); the screen adds only the user-driven Retry and password re-submit on top.
- CORRECTED: the public info/download endpoints are unauthenticated, so the AND-013 session-refresh-on-401 authenticator does **not** apply here (and the web client does not send credentials to them). The password gate is detected from the `requires_password` flag on the 200 info payload, and a wrong password produces a **403 on the download** call (mapped to "Invalid password."), not a session 401. Do not route these through session refresh.
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
- **Password handling**: the share password is held only in transient Compose/VM state, sent over the request, and **never** logged, cached, or persisted across process death. CORRECTED: there is **no** `X-Share-Password` header form — the backend accepts the password only as a `?password=` query param (GET download) or a JSON `{password}` body (POST download). Because `DownloadManager` only does GET, the password travels in the query string; treat the download URL as sensitive (do not log it) and rely on HTTPS in production to keep it off the wire. Max password length is 128 (`ShareLinkDownloadIn.password.maxLength`).
- **No sensitive logging**: log only `linkId` (already in the URL) and HTTP status; never log the download URL (it may carry `?password=`), file bytes, passwords, cookies, or CSRF tokens.
- **No cookie/CSRF forwarding to DownloadManager**: CORRECTED — the public info/download endpoints are unauthenticated and the web client sends them with neither credentials nor CSRF (`fileShareLinks.ts` raw `fetch`). Do **not** attach the session cookie jar or `X-CSRF-Token` to the `DownloadManager` request; the prior "cookie forwarding" design is unnecessary and is dropped. (`ShareDownloadEnqueuer` therefore needs no `PersistentCookieJar` dependency — see §4 note.)
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
- 200 with `requires_password=true` → `PasswordRequired` (CORRECTED: detected from the 200 payload flag, not a 401/403 on info).
- wrong password → download **403** re-surfaced as `PasswordRequired(error="Invalid password.")`.
- info fetch non-OK → `NotFound` (no retry).
- 200 payload with `is_revoked`/`is_expired`/`is_used` → `Unavailable(REVOKED/EXPIRED/USED)` with correct mapping (CORRECTED field names; no `LIMIT_REACHED`/`download_limit_reached`).
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
- `DownloadManager` enqueue smoke test against a MockWebServer-served binary (AND-046 harness) verifying a request is created with the correct `/public/files/share/{linkId}/download` URL, the `?password=` query param when gated, and **no** `Cookie`/`X-CSRF-Token` header (CORRECTED: public endpoint, no auth).

**Acceptance mapping**: the deep-link + enqueue tests cover “public download works”; not-found/revoked/password unit+UI tests cover the terminal/gated branches.

## 12. Dependencies & Sequencing

- **Blocked by AND-335 (Share links + public download)**: must land first — provides `FileShareApi`/`fileShareLinks.ts`, share DTOs/`PublicShare` model, the `FileShareRepository`, and the public-page contract. If AND-335 slips, this screen can be built against a fake repository and wired on merge; the `resolvePublicShare(linkId, password)` signature is the integration seam to agree on early.
- **Transitively depends on**: AND-331 (file DTOs), AND-022 (NavHost + deep links), AND-015/016/018 (error mapping, idempotent retry, `ApiResult`), AND-011/012/013 (cookie jar, CSRF, refresh-authenticator), AND-046 (MockWebServer harness for tests).
- **Sibling**: AND-391 (Public event) is the parallel M8/E51 public-link screen; share the App Link host-split pattern and the deep-link cold-start Back behaviour.
- **Blocks**: none recorded in backlog. Keep `navigateToPublicDownload(linkId)` and `PublicDownloadRoute` stable as public API for the AND-335 share-sheet/created-link confirmation to navigate into.
- **External prerequisite**: production `/.well-known/assetlinks.json` for App Link autoVerify (release/CI ticket).

## 13. Risks & Open Questions

- **R1 — Exact endpoint paths**: *RESOLVED.* Verified against OpenAPI: info = `GET /public/files/share/{linkId}/info` (`ShareLinkPublicInfoOut`); download = `GET /public/files/share/{linkId}/download?password=` (web uses POST variant). The spec previously had the wrong `/ui/files/share/{linkId}` paths — corrected in §3/§5.
- **R2 — Password transport**: *RESOLVED.* No header form exists. Backend accepts password as a `?password=` query param (GET) or JSON `{password}` body (POST, `ShareLinkDownloadIn`, maxLength 128). Native uses the query param because `DownloadManager` is GET-only; treat the URL as sensitive.
- **R3 — App Link verification on plaintext dev host**: cannot autoVerify HTTP. Mitigated by per-build `APP_LINK_HOST` + custom scheme on non-release; confirm production HTTPS host and assetlinks owner. *Open (release-ops; unverifiable from API/web sources).*
- **R4 — Revoked vs not-found ambiguity**: *PARTIALLY RESOLVED.* Revoked/expired/used are returned as **200-payload booleans** (`is_revoked`/`is_expired`/`is_used`), NOT a 404/410 on info, so they do not collide with not-found. The exact not-found status on info is still unspecified by OpenAPI (documents only 200/422); web treats any non-OK info response as not-found. *Open: confirm not-found status code.*
- **R5 — DownloadManager auth**: *RESOLVED.* The public download endpoint is **unauthenticated** — the web client calls it with no credentials/CSRF. No cookie/session concern; the cookie-forwarding design is dropped (§8). Only the optional `?password=` gate applies.
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
- Download delegated to `DownloadManager` with sanitized filename and the optional `?password=` query param; **no** cookie/CSRF attached (public endpoint — CORRECTED).
- Unit + Compose + deep-link/instrumentation tests written and green; all §11 branches covered.
- Telemetry emitted with no PII/password/token/payload logging.
- Code review approved; merged to `android-port`; CI (build + lint + tests) green.
- Open questions R1–R5 resolved or explicitly deferred with owners before release tagging.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and exact SOURCE pointer.

1. **Public resolve endpoint is `GET /public/files/share/{linkId}/info`.** VERDICT: Corrected (spec said `GET /ui/files/share/{linkId}`). SOURCE: OpenAPI `GET /public/files/share/{link_id}/info` (op `get_share_link_info_endpoint_public_files_share__link_id__info_get`, resp `200:ShareLinkPublicInfoOut`); `src/api/endpoints/fileShareLinks.ts: getShareLinkInfo`.
2. **Public resolve response schema is `ShareLinkPublicInfoOut` with fields `file_name`, `file_size_bytes`, `content_type`, `requires_password`, `is_expired`, `is_revoked`, `is_used`, `remaining_downloads`.** VERDICT: Corrected (spec had `size_bytes`, `owner_display_name`, `expires_at`, `downloads_remaining`, `preview_url`, `revoked`, `link_id` — none exist). SOURCE: `components.schemas.ShareLinkPublicInfoOut` (openapi.pretty.json); `src/api/types.ts: ShareLinkPublicInfo`.
3. **Required fields are `file_name`, `file_size_bytes`, `content_type`; booleans default false; `remaining_downloads` defaults 0.** VERDICT: Verified. SOURCE: `components.schemas.ShareLinkPublicInfoOut.required` + per-field `default` (openapi.pretty.json).
4. **There is no `owner_display_name` / `expires_at` / `preview_url` in the public payload.** VERDICT: Corrected (these were invented; FR-4 referenced them). SOURCE: `components.schemas.ShareLinkPublicInfoOut` (no such properties); `src/api/types.ts: ShareLinkPublicInfo`.
5. **Download endpoint (native, GET) is `GET /public/files/share/{linkId}/download?password=`.** VERDICT: Corrected (spec said `/ui/files/share/{linkId}/download`). SOURCE: OpenAPI `GET /public/files/share/{link_id}/download` (op `download_share_link_get_endpoint...`, params `link_id,password`).
6. **The web client downloads via POST `/public/files/share/{linkId}/download` with JSON body `ShareLinkDownloadIn {password?}`.** VERDICT: Verified. SOURCE: `src/api/endpoints/fileShareLinks.ts: downloadShareLink` (method POST, body `{password}`); OpenAPI POST `download_share_link_endpoint...` reqBody `ShareLinkDownloadIn`; `components.schemas.ShareLinkDownloadIn` (`password` maxLength 128, nullable).
7. **Native must use the GET download form because `DownloadManager` is GET-only.** VERDICT: Unverified-assumption (framework constraint, not from sources). SOURCE: framework ref — Android `DownloadManager.Request` issues HTTP GET only (https://developer.android.com/reference/android/app/DownloadManager.Request).
8. **Password transport is `?password=` query (GET) or JSON `{password}` body (POST); there is NO `X-Share-Password` header.** VERDICT: Corrected (spec proposed `X-Share-Password`). SOURCE: OpenAPI GET download `params=link_id,password` (query); `components.schemas.ShareLinkDownloadIn`.
9. **Public info/download endpoints take no auth, no cookies, no CSRF.** VERDICT: Corrected (spec attached CSRF + cookie jar). SOURCE: `src/api/endpoints/fileShareLinks.ts` uses raw `fetch` (no `credentials`, no CSRF) for the public calls, unlike the `api` client (`src/api/client.ts` lines ~124/168 add `credentials:"include"` + `X-CSRF-Token`) used only for the owner `/ui/files/share-links*` calls.
10. **Password gate is detected from `requires_password==true` on the 200 info payload (not a 401/403 on resolve).** VERDICT: Corrected. SOURCE: `src/pages/files/PublicDownloadPage.tsx` (`data.requires_password` gates the password `Input`); OpenAPI info endpoint documents only `200/422`.
11. **A wrong password returns HTTP 403 on the download call → "Invalid password."** VERDICT: Verified. SOURCE: `src/pages/files/PublicDownloadPage.tsx: handleDownload` (`err.status === 403 → "Invalid password."`).
12. **Revoked/expired/used are 200-payload booleans (`is_revoked`/`is_expired`/`is_used`), not HTTP 410 on info.** VERDICT: Corrected (spec mapped 410 + `code` like `link_revoked`/`download_limit_reached`). SOURCE: `components.schemas.ShareLinkPublicInfoOut`; `src/pages/files/PublicDownloadPage.tsx: unavailableMessage()`.
13. **On the download call, HTTP 410 → "This link is no longer available."** VERDICT: Verified. SOURCE: `src/pages/files/PublicDownloadPage.tsx: handleDownload` (`err.status === 410`).
14. **There is no `download_limit_reached`/`LIMIT_REACHED` concept; `is_used` covers consumed/limit and `remaining_downloads` is informational.** VERDICT: Corrected. SOURCE: `components.schemas.ShareLinkPublicInfoOut` (only `is_used` + `remaining_downloads`); `unavailableMessage()` checks `is_used`.
15. **Not-found is signaled by any non-OK info response (web renders "Share link not found.").** VERDICT: Unverified-assumption for the exact status code (OpenAPI documents only `200/422` for info). SOURCE: `src/api/endpoints/fileShareLinks.ts: getShareLinkInfo` (throws on `!resp.ok`); `src/pages/files/PublicDownloadPage.tsx` (`isError → "Share link not found."`).
16. **Owner-side management endpoints are `GET/POST /ui/files/share-links` and `DELETE /ui/files/share-links/{link_id}` (AND-335, not this ticket).** VERDICT: Verified. SOURCE: OpenAPI lines for `list_share_links_endpoint...`, `create_share_link_endpoint...`, `revoke_share_link_endpoint...`; `src/api/endpoints/fileShareLinks.ts` (`createShareLink`/`listShareLinks`/`revokeShareLink`).
17. **Web page filename comes from `data.file_name` (fallback to Content-Disposition `filename="..."`).** VERDICT: Verified. SOURCE: `src/pages/files/PublicDownloadPage.tsx: handleDownload` (`data?.file_name || fileName`); `downloadShareLink` parses `Content-Disposition`.
18. **Web DTO type name is `ShareLinkPublicInfo` (not `PublicShare`).** VERDICT: Corrected (spec called the domain model `PublicShare`; acceptable as a *native* model name but the source DTO is `ShareLinkPublicInfo`). SOURCE: `src/api/types.ts: ShareLinkPublicInfo`.
19. **App Links require HTTPS + Digital Asset Links verification; cannot autoVerify the plaintext dev host.** VERDICT: Unverified-assumption (framework choice; not derivable from API/web). SOURCE: framework ref — Android App Links / `autoVerify` + `assetlinks.json` (https://developer.android.com/training/app-links/verify-android-applinks).
20. **`linkId` is URL-encoded in transit and decoded once.** VERDICT: Verified (web encodes). SOURCE: `src/api/endpoints/fileShareLinks.ts` (`encodeURIComponent(linkId)` on info + download).

### Corrections made
- Resolve path `/ui/files/share/{linkId}` → `GET /public/files/share/{linkId}/info` (§2, §3 FR-3, §5).
- Download path `/ui/files/share/{linkId}/download` → `GET /public/files/share/{linkId}/download?password=` (§3 FR-5, §4 enqueuer, §5, §15).
- Response field set rewritten to the real `ShareLinkPublicInfoOut` (`file_name`/`file_size_bytes`/`content_type`/`requires_password`/`is_expired`/`is_revoked`/`is_used`/`remaining_downloads`); removed invented `link_id`/`owner_display_name`/`expires_at`/`downloads_remaining`/`preview_url`/`revoked` (§4 sample, §5, FR-4).
- Removed owner-display-name and expiry-timestamp rendering from FR-4 (not in payload).
- Password transport corrected: query param / POST body only; removed `X-Share-Password` header proposal (§5, §8, R2).
- Removed CSRF + cookie-jar forwarding to `DownloadManager`; dropped `PersistentCookieJar` from `ShareDownloadEnqueuer`; removed AND-013 session-refresh-on-401 path for these public calls (§4, §5, §7, §8, §15, §11 enqueue test).
- Unavailability reclassified from HTTP 410 + `code` to 200-payload booleans; `UnavailableReason.LIMIT_REACHED` → `USED` (§4 enum, §5, §7, FR-8, §11).
- Password gate detection corrected from "200 or 401/403" to "200 payload `requires_password` flag"; wrong-password = download 403 (§3 FR-6, §5, §7, §11).
- Risks R1, R2, R5 marked RESOLVED; R4 marked partially resolved (§13).

### Open assumptions
- **Not-found HTTP status** for the info endpoint is unspecified — OpenAPI documents only `200`/`422`; the web client branches on `!resp.ok` without inspecting the status. Native classifies any non-2xx/non-422 info failure as `NotFound`. (Why: no contract source defines 404/410/4xx for info.)
- **Offline metadata caching / `ApiResult.Stale`** (FR-9, §6) is an AND-335 repository concern; neither the OpenAPI nor the web client model it (the web uses TanStack Query with `retry:false` and no offline cache). Treated as an internal design assumption, not a backend contract. (Why: not present in sources.)
- **App Link host split / `autoVerify` / `assetlinks.json`** (§8) is a framework + release-ops decision, not verifiable from API/web sources (framework ref cited above).
- **`DownloadManager` GET-only constraint** driving the GET-vs-POST choice is a framework fact (framework ref), not a project source.
- **Telemetry event shapes** (§10) are an internal analytics design; no source defines them.

## 17. Test Plan

IDs `TC-AND-392-NN`. "Traces" links to §14 Acceptance Criteria. Error shapes use the verified sources (info booleans; download 403/410). Default target is the headless emulator AVD `test35` (API 35) for instrumented/Compose suites unless a case needs API-34/arm64 or real hardware, in which case the physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34) is specified.

- **TC-AND-392-01 — Resolve happy path (non-gated).** Type: contract/MockWebServer (JVM). Target: JVM/Robolectric. Preconditions: MockWebServer returns `200 ShareLinkPublicInfoOut` with `requires_password=false`, all `is_*=false`. Steps: ViewModel `init` → `resolvePublicShare`. Expected: `GET /public/files/share/{linkId}/info` issued (no Cookie/CSRF header); state = `Resolved(stale=false)` with `file_name`/`file_size_bytes`/`content_type` mapped. Traces: AC-2.
- **TC-AND-392-02 — Download enqueue (non-gated).** Type: instrumented/e2e. Target: PHYSICAL DEVICE (real `DownloadManager` write to `Downloads/`). Preconditions: resolved non-gated state; MockWebServer (or test host) serves a small binary at `/public/files/share/{linkId}/download`. Steps: tap Download. Expected: `DownloadManager` enqueues `GET .../download` (no `?password=`, no Cookie/CSRF); file lands in public `Downloads/` with sanitized `file_name`; "Download started" snackbar. Traces: AC-2, AC-7. (MUST run on physical device — real DownloadManager + scoped storage on API 34.)
- **TC-AND-392-03 — Password-gated resolve renders prompt.** Type: Compose-UI. Target: emulator `test35`. Preconditions: info `200` with `requires_password=true`. Steps: render screen. Expected: file card shown; password field (`KeyboardType.Password`, reveal toggle) visible; Download disabled until a password is entered. Traces: AC-3.
- **TC-AND-392-04 — Correct password downloads.** Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: gated info; download endpoint returns `200` binary when `?password=<correct>` present. Steps: enter password, tap Download. Expected: enqueued URL contains `?password=<url-encoded>`; `DownloadEvent.Started`. Traces: AC-3.
- **TC-AND-392-05 — Wrong password → 403 inline error.** Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`. Preconditions: gated; download returns `403`. Steps: submit wrong password. Expected: inline field error "Invalid password." (mirrors web `status===403`); user stays on screen, can retry; no navigation. Traces: AC-3.
- **TC-AND-392-06 — Not-found terminal state.** Type: contract/MockWebServer + Compose-UI. Target: emulator `test35`. Preconditions: info fetch returns a non-OK response (e.g. 404). Steps: enter screen. Expected: state `NotFound` ("This link doesn’t exist"); Back present, **no** Retry; no retry GET issued. Traces: AC-4.
- **TC-AND-392-07 — Unavailable via payload flags.** Type: unit (JVM) + Compose-UI. Target: JVM/Robolectric + emulator `test35`. Preconditions: info `200` with (a) `is_revoked=true`, (b) `is_expired=true`, (c) `is_used=true` (three sub-cases). Steps: resolve each. Expected: `Unavailable(REVOKED/EXPIRED/USED)` with matching message; Back, no Retry. Traces: AC-4.
- **TC-AND-392-08 — Transient error → Retry re-issues idempotent GET.** Type: unit (JVM). Target: JVM/Robolectric (coroutines-test + Turbine). Preconditions: info fails with timeout/5xx then succeeds. Steps: observe `Loading → Error(retryable=true)`; call `retry()`. Expected: second `GET .../info` issued; `→ Loading → Resolved`. Traces: AC-5.
- **TC-AND-392-09 — Offline stale banner + disabled download.** Type: Compose-UI. Target: emulator `test35` (airplane mode / network off via test API). Preconditions: cached metadata exists; network fails. Steps: enter screen offline. Expected: `Resolved(stale=true)`; "Showing saved info" banner; Download disabled; tapping a (disabled) download path emits `DownloadEvent.OfflineNoDownload`, no enqueue. Traces: AC-5, AC-2. (Flaky-host/offline path.)
- **TC-AND-392-10 — App Link deep link (release, verified host).** Type: instrumented/e2e. Target: PHYSICAL DEVICE (real App Link verification + browser handoff). Steps: `adb -s R5CX821TA9R shell am start -W -a android.intent.action.VIEW -d "https://<verified-host>/share/9fK3xQ"`. Expected: app opens `PublicDownloadScreen` with `linkId=="9fK3xQ"`; `source="applink"`. Traces: AC-1. (MUST run on physical device for real autoVerify behavior; emulator `test35` can validate the intent-filter routing but not Digital Asset Links verification.)
- **TC-AND-392-11 — Custom-scheme deep link (all builds) + URL-decode.** Type: instrumented. Target: emulator `test35`. Steps: `am start -a VIEW -d "testlogon://share/a%20b"`. Expected: routes to screen with `linkId=="a b"` (decoded once); `source="deep_scheme"`. Traces: AC-1.
- **TC-AND-392-12 — Deep-link cold-start Back → home.** Type: instrumented. Target: emulator `test35`. Preconditions: app not running; launched via deep link onto empty back stack. Steps: press system Back. Expected: navigates to app start destination, app does not exit. Traces: AC-6.
- **TC-AND-392-13 — Filename sanitization & no-secret logging.** Type: unit (JVM). Target: JVM/Robolectric. Preconditions: `file_name = "../../etc/x.pdf"` (traversal) and an empty-name case; gated download with password. Steps: build enqueue request; capture logs. Expected: destination filename stripped of `../`/reserved chars (empty → `download-<linkId>`); logs contain only `linkId`+status — no password, no download URL (which carries `?password=`), no bytes. Traces: AC-7.
- **TC-AND-392-14 — Accessibility (TalkBack reading order + targets).** Type: Compose-UI (accessibility). Target: emulator `test35`. Preconditions: resolved gated state. Steps: assert semantics. Expected: file icon/thumbnail has `contentDescription "<file name>, <type>"`; Back labeled; reading order title → file name → size/type → downloads-remaining → Download; error/unavailable states `liveRegion=Polite`; Download/Retry ≥48dp; password field has accessible reveal toggle. Traces: AC-1, AC-3, AC-4.

### Coverage matrix
| AC (§14) | Covered by |
|---|---|
| AC-1 (deep links open correct linkId) | TC-10, TC-11, TC-12, TC-14 |
| AC-2 (resolve + DownloadManager download) | TC-01, TC-02, TC-09 |
| AC-3 (password prompt / correct / wrong) | TC-03, TC-04, TC-05, TC-14 |
| AC-4 (not-found + revoked/expired/used) | TC-06, TC-07, TC-14 |
| AC-5 (transient Retry + offline stale) | TC-08, TC-09 |
| AC-6 (deep-link cold-start Back → home) | TC-12 |
| AC-7 (no secret logging + sanitized filename) | TC-02, TC-13 |
| AC-8 (all tests green in CI) | TC-01…TC-14 (the suite itself) |
