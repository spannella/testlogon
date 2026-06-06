---
id: AND-385
title: Privacy / data export
milestone: M8
epic: E50
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-385 — Privacy / data export

## 1. Overview & Goal

Provide an authenticated, in-app **Privacy & Data Export** surface that lets a signed-in user (a) request a machine-readable export of their personal account data, (b) view the history/status of all of their export requests, and (c) download a completed export artifact to device storage. This implements the client side of the FastAPI privacy endpoints rooted at `/ui/privacy/account-deletion/export` plus the export-requests listing.

The goal is a self-service GDPR/CCPA-style "right to data portability" flow that is resilient against the unreliable plaintext dev backend (`http://18.222.237.167:8000`): export generation is asynchronous and server-side, so the client must model a request → polling/refresh → download lifecycle with clear pending/ready/expired/failed states and offline-tolerant UI.

Out of scope: actual **account deletion** execution (this ticket only consumes the *export* sub-resource of the account-deletion namespace), and any admin/back-office data tooling. Deletion confirmation is owned by a separate ticket in the E50 privacy epic.

## 2. Context & References

- **Module:** `feature-privacy` (new feature module under the `app -> feature-* -> core-*` layering). Depends on `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Dependency AND-027 (AuthApi / session endpoints):** supplies the authenticated, cookie-based Retrofit stack — persistent cookie jar, `ui_csrf` cookie echoed as `X-CSRF-Token`, single `POST /ui/session/refresh` retry on 401, and the shared `ApiResult<T>` type and FastAPI `detail` error mapping. All export calls reuse that authenticated `OkHttpClient`/`Retrofit` instance. No export endpoint is reachable for an anonymous user.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`. Web reference for endpoint shapes: `frontend/src/api/endpoints/privacy.ts` (or nearest privacy module) and shared types in `frontend/src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, DataStore for small prefs, Paging 3 optional for long request lists. minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Namespace:** `com.testlogon.android.feature.privacy` (export package `com.testlogon.android.feature.privacy.export`).

## 3. Functional Requirements

FR-1. **Request export.** A primary "Request data export" action issues `POST /ui/privacy/account-deletion/export`. On success the new request appears at the top of the requests list in a `PENDING` state. The action is disabled while a request is already `PENDING`/`PROCESSING` to prevent duplicate spam.

FR-2. **List requests.** The screen displays all of the user's prior export requests via `GET /ui/privacy/account-deletion/export` (collection), newest first, showing: requested-at timestamp, status, expiry (if ready), and a per-row affordance (Download when ready, Retry when failed, status chip otherwise).

FR-3. **Status refresh.** Because export generation is asynchronous, the list supports pull-to-refresh and an automatic bounded foreground poll (every ~10s, max ~5 polls, idempotent GET only) while any request is in a non-terminal state. Polling stops on terminal states (`READY`, `FAILED`, `EXPIRED`) or when the screen is not resumed.

FR-4. **Download artifact.** For a `READY` request, the user can download the export file via `GET /ui/privacy/account-deletion/export/{requestId}/download`. The downloaded bytes are written to the app's Downloads/MediaStore location and a completion notification/snackbar with an "Open" affordance is shown.

FR-5. **Empty / first-run state.** When the user has no export requests, show an explanatory empty state with the request CTA and a one-line description of what the export contains and typical readiness time.

FR-6. **Offline / stale state.** If the list cannot be fetched (network/timeout), show last-known cached requests (if any) tagged "Showing offline data" plus a retry button; never silently show an empty list as if no requests exist.

FR-7. **Auth gating.** Entering the screen while unauthenticated routes the user to the sign-in flow; a 401 mid-session is handled transparently by the AND-027 refresh-once-then-retry interceptor.

## 4. Technical Design

New module `feature-privacy`. Layering: Compose screen → `PrivacyExportViewModel` (StateFlow) → `PrivacyExportRepository` → `PrivacyApi` (Retrofit) + a small local cache.

**Retrofit service** (`core-network` or feature-local, injected via Hilt):

```kotlin
interface PrivacyApi {
    @POST("ui/privacy/account-deletion/export")
    suspend fun requestExport(): Response<ExportRequestDto>

    @GET("ui/privacy/account-deletion/export")
    suspend fun listExportRequests(): Response<ExportRequestListDto>

    @Streaming
    @GET("ui/privacy/account-deletion/export/{requestId}/download")
    suspend fun downloadExport(@Path("requestId") requestId: String): Response<ResponseBody>
}
```

`@Streaming` is mandatory on the download so the artifact is not buffered fully into memory; bytes are copied to a `MediaStore` `OutputStream` in `Dispatchers.IO`.

**Models** (`core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class ExportRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,        // pending|processing|ready|failed|expired
    @Json(name = "requested_at") val requestedAt: String,   // ISO-8601 UTC
    @Json(name = "expires_at") val expiresAt: String? = null,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
    @Json(name = "error") val error: String? = null,
)

@JsonClass(generateAdapter = true)
data class ExportRequestListDto(
    @Json(name = "items") val items: List<ExportRequestDto>,
)

enum class ExportStatus { PENDING, PROCESSING, READY, FAILED, EXPIRED, UNKNOWN }

data class ExportRequest(
    val id: String,
    val status: ExportStatus,
    val requestedAt: Instant,
    val expiresAt: Instant?,
    val sizeBytes: Long?,
    val error: String?,
) { val isTerminal get() = status in setOf(ExportStatus.READY, ExportStatus.FAILED, ExportStatus.EXPIRED) }
```

Unknown status strings map to `UNKNOWN` (forward-compatible) and render as a neutral chip without enabling download.

**Repository:**

```kotlin
class PrivacyExportRepository @Inject constructor(
    private val api: PrivacyApi,
    private val cache: ExportRequestCacheDataSource,   // see §6
    private val downloader: ExportDownloader,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun observeRequests(): Flow<List<ExportRequest>>             // cache-backed
    suspend fun refresh(): ApiResult<List<ExportRequest>>        // network -> cache
    suspend fun requestExport(): ApiResult<ExportRequest>
    suspend fun download(id: String): ApiResult<Uri>            // returns saved file Uri
}
```

**ViewModel & UiState:**

```kotlin
@HiltViewModel
class PrivacyExportViewModel @Inject constructor(
    private val repo: PrivacyExportRepository,
) : ViewModel() {
    val uiState: StateFlow<PrivacyExportUiState>
    fun onRequestExport()
    fun onDownload(id: String)
    fun onRefresh()
    fun onRetry(id: String)   // = onRequestExport when prior failed
}

data class PrivacyExportUiState(
    val requests: List<ExportRequestUi> = emptyList(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val requestInFlight: Boolean = false,
    val isOffline: Boolean = false,
    val downloading: Set<String> = emptySet(),
    val error: UiError? = null,        // transient, surfaced via snackbar
    val canRequest: Boolean = true,    // false while a non-terminal request exists
)

data class ExportRequestUi(
    val id: String,
    val statusLabel: String,
    val status: ExportStatus,
    val requestedAtDisplay: String,
    val expiresAtDisplay: String?,
    val sizeDisplay: String?,
    val downloadable: Boolean,
    val retryable: Boolean,
)
```

**Compose UI:** `PrivacyExportScreen(state, onRequestExport, onDownload, onRefresh, onRetry)` — Material 3 `Scaffold` + `TopAppBar`, `PullToRefreshBox`, `LazyColumn` of `ExportRequestRow`, an empty-state composable, an offline banner, and a `SnackbarHost`. A bottom-docked filled button drives "Request data export"; it is disabled when `!canRequest || requestInFlight`. Per-row trailing slot is `Download` button (`READY`), `Retry` button (`FAILED`), or status chip.

**Navigation:** route `privacy_export` added to the app `NavGraph`; reached from Settings → Privacy. The composable collects `uiState` with `collectAsStateWithLifecycle()`.

**Polling:** ViewModel launches a poll loop in `viewModelScope` guarded by a `DisposableEffect`/lifecycle-aware trigger from the screen (`LifecycleResumeEffect`). The loop runs only while `requests.any { !it.isTerminal }`, sleeps 10s, calls `repo.refresh()`, and caps at 5 iterations before requiring manual pull-to-refresh.

## 5. API Contract

All calls are authenticated (cookie jar + `X-CSRF-Token` from AND-027). Base path `/ui/privacy/account-deletion/export`.

**Create export request** — `POST /ui/privacy/account-deletion/export` (no body required; CSRF header required).

```json
// 201 / 200
{ "request_id": "exp_8f2c1", "status": "pending",
  "requested_at": "2026-06-05T14:03:11Z", "expires_at": null }
```

**List export requests** — `GET /ui/privacy/account-deletion/export` (idempotent; eligible for bounded backoff retry).

```json
// 200
{ "items": [
  { "request_id": "exp_8f2c1", "status": "ready",
    "requested_at": "2026-06-04T09:00:00Z", "expires_at": "2026-06-11T09:00:00Z",
    "size_bytes": 184320, "download_url": "/ui/privacy/account-deletion/export/exp_8f2c1/download" },
  { "request_id": "exp_7a9", "status": "expired",
    "requested_at": "2026-05-01T09:00:00Z", "expires_at": "2026-05-08T09:00:00Z" }
] }
```

**Download artifact** — `GET /ui/privacy/account-deletion/export/{requestId}/download`. Returns binary (`application/zip` or `application/json`), `Content-Disposition: attachment; filename=...`. 410 when expired, 409 when not yet ready, 404 unknown id.

**Errors:** FastAPI `detail` mapped per AND-027 convention — `detail` may be a `string`, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`. Notable codes: 401 → refresh-once-then-retry (handled by interceptor); 403 → CSRF/permission; 409 `export_in_progress`; 429 rate-limited (respect `Retry-After`); 410 `export_expired`.

If the actual field names diverge from the OpenAPI spec at integration time, prefer `/openapi.json` and `frontend/src/api/types.ts` and adjust the Moshi `@Json` names only — the domain model and UI contract stay fixed.

## 6. Data & State Management

- **Single source of truth:** `PrivacyExportRepository.observeRequests()` exposes a `Flow<List<ExportRequest>>` from a local cache; `refresh()` writes network results into that cache so the UI updates reactively.
- **Cache:** a lightweight Room table `export_requests` (`core-data`) keyed by `request_id` with columns mirroring `ExportRequest`. This satisfies FR-6 (offline/stale) by surviving process death and showing last-known requests. (Room is justified over DataStore because the data is a per-user list, not scalar prefs.)

```kotlin
@Entity(tableName = "export_requests")
data class ExportRequestEntity(
    @PrimaryKey val id: String, val status: String,
    val requestedAt: Long, val expiresAt: Long?,
    val sizeBytes: Long?, val error: String?, val syncedAt: Long,
)
```

- **DataStore:** stores only `last_export_synced_at` (epoch millis) to drive the "Showing offline data" freshness label.
- **State flow:** `uiState` is built by combining `observeRequests()` with internal mutable signals (loading, in-flight, downloading set, transient error) and exposed via `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)`.
- **Downloads:** written via `MediaStore.Downloads` (API 29+) or `MediaStore`/app-specific external dir fallback on API 24–28; filename `testlogon-export-<requestId>-<yyyyMMdd>.zip`. Saved `Uri` retained in state for the snackbar "Open" intent (`ACTION_VIEW`). Export files are user data and are not cached in the app sandbox beyond the download target.

## 7. Error Handling & Resilience

- **Timeouts:** reuse AND-027 OkHttp config (~20s call timeout) given the unreliable dev host. Downloads use a longer read timeout (no body-size cap from buffering thanks to `@Streaming`).
- **Retry policy:** only the idempotent `GET` list endpoint gets bounded exponential backoff (e.g., 3 attempts, 1s/2s/4s jitter). `POST` request-export and the download are **not** auto-retried (download retry is user-initiated to avoid duplicate large transfers; export creation re-press is gated by `canRequest`).
- **401:** delegated to AND-027 authenticator (single `POST /ui/session/refresh` then retry). If refresh fails, surface re-auth and navigate to sign-in.
- **409 export_in_progress:** treat as success-ish — refresh the list and keep the CTA disabled rather than showing an error.
- **429:** honor `Retry-After`; disable CTA for that interval and show a "please wait" snackbar.
- **410/expired:** mark row `EXPIRED`, hide Download, offer a fresh request.
- **Download failures (partial write):** delete the partial MediaStore entry, emit a retryable error snackbar; never leave a truncated file presented as complete.
- **Offline:** `refresh()` returning `ApiResult.NetworkError` sets `isOffline = true` and keeps cached rows visible.
- All terminal errors are mapped to a `UiError` with a human-readable message from the `detail` mapper plus a stable `code` for telemetry.

## 8. Security & Privacy

- Every request is authenticated; no export endpoint is callable anonymously. CSRF header (`X-CSRF-Token` from `ui_csrf` cookie) is attached to the mutating `POST` by the shared interceptor.
- **Dev backend is plaintext HTTP.** Network-security config must permit cleartext **only** for the dev host (`18.222.237.167`) via a scoped `network_security_config.xml` domain entry; production builds must require TLS. Export payloads contain PII, so cleartext transport is a known dev-only risk documented in §13.
- Exported file contents are user PII: do **not** log file bodies, download URLs with embedded tokens, or `request_id` values at INFO. Saved files go to user-visible Downloads by explicit user action only.
- No export data is written to logs, crash reports, or analytics payloads. The saved `Uri` is shared via `ACTION_VIEW` with a content URI (FileProvider / MediaStore), never a raw file path.
- Respect screenshot/secure-window policy consistent with the rest of the authenticated app (no special FLAG_SECURE required for the list, but file contents are never rendered in-app).

## 9. Accessibility & i18n

- All actionable controls (Request, Download, Retry, Refresh) have `contentDescription`/`semantics` and minimum 48dp touch targets. Status chips expose status as text, not color alone (color + label + optional icon).
- Live-region announcement when a request transitions to `READY` ("Export ready to download") and on download completion.
- All copy in `strings.xml` with no concatenation; timestamps and file sizes formatted via `DateUtils`/`Formatter.formatShortFileSize` for locale + RTL correctness. Relative time ("Requested 2 days ago") localized.
- Dynamic type / font scaling respected; rows reflow rather than truncate critical status text. Tested with TalkBack and 200% font scale.

## 10. Telemetry & Logging

- Events (via the app analytics abstraction, no PII): `privacy_export_requested`, `privacy_export_list_viewed`, `privacy_export_download_started`, `privacy_export_download_succeeded { size_bucket }`, `privacy_export_download_failed { error_code }`, `privacy_export_request_failed { error_code }`. Size is bucketed (e.g., `<1MB`, `1-10MB`, `>10MB`), never exact bytes tied to identity beyond that.
- `request_id` is hashed/truncated or omitted from analytics; only counts and error codes are reported.
- Logging at DEBUG only, redacting URLs and ids; WARN/ERROR for failed network calls with mapped `code` but no response bodies.

## 11. Testing Strategy

- **Unit (`core-testing` + MockWebServer):**
  - `PrivacyApi` paths/verbs match contract for create, list, download (`@Streaming` returns body).
  - Status string → `ExportStatus` mapping incl. `UNKNOWN`.
  - `detail` error mapping for string / list / object forms; 401→refresh→retry path; 409/429/410 handling.
- **Repository tests:** cache-then-network (`observeRequests` emits cached then refreshed); offline path keeps cache and sets offline; `download()` writes to a fake `OutputStream` and deletes partial on failure.
- **ViewModel tests** (`StandardTestDispatcher`, Turbine): `canRequest` toggles off while non-terminal request exists; polling loop runs only for non-terminal states and stops at terminal/unsubscribed; download set add/remove; retry maps to new request.
- **Compose UI tests:** empty state shows CTA; ready row shows Download and triggers callback; failed row shows Retry; offline banner visible on network error; semantics/contentDescriptions present.
- **Instrumented (optional):** real MediaStore write on an emulator (API 24 + API 35) verifying file is readable and openable.
- Coverage target: repository + viewmodel ≥ 80% line.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-027** (AuthApi/session endpoints) — provides the authenticated cookie+CSRF Retrofit client, `ApiResult<T>`, and the 401-refresh interceptor that all three privacy calls require. This ticket cannot integrate until AND-027 merges.
- Reuses existing `core-network`, `core-model`, `core-data`, `core-ui`, `core-testing` modules (assumed present from earlier milestones).
- **Sequencing:** (1) add `PrivacyApi` + DTOs + MockWebServer tests; (2) repository + Room cache; (3) ViewModel + state; (4) Compose screen + nav entry from Settings → Privacy; (5) MediaStore downloader + network-security cleartext scoping; (6) telemetry + a11y pass.
- **Blocks:** none currently listed; an account-deletion confirmation ticket in epic E50 may build on this screen's scaffolding but is not declared as blocked here.

## 13. Risks & Open Questions

- **Async readiness latency unknown.** Server-side generation time is undefined; bounded foreground polling (5×10s) may not catch readiness. Mitigation: rely on pull-to-refresh; revisit push/notification later. *Open: typical generation SLA?*
- **Exact endpoint shapes.** Field names (`request_id` vs `id`, list envelope `items` vs bare array, presence of `download_url`) must be confirmed against `/openapi.json` / `frontend` before merge. DTOs are isolated so only `@Json` names change.
- **Download URL form.** Whether `download` is a stable sub-path (assumed) or a one-time signed `download_url` returned in the list affects the download call. If signed URLs are used, call them directly (still through the authed client) instead of the `{requestId}/download` path. *Open.*
- **Plaintext PII transport** on dev host is a privacy risk acceptable only for dev; production must enforce TLS and is a release gate.
- **Rate limiting / quotas** on export creation are unspecified; 429 handling is implemented defensively. *Open: max concurrent/lifetime requests per user?*

## 14. Acceptance Criteria

AC-1. An authenticated user can tap "Request data export"; a `POST /ui/privacy/account-deletion/export` is sent with the CSRF header and a new `PENDING` row appears at the top of the list. (Satisfies backlog "Export requested".)
AC-2. The screen lists all prior export requests from `GET /ui/privacy/account-deletion/export`, newest first, with correct status chips, requested-at, and expiry. Unknown statuses render neutrally without enabling download.
AC-3. A `READY` request shows a Download action that fetches `GET .../{requestId}/download`, writes the file to Downloads via MediaStore, and shows a completion snackbar with "Open". (Satisfies "downloadable".)
AC-4. While any request is non-terminal, the CTA is disabled and bounded polling (≤5×, 10s) refreshes status until terminal or screen unsubscribed; pull-to-refresh always works.
AC-5. On network failure the list shows cached requests with an offline banner and a working Retry; it never shows a false empty state.
AC-6. 401 mid-session is resolved transparently by the AND-027 refresh-once interceptor; persistent auth failure routes to sign-in.
AC-7. MockWebServer tests prove paths/verbs/bodies and `detail` error mapping; ViewModel tests prove `canRequest` gating, polling lifecycle, and download set behavior.
AC-8. No export file contents, download URLs, or raw `request_id`s appear in logs or analytics.

## 15. Definition of Done

- `feature-privacy` module builds on Kotlin 2.0.21 / AGP 8.7.3 / compileSdk 35; lint and detekt clean; no new cleartext exposure outside the scoped dev host.
- `PrivacyApi`, DTOs, repository, Room cache, ViewModel, and Compose screen implemented with the signatures in §4; nav entry wired from Settings → Privacy under `com.testlogon.android.feature.privacy`.
- All §11 unit/repository/ViewModel/Compose tests pass in CI with ≥80% coverage on repository + ViewModel; one instrumented MediaStore download test green on API 24 and API 35 emulators.
- Acceptance criteria AC-1…AC-8 verified against the dev backend (or MockWebServer where the dev host is unavailable).
- a11y verified with TalkBack + 200% font scale; all strings externalized and RTL-safe.
- Telemetry events emit with bucketed/redacted fields only; PRIVACY review sign-off on logging/transport notes in §8/§13.
- PR merged to `android-port`; depends-on AND-027 confirmed merged; open questions in §13 either resolved or filed as follow-ups.
