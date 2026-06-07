---
id: AND-385
title: Privacy / data export
milestone: M8
epic: E50
priority: P1
size: M
status: reviewed
depends_on: [AND-027]
blocks: []
reviewed_on: 2026-06-06
---

# AND-385 — Privacy / data export

## 1. Overview & Goal

Provide an authenticated, in-app **Privacy & Data Export** surface that lets a signed-in user (a) request a machine-readable export of their personal account data (selecting which data categories to include), (b) view the status of an export request, and (c) download a completed export artifact to device storage. This implements the client side of the FastAPI privacy endpoints rooted at `/ui/privacy/account-deletion/export`.

> **REVIEW CORRECTION (scope).** The backend exposes **no** "list all export requests" endpoint. The export sub-resource is exactly three operations: `POST /ui/privacy/account-deletion/export` (create — returns the status object immediately), `GET /ui/privacy/account-deletion/export/{request_id}` (single-request status poll), and `GET /ui/privacy/account-deletion/export/{request_id}/download`. The web reference (`src/pages/settings/AccountDeletionPage.tsx`) therefore tracks **one** latest export status object in component state, not a list, and does not poll it. A general privacy-request history (covering both exports and deletions) is available separately via `GET /ui/privacy/requests` → `DataRequestListOut` (each `DataRequest` has `request_type: "export" | "deletion"`); if a true history list is desired on Android, use that endpoint, not the export sub-resource. See §16.

The goal is a self-service GDPR/CCPA-style "right to data portability" flow that is resilient against the unreliable plaintext dev backend (`http://18.222.237.167:8000`): the client must model a request → status → download lifecycle with clear pending/processing/completed/failed states and offline-tolerant UI. (Note: the backend `PrivacyExportStatusOut` returned by the create call may already carry a `download_url`; whether generation is truly asynchronous with a long pending window is an **unverified assumption** — the web client treats the create response as immediately actionable. See §16.)

Out of scope: actual **account deletion** execution (this ticket only consumes the *export* sub-resource of the account-deletion namespace), and any admin/back-office data tooling. Deletion confirmation is owned by a separate ticket in the E50 privacy epic.

## 2. Context & References

- **Module:** `feature-privacy` (new feature module under the `app -> feature-* -> core-*` layering). Depends on `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Dependency AND-027 (AuthApi / session endpoints):** supplies the authenticated Retrofit stack — single `POST /ui/session/refresh` retry on 401, and the shared `ApiResult<T>` type and FastAPI `detail` error mapping. All export calls reuse that authenticated `OkHttpClient`/`Retrofit` instance. No export endpoint is reachable for an anonymous user. **REVIEW CORRECTION (auth shape):** per the web reference (`src/api/client.ts`), the transport sends THREE auth-related headers, not just a cookie jar: `Authorization: Bearer <accessToken>` (from the auth store), `X-CSRF-Token` (read from the `ui_csrf` cookie), and an optional `X-IMPERSONATION-TOKEN`. The `X-CSRF-Token` header is attached to **every** request (GET and POST alike), not only mutating calls. `credentials: include` is set so cookies still flow. The Android client must mirror whatever AND-027 actually implements for these headers; treat "cookie-jar-only" as inaccurate.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`. Web reference for endpoint shapes: `src/api/endpoints/accountDeletion.ts` (the privacy export/deletion calls live here, not a `privacy.ts`), the screen `src/pages/settings/AccountDeletionPage.tsx`, and shared types in `src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, DataStore for small prefs, Paging 3 optional for long request lists. minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Namespace:** `com.testlogon.android.feature.privacy` (export package `com.testlogon.android.feature.privacy.export`).

## 3. Functional Requirements

FR-1. **Request export.** A primary "Request data export" action issues `POST /ui/privacy/account-deletion/export`. **REVIEW CORRECTION:** this POST requires a JSON body `PrivacyExportRequestIn` = `{ "categories": { "<key>": <bool>, ... } }` (a map of data-category keys to include-flags), NOT an empty body. The web client offers category checkboxes (`profile, messages, posts, billing, files, contacts, calendar, subscriptions, push_devices, tickets, sessions`), defaulting all to `true`. The response is a `PrivacyExportStatusOut` (status `201`). On success the returned status (with its `request_id` and possibly a `download_url`) becomes the current/latest export shown to the user. The action is disabled while a request is already in a non-terminal state to prevent duplicate spam.

FR-2. **Show export status / history.** **REVIEW CORRECTION:** there is no `GET /ui/privacy/account-deletion/export` collection endpoint — it does not exist. Two correct options: (a) MINIMAL (matches web): keep the single latest `PrivacyExportStatusOut` returned by the create call and refresh it via `GET /ui/privacy/account-deletion/export/{request_id}`; (b) HISTORY (Android enhancement, satisfies the backlog "requests list"): fetch `GET /ui/privacy/requests` → `DataRequestListOut { requests: DataRequest[], next_cursor? }`, filter `request_type == "export"`, newest first, showing: `created_at` timestamp, `status`, `grace_period_ends_at`/expiry if present, and a per-row affordance (Download when `export_download_url` present, Retry when failed, status chip otherwise). This spec adopts option (b) for the history list and option (a)'s single-request GET for live status of an in-flight request.

FR-3. **Status refresh.** The status of a specific request is refreshed via the idempotent `GET /ui/privacy/account-deletion/export/{request_id}` (single request) and/or `GET /ui/privacy/requests` for the history list. The screen supports pull-to-refresh and an automatic bounded foreground poll (every ~10s, max ~5 polls, idempotent GET only) while a tracked request is in a non-terminal state. **REVIEW NOTE:** the web client does NOT poll export status (it treats the create response as immediately actionable); bounded polling is an Android-side defensive addition for the case where the create response status is `pending`/`processing`. Polling stops on terminal states (`completed`, `failed`, `cancelled`) or when the screen is not resumed.

FR-4. **Download artifact.** For a `READY` request, the user can download the export file via `GET /ui/privacy/account-deletion/export/{requestId}/download`. The downloaded bytes are written to the app's Downloads/MediaStore location and a completion notification/snackbar with an "Open" affordance is shown.

FR-5. **Empty / first-run state.** When the user has no export requests, show an explanatory empty state with the request CTA and a one-line description of what the export contains and typical readiness time.

FR-6. **Offline / stale state.** If the list cannot be fetched (network/timeout), show last-known cached requests (if any) tagged "Showing offline data" plus a retry button; never silently show an empty list as if no requests exist.

FR-7. **Auth gating.** Entering the screen while unauthenticated routes the user to the sign-in flow; a 401 mid-session is handled transparently by the AND-027 refresh-once-then-retry interceptor.

## 4. Technical Design

New module `feature-privacy`. Layering: Compose screen → `PrivacyExportViewModel` (StateFlow) → `PrivacyExportRepository` → `PrivacyApi` (Retrofit) + a small local cache.

**Retrofit service** (`core-network` or feature-local, injected via Hilt):

**REVIEW CORRECTION:** the original interface listed a non-existent `GET ui/privacy/account-deletion/export` collection and a body-less POST. Corrected interface (verified against OpenAPI index lines 1732–1734, 1742 and `src/api/endpoints/accountDeletion.ts`):

```kotlin
interface PrivacyApi {
    // POST takes a PrivacyExportRequestIn body; returns 201 PrivacyExportStatusOut
    @POST("ui/privacy/account-deletion/export")
    suspend fun requestExport(@Body body: ExportRequestBodyDto): Response<ExportStatusDto>

    // Single-request status poll (NOT a collection)
    @GET("ui/privacy/account-deletion/export/{requestId}")
    suspend fun getExport(@Path("requestId") requestId: String): Response<ExportStatusDto>

    @Streaming
    @GET("ui/privacy/account-deletion/export/{requestId}/download")
    suspend fun downloadExport(@Path("requestId") requestId: String): Response<ResponseBody>

    // History list (covers export + deletion request types); filter request_type == "export"
    @GET("ui/privacy/requests")
    suspend fun listPrivacyRequests(): Response<DataRequestListDto>
}
```

`@Streaming` is mandatory on the download so the artifact is not buffered fully into memory; bytes are copied to a `MediaStore` `OutputStream` in `Dispatchers.IO`.

**Models** (`core-model`):

**REVIEW CORRECTION:** the original DTO field names/types were wrong. Verified shapes against OpenAPI `components.schemas.PrivacyExportStatusOut`, `PrivacyExportRequestIn`, `DataRequestListOut`/`DataRequest`, and `src/api/types.ts`. Key fixes: timestamps are **integer epoch seconds**, not ISO-8601 strings; the size field is `file_size_bytes` (not `size_bytes`); the expiry field is `download_expires_at` (not `expires_at`); there is **no `error` field** on the export status; the list response uses key `requests` from `DataRequestListOut` (not `items`); the POST body carries a `categories` map.

```kotlin
// POST body — PrivacyExportRequestIn
@JsonClass(generateAdapter = true)
data class ExportRequestBodyDto(
    @Json(name = "categories") val categories: Map<String, Boolean>,
)

// Response — PrivacyExportStatusOut (required: request_id, status, created_at)
@JsonClass(generateAdapter = true)
data class ExportStatusDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,                 // free-form string; see mapping below
    @Json(name = "created_at") val createdAt: Long,            // epoch SECONDS (integer)
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "download_expires_at") val downloadExpiresAt: Long? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
    @Json(name = "categories_requested") val categoriesRequested: Int = 0,
    @Json(name = "data") val data: Map<String, Any?>? = null,  // inline payload, may be null
)

// History list — DataRequestListOut (each row is a DataRequest with request_type "export"|"deletion")
@JsonClass(generateAdapter = true)
data class DataRequestListDto(
    @Json(name = "requests") val requests: List<DataRequestDto>,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class DataRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "request_type") val requestType: String,     // "export" | "deletion"
    @Json(name = "status") val status: String,                // pending|processing|completed|cancelled|failed|rejected|held
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "export_size_bytes") val exportSizeBytes: Long? = null,
    @Json(name = "export_download_url") val exportDownloadUrl: String? = null,
)

// Domain status enum. Strings observed: pending, processing, completed, cancelled, failed, rejected, held.
enum class ExportStatus { PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED, REJECTED, HELD, UNKNOWN }

data class ExportRequest(
    val id: String,
    val status: ExportStatus,
    val createdAt: Instant,            // built from epoch seconds * 1000
    val downloadExpiresAt: Instant?,
    val sizeBytes: Long?,
    val downloadUrl: String?,
) { val isTerminal get() = status in setOf(ExportStatus.COMPLETED, ExportStatus.FAILED, ExportStatus.CANCELLED, ExportStatus.REJECTED) }
```

Unknown status strings map to `UNKNOWN` (forward-compatible) and render as a neutral chip without enabling download. The export status is a free-form `string` in the schema; `READY`/`EXPIRED` were assumed in the original draft — the actual web/`DataRequest` vocabulary is `pending|processing|completed|cancelled|failed|rejected|held`, so "completed" (with a non-null `download_url`) is the downloadable state and there is no distinct "ready"/"expired" status (expiry is implied by `download_expires_at` having passed).

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

All calls are authenticated (`Authorization: Bearer`, `X-CSRF-Token`, cookies via AND-027). Base path `/ui/privacy/account-deletion/export`. **REVIEW CORRECTION:** the original §5 examples used wrong field names, a fictional list envelope, and unverified error codes — corrected below against OpenAPI (index lines 1732–1734) and `src/api/types.ts`.

**Create export request** — `POST /ui/privacy/account-deletion/export` (CSRF header + JSON body required; returns `201`).

```jsonc
// request body — PrivacyExportRequestIn
{ "categories": { "profile": true, "messages": true, "billing": false } }

// 201 response — PrivacyExportStatusOut (created_at is epoch SECONDS, integer)
{ "request_id": "exp_8f2c1", "status": "completed",
  "created_at": 1749132191, "completed_at": 1749132195,
  "download_url": "/ui/privacy/account-deletion/export/exp_8f2c1/download",
  "download_expires_at": 1749736991, "file_size_bytes": 184320,
  "categories_requested": 2, "data": null }
```

**Get single export status** — `GET /ui/privacy/account-deletion/export/{request_id}` → `PrivacyExportStatusOut` (200). Idempotent; eligible for bounded backoff retry. (There is NO collection endpoint at `/ui/privacy/account-deletion/export`.)

**History list (export + deletion)** — `GET /ui/privacy/requests` → `DataRequestListOut` (200).

```jsonc
// 200 — DataRequestListOut
{ "requests": [
  { "request_id": "exp_8f2c1", "request_type": "export", "status": "completed",
    "created_at": 1749045600, "completed_at": 1749045630,
    "export_size_bytes": 184320,
    "export_download_url": "/ui/privacy/account-deletion/export/exp_8f2c1/download" },
  { "request_id": "del_7a9", "request_type": "deletion", "status": "pending",
    "created_at": 1746090000, "grace_period_ends_at": 1746694800 }
], "next_cursor": null }
```

**Download artifact** — `GET /ui/privacy/account-deletion/export/{request_id}/download`. Returns binary; in OpenAPI the response is declared only as `200` (untyped body) and `422` HTTPValidationError. `Content-Disposition`/content-type behavior (e.g. `application/zip`) is an **unverified assumption** (not declared in OpenAPI); the client must read `Content-Type`/`Content-Disposition` defensively rather than hard-code `.zip`.

**Errors:** FastAPI `detail` mapped per AND-027 convention — `detail` may be a `string`, `[{ "msg": "..." }]`, or `{ "code": "...", ... }` (see `normalizeErrorDetail`/`mapAuthorizationError` in `src/api/client.ts`). **REVIEW CORRECTION:** OpenAPI declares ONLY `422 HTTPValidationError` (plus the implicit `200`/`201`) for all three export endpoints and `/ui/privacy/requests`. The previously asserted `409 export_in_progress`, `410 export_expired`, and `429`/`Retry-After` codes are **unverified assumptions** not present in the spec — keep that handling as defensive-only and do not treat those codes/bodies as contractually guaranteed. `401` (refresh-once-then-retry) and `403` (permission, with `code`-based messages) are handled by the shared AND-027 transport.

If field names diverge at integration time, prefer `/openapi.json` and `src/api/types.ts` and adjust the Moshi `@Json` names only — the domain model and UI contract stay fixed.

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
- **409 export_in_progress (UNVERIFIED — not in OpenAPI):** if the backend ever returns it, treat as success-ish — refresh status and keep the CTA disabled rather than showing an error. Do not depend on this code existing.
- **429 (UNVERIFIED — not in OpenAPI):** if returned, honor `Retry-After`; disable CTA for that interval and show a "please wait" snackbar.
- **Expiry:** there is no `410`/`EXPIRED` status in the contract; expiry is inferred from `download_expires_at` (epoch) being in the past. When past, hide Download, mark the row expired (UI-only), and offer a fresh request.
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
- **Exact endpoint shapes.** RESOLVED in this review: there is no export collection endpoint; status fields are `request_id`/`status`/`created_at`(epoch)/`completed_at`/`download_url`/`download_expires_at`/`file_size_bytes`/`categories_requested`/`data`; the history list lives at `GET /ui/privacy/requests` with envelope key `requests` (not `items`). See §16. DTOs remain isolated so only `@Json` names change if the backend evolves.
- **Download URL form.** The status object returns `download_url` (web `PrivacyExportStatus.download_url`, list `DataRequest.export_download_url`) AND a stable `{request_id}/download` sub-path exists. The web client links directly to `download_url`. *Open:* whether `download_url` is a one-time signed URL vs the same stable sub-path is not stated in OpenAPI; prefer calling the returned `download_url` (resolved against the API base) through the authed client, falling back to the `{request_id}/download` path. The `download_url` values in the schema appear to be relative paths, so resolve against the API base before use.
- **Plaintext PII transport** on dev host is a privacy risk acceptable only for dev; production must enforce TLS and is a release gate.
- **Rate limiting / quotas** on export creation are unspecified; 429 handling is implemented defensively. *Open: max concurrent/lifetime requests per user?*

## 14. Acceptance Criteria

AC-1. An authenticated user can tap "Request data export"; a `POST /ui/privacy/account-deletion/export` is sent with the CSRF header and a `PrivacyExportRequestIn` `{ categories }` body, the returned `PrivacyExportStatusOut` becomes the current export, and a corresponding row appears at the top of the history list. (Satisfies backlog "Export requested".)
AC-2. The screen lists prior privacy requests from `GET /ui/privacy/requests` (filtered to `request_type == "export"`), newest first by `created_at`, with correct status chips, created-at, and expiry. Unknown statuses render neutrally without enabling download. (CORRECTED: the export sub-resource has no list endpoint; `/ui/privacy/requests` is the listing source.)
AC-3. A `completed` request with a non-null `download_url` shows a Download action that fetches `GET .../{request_id}/download` (or the returned `download_url`), writes the file to Downloads via MediaStore, and shows a completion snackbar with "Open". (Satisfies "downloadable".)
AC-4. While a tracked request is non-terminal, the CTA is disabled and bounded polling (≤5×, 10s) via `GET .../export/{request_id}` (and/or `/ui/privacy/requests`) refreshes status until terminal or screen unsubscribed; pull-to-refresh always works.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI full `reference/openapi.pretty.json` (`components.schemas.*`), and frontend `reference/src/*`.

1. **POST create export endpoint** is `POST /ui/privacy/account-deletion/export`. **Verified.** OpenAPI `POST /ui/privacy/account-deletion/export` (index line 1732, op `create_export_ui_privacy_account_deletion_export_post`); `src/api/endpoints/accountDeletion.ts: requestPrivacyExport`.
2. **POST returns `201` with `PrivacyExportStatusOut`.** **Verified.** index line 1732 (`resp=201:PrivacyExportStatusOut`).
3. **POST requires a JSON body `PrivacyExportRequestIn` = `{ categories: Map<String,Boolean> }`** (original draft said "no body required"). **Corrected.** OpenAPI `req=PrivacyExportRequestIn` (index line 1732); schema `components.schemas.PrivacyExportRequestIn` (`categories`: object of booleans); `src/api/types.ts: PrivacyExportRequestBody`; web sends `{ categories }` (`AccountDeletionPage.tsx`, `EXPORT_CATEGORIES`).
4. **No export collection endpoint** `GET /ui/privacy/account-deletion/export` (original draft asserted one returning `{ items: [...] }`). **Corrected.** No such path in `openapi.index.txt`; only `GET .../export/{request_id}` (line 1733) and `.../{request_id}/download` (line 1734) exist; `accountDeletion.ts` has no list-exports call.
5. **Single-request status** is `GET /ui/privacy/account-deletion/export/{request_id}` → `PrivacyExportStatusOut`. **Verified.** index line 1733 (op `get_export_...`); `accountDeletion.ts: getPrivacyExport`.
6. **History list** source is `GET /ui/privacy/requests` → `DataRequestListOut`. **Verified.** index line 1742 (op `list_privacy_requests_...`, `resp=200:DataRequestListOut`); `src/api/types.ts: DataRequestListResp { requests, next_cursor }` and `DataRequest { request_type: "export"|"deletion", ... }`.
7. **Status field shape** `PrivacyExportStatusOut`: `request_id`(str, req), `status`(str, req), `created_at`(int epoch, req), `completed_at`(int|null), `download_url`(str|null), `download_expires_at`(int|null), `file_size_bytes`(int|null), `categories_requested`(int), `data`(obj|null). **Corrected** (draft used `requested_at` ISO string, `expires_at`, `size_bytes`, and an `error` field that does not exist). Source: `components.schemas.PrivacyExportStatusOut` (openapi.pretty.json ~line 57251); `src/api/types.ts: PrivacyExportStatus`.
8. **Timestamps are integer epoch seconds, not ISO-8601 strings.** **Corrected.** `created_at`/`completed_at`/`download_expires_at` typed `integer` in `PrivacyExportStatusOut`; web renders `new Date(r.created_at * 1000)` (`AccountDeletionPage.tsx`).
9. **List envelope key is `requests` (not `items`)**, with optional `next_cursor`. **Corrected.** `components.schemas.DataRequestListOut`; `src/api/types.ts: DataRequestListResp`.
10. **Download endpoint** `GET /ui/privacy/account-deletion/export/{request_id}/download`. **Verified.** index line 1734 (op `download_export_...`); `accountDeletion.ts: privacyExportDownloadUrl`.
11. **Download content-type `application/zip` + `Content-Disposition: attachment`.** **Unverified-assumption.** OpenAPI declares only `resp=200:` (untyped) `;422:HTTPValidationError` for line 1734 — no media type. Client must read headers defensively. (why unverifiable: response body media type absent from the spec.)
12. **Error codes `409 export_in_progress`, `410 export_expired`, `429`/`Retry-After` for export.** **Unverified-assumption (likely incorrect).** All four export/requests endpoints declare only `422 HTTPValidationError` in OpenAPI (index lines 1732–1734, 1742). No 409/410/429 declared. Kept as defensive-only.
13. **`detail` may be string / `[{msg}]` / `{code,...}` and is mapped to a message.** **Verified.** `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError` (handles `role_required*`, geo_blocked, etc.); schema `components.schemas.HTTPValidationError` uses the `[{loc,msg,type}]` form.
14. **401 → single `POST /ui/session/refresh` then retry once; persistent failure → logout/sign-in.** **Verified.** `src/api/client.ts: refreshSession` + 401 branch (single in-flight `refreshPromise`, retry, `logout("session_expired")`).
15. **Auth headers: `Authorization: Bearer`, `X-CSRF-Token` (from `ui_csrf` cookie) on every request, optional `X-IMPERSONATION-TOKEN`, `credentials: include`.** **Corrected** (draft said cookie-jar-only and CSRF on mutating POST only). Source: `src/api/client.ts` (header construction, applies to GET and POST). Note: per-endpoint `params` in the index also list `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`/`user_sub` — exact server auth scheme is owned by AND-027.
16. **No export endpoint is reachable anonymously.** **Verified (by design).** All privacy endpoints are under `/ui/...` behind the authed transport; `client.ts` propagates 401 for unauthenticated callers.
17. **Web export flow is effectively immediate (no polling); create response carries actionable `download_url`.** **Verified.** `AccountDeletionPage.tsx: exportMut` sets `lastExport = res` and toasts "Data export ready" with a direct `download_url` link; no polling code. Android bounded polling is an additive defensive design, not a web-parity requirement.
18. **Status vocabulary `pending|processing|completed|cancelled|failed|rejected|held`** (draft used `ready`/`expired`). **Corrected.** `src/api/types.ts: DataRequest.status` union; `PrivacyExportStatusOut.status` is free-form `string` so `UNKNOWN` mapping is retained for forward-compat.
19. **Export categories** keys (`profile, messages, posts, billing, files, contacts, calendar, subscriptions, push_devices, tickets, sessions`). **Verified.** `AccountDeletionPage.tsx: EXPORT_CATEGORIES`.
20. **Framework choices** — Jetpack Compose Material 3 `PullToRefreshBox`, `collectAsStateWithLifecycle`, MediaStore Downloads (API 29+) with pre-29 fallback, Retrofit `@Streaming`. **Unverified-assumption (framework ref).** Not derivable from backend/frontend sources; standard Android APIs (framework refs: developer.android.com/jetpack/compose, developer.android.com/training/data-storage/shared/media, square.github.io/retrofit). Reasonable engineering defaults; not contractually constrained.

### Corrections made
- Removed the fictional `GET /ui/privacy/account-deletion/export` collection endpoint; replaced the history-list source with `GET /ui/privacy/requests` (`DataRequestListOut`, key `requests`) and the per-request status source with `GET .../export/{request_id}` (§1, §3 FR-2/FR-3, §4 interface, §5, §14 AC-2/AC-4).
- POST now correctly requires a `PrivacyExportRequestIn` `{ categories }` body (§3 FR-1, §4, §5, §14 AC-1).
- DTO fields corrected: epoch-integer timestamps; `file_size_bytes`, `download_expires_at`, `categories_requested`, `data`; removed nonexistent `error` and `expires_at`/`requested_at`/`size_bytes` (§4 models, §5 examples).
- Status enum corrected to the real vocabulary; `READY`/`EXPIRED` replaced (expiry inferred from `download_expires_at`) (§4, §7, §14).
- Error-code handling for 409/410/429 demoted to defensive/unverified; OpenAPI declares only 422 (§5, §7).
- Auth model corrected to Bearer + per-request `X-CSRF-Token` + optional impersonation header (§2, §5).

### Open assumptions
- **Download media type / `Content-Disposition`** — not in OpenAPI (response body untyped). Filename/extension must be derived from headers at runtime. (claim 11)
- **Export generation asynchrony / SLA** — web treats create as immediate; whether `status` can legitimately stay `pending`/`processing` for long is unknown, so bounded polling is precautionary. (claim 17, §13)
- **`download_url` signed vs stable** — both a returned `download_url` and a stable `{request_id}/download` path exist; whether the URL is one-time-signed is unstated. (§13)
- **409/429 rate-limit/quota semantics** — undeclared in OpenAPI; handled defensively only. (claim 12)
- **Exact server auth enforcement** (`X-SESSION-ID`, `user_sub`, impersonation) is owned by AND-027 and not re-derived here. (claim 15)

## 17. Test Plan

IDs `TC-AND-385-NN`. Targets: JVM/Robolectric (local), emulator AVD `test35` (x86_64, API 35), and PHYSICAL DEVICE Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). MediaStore/file-download and notification-tap cases that exercise real OS storage/UX SHOULD run on the physical device; ABI/API-34-vs-35 differences MUST be checked on both the physical device and `test35`.

- **TC-AND-385-01 — Happy path: request export.** Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: authenticated stack stubbed; MockWebServer enqueues `201` `PrivacyExportStatusOut` with `status:"completed"`, non-null `download_url`. Steps: call `PrivacyApi.requestExport({categories})`; assert request method `POST`, path `/ui/privacy/account-deletion/export`, `X-CSRF-Token` header present, body JSON `{ "categories": {...} }`; map response to `ExportRequest`. Expected: parsed `ExportStatusDto` has `createdAt` (epoch), `downloadUrl` non-null, `status` → `COMPLETED`; domain `isTerminal == true`. Traces: AC-1.
- **TC-AND-385-02 — Status field mapping incl. epoch + UNKNOWN.** Type: unit. Target: JVM. Preconditions: sample JSON bodies. Steps: deserialize `PrivacyExportStatusOut` with integer `created_at`/`download_expires_at`; map status strings `pending/processing/completed/cancelled/failed/rejected/held/wibble`. Expected: timestamps become `Instant` via `*1000`; known strings map to enum, `wibble`→`UNKNOWN` (no download enabled); absence of `error`/`size_bytes` fields does not break parsing. Traces: AC-2.
- **TC-AND-385-03 — History list from `/ui/privacy/requests`.** Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200` `DataRequestListOut` with mixed `request_type` rows + `next_cursor`. Steps: call `listPrivacyRequests()`; filter `request_type=="export"`, sort by `created_at` desc. Expected: only export rows kept; envelope key `requests` parsed (not `items`); a `completed` row with `export_download_url` is `downloadable`. Traces: AC-2.
- **TC-AND-385-04 — `detail` error mapping (string / list / object).** Type: unit. Target: JVM. Preconditions: three `422`/`403` bodies: `{"detail":"nope"}`, `{"detail":[{"msg":"bad","loc":[...]}]}`, `{"detail":{"code":"role_required"}}`. Steps: run through the AND-027 `detail` mapper. Expected: messages `"nope"`, `"bad"`, and the humanized role message respectively; stable `code` preserved for telemetry. Traces: AC-7.
- **TC-AND-385-05 — 401 → refresh-once → retry.** Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the retried list GET. Steps: trigger `refresh()`. Expected: exactly one `/ui/session/refresh` POST; original request retried once and succeeds; on a second `401` after refresh, surface re-auth/navigate to sign-in. Traces: AC-6.
- **TC-AND-385-06 — Offline keeps cache, no false empty.** Type: integration (repository). Target: JVM/Robolectric. Preconditions: Room cache pre-seeded with 2 export rows; network call throws (timeout/`NetworkError`). Steps: `observeRequests()` then `refresh()`. Expected: cached rows still emitted; `isOffline=true`; "Showing offline data" label; never an empty list. Maps to the flaky-dev-host/offline path. Traces: AC-5.
- **TC-AND-385-07 — `canRequest` gating + polling lifecycle.** Type: unit (ViewModel, Turbine + `StandardTestDispatcher`). Target: JVM. Preconditions: a tracked request in `processing`. Steps: collect `uiState`; advance virtual time. Expected: `canRequest=false` while non-terminal; poll loop calls status GET ≤5×/10s, stops on terminal (`completed`) or on unsubscribe; CTA re-enables at terminal. Traces: AC-4.
- **TC-AND-385-08 — Download writes to MediaStore + Open intent.** Type: instrumented/e2e. Target: PHYSICAL DEVICE (real MediaStore/Downloads + `ACTION_VIEW`). Preconditions: a `completed` export with reachable download (MockWebServer or dev host) returning bytes + `Content-Disposition`. Steps: tap Download; stream bytes via `@Streaming` to `MediaStore.Downloads`; tap "Open" in snackbar. Expected: file saved with header-derived name, readable, opens via content URI; no raw file path leaked. MUST run on physical device for real storage/intent behavior. Traces: AC-3.
- **TC-AND-385-09 — Download partial-failure cleanup.** Type: integration (repository). Target: JVM/Robolectric (fake `OutputStream`). Preconditions: stream throws mid-write. Steps: invoke `download(id)`. Expected: partial MediaStore entry deleted; retryable error surfaced; no truncated file presented as complete. Traces: AC-3, AC-5.
- **TC-AND-385-10 — ABI/API parity for MediaStore download.** Type: instrumented. Target: BOTH emulator `test35` (API 35, x86_64) AND physical device (API 34, arm64-v8a). Preconditions: same `completed` export fixture. Steps: run TC-08 download assertions on each. Expected: identical saved-file result on API 34/arm64 and API 35/x86_64 (covers pre-29 vs 29+ MediaStore path if a minSdk emulator is also used). Traces: AC-3.
- **TC-AND-385-11 — Security: anonymous access blocked + no PII in logs.** Type: integration + manual log inspection. Target: JVM/Robolectric. Preconditions: unauthenticated state; logcat capture. Steps: attempt to enter screen / call endpoints unauthenticated; perform a full request+download with DEBUG logging on. Expected: unauthenticated entry routes to sign-in (no export call leaves the device); logs/analytics contain no file bodies, no `download_url`, no raw `request_id` (hashed/omitted), no `data` payload. Traces: AC-6, AC-8.
- **TC-AND-385-12 — Security: cleartext scoping.** Type: instrumented. Target: emulator `test35`. Preconditions: `network_security_config.xml` permitting cleartext only for `18.222.237.167`. Steps: attempt cleartext to dev host (allowed) and to an arbitrary other host (blocked). Expected: dev host reachable over HTTP; any other cleartext domain rejected; CSRF header attached. Traces: AC-1, AC-8.
- **TC-AND-385-13 — Compose UI: empty, ready, failed, offline + a11y.** Type: Compose-UI. Target: emulator `test35`. Preconditions: state fixtures for each variant. Steps: render `PrivacyExportScreen`; assert empty-state CTA; `completed` row shows Download → fires callback; `failed` row shows Retry; offline banner on network error; assert `contentDescription`/`semantics` on Request/Download/Retry/Refresh, ≥48dp targets, status conveyed as text+chip (not color alone). Expected: all assertions pass. Traces: AC-2, AC-3, AC-5.
- **TC-AND-385-14 — Accessibility: TalkBack + 200% font + READY live region.** Type: manual (instrumented-assisted). Target: PHYSICAL DEVICE (real TalkBack). Preconditions: TalkBack on, font scale 200%. Steps: navigate the screen; trigger a request that transitions to `completed`; complete a download. Expected: rows reflow without truncating status; live-region announces "Export ready to download" and download completion; all controls focusable/announced. MUST run on physical device for genuine TalkBack behavior. Traces: AC-2, AC-3.

### Coverage matrix
| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (request export, CSRF, body, row appears) | TC-01, TC-12 |
| AC-2 (history list, statuses, unknown neutral) | TC-02, TC-03, TC-13, TC-14 |
| AC-3 (completed → download to MediaStore + Open) | TC-08, TC-09, TC-10, TC-13, TC-14 |
| AC-4 (CTA gating + bounded polling + pull-to-refresh) | TC-07 |
| AC-5 (offline cache, no false empty, retry) | TC-06, TC-09, TC-13 |
| AC-6 (401 refresh-once; persistent → sign-in) | TC-05, TC-11 |
| AC-7 (MockWebServer paths/verbs/bodies + detail mapping) | TC-01, TC-03, TC-04 |
| AC-8 (no PII in logs/analytics) | TC-11, TC-12 |
