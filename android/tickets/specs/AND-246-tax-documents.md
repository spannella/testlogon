---
id: AND-246
title: Tax documents
milestone: M5
epic: E33
priority: P2
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-246 — Tax documents

## 1. Overview & Goal

Implement the **Tax documents** feature for the TestLogon native Android app: a
screen that lists a signed-in user's tax documents (e.g. annual statements,
1099-style forms) returned by the backend, and lets the user download an
individual document to local storage and open it in an external viewer.

This mirrors the web reference module `frontend/src/api/endpoints/taxDocuments.ts`
and reuses the billing data plumbing delivered by **AND-223** (Billing API +
DTOs). The deliverable is the full vertical slice for tax documents inside
`feature-billing` (or `feature-tax`, see §4): API surface, repository, ViewModel,
Compose UI, and download handling, wired into the existing Hilt graph and
cookie-based session.

Goal, stated as a single testable outcome: **a signed-in user can see their list
of tax documents and download any one of them to device storage, with correct
behavior on empty, offline, error, and slow-network conditions.**

Out of scope: in-app PDF rendering (we hand off to a system viewer via
`ACTION_VIEW`), document e-signing, generating/regenerating tax documents
server-side, and any billing/invoice UI (owned by the broader billing epic).

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/taxDocuments.ts` (authoritative
  for endpoint paths, query params, and DTO field names), `frontend/src/api/types.ts`
  (shared `TaxDocument` shape), and the FastAPI error contract used across the app.
- **OpenAPI:** `GET http://18.222.237.167:8000/openapi.json` — confirm the exact
  `/ui/billing/*` (or `/api/billing/*`) tax-document routes and response schema at
  implementation time; the paths in §5 are taken from the web module and MUST be
  reconciled against `openapi.json`.
- **Upstream dependency AND-223 (Billing API + DTOs):** provides
  `core-network` Retrofit wiring for billing, Moshi adapters, the shared
  `ApiResult<T>` error mapping, and the cookie/CSRF `OkHttp` stack. Tax documents
  is treated as a sub-resource of billing and reuses that infrastructure.
- **Session/auth:** cookie-based session established via `/ui/session/start` →
  MFA → `/ui/session/finalize`; all requests here are authenticated GETs that ride
  the persistent cookie jar and echo `ui_csrf` as `X-CSRF-Token`. On `401` the
  shared authenticator performs one `POST /ui/session/refresh` then retries.
- **Stack/layering:** `app -> feature-* -> core-*`; Kotlin 2.0.21, Compose +
  Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Paging 3 (not required here — the list is expected to be small and
  unpaged), minSdk 24 / target 35. Namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **List tax documents.** On entering the Tax Documents screen, the app fetches
the current user's tax documents via `GET /ui/billing/tax-documents` and renders
them as a scrollable list sorted newest-first (by `tax_year` desc, then `issued_at`
desc).

FR-2. **List item content.** Each row shows: document title/label, tax year, form
type (e.g. `1099-MISC`), issue date (localized), and file size (humanized, e.g.
`248 KB`) when present. A trailing download affordance (icon button) is shown per row.

FR-3. **Empty state.** When the API returns an empty list, show a non-error empty
state ("No tax documents available yet.") with a retry/refresh action.

FR-4. **Download.** Tapping a row's download action downloads the document bytes
from `GET /ui/billing/tax-documents/{documentId}/download` to app-scoped external
storage and then offers to open it via a system `ACTION_VIEW` intent using a
`FileProvider` content URI. A per-row progress/disabled state is shown while the
download is in flight.

FR-5. **Re-download / open existing.** If a document was already downloaded this
session and the file still exists, tapping again opens the existing file instead of
re-fetching.

FR-6. **Refresh.** Pull-to-refresh and an explicit retry button re-issue the list
request. The list request is an idempotent GET and is subject to bounded backoff
retry (§7).

FR-7. **Slow/unreliable host handling.** All network calls use a ~20s timeout. The
list shows a loading state, then either content, an error state with retry, or a
stale-cache banner (§6) if cached data is shown after a failed refresh.

FR-8. **Navigation.** The screen is reachable from the Billing/Account area via a
Navigation-Compose route `billing/tax-documents`. No deep-link requirement for this
ticket.

## 4. Technical Design

**Module placement.** Implement in the existing `feature-billing` module (the web
module lives alongside `billing.ts`), package
`com.testlogon.android.feature.billing.tax`. If `feature-billing` is not yet
materialized when this ticket starts, create `feature-tax` with the same package
suffix; either way it depends only on `core-network`, `core-model`, `core-ui`,
`core-data`, and (test) `core-testing`.

**Layers.**

```
TaxDocumentsScreen (Compose)
   └─ TaxDocumentsViewModel : StateFlow<TaxDocumentsUiState>
        └─ TaxDocumentsRepository (interface, core-data binding)
             ├─ TaxDocumentsApi (Retrofit, core-network)
             └─ TaxDocumentDownloader (OkHttp streaming + FileProvider)
```

**Model (core-model).**

```kotlin
data class TaxDocument(
    val id: String,
    val title: String,
    val taxYear: Int,
    val formType: String?,        // e.g. "1099-MISC"
    val issuedAt: Instant?,       // ISO-8601 from server
    val sizeBytes: Long?,
    val mimeType: String?,        // defaults to application/pdf
    val downloadable: Boolean,
)
```

**API (core-network).**

```kotlin
interface TaxDocumentsApi {
    @GET("ui/billing/tax-documents")
    suspend fun listTaxDocuments(
        @Query("tax_year") taxYear: Int? = null,
    ): TaxDocumentListDto

    @Streaming
    @GET("ui/billing/tax-documents/{documentId}/download")
    suspend fun downloadTaxDocument(
        @Path("documentId") documentId: String,
    ): ResponseBody
}
```

`@Streaming` is mandatory so the response body is not buffered fully into memory.

**Repository (interface in core-data, impl in feature module).**

```kotlin
interface TaxDocumentsRepository {
    suspend fun getTaxDocuments(forceRefresh: Boolean): ApiResult<List<TaxDocument>>
    suspend fun downloadTaxDocument(doc: TaxDocument): ApiResult<DownloadedFile>
}

data class DownloadedFile(val uri: Uri, val mimeType: String, val displayName: String)
```

**ViewModel.**

```kotlin
@HiltViewModel
class TaxDocumentsViewModel @Inject constructor(
    private val repository: TaxDocumentsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TaxDocumentsUiState())
    val uiState: StateFlow<TaxDocumentsUiState> = _uiState.asStateFlow()

    fun load(forceRefresh: Boolean = false) { /* launch, collect ApiResult */ }
    fun onDownloadClicked(doc: TaxDocument) { /* per-item download state */ }
    fun consumeDownloadEvent() { /* clear one-shot open event */ }
}
```

**UI state.**

```kotlin
data class TaxDocumentsUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val documents: List<TaxDocumentRow> = emptyList(),
    val isStale: Boolean = false,            // cached data shown after failed refresh
    val error: UiError? = null,              // full-screen error (no content)
    val downloadEvent: DownloadEvent? = null // one-shot: open file / show snackbar
)

data class TaxDocumentRow(
    val doc: TaxDocument,
    val downloadState: DownloadState,        // Idle | InProgress | Failed
)

sealed interface DownloadEvent {
    data class Open(val file: DownloadedFile) : DownloadEvent
    data class Error(val message: String) : DownloadEvent
}
```

**Compose.**

```kotlin
@Composable
fun TaxDocumentsScreen(
    viewModel: TaxDocumentsViewModel = hiltViewModel(),
    onOpenFile: (DownloadedFile) -> Unit, // host launches ACTION_VIEW intent
)
```

The screen uses Material 3 `PullToRefreshBox`, a `LazyColumn` of
`TaxDocumentItem` rows, full-screen `LoadingState`/`ErrorState`/`EmptyState`
composables from `core-ui`, and a `Snackbar` host. The `DownloadEvent.Open`
one-shot is collected via `LaunchedEffect(uiState.downloadEvent)` and forwarded to
`onOpenFile`, which is implemented in the single Activity using a `FileProvider`
content URI and `Intent.FLAG_GRANT_READ_URI_PERMISSION`.

**Downloader.** `TaxDocumentDownloader` writes the `@Streaming` `ResponseBody`
to `context.getExternalFilesDir("tax")` (app-scoped, no runtime storage permission
on any supported API level), buffering with `source.readAll(sink)` on
`Dispatchers.IO`, then returns a `content://com.testlogon.android.fileprovider/...`
URI. Filename is derived as `${doc.taxYear}-${sanitize(doc.title)}.pdf` (or the
extension implied by `mimeType`). A `FileProvider` entry and `provider_paths.xml`
(`<external-files-path name="tax" path="tax/"/>`) are added to the feature module's
manifest/res.

**Navigation.** Register route `billing/tax-documents` in the app nav graph;
`TaxDocumentsScreen` receives `onOpenFile` from the Activity-level intent launcher.

## 5. API Contract

All paths reconciled against `/openapi.json` and `taxDocuments.ts` at build time.
Base URL `http://18.222.237.167:8000` (dev, plaintext). Cookie session + CSRF apply.

**List — request**

```
GET /ui/billing/tax-documents?tax_year=2025      (tax_year optional)
Cookie: <session cookies>; ui_csrf=<token>
X-CSRF-Token: <token>
Accept: application/json
```

**List — response 200**

```json
{
  "tax_documents": [
    {
      "id": "txd_01HZY...",
      "title": "2024 Annual Tax Statement",
      "tax_year": 2024,
      "form_type": "1099-MISC",
      "issued_at": "2025-01-31T00:00:00Z",
      "size_bytes": 254013,
      "mime_type": "application/pdf",
      "downloadable": true
    }
  ]
}
```

Moshi DTO maps `tax_documents` → `documents`, snake_case → camelCase via
`@Json(name=...)`. A bare top-level array response is also tolerated by the adapter
(the web module returns `data.tax_documents ?? data`).

**Download — request**

```
GET /ui/billing/tax-documents/{documentId}/download
Cookie / X-CSRF-Token as above
Accept: application/pdf, application/octet-stream
```

**Download — response 200:** binary body; `Content-Type` (used for MIME),
`Content-Disposition` filename (used if present), `Content-Length` for progress.

**Errors (FastAPI `detail`):** `401` → trigger one `/ui/session/refresh` + retry
(shared authenticator); `403` → not-authorized message; `404` → "Document no longer
available", refresh list; `422` → validation (rare for GET); `5xx`/timeout →
retryable error. `detail` is mapped through the shared decoder handling
`string | [{msg}] | {code,...}` shapes delivered by AND-223.

## 6. Data & State Management

- **Source of truth:** `TaxDocumentsViewModel.uiState` (`StateFlow`), survives
  config changes; downloads run in `viewModelScope`.
- **Caching:** Reuse the Room cache pattern from billing. Add a `TaxDocumentEntity`
  table keyed by `id` with `fetchedAt` epoch millis. The repository emits cached
  rows immediately when present, then refreshes from network; on refresh failure it
  keeps cached rows and sets `isStale = true` (drives a "Showing saved list" banner
  with last-updated time). Cache TTL is advisory only — staleness is surfaced, not
  enforced by hiding data.
- **Downloaded files:** stored in `getExternalFilesDir("tax")`; a transient
  in-memory `Map<documentId, File>` lets the session reopen without re-fetch (FR-5).
  Files are not tracked in Room; they are best-effort cache and may be cleared by the
  OS.
- **No DataStore writes** for this feature beyond any existing "last viewed" prefs
  (none required here).
- **One-shot events:** `downloadEvent` is consumed via `consumeDownloadEvent()` to
  avoid re-firing the open intent on recomposition/rotation.

## 7. Error Handling & Resilience

- **Timeouts:** call/read/connect timeouts ~20s, inherited from the shared OkHttp
  client (AND-223). Download read timeout may be longer per the streaming client.
- **Retry:** the list GET is idempotent → bounded exponential backoff (e.g. 2
  retries, 500ms → 1s, jittered) for transient `IOException`/`5xx`. The download GET
  is also idempotent and may retry once; partial files are deleted before retry.
- **401 handling:** delegated to the shared authenticator (single
  `/ui/session/refresh` then retry); if refresh fails the user is routed to
  re-auth by the app-level session observer — this screen just shows a generic auth
  error.
- **Offline:** if cached rows exist, show them with `isStale` banner; otherwise show
  a full-screen offline error with Retry.
- **Download failures:** surface a `Snackbar` (`DownloadEvent.Error`) and reset the
  row's `DownloadState` to `Failed` (tappable to retry). Disk-full / write errors are
  caught and reported distinctly from network errors.
- **No system viewer:** if `ACTION_VIEW` resolves to no activity, show a Snackbar
  ("No app available to open this file") and keep the downloaded file.

## 8. Security & Privacy

- **Transport:** dev host is plaintext HTTP; release builds MUST use HTTPS only.
  `usesCleartextTraffic` is restricted to the dev domain via `network_security_config`
  (owned by the network/bootstrap ticket); no new cleartext exemptions added here.
- **Auth:** all requests authenticated via the persistent cookie jar; CSRF token
  echoed as `X-CSRF-Token`. No tokens or session cookies are logged.
- **PII:** tax documents are sensitive financial PII. Files are written only to
  app-scoped `getExternalFilesDir` (not shared `Downloads`, not MediaStore) so they
  are not world-readable and are removed on uninstall. `FileProvider` grants
  read-only, time-bound URI permission to the chosen viewer only.
- **Logging:** never log document bytes, full URLs with IDs at info level, or
  `Content-Disposition` filenames containing user names beyond debug builds.
- **Screenshots:** consider `FLAG_SECURE` for this screen is deferred to a global
  privacy ticket; not enforced here.

## 9. Accessibility & i18n

- All actionable elements (download icon button, retry, refresh) have
  `contentDescription` (e.g. "Download 2024 tax statement"). Download progress sets
  a live-region status so screen readers announce completion/failure.
- Touch targets ≥ 48dp; row is a single semantics node summarizing
  title/year/type/date.
- Dates (`issued_at`) formatted via `java.time` + locale; file sizes via a localized
  humanizer; tax years are numeric and locale-neutral. All strings in
  `strings.xml` (no hardcoded UI text), supporting RTL mirroring.
- Color is not the sole carrier of state (stale banner and error states include
  text + icon).

## 10. Telemetry & Logging

- Emit analytics events through the shared analytics interface (if present at M5;
  otherwise gate behind the analytics ticket): `tax_documents_viewed`
  (count, isStale), `tax_document_download_started` (documentId, taxYear),
  `tax_document_download_succeeded` (durationMs, sizeBytes),
  `tax_document_download_failed` (errorType), `tax_document_opened`.
- Structured logs at debug for request lifecycle (no PII/bytes). Network errors
  logged with mapped error category, not raw response bodies. Crash-free download
  path verified via instrumentation (§11).

## 11. Testing Strategy

**Unit (core-testing + JUnit/Turbine/MockWebServer):**

- DTO mapping: `tax_documents` array, bare-array fallback, missing optional fields
  (`form_type`, `size_bytes`, `issued_at`), unknown JSON keys ignored.
- Repository: success → mapped list; network failure with cache → stale list +
  `isStale`; network failure without cache → error; sort order (year desc).
- ViewModel (`StateFlow` via Turbine): loading → content; empty → empty state;
  error → error state; download click → InProgress → Open event; download failure →
  Failed state + Error event; `consumeDownloadEvent()` clears the one-shot.
- Downloader: streams `ResponseBody` to a temp file, returns FileProvider URI,
  deletes partial file on failure, reuses existing file (FR-5).
- Error mapping: `401`/`403`/`404`/`422`/`5xx`/timeout produce expected `UiError`.

**Instrumentation/Compose UI tests:**

- List renders rows; empty/loading/error/stale states render correct copy &
  actions; pull-to-refresh triggers reload; download button shows progress then
  fires `onOpenFile`; accessibility nodes/contentDescriptions present.

**Coverage acceptance:** repository + ViewModel + DTO mapping have unit tests; the
"list + download" happy path and at least one failure path are covered.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs, P0):** Retrofit/OkHttp billing wiring,
  Moshi adapters, `ApiResult`/error mapping, cookie+CSRF stack. This ticket cannot
  start its API layer until AND-223's `billing.ts` DTO patterns and `core-network`
  client are merged.
- **Implicitly relies on** the established session/auth stack (cookie jar, CSRF,
  401-refresh authenticator) and `core-ui` shared state composables
  (Loading/Empty/Error). If a shared `FileProvider`/download utility is not yet
  present, this ticket introduces a minimal one scoped to the feature module.
- **Blocks:** none currently.
- **Sequencing:** land DTO + API + repository (testable in isolation against
  MockWebServer) first, then ViewModel, then Compose screen + downloader + nav wiring.

## 13. Risks & Open Questions

- **Endpoint shape unconfirmed:** the `/ui/billing/tax-documents` paths and the
  `tax_documents` envelope are inferred from `taxDocuments.ts`; MUST be verified
  against `/openapi.json`. If tax docs live under `/api/billing/*` or a separate
  `/ui/tax/*` namespace, adjust §5 accordingly (low effort).
- **Download auth on dev host:** unreliable plaintext host may stall mid-download;
  partial-file cleanup and retry mitigate, but large files over a flaky link remain
  a UX risk.
- **MIME/filename:** server may omit `Content-Type`/`Content-Disposition`; we default
  to `application/pdf` and a derived filename — confirm real responses.
- **In-app vs external viewer:** product may later want in-app PDF preview; current
  scope hands off to the system viewer. Open question whether that suffices for M5.
- **Pagination:** assumed small unpaged list; if a user can have many years of
  documents, a follow-up Paging 3 ticket may be needed.

## 14. Acceptance Criteria

- AC-1. A signed-in user opening `billing/tax-documents` sees their tax documents
  list (newest year first) populated from `GET /ui/billing/tax-documents`.
- AC-2. An empty API result renders the non-error empty state with a refresh action.
- AC-3. Tapping a row's download action downloads the document and opens it in a
  system viewer via a `FileProvider` content URI; a previously downloaded file in the
  same session opens without re-fetching.
- AC-4. Loading, error (with Retry), and stale-cache states render correctly; failed
  refresh with cached data keeps showing the list with a stale banner.
- AC-5. List and download GETs use ~20s timeouts; list retries with bounded backoff
  on transient failures; a `401` triggers exactly one session refresh + retry.
- AC-6. DTO mapping (incl. missing optionals and bare-array fallback) and
  ViewModel state transitions are covered by passing unit tests (the backlog
  acceptance: "Tax docs list + download", tested).
- AC-7. Files are written only to app-scoped external storage; no session cookies,
  CSRF tokens, or document bytes appear in logs.
- AC-8. All interactive elements have content descriptions; all user-facing strings
  are in `strings.xml`.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.billing.tax`
  (or `feature-tax`), wired into the Hilt graph and Navigation-Compose route
  `billing/tax-documents`.
- `TaxDocumentsApi`, `TaxDocumentsRepository(+Impl)`, `TaxDocumentsViewModel`,
  `TaxDocumentsScreen`, `TaxDocumentDownloader`, `FileProvider` + `provider_paths.xml`,
  and `TaxDocumentEntity`/DAO implemented.
- Unit + Compose tests in §11 pass in CI; ktlint/detekt clean; build green on
  Gradle 8.9 / AGP 8.7.3 / JDK 17.
- All acceptance criteria (§14) verified manually against the dev backend
  (`http://18.222.237.167:8000`) and via tests.
- Endpoint paths reconciled with `/openapi.json`; any deviations from §5 reflected in
  the merged code and noted in the PR.
- No new cleartext-traffic exemptions, no PII in logs, strings externalized, a11y
  checks pass.
