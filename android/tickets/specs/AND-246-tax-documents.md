---
id: AND-246
title: Tax documents
milestone: M5
epic: E33
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-223]
blocks: []
---

# AND-246 — Tax documents

## 1. Overview & Goal

Implement the **Tax documents** feature for the TestLogon native Android app: a
screen that lists a signed-in user's previously generated tax documents (annual
earnings summaries, `doc_type` typically `annual_summary`) returned by the
backend, and lets the user download a document PDF (by tax **year**) to local
storage and open it in an external viewer.

> **Reviewer note (corrected):** the backend models these as *annual earnings
> summaries*, not 1099-style forms. 1099 forms are a **distinct** resource under
> `/ui/tax-forms/1099s*` (see `src/api/types.ts: TaxForm1099`) and are out of
> scope for this ticket. References to "1099" as the primary document type in the
> original draft were inaccurate and have been corrected throughout.

This mirrors the web reference module `frontend/src/api/endpoints/taxDocuments.ts`
and reuses the billing data plumbing delivered by **AND-223** (Billing API +
DTOs). The deliverable is the full vertical slice for tax documents inside
`feature-billing` (or `feature-tax`, see §4): API surface, repository, ViewModel,
Compose UI, and download handling, wired into the existing Hilt graph and
cookie-based session.

Goal, stated as a single testable outcome: **a signed-in user can see their list
of generated tax documents and download a document PDF (by year) to device
storage, with correct behavior on empty, offline, error, and slow-network
conditions.**

Out of scope: in-app PDF rendering (we hand off to a system viewer via
`ACTION_VIEW`), document e-signing, generating/regenerating tax documents
server-side (`POST /ui/tax-documents/generate`), the spending-summary and
year-comparison cards shown on the web page, 1099 forms (`/ui/tax-forms/*`),
and any billing/invoice UI (owned by the broader billing epic).

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/taxDocuments.ts` (authoritative
  for endpoint paths, query params, and DTO field names), `frontend/src/api/types.ts`
  (shared `TaxDocument` shape), and the FastAPI error contract used across the app.
- **OpenAPI:** `GET http://18.222.237.167:8000/openapi.json` — routes have been
  reconciled (2026-06-06). The tax-document routes live under **`/ui/tax-documents/*`**
  (NOT `/ui/billing/*` or `/api/billing/*`, which do not exist for this resource).
  Verified routes: `GET /ui/tax-documents/history` (op
  `get_history_ui_tax_documents_history_get`, resp `TaxDocumentListOut`) and
  `GET /ui/tax-documents/document/{year}/pdf` (op
  `download_document_pdf_ui_tax_documents_document__year__pdf_get`, binary resp).
- **Upstream dependency AND-223 (Billing API + DTOs):** provides
  `core-network` Retrofit wiring for billing, Moshi adapters, the shared
  `ApiResult<T>` error mapping, and the cookie/CSRF `OkHttp` stack. Tax documents
  is treated as a sub-resource of billing and reuses that infrastructure.
- **Session/auth:** cookie-based session established via `POST /ui/session/start`
  → `POST /ui/session/finalize` (both verified in the OpenAPI index); all requests
  here are authenticated GETs that ride the persistent cookie jar and echo `ui_csrf`
  as `X-CSRF-Token`. **Correction:** the web client (`src/api/client.ts`) also sends
  an `Authorization: Bearer <accessToken>` header from its auth store on requests
  routed through the `api` wrapper — so auth is cookie **+** optional bearer, not
  cookie-only. Note the web *download* helpers in `taxDocuments.ts` use a raw
  `fetch(..., { credentials: "include" })` that bypasses the wrapper and sends
  **neither** `Authorization` nor `X-CSRF-Token` (CSRF is not required for GETs).
  On `401` the shared `api` wrapper performs one `POST /ui/session/refresh` then
  retries exactly once (`src/api/client.ts: refreshSession`).
- **Stack/layering:** `app -> feature-* -> core-*`; Kotlin 2.0.21, Compose +
  Material 3, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Paging 3 (not required here — the list is expected to be small and
  unpaged), minSdk 24 / target 35. Namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **List tax documents.** On entering the Tax Documents screen, the app fetches
the current user's previously generated tax documents via
`GET /ui/tax-documents/history` (corrected from `/ui/billing/tax-documents`) and
renders them as a scrollable list sorted newest-first (by `year` desc, then
`created_at` desc). The endpoint takes **no query parameters** (the original draft's
`tax_year` filter does not exist on `history`).

FR-2. **List item content.** Each row shows the fields the backend actually returns
(`TaxDocumentOut`): tax **year** (`year`, nullable → show "—"), document **type**
(`doc_type`, e.g. `annual_summary`), **grand total** (`grand_total_cents`, money-
formatted), and **transaction count** (`transaction_count`). A trailing download
affordance (icon button) is shown per row. **Correction:** the original draft's
`title`, `form_type` (`1099-MISC`), `issued_at`, and humanized `size_bytes` are NOT
provided by the API and have been removed; there is no `Content-Length`-based size
in the list. A row label may be derived locally as "{year} Annual Tax Statement".

FR-3. **Empty state.** When the API returns an empty `documents` list, show a
non-error empty state. The web copy is "No documents generated yet."
(`TaxDocumentsPage.tsx`); the Android string should match intent. A retry/refresh
action is shown.

FR-4. **Download.** Tapping a row's download action downloads the document PDF for
that row's **year** from `GET /ui/tax-documents/document/{year}/pdf` (corrected from
`/ui/billing/tax-documents/{documentId}/download`; the resource is keyed by year,
not by `documentId`) to app-scoped external storage and then offers to open it via a
system `ACTION_VIEW` intent using a `FileProvider` content URI. A per-row
progress/disabled state is shown while the download is in flight. Rows whose `year`
is null cannot be downloaded by this endpoint (disable the affordance).

FR-5. **Re-download / open existing.** If a document (keyed by year) was already
downloaded this session and the file still exists, tapping again opens the existing
file instead of re-fetching.

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
// Corrected to match TaxDocumentOut (openapi.pretty.json) /
// src/api/types.ts: TaxDocument. Server uses unix-epoch seconds (integers)
// for date_from/date_to/created_at, NOT ISO-8601 strings.
data class TaxDocument(
    val docId: String,            // doc_id (the only required field)
    val docType: String,          // doc_type, default "annual_summary"
    val year: Int?,               // nullable
    val dateFrom: Long,           // date_from (unix seconds, default 0)
    val dateTo: Long,             // date_to (unix seconds, default 0)
    val grandTotalCents: Long,    // grand_total_cents (default 0)
    val transactionCount: Int,    // transaction_count (default 0)
    val currency: String,         // currency, default "usd"
    val createdAt: Long,          // created_at (unix seconds, default 0)
)
// NOTE: there is no title / form_type / size_bytes / mime_type / downloadable
// field on the server model. MIME is assumed application/pdf for the download.
```

**API (core-network).**

```kotlin
interface TaxDocumentsApi {
    // Corrected path; history takes no query params.
    @GET("ui/tax-documents/history")
    suspend fun listTaxDocuments(): TaxDocumentListDto

    // Corrected: download is keyed by YEAR, not documentId.
    @Streaming
    @GET("ui/tax-documents/document/{year}/pdf")
    suspend fun downloadTaxDocument(
        @Path("year") year: Int,
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
URI. Filename is derived as `tax-document-${doc.year}.pdf` (mirroring the web
client's `earnings-summary-${year}.pdf`); a `Content-Disposition` filename is used
if the server provides one. There is no server `title`/`mime_type` to derive from,
so the extension is fixed to `.pdf`. A `FileProvider` entry and `provider_paths.xml`
(`<external-files-path name="tax" path="tax/"/>`) are added to the feature module's
manifest/res.

**Navigation.** Register route `billing/tax-documents` in the app nav graph;
`TaxDocumentsScreen` receives `onOpenFile` from the Activity-level intent launcher.

## 5. API Contract

All paths reconciled against `/openapi.json` and `taxDocuments.ts` (2026-06-06).
Base URL `http://18.222.237.167:8000` (dev, plaintext). Cookie session + CSRF apply.

**List — request** (corrected path; no query params)

```
GET /ui/tax-documents/history
Cookie: <session cookies>; ui_csrf=<token>
X-CSRF-Token: <token>              (echoed by the api wrapper; not required for GET)
Authorization: Bearer <accessToken> (if present in auth store)
Accept: application/json
```

**List — response 200** (schema `TaxDocumentListOut` → `TaxDocumentOut`)

```json
{
  "documents": [
    {
      "doc_id": "txd_01HZY...",
      "doc_type": "annual_summary",
      "year": 2024,
      "date_from": 1704067200,
      "date_to": 1735689599,
      "grand_total_cents": 254013,
      "transaction_count": 87,
      "currency": "usd",
      "created_at": 1738281600
    }
  ]
}
```

`doc_id` is the only required field; all others have server defaults
(`doc_type="annual_summary"`, `currency="usd"`, numerics `0`, `year` nullable).
Dates are **unix-epoch seconds (integers)**, not ISO-8601 strings. Moshi DTO maps
the `documents` envelope → `List<TaxDocument>`, snake_case → camelCase via
`@Json(name=...)`. (The original draft's `tax_documents` envelope and bare-array
fallback are not what the API returns; the real envelope key is `documents`.)

**Download — request** (corrected: keyed by year, returns raw PDF)

```
GET /ui/tax-documents/document/{year}/pdf
Cookie / X-CSRF-Token / Authorization as above
Accept: application/pdf, application/octet-stream
```

**Download — response 200:** binary PDF body (OpenAPI declares no JSON schema for
the 200, i.e. a raw file stream); use `Content-Type` for MIME if present,
`Content-Disposition` filename if present, `Content-Length` for progress.

**Errors (FastAPI `detail`):** declared error response for both endpoints is
**`422 HTTPValidationError`** (e.g. a non-integer `year` path segment). `401` →
trigger one `POST /ui/session/refresh` + retry (matches `src/api/client.ts`); `403`
→ not-authorized message (the web client maps `detail.code` values like
`role_required` via `mapAuthorizationError`); `404` → "Document no longer
available", refresh list; `5xx`/timeout → retryable error. FastAPI `detail` is
mapped through a decoder handling `string | [{msg}] | {code,...}` shapes, mirroring
`normalizeErrorDetail` in `src/api/client.ts` and delivered by AND-223. Note network
errors surface in the web client as `ApiError(0, "Network error")`.

## 6. Data & State Management

- **Source of truth:** `TaxDocumentsViewModel.uiState` (`StateFlow`), survives
  config changes; downloads run in `viewModelScope`.
- **Caching:** Reuse the Room cache pattern from billing. Add a `TaxDocumentEntity`
  table keyed by `doc_id` with `fetchedAt` epoch millis. The repository emits cached
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

- DTO mapping: `documents` envelope, missing optional fields applying server
  defaults (`doc_type`, `currency`, numerics → 0, `year` → null), unix-seconds dates
  parsed as `Long`, unknown JSON keys ignored. (Corrected: there is no
  `tax_documents` envelope or bare-array fallback in the real API.)
- Repository: success → mapped list; network failure with cache → stale list +
  `isStale`; network failure without cache → error; sort order (year desc, nulls
  last).
- ViewModel (`StateFlow` via Turbine): loading → content; empty → empty state;
  error → error state; download click → InProgress → Open event; download failure →
  Failed state + Error event; `consumeDownloadEvent()` clears the one-shot.
- Downloader: streams `ResponseBody` to a temp file, returns FileProvider URI,
  deletes partial file on failure, reuses existing file (FR-5).
- Error mapping: `401`/`403`/`404`/`422`/`5xx`/timeout/network(`0`) produce expected
  `UiError`; FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) normalize
  correctly.

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

- **Endpoint shape — RESOLVED (2026-06-06):** paths verified against `/openapi.json`
  and `taxDocuments.ts`. Real routes are `GET /ui/tax-documents/history` and
  `GET /ui/tax-documents/document/{year}/pdf`; envelope key is `documents`; download
  is keyed by **year**. The original `/ui/billing/tax-documents` paths and
  `tax_documents` envelope were incorrect and have been corrected in §5. Residual
  open question: whether the dev backend ever populates a `Content-Disposition`
  filename (assumed absent → derived name).
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
  list (newest year first) populated from `GET /ui/tax-documents/history`.
- AC-2. An empty API result renders the non-error empty state with a refresh action.
- AC-3. Tapping a row's download action downloads the document and opens it in a
  system viewer via a `FileProvider` content URI; a previously downloaded file in the
  same session opens without re-fetching.
- AC-4. Loading, error (with Retry), and stale-cache states render correctly; failed
  refresh with cached data keeps showing the list with a stale banner.
- AC-5. List and download GETs use ~20s timeouts; list retries with bounded backoff
  on transient failures; a `401` triggers exactly one session refresh + retry.
- AC-6. DTO mapping (incl. missing optionals with server defaults and unix-seconds
  dates) and
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **List endpoint is `GET /ui/tax-documents/history`** — *Corrected* (draft said
   `GET /ui/billing/tax-documents`). Source: OpenAPI `GET /ui/tax-documents/history`
   (op `get_history_ui_tax_documents_history_get`, resp `TaxDocumentListOut`);
   `src/api/endpoints/taxDocuments.ts: getDocumentHistory`.
2. **List response envelope key is `documents` (array of `TaxDocumentOut`)** —
   *Corrected* (draft said `tax_documents` with bare-array fallback). Source:
   `components.schemas.TaxDocumentListOut` and `src/api/types.ts: TaxDocumentList`.
3. **`TaxDocumentOut` fields = `doc_id` (required), `doc_type`, `year?`,
   `date_from`, `date_to`, `grand_total_cents`, `transaction_count`, `currency`,
   `created_at`** — *Corrected* (draft invented `title`, `tax_year`, `form_type`,
   `issued_at`, `size_bytes`, `mime_type`, `downloadable`). Source:
   `components.schemas.TaxDocumentOut`; `src/api/types.ts: TaxDocument`.
4. **Date fields are unix-epoch seconds (integers), not ISO-8601** — *Corrected*
   (draft modeled `issuedAt: Instant` from an ISO string). Source: `TaxDocumentOut`
   (`date_from`/`date_to`/`created_at` `type: integer`); web formats via
   `fmtCents`/numeric handling in `TaxDocumentsPage.tsx`.
5. **Download endpoint is `GET /ui/tax-documents/document/{year}/pdf`, keyed by
   year, returning a raw PDF** — *Corrected* (draft said
   `GET /ui/billing/tax-documents/{documentId}/download`). Source: OpenAPI
   `GET /ui/tax-documents/document/{year}/pdf` (op
   `download_document_pdf_ui_tax_documents_document__year__pdf_get`, resp `200:` with
   no JSON schema = binary); `src/api/endpoints/taxDocuments.ts: downloadDocumentPdf`.
6. **`history` takes no query params (no `tax_year` filter)** — *Corrected* (draft
   had `@Query("tax_year")`). Source: OpenAPI index line for
   `/ui/tax-documents/history` (`params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`
   only — no `tax_year`); `getDocumentHistory()` passes no params.
7. **The web "tax documents" feature is annual earnings summaries, not 1099 forms;
   1099s are a distinct resource** — *Corrected* (draft framed the docs as
   "1099-style"). Source: `TaxDocumentOut.doc_type` default `annual_summary`;
   `src/api/types.ts` comment "DISTINCT from the consumer TaxDocument types above";
   1099 routes under `/ui/tax-forms/1099s*` returning `TaxForm1099Out`.
8. **Empty-state copy "No documents generated yet."** — *Verified*. Source:
   `src/pages/billing/TaxDocumentsPage.tsx` (`EmptyState title="No documents
   generated yet"`).
9. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`** — *Verified*. Source:
   `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
10. **Auth also sends `Authorization: Bearer <accessToken>` (not cookie-only)** —
    *Corrected* (draft implied cookie-only). Source: `src/api/client.ts`
    (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
11. **Web download helpers bypass the `api` wrapper (raw `fetch`,
    `credentials:"include"`, no CSRF/Bearer header)** — *Verified* (contract nuance).
    Source: `src/api/endpoints/taxDocuments.ts: downloadBlob`.
12. **`401` triggers exactly one `POST /ui/session/refresh` then one retry** —
    *Verified*. Source: `src/api/client.ts: refreshSession` + the single
    `refreshPromise`/retry path; OpenAPI `POST /ui/session/refresh`.
13. **Session established via `POST /ui/session/start` → `POST /ui/session/finalize`**
    — *Verified*. Source: OpenAPI `POST /ui/session/start` (`UiSessionStartReq` →
    `UiSessionStartResp`) and `POST /ui/session/finalize` (`UiSessionFinalizeReq`).
    (The intermediate "MFA" step is not a single named endpoint in the index;
    treated as part of the start/finalize flow.)
14. **Declared error response for both tax endpoints is `422 HTTPValidationError`** —
    *Verified*. Source: OpenAPI index lines for `/ui/tax-documents/history` and
    `/ui/tax-documents/document/{year}/pdf` (`resp=...;422:HTTPValidationError`).
15. **FastAPI `detail` normalization handles `string | [{msg}] | {code,...}`** —
    *Verified*. Source: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError` (e.g. `code === "role_required_scope"`).
16. **Network/offline error surfaces as status `0`** — *Verified*. Source:
    `src/api/client.ts` (`throw new ApiError(0, "Network error", err)`).
17. **Dev base URL `http://18.222.237.167:8000` (plaintext)** — *Unverified-
    assumption* (carried from draft/ticket; not present in the provided OpenAPI
    `servers` excerpt). Treated as a dev-environment config value.
18. **`@Streaming` Retrofit + write to `getExternalFilesDir` needs no runtime
    storage permission; `FileProvider` + `ACTION_VIEW` for hand-off** — *Verified
    (framework ref)*. Android docs: app-specific external files dir requires no
    permission (developer.android.com/training/data-storage/app-specific);
    FileProvider/`FLAG_GRANT_READ_URI_PERMISSION`
    (developer.android.com/reference/androidx/core/content/FileProvider).
19. **Material 3 `PullToRefreshBox` for pull-to-refresh** — *Unverified-assumption
    (framework ref)*. API name from Compose Material3 docs
    (developer.android.com/jetpack/compose) but the exact composable name/signature
    is version-dependent (Compose BOM at M5 not pinned in sources).

### Corrections made

- Endpoint paths: list `→ /ui/tax-documents/history`; download `→
  /ui/tax-documents/document/{year}/pdf` (year-keyed, raw PDF). (Claims 1, 5)
- Response envelope `tax_documents` + bare-array fallback `→ documents`. (Claim 2)
- `TaxDocument` model rewritten to the real `TaxDocumentOut` fields; removed
  invented `title/form_type/issued_at/size_bytes/mime_type/downloadable`. (Claim 3)
- Dates retyped from `Instant`/ISO-8601 to `Long` unix-seconds. (Claim 4)
- Removed non-existent `tax_year` query param on `history`. (Claim 6)
- Reframed document type from "1099-style" to annual earnings summary; 1099s noted
  as out of scope. (Claim 7)
- Auth note: added `Authorization: Bearer` + download-helper CSRF/bearer bypass.
  (Claims 10, 11)
- Declared error response clarified as `422 HTTPValidationError`; added network
  status `0`. (Claims 14, 16)
- Updated FR-1/FR-2/FR-3/FR-4/FR-5, §4 model+API, §5 contract, §6 cache key,
  §11 tests, §13 risks, AC-1/AC-6 accordingly.

### Open assumptions

- Dev base URL/host (`18.222.237.167:8000`): not in the provided OpenAPI `servers`
  excerpt — environment config, unverifiable from sources. (Claim 17)
- `Content-Type`/`Content-Disposition`/`Content-Length` headers on the PDF download:
  the OpenAPI 200 has no declared schema/headers, so MIME=`application/pdf`,
  derived filename, and length-based progress are best-effort assumptions to confirm
  against a live response.
- Exact Compose Material3 pull-to-refresh API at M5 (BOM version not pinned in the
  sources). (Claim 19)
- The intermediate MFA step in the session flow is not a single named endpoint in
  the index; modeled as part of start→finalize.
- Sort order (year desc, then created_at desc, nulls last) is an Android UX choice;
  the web page renders `history` rows in server order with no client sort.

## 17. Test Plan

Test target legend per the CI/dev environment: **JVM** = JVM unit/Robolectric (no
device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **phys** =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a).
Use **phys** for real hardware/behavior; ABI/API-34-vs-35 differences.

- **TC-AND-246-01** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer enqueues a 200 `{"documents":[…]}` with two `TaxDocumentOut` items
  (years 2024, 2023). Steps: call `TaxDocumentsApi.listTaxDocuments()`; map to
  `List<TaxDocument>`; sort. Expected: request path is `/ui/tax-documents/history`
  with **no** query string; two items mapped with `docId/docType/year/
  grandTotalCents/transactionCount/currency` correct; list sorted year-desc.
  Traces: AC-1, AC-6.
- **TC-AND-246-02** — Type: unit. Target: JVM. Preconditions: JSON with only
  `doc_id` present (all other fields omitted) plus a row with `year: null`. Steps:
  Moshi-decode. Expected: server defaults applied (`doc_type="annual_summary"`,
  `currency="usd"`, numerics 0), `year` is null, unix-seconds parse to `Long`,
  unknown keys ignored, no crash. Traces: AC-6.
- **TC-AND-246-03** — Type: unit. Target: JVM. Preconditions: list containing
  years `[2023, null, 2025, 2024]`. Steps: apply repository sort. Expected: order
  `2025, 2024, 2023, null` (year desc, nulls last). Traces: AC-1, AC-6.
- **TC-AND-246-04** — Type: unit (Turbine). Target: JVM. Preconditions: repository
  fake returns success then a populated list. Steps: `viewModel.load()`; collect
  `uiState`. Expected: emissions `isLoading=true` → content (documents non-empty,
  `error=null`). Traces: AC-1.
- **TC-AND-246-05** — Type: unit (Turbine). Target: JVM. Preconditions: repository
  returns empty `documents`. Steps: `load()`. Expected: terminal state has empty
  documents and an empty-state flag (not `error`); refresh action available.
  Traces: AC-2.
- **TC-AND-246-06** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `422` with body `{"detail":[{"msg":"value is not a valid integer"}]}`
  for `history`. Steps: call repository; map error. Expected: `detail` normalized
  to the `msg` string; mapped to a retryable/validation `UiError`; nothing logged
  raw. Traces: AC-5, AC-6, AC-7.
- **TC-AND-246-07** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `401` once, then a 200 list; a fake refresher handles
  `POST /ui/session/refresh`. Steps: call repository. Expected: exactly one refresh
  call then one retry; final result is the 200 list; a second consecutive `401`
  produces an auth error without a second refresh. Traces: AC-5.
- **TC-AND-246-08** — Type: unit (Turbine). Target: JVM. Preconditions: repository
  has cached rows; network refresh throws `IOException`. Steps: `load(forceRefresh
  = true)`. Expected: cached rows retained, `isStale=true`, no full-screen error;
  with no cache, full-screen offline error + Retry. Traces: AC-4.
- **TC-AND-246-09** — Type: unit. Target: JVM. Preconditions: `TaxDocumentDownloader`
  with a MockWebServer `@Streaming` body for year 2024; temp dir as
  external-files. Steps: download year 2024; then download again. Expected: first
  call requests `/ui/tax-documents/document/2024/pdf`, writes
  `tax-document-2024.pdf`, returns a `content://…fileprovider/…` URI; second call
  reuses the existing file without a new request (FR-5). On simulated failure mid-
  stream, the partial file is deleted. Traces: AC-3, AC-7.
- **TC-AND-246-10** — Type: Compose-UI. Target: emu35. Preconditions: ViewModel
  seeded with two rows (one with `year=null`). Steps: render
  `TaxDocumentsScreen`; assert rows, then assert states by re-seeding loading/empty/
  error/stale. Expected: rows show year/type/total/count; loading shows spinner;
  empty shows "No documents generated yet." copy + refresh; error shows Retry;
  stale shows the saved-list banner; the `year=null` row's download affordance is
  disabled. Traces: AC-1, AC-2, AC-4.
- **TC-AND-246-11** — Type: Compose-UI (accessibility). Target: emu35.
  Preconditions: one row rendered. Steps: query semantics tree; trigger TalkBack-
  style assertions. Expected: download icon button has a non-empty
  `contentDescription` (e.g. "Download 2024 tax statement"); touch targets ≥ 48dp;
  row is a single merged semantics node; download progress exposes a live-region
  status; no hardcoded strings (all from `strings.xml`). Traces: AC-8.
- **TC-AND-246-12** — Type: instrumented/e2e. Target: **phys** (must run on the
  physical device). Preconditions: app pointed at dev backend with a session that
  has ≥1 generated document; system PDF viewer installed. Steps: open
  `billing/tax-documents`; tap a row's download; wait for completion; confirm the
  `ACTION_VIEW` chooser/viewer launches on the real PDF. Expected: file written to
  app-scoped external storage, `FileProvider` URI opens read-only in an external
  viewer; re-tap opens existing file without re-download. Rationale for phys: real
  external-storage/FileProvider grant behavior and arm64/API-34 differ from the
  x86_64/API-35 emulator. Traces: AC-3, AC-7.
- **TC-AND-246-13** — Type: instrumented (resilience). Target: **phys** (real
  flaky-network behavior). Preconditions: device on a throttled/intermittent link
  to the dev host. Steps: start a download, drop connectivity mid-stream, then
  retry; also attempt with airplane mode on. Expected: ~20s timeout enforced;
  partial file deleted before retry; download Snackbar error + row `Failed` state
  (tappable to retry); offline list shows stale cache (if present) or offline error.
  Rationale for phys: real radio/connectivity transitions. Traces: AC-4, AC-5.
- **TC-AND-246-14** — Type: manual (security/privacy). Target: phys or emu35 with
  logcat capture. Preconditions: debug build, logcat capturing during a full
  list+download cycle. Steps: exercise list, download, open; inspect logcat and the
  written file location. Expected: no session cookies, `ui_csrf`/`X-CSRF-Token`
  values, `Authorization` bearer, or document bytes in logs; file resides only in
  `getExternalFilesDir("tax")` (not `Downloads`/MediaStore), removed on uninstall;
  FileProvider grant is read-only and scoped to the chosen viewer. Traces: AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (list, newest-first, from `/ui/tax-documents/history`) | TC-01, TC-03, TC-04, TC-10 |
| AC-2 (empty state + refresh) | TC-05, TC-10 |
| AC-3 (download → open via FileProvider; reuse existing) | TC-09, TC-12 |
| AC-4 (loading/error/stale states; failed refresh keeps cache) | TC-08, TC-10, TC-13 |
| AC-5 (~20s timeouts, bounded retry, one 401 refresh+retry) | TC-06, TC-07, TC-13 |
| AC-6 (DTO mapping incl. defaults/nulls; ViewModel transitions) | TC-01, TC-02, TC-03, TC-04, TC-06 |
| AC-7 (app-scoped storage; no cookies/CSRF/bytes in logs) | TC-06, TC-09, TC-12, TC-14 |
| AC-8 (content descriptions; strings externalized) | TC-11 |
