---
id: AND-247
title: 1099 tax forms
milestone: M5
epic: E33
priority: P2
size: M
status: draft
depends_on: [AND-246]
blocks: []
---

# AND-247 — 1099 tax forms

## 1. Overview & Goal

This ticket delivers the native Android experience for viewing and downloading IRS
**Form 1099** tax forms (1099-NEC / 1099-K / 1099-MISC) that the TestLogon backend
issues to creators and other payees. It is the year-end, regulated subset of the
broader tax-document surface built in **AND-246** (Tax documents list/download). Where
AND-246 renders an undifferentiated list of arbitrary tax documents and a generic
download flow, AND-247 adds the **1099-specific** affordances: a dedicated 1099 section
grouped by tax year, per-form metadata (form type, tax year, payer/payee TIN-masked
identity, gross amount, correction/voided status), an inline rendered preview of the
official PDF, and a download path that produces an audit-grade, content-addressable PDF
artifact.

The deliverable mirrors the web reference module `taxForm1099.ts`. Scope is the
Compose UI, ViewModel, repository, API binding, and Room cache for 1099 forms inside the
existing `feature-billing` tax area. The goal: from a creator's billing/tax screen, a
user can see every 1099 the platform has issued them, open a faithful preview, and
download/share the official PDF — working correctly against the unreliable dev backend,
offline-aware, and with the sensitivity controls a financial tax form demands.

**Success = a 1099 renders (preview) and downloads (PDF to device + share sheet),
verified by instrumented tests.**

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Module:** `feature-billing` (tax sub-package), consuming `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`.
- **Package base:** `com.testlogon.android` (forms live under
  `com.testlogon.android.feature.billing.tax.form1099`).
- **Web reference:** `frontend/src/api/endpoints/taxForm1099.ts` (this ticket's named
  scope), shared types in `frontend/src/api/types.ts`, and `taxDocuments.ts` from
  AND-246 for the parent list pattern.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf`
  echoed as `X-CSRF-Token`; 401 → `POST /ui/session/refresh` once → retry.
- **Upstream deps:**
  - **AND-246** (Tax documents): owns the parent `TaxDocumentsScreen`, the
    `TaxRepository` skeleton, download/file-write plumbing, and the entry point this
    ticket plugs a "1099 forms" section into. AND-247 **must not** re-implement the
    generic download writer; it reuses AND-246's `TaxFileDownloader`.
  - **AND-223** (Billing API + DTOs): provides `billing.ts` DTO conventions, the
    `ApiResult<T>` envelope, FastAPI `detail` error mapping, and the authenticated
    Retrofit `BillingApi`/`TaxApi` service host used here (transitively via AND-246).
- **Cross-cutting:** persistent cookie jar, `X-CSRF-Token` interceptor, and 20s timeout
  / bounded-retry OkHttp client are established earlier in M1/M5 and are consumed, not
  built, here.

## 3. Functional Requirements

FR-1. **List 1099 forms.** When the user opens the Tax area (AND-246) the screen shows
a "1099 Forms" section listing every 1099 issued to the authenticated user, newest tax
year first, then by issue date descending within a year.

FR-2. **Group by tax year.** Forms are grouped under collapsible year headers
(e.g., "2025", "2024"). Each header shows the count of forms for that year.

FR-3. **Per-row metadata.** Each row shows: form type badge (`1099-NEC`, `1099-K`,
`1099-MISC`), tax year, gross/reported amount formatted as USD currency, issue date,
and a status chip when the form is `corrected` or `voided`.

FR-4. **Open preview.** Tapping a row navigates to `Form1099DetailScreen`, which renders
an inline preview of the official 1099 PDF (first page minimum; pageable if multi-page).

FR-5. **Download.** The detail screen exposes a **Download** action that fetches the PDF
bytes and writes them to the device's Downloads collection via MediaStore (no broad
storage permission on minSdk 24+ using the app-scoped/MediaStore path provided by
AND-246's `TaxFileDownloader`), then offers an OS **Share** sheet.

FR-6. **Filename.** Downloaded files are named
`TestLogon_1099-<type>_<taxYear>_<last4 of formId>.pdf`
(e.g., `TestLogon_1099-NEC_2025_a3f9.pdf`).

FR-7. **Empty / not-eligible state.** If the user has zero 1099 forms, the section
either collapses to a single informational row ("No 1099 forms issued") or is hidden
when the parent has other tax docs — controlled by AND-246's section visibility contract.

FR-8. **Offline / stale.** Previously fetched 1099 metadata is served from Room when
offline, with a "Showing saved data" banner. PDF preview/download requires connectivity
and surfaces an offline error if attempted offline without a cached file.

FR-9. **Corrected / voided handling.** A `voided` form is visually de-emphasized and its
download is allowed but labeled "VOIDED". A `corrected` form links to (or supersedes)
the original where `supersedesFormId` is present.

## 4. Technical Design

**Layering.** `Form1099DetailScreen` (Compose) → `Form1099ViewModel`
(`StateFlow<Form1099UiState>`) → `TaxForm1099Repository` → `TaxForm1099Api`
(Retrofit) + `Form1099Dao` (Room). List rows are surfaced through AND-246's existing
`TaxDocumentsViewModel` by adding a `form1099` sub-state, keeping a single screen owner.

**Package:** `com.testlogon.android.feature.billing.tax.form1099`.

**Models (`core-model`):**

```kotlin
enum class Form1099Type { NEC, K, MISC, UNKNOWN }
enum class Form1099Status { ISSUED, CORRECTED, VOIDED }

data class Form1099(
    val formId: String,
    val taxYear: Int,
    val type: Form1099Type,
    val status: Form1099Status,
    val grossAmountCents: Long,          // reported amount, USD minor units
    val currency: String,                // "USD"
    val payerName: String,
    val payerTinMasked: String,          // e.g. "**-***1234"
    val recipientTinMasked: String,
    val issuedAt: Instant,
    val supersedesFormId: String?,
    val pdfUrlPath: String,              // server path, NOT a full URL
    val pageCount: Int?,
)
```

**ViewModel:**

```kotlin
@HiltViewModel
class Form1099ViewModel @Inject constructor(
    private val repo: TaxForm1099Repository,
    private val downloader: TaxFileDownloader,   // from AND-246
    savedState: SavedStateHandle,
) : ViewModel() {
    private val formId: String = savedState["formId"]!!
    val uiState: StateFlow<Form1099UiState>
    fun retry()
    fun download()                                // -> emits DownloadState
    fun share()
}

sealed interface Form1099UiState {
    data object Loading : Form1099UiState
    data class Ready(
        val form: Form1099,
        val preview: PreviewState,
        val download: DownloadState,
        val isStale: Boolean,
    ) : Form1099UiState
    data class Error(val message: String, val retryable: Boolean) : Form1099UiState
}

sealed interface PreviewState { object Loading; data class Rendered(val pages: List<Bitmap>); data class Failed(val message: String) }
sealed interface DownloadState { object Idle; object InProgress; data class Done(val uri: Uri); data class Failed(val message: String) }
```

**PDF rendering.** Preview uses Android's built-in `android.graphics.pdf.PdfRenderer`
(no third-party dep, available since API 21). The repository downloads PDF bytes to a
cache file, opens a `ParcelFileDescriptor`, and renders page bitmaps at a density-scaled
width on `Dispatchers.Default`. Bitmaps are recycled on `onCleared`. Multi-page forms use
a horizontally paged `HorizontalPager` (Compose Foundation).

**Compose:**

```kotlin
@Composable fun Form1099DetailScreen(onBack: () -> Unit, vm: Form1099ViewModel = hiltViewModel())
@Composable fun Form1099Row(form: Form1099, onClick: () -> Unit)         // used by AND-246 list
@Composable fun Form1099YearHeader(year: Int, count: Int, expanded: Boolean, onToggle: () -> Unit)
@Composable private fun Pdf1099Preview(state: PreviewState, modifier: Modifier)
```

**Navigation.** New route registered in the billing nav graph:
`tax/1099/{formId}` → `Form1099DetailScreen`. Type-safe arg via `formId: String`.

**DI.** A `TaxForm1099Module` (`@Module @InstallIn(SingletonComponent::class)`) provides
`TaxForm1099Api` (via the existing authenticated Retrofit instance) and binds
`TaxForm1099RepositoryImpl`.

## 5. API Contract

All paths are relative to the dev host and ride the cookie session + `X-CSRF-Token`. The
exact paths must be confirmed against `/openapi.json`; the web `taxForm1099.ts` is
authoritative for shape. Expected surface:

**List 1099 forms** — `GET /ui/billing/tax/1099`

Response `200`:
```json
{
  "forms": [
    {
      "form_id": "tf_1099_01J9...",
      "tax_year": 2025,
      "type": "1099-NEC",
      "status": "issued",
      "gross_amount_cents": 1284500,
      "currency": "USD",
      "payer_name": "TestLogon, Inc.",
      "payer_tin_masked": "**-***6789",
      "recipient_tin_masked": "***-**-1234",
      "issued_at": "2026-01-31T08:00:00Z",
      "supersedes_form_id": null,
      "pdf_url_path": "/ui/billing/tax/1099/tf_1099_01J9.../pdf",
      "page_count": 1
    }
  ]
}
```

**Form metadata** — `GET /ui/billing/tax/1099/{formId}` → single object matching a
`forms[]` element.

**Download PDF** — `GET /ui/billing/tax/1099/{formId}/pdf`
- Returns `application/pdf` bytes (`Content-Disposition: attachment`).
- Idempotent GET → eligible for bounded backoff retry.

**Retrofit:**
```kotlin
interface TaxForm1099Api {
    @GET("ui/billing/tax/1099")
    suspend fun list(): Form1099ListDto

    @GET("ui/billing/tax/1099/{formId}")
    suspend fun get(@Path("formId") id: String): Form1099Dto

    @Streaming @GET("ui/billing/tax/1099/{formId}/pdf")
    suspend fun downloadPdf(@Path("formId") id: String): ResponseBody
}
```

Repository wraps each call in `ApiResult<T>`; DTO→domain mapping lives in
`Form1099Dto.toDomain()` and uses a Moshi enum adapter mapping wire strings
(`"1099-NEC"`, `"corrected"`, `"voided"`) to enums with `UNKNOWN`/`ISSUED` fallbacks for
forward compatibility.

**N/A:** No write/POST endpoints — 1099 forms are read-only artifacts.

## 6. Data & State Management

**Room (`core-data`).** Entity `Form1099Entity` (PK `formId`, indexed `taxYear`) caches
metadata for offline list rendering. PDF bytes are **not** stored in Room; the preview
file is cached under `context.cacheDir/tax1099/<formId>.pdf` and is treated as
disposable. A `Form1099Dao` exposes:

```kotlin
@Dao interface Form1099Dao {
    @Query("SELECT * FROM form_1099 ORDER BY taxYear DESC, issuedAt DESC")
    fun observeAll(): Flow<List<Form1099Entity>>
    @Query("SELECT * FROM form_1099 WHERE formId = :id") suspend fun byId(id: String): Form1099Entity?
    @Upsert suspend fun upsertAll(items: List<Form1099Entity>)
}
```

**Repository policy.** List = Room-first (`observeAll`) with a network refresh that
upserts on success; offline failures keep the cached flow and set `isStale = true`.
Metadata is small; no Paging 3 needed (1099 counts are low — typically < 10 per user),
so a plain `Flow<List<Form1099>>` is used rather than Paging.

**Currency formatting** uses `NumberFormat.getCurrencyInstance(Locale)` seeded from
`currency`, computed in the ViewModel/mapper, never in Compose.

**StateFlow** is exposed via `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), Loading)`.
Preview/download are one-shot operations gated by `DownloadState`/`PreviewState` so
config changes don't re-trigger a download.

## 7. Error Handling & Resilience

- **Network envelope:** all calls return `ApiResult<T>` (`Success`/`Error`). FastAPI
  `detail` is mapped per project convention (string | `[{msg}]` | `{code,...}`) into a
  user-facing message via the shared `ErrorMapper` from AND-223.
- **Timeouts:** the shared OkHttp client's ~20s timeouts apply. PDF download uses
  `@Streaming` to avoid buffering large bodies into memory.
- **Retry:** list/metadata/PDF are idempotent GETs → bounded exponential backoff
  (max 3 attempts, 0.5s→1s→2s, jittered) via the shared retry interceptor. No retry on
  4xx.
- **401:** handled by the shared auth interceptor (single `POST /ui/session/refresh`
  then retry); on second 401 the ViewModel emits a re-auth `Error`.
- **Offline list:** serve Room cache, show "Showing saved data" banner, allow retry.
- **Offline preview/download:** emit `PreviewState.Failed` / `DownloadState.Failed` with
  "You're offline — connect to view this form."
- **Corrupt/empty PDF:** if `PdfRenderer` throws or body is empty/non-PDF
  (`Content-Type` not `application/pdf`), emit `PreviewState.Failed("Couldn't open this
  form")` and still allow raw download so the user can open it externally.
- **MediaStore write failure:** `DownloadState.Failed` with a Snackbar + retry.

## 8. Security & Privacy

- **Sensitive financial PII.** 1099 forms contain TINs/SSNs and earnings. The API
  returns **masked** TINs only; the app never reconstructs or logs full TINs.
- **No logging of PDF bytes or amounts.** Telemetry (§10) records only non-PII metadata
  (formId hash, type, taxYear, status). Amounts and names are never sent to analytics.
- **Cache hygiene.** The cached preview PDF lives in app-private `cacheDir` (not
  externally readable). It is deleted on `onCleared` of the detail ViewModel when the
  form was only previewed, and always cleared on logout via the existing
  session-clear hook.
- **Transport.** Dev host is plaintext HTTP (cleartext permitted only for the dev
  domain via the network-security-config established earlier). Production builds must use
  HTTPS; cleartext is restricted to `18.222.237.167`.
- **Auth required.** Every endpoint requires the cookie session + `X-CSRF-Token`. No
  anonymous access; downloads inherit session auth.
- **Share scope.** When sharing, the file is exposed only via a `FileProvider`
  content URI with a time-bounded grant (`FLAG_GRANT_READ_URI_PERMISSION`), never a raw
  `file://` path.
- **Screenshot consideration:** optionally set `FLAG_SECURE` on the detail screen
  (open question §13) given the PII content.

## 9. Accessibility & i18n

- All rows, chips, and actions have Compose `contentDescription` / `semantics`. Form
  type badge announces full name ("Form 1099-NEC, tax year 2025, voided").
- Preview pager pages are individually labeled ("Page 1 of 2"); the rendered bitmap has a
  text-alternative describing the form (type, year, amount).
- Touch targets ≥ 48dp; Download/Share are `IconButton`s with text labels.
- Dynamic type / font scaling supported; preview zoom respects pinch gestures and is not
  the only way to read content (download path is the accessible fallback).
- All strings in `strings.xml` (`feature-billing`), no hardcoded literals. Currency and
  dates formatted via locale-aware `NumberFormat`/`DateTimeFormatter`. "1099" and form
  type codes are not translated (legal identifiers); surrounding labels are.
- Color is not the sole status signal — voided/corrected use icon + text chip.

## 10. Telemetry & Logging

Events via the existing analytics facade (`core-data`):
- `tax_1099_list_viewed` { count, years[] }
- `tax_1099_detail_viewed` { form_type, tax_year, status }
- `tax_1099_preview_rendered` { form_type, page_count, render_ms }
- `tax_1099_preview_failed` { reason }
- `tax_1099_download_started` / `tax_1099_download_completed` { form_type, tax_year }
- `tax_1099_download_failed` { reason }
- `tax_1099_shared` { form_type }

No amounts, names, TINs, or formIds-in-clear are logged. `formId` may be sent only as a
salted hash if correlation is needed. Debug `Timber` logs at `VERBOSE` exclude body
content; network logging interceptor is `NONE`/`BASIC` only (no body) on this surface.

## 11. Testing Strategy

**Unit (JUnit + Turbine, `core-testing`):**
- `Form1099Dto.toDomain()` mapping incl. unknown type/status fallbacks and masked-TIN
  passthrough.
- Filename builder produces `TestLogon_1099-NEC_2025_a3f9.pdf`.
- `TaxForm1099Repository`: Room-first + network refresh upsert; offline → stale flag;
  `ApiResult.Error` mapping from FastAPI `detail` variants.
- `Form1099ViewModel`: Loading→Ready, retry, download state machine, offline preview
  error. MockWebServer for 200/401(→refresh)/500/timeout.

**Instrumented (Compose UI test + MediaStore, the acceptance proof):**
- **1099 renders:** given a fixture PDF, `Form1099DetailScreen` shows a non-empty
  `Pdf1099Preview` (assert rendered bitmap node present / not in `Failed`).
- **1099 downloads:** tapping Download writes a file to MediaStore Downloads and emits
  `DownloadState.Done`; assert the resulting URI is readable and is a valid PDF
  (magic bytes `%PDF`).
- List grouping: year headers + counts render in correct order; voided chip shown.
- Empty state row renders when list is empty.

**Test fixtures:** a small valid single-page `sample_1099.pdf` in
`feature-billing/src/androidTest/assets/`, plus JSON fixtures for list/metadata served by
MockWebServer.

## 12. Dependencies & Sequencing

- **Hard dep — AND-246 (Tax documents):** must land first; provides the parent screen,
  `TaxRepository`/`TaxFileDownloader`, MediaStore write + FileProvider share plumbing,
  and the section slot AND-247 fills. This ticket adds the 1099 sub-feature, not the
  download infrastructure.
- **Transitive — AND-223 (Billing API + DTOs):** `ApiResult<T>`, error mapping,
  authenticated Retrofit host.
- **Sequencing:** (1) confirm endpoint shapes vs `/openapi.json` and `taxForm1099.ts`;
  (2) add `core-model` types + Moshi adapters; (3) `TaxForm1099Api` + repository + Room
  DAO; (4) ViewModel + state machine; (5) Compose detail + row/header, wire into AND-246
  list; (6) PDF render + MediaStore download/share; (7) tests.
- **Blocks:** none currently. Earnings/tax-summary surfaces (E34) may later reference the
  1099 row component but do not block this.

## 13. Risks & Open Questions

- **R1 — Endpoint shape unverified.** Paths/field names above are inferred from
  conventions; must be reconciled with `/openapi.json` and `taxForm1099.ts`. *Mitigation:*
  schema-confirm before coding step 2.
- **R2 — PDF size / multi-page.** Large or multi-page 1099s could pressure memory on
  `PdfRenderer`. *Mitigation:* render lazily per page, scale to screen width, recycle
  bitmaps.
- **R3 — Dev backend instability.** PDF fetch may time out. *Mitigation:* streaming +
  bounded retry + clear failed/retry UI; download path independent of preview.
- **OQ1 — `FLAG_SECURE`?** Should the 1099 detail screen block screenshots given PII?
  Product/security to decide.
- **OQ2 — Does the backend serve a pre-rendered PDF or structured fields?** This spec
  assumes a server-rendered PDF (consistent with AND-246). If only structured data is
  returned, a client-side template renderer becomes a follow-up ticket.
- **OQ3 — Corrected-form chaining.** Behavior when `supersedesFormId` points to a form
  not in the list (e.g., prior-year). Assume show as standalone "Corrected".

## 14. Acceptance Criteria

- **AC-1 (renders):** Opening a 1099 from the tax list displays an inline PDF preview of
  the official form; verified by an instrumented test asserting a rendered preview (not a
  `Failed` state) for a fixture PDF. *(maps to ticket "1099 renders")*
- **AC-2 (downloads):** The Download action writes a valid `%PDF` file to the device
  Downloads collection named per FR-6 and surfaces a Share sheet; verified by an
  instrumented test asserting `DownloadState.Done` and a readable PDF URI. *(maps to
  "1099 downloads")*
- **AC-3:** The tax screen lists all of the user's 1099 forms grouped by tax year,
  newest first, with type badge, USD amount, issue date, and voided/corrected status.
- **AC-4:** List metadata renders from Room cache when offline with a "Showing saved
  data" banner; preview/download offline shows a clear offline error.
- **AC-5:** All API calls go through `ApiResult<T>`; FastAPI `detail` errors map to
  user-facing messages; 401 triggers a single refresh-and-retry.
- **AC-6:** No TINs, amounts, names, or raw formIds appear in logs or analytics; cached
  preview PDF is app-private and cleared on logout.
- **AC-7:** All package references use `com.testlogon.android`; new code lives in
  `feature-billing` and reuses AND-246's `TaxFileDownloader`.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.billing.tax.form1099`.
- `TaxForm1099Api`, `TaxForm1099Repository(+Impl)`, `Form1099Dao`/`Form1099Entity`,
  `Form1099ViewModel`, and Compose `Form1099DetailScreen`/`Form1099Row`/
  `Form1099YearHeader` implemented and wired into the AND-246 tax screen + nav graph.
- Moshi adapters and `core-model` types added; DTO→domain mapping tested.
- Unit + instrumented tests (AC-1, AC-2 explicitly) pass in CI; coverage on repository +
  mapper ≥ existing module threshold.
- ktlint/detekt clean; no new lint baseline suppressions; builds with Kotlin 2.0.21 /
  AGP 8.7.3 / Gradle 8.9 / JDK 17, minSdk 24 / target 35.
- Strings externalized; basic TalkBack pass on list + detail.
- No PII in logs/telemetry verified; FileProvider share grant scoped.
- Endpoint shapes reconciled against `/openapi.json`; open questions (§13) resolved or
  re-filed as follow-up tickets.
- Spec acceptance criteria (§14) demonstrably met; PR links the instrumented test run.
