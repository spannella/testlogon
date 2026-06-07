---
id: AND-247
title: 1099 tax forms
milestone: M5
epic: E33
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-246]
blocks: []
---

# AND-247 — 1099 tax forms

## 1. Overview & Goal

This ticket delivers the native Android experience for viewing and downloading IRS
**Form 1099** tax forms that the TestLogon backend issues to creators. **Verified scope:
the backend issues 1099-NEC only** (nonemployee compensation; the web reference page is
titled "Tax Forms (1099-NEC)" and there is no form-type discriminator in the API — see
§16). Earlier drafts assumed 1099-NEC / 1099-K / 1099-MISC; that is NOT supported by the
backend and has been corrected throughout. It is the year-end, regulated subset of the
broader tax-document surface built in **AND-246** (Tax documents list/download). Where
AND-246 renders an undifferentiated list of arbitrary tax documents and a generic
download flow, AND-247 adds the **1099-specific** affordances: a dedicated 1099 section
keyed by tax year, per-form metadata (tax year, total reportable earnings, payer name and
payer TIN last-4, status, correction count), and a download path. **Verified: there is no
server-streamed `application/pdf` endpoint** — `GET /ui/tax-forms/1099s/{tax_year}/download`
returns JSON `{ "download_url": "..." }`, and the PDF is fetched from that (typically
presigned/external) URL. Any "inline PDF preview" must therefore fetch and render bytes
from `download_url`, not from an API `/pdf` path (see §16 corrections).

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
- **Web reference:** `src/api/endpoints/taxForm1099.ts` (this ticket's named scope; the
  creator-scoped calls `listMy1099s`, `getMy1099`, `generateMy1099`, `downloadMy1099`),
  shared types in `src/api/types.ts` (`TaxForm1099`, `TaxForm1099List`,
  `TaxForm1099Download`), the screen `src/pages/billing/TaxForm1099Page.tsx`, and
  `taxDocuments.ts` from AND-246 for the parent list pattern.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. **Verified (src/api/client.ts):** the web
  client sends both the cookie session (`credentials: include`) **and** an
  `Authorization: Bearer <accessToken>` header, plus the `ui_csrf` cookie echoed as
  `X-CSRF-Token`; on 401 (only if already authenticated) it calls `POST /ui/session/refresh`
  **once**, retries, and on a second 401 logs out. Network/transport failure surfaces as
  an `ApiError(status=0, "Network error")` — relevant to the offline path below.
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
a "1099 Forms (1099-NEC)" section listing every 1099-NEC issued to the authenticated user
(`GET /ui/tax-forms/1099s` → `{items:[...]}`), newest tax year first. **Note (verified):
each user has at most one 1099-NEC per tax year**, so the natural row identity is the tax
year, not a `formId`.

FR-2. **Order by tax year.** Rows are ordered newest tax year first. Collapsible per-year
grouping is optional polish, not a backend requirement (the web reference renders a flat
year-keyed table, one row per year, no grouping). Where the parent AND-246 section uses
year headers, the count per year will be 1.

FR-3. **Per-row metadata.** Each row shows: tax year, **total reportable earnings**
(`total_earnings_cents`, formatted as USD), and a **status** chip (`status` is a free
string defaulting to `"generated"`; observed values include `generated` and correction
states). There is **no per-form type badge** (NEC-only) and **no issue date field on the
wire other than epoch `generated_at`/`updated_at`** — render the issue date from
`generated_at` (epoch seconds). A "corrected" indicator derives from `correction_count > 0`
(verified field), not a `voided`/`corrected` enum.

FR-4. **Open preview.** Tapping a row navigates to `Form1099DetailScreen`, which fetches
`GET /ui/tax-forms/1099s/{tax_year}` for metadata, then obtains the PDF via the download
URL (FR-5) and renders an inline preview of the official 1099-NEC PDF (first page minimum;
pageable if multi-page). **The form is addressed by `{tax_year}`, not `{formId}`.**

FR-5. **Download.** The detail/row exposes a **Download** action that calls
`GET /ui/tax-forms/1099s/{tax_year}/download`, which returns JSON
`{ "download_url": "<url>" }` (verified — **not** raw `application/pdf` bytes). The app then
fetches the PDF bytes from `download_url` and writes them to the device's Downloads
collection via MediaStore (no broad storage permission on minSdk 24+ using the
app-scoped/MediaStore path provided by AND-246's `TaxFileDownloader`), then offers an OS
**Share** sheet. (The web client simply does `window.open(download_url)`.)

FR-6. **Filename.** Downloaded files are named
`TestLogon_1099-NEC_<taxYear>.pdf` (e.g., `TestLogon_1099-NEC_2025.pdf`). *(Corrected: the
prior `<type>` and `<last4 of formId>` segments are dropped — type is always NEC and
`form_id` may be empty (`default: ""` in `TaxForm1099Out`); tax year uniquely identifies
the form per user. If desired, a `form_id` last-4 may be appended only when non-empty.)*

FR-7. **Empty / not-eligible state.** If the user has zero 1099 forms, the section
either collapses to a single informational row ("No 1099 forms issued") or is hidden
when the parent has other tax docs — controlled by AND-246's section visibility contract.

FR-8. **Offline / stale.** Previously fetched 1099 metadata is served from Room when
offline, with a "Showing saved data" banner. PDF preview/download requires connectivity
and surfaces an offline error if attempted offline without a cached file.

FR-9. **Corrected handling.** *(Corrected from earlier draft.)* There is **no `voided`
status and no `supersedesFormId` field** on the wire. The verified signal is
`correction_count` (integer, default 0) plus the free-string `status`. When
`correction_count > 0`, show a "Corrected" chip; download remains allowed. Treat any
unrecognized `status` string as a plain label (forward-compatible). Admin correction
(`POST /ui/tax-forms/admin/1099s/{tax_year}/correct`) is out of scope for this
creator-facing ticket.

## 4. Technical Design

**Layering.** `Form1099DetailScreen` (Compose) → `Form1099ViewModel`
(`StateFlow<Form1099UiState>`) → `TaxForm1099Repository` → `TaxForm1099Api`
(Retrofit) + `Form1099Dao` (Room). List rows are surfaced through AND-246's existing
`TaxDocumentsViewModel` by adding a `form1099` sub-state, keeping a single screen owner.

**Package:** `com.testlogon.android.feature.billing.tax.form1099`.

**Models (`core-model`):**

*(Model corrected to match the verified `TaxForm1099Out` wire shape — see §16. Fields
`type`, `currency`, `recipientTinMasked`, `supersedesFormId`, `pdfUrlPath`, `pageCount`
and the `voided` status do NOT exist on the wire and have been removed. Form type is
always 1099-NEC; the form is keyed by `taxYear`.)*

```kotlin
// Status is a free string on the wire (default "generated"); model defensively.
enum class Form1099Status { GENERATED, CORRECTED, UNKNOWN } // map from `status` + correction_count

data class Form1099(
    val formId: String,                  // may be "" (default on wire); not a reliable key
    val userSub: String,
    val taxYear: Int,                    // primary identity for fetch/download
    val totalEarningsCents: Long,        // wire: total_earnings_cents (USD minor units)
    val qualifies: Boolean,              // wire: qualifies (>= $600 threshold)
    val status: Form1099Status,
    val statusRaw: String,               // preserve original string for display/forward-compat
    val correctionCount: Int,            // wire: correction_count
    val payerName: String,               // wire: payer_name
    val payerTinLast4: String,           // wire: payer_tin_last4 (NOT a full masked TIN)
    val generatedAt: Instant,            // wire: generated_at (epoch SECONDS)
    val updatedAt: Instant,              // wire: updated_at (epoch seconds)
    val downloadUrl: String?,            // wire: download_url (nullable); usually fetched via /download
)
```

Currency is implicitly USD (no `currency` field; web formats with a literal `$`). There is
**no recipient TIN, no page count, and no `pdf_url_path`** on the wire — the preview must
render from the bytes fetched at `downloadUrl` (see §5).

**ViewModel:**

```kotlin
@HiltViewModel
class Form1099ViewModel @Inject constructor(
    private val repo: TaxForm1099Repository,
    private val downloader: TaxFileDownloader,   // from AND-246
    savedState: SavedStateHandle,
) : ViewModel() {
    private val taxYear: Int = savedState["taxYear"]!!   // corrected: keyed by tax year
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
`tax/1099/{taxYear}` → `Form1099DetailScreen`. Type-safe arg via `taxYear: Int`.
*(Corrected from `{formId}` — the detail/download endpoints are keyed by tax year.)*

**DI.** A `TaxForm1099Module` (`@Module @InstallIn(SingletonComponent::class)`) provides
`TaxForm1099Api` (via the existing authenticated Retrofit instance) and binds
`TaxForm1099RepositoryImpl`.

## 5. API Contract

All paths are relative to the dev host and ride the cookie session + `Authorization: Bearer`
+ `X-CSRF-Token`. **The paths below are VERIFIED against `openapi.index.txt` and
`src/api/endpoints/taxForm1099.ts`.** The earlier `/ui/billing/tax/1099*` paths were
WRONG; the correct prefix is `/ui/tax-forms/1099s`. Optional query param `user_sub` exists
on these endpoints but is server-resolved from the session for the creator-scoped calls.

**List 1099 forms** — `GET /ui/tax-forms/1099s`
(op `list_my_1099s_ui_tax_forms_1099s_get`; resp `200: TaxForm1099ListOut`, `422:
HTTPValidationError`)

Response `200` (`TaxForm1099ListOut`, items are `TaxForm1099Out`):
```json
{
  "items": [
    {
      "form_id": "tf_1099_01J9...",
      "user_sub": "auth0|...",
      "tax_year": 2025,
      "total_earnings_cents": 1284500,
      "qualifies": true,
      "status": "generated",
      "correction_count": 0,
      "generated_at": 1738310400,
      "updated_at": 1738310400,
      "payer_name": "TestLogon, Inc.",
      "payer_tin_last4": "6789",
      "download_url": null
    }
  ]
}
```
Note: `generated_at`/`updated_at` are **epoch integers (seconds)**, not ISO-8601 strings;
all scalar fields have server defaults (`form_id` may be `""`).

**Form metadata** — `GET /ui/tax-forms/1099s/{tax_year}`
(op `get_my_1099_...`; resp `200: TaxForm1099Out`, `422: HTTPValidationError`) → a single
`TaxForm1099Out`. **Keyed by `tax_year` (integer), not `formId`.**

**Download (get URL)** — `GET /ui/tax-forms/1099s/{tax_year}/download`
(op `download_my_1099_...`; resp `200: TaxForm1099DownloadOut`, `422: HTTPValidationError`)
- Returns JSON `{ "download_url": "<string>" }` (`TaxForm1099DownloadOut`). **NOT raw
  `application/pdf` bytes.** The app then GETs the PDF from `download_url`. *(Corrected: the
  prior `/{formId}/pdf` `application/pdf`/`Content-Disposition` design was wrong.)*
- Idempotent GET → eligible for bounded backoff retry.

**Generate (optional, creator-triggered)** — `POST /ui/tax-forms/1099s/{tax_year}/generate`
(op `generate_my_1099_...`; resp `200: TaxForm1099Out`). The web page exposes a "Generate
1099" button. *(Corrected: the prior "No write/POST endpoints" claim was wrong.)* Whether
the Android client surfaces generation is a product call (see §13 / §16 open assumptions);
viewing/downloading is the AC. Admin endpoints (`/ui/tax-forms/admin/...`) are out of scope.

**Retrofit (corrected):**
```kotlin
interface TaxForm1099Api {
    @GET("ui/tax-forms/1099s")
    suspend fun list(): Form1099ListDto                       // { items: [...] }

    @GET("ui/tax-forms/1099s/{taxYear}")
    suspend fun get(@Path("taxYear") year: Int): Form1099Dto

    @GET("ui/tax-forms/1099s/{taxYear}/download")
    suspend fun downloadUrl(@Path("taxYear") year: Int): Form1099DownloadDto  // { download_url }

    // Optional, only if generation is exposed in-app:
    // @POST("ui/tax-forms/1099s/{taxYear}/generate")
    // suspend fun generate(@Path("taxYear") year: Int): Form1099Dto
}
```
The actual PDF bytes are fetched from `download_url` via a separate streaming OkHttp/Retrofit
call (the URL may be absolute/presigned and outside the API host), e.g. an
`@Streaming @GET suspend fun fetchPdf(@Url url: String): ResponseBody`.

Repository wraps each call in `ApiResult<T>`; DTO→domain mapping lives in
`Form1099Dto.toDomain()`. The status mapper handles a **free-string** `status` (default
`"generated"`) plus `correction_count` → `Form1099Status` with an `UNKNOWN` fallback for
forward compatibility (no fixed `"voided"`/`"issued"` enum exists on the wire).

## 6. Data & State Management

**Room (`core-data`).** Entity `Form1099Entity` (PK `taxYear`) caches
metadata for offline list rendering. PDF bytes are **not** stored in Room; the preview
file is cached under `context.cacheDir/tax1099/<taxYear>.pdf` (corrected from `<formId>`,
which may be empty) and is treated as disposable. A `Form1099Dao` exposes:

```kotlin
@Dao interface Form1099Dao {
    @Query("SELECT * FROM form_1099 ORDER BY taxYear DESC, generatedAt DESC")
    fun observeAll(): Flow<List<Form1099Entity>>
    // Keyed by taxYear (corrected from formId, which may be empty on the wire):
    @Query("SELECT * FROM form_1099 WHERE taxYear = :year") suspend fun byYear(year: Int): Form1099Entity?
    @Upsert suspend fun upsertAll(items: List<Form1099Entity>)
}
```
*(Entity PK is `taxYear` (one 1099-NEC per user per year); `generatedAt` replaces the
non-existent `issuedAt`.)*

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
- **Missing/expired download URL:** if `/download` returns an empty/absent `download_url`,
  or the subsequent `download_url` fetch returns non-200/expired, emit
  `PreviewState.Failed`/`DownloadState.Failed` and offer retry (retry re-requests a fresh
  `download_url`, since presigned links expire).
- **Corrupt/empty PDF:** if `PdfRenderer` throws or the fetched body is empty / not a PDF
  (first bytes not `%PDF`; do not rely on a `Content-Type` header from the external URL),
  emit `PreviewState.Failed("Couldn't open this form")` and still allow raw download so the
  user can open it externally.
- **MediaStore write failure:** `DownloadState.Failed` with a Snackbar + retry.

## 8. Security & Privacy

- **Sensitive financial PII.** 1099-NEC forms contain TINs and earnings. **Verified:** the
  metadata API exposes only the **payer TIN last-4** (`payer_tin_last4`) — there is **no
  recipient TIN field and no full TIN** in the JSON; full identifiers exist only inside the
  rendered PDF. The app never reconstructs or logs full TINs and treats the PDF bytes as
  sensitive.
- **No logging of PDF bytes or amounts.** Telemetry (§10) records only non-PII metadata
  (formId hash, type, taxYear, status). Amounts and names are never sent to analytics.
- **Cache hygiene.** The cached preview PDF lives in app-private `cacheDir` (not
  externally readable). It is deleted on `onCleared` of the detail ViewModel when the
  form was only previewed, and always cleared on logout via the existing
  session-clear hook.
- **Transport.** Dev host is plaintext HTTP (cleartext permitted only for the dev
  domain via the network-security-config established earlier). Production builds must use
  HTTPS; cleartext is restricted to `18.222.237.167`.
- **Auth required.** Every API endpoint requires the cookie session + `Authorization:
  Bearer` + `X-CSRF-Token` (verified in `src/api/client.ts`). No anonymous access. **Caveat:
  the PDF is fetched from `download_url`, which may be a presigned/external URL** — that
  fetch may NOT carry the session and must be treated as a short-lived, capability-bearing
  link; do not log it and do not persist it beyond the download.
- **Share scope.** When sharing, the file is exposed only via a `FileProvider`
  content URI with a time-bounded grant (`FLAG_GRANT_READ_URI_PERMISSION`), never a raw
  `file://` path.
- **Screenshot consideration:** optionally set `FLAG_SECURE` on the detail screen
  (open question §13) given the PII content.

## 9. Accessibility & i18n

- All rows, chips, and actions have Compose `contentDescription` / `semantics`. The row
  announces the full context ("Form 1099-NEC, tax year 2025, status generated" or
  "...corrected" when `correction_count > 0").
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
- Filename builder produces `TestLogon_1099-NEC_2025.pdf` (corrected; see FR-6).
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

- **R1 — Endpoint shape (RESOLVED in this review).** Paths and field names are now verified
  against `openapi.index.txt`, `TaxForm1099Out`/`TaxForm1099ListOut`/`TaxForm1099DownloadOut`,
  and `src/api/endpoints/taxForm1099.ts`. See §16 for the corrections (wrong path prefix,
  year-keyed not formId-keyed, JSON `download_url` not raw PDF, NEC-only, field renames).
- **R2 — PDF size / multi-page.** Large or multi-page 1099s could pressure memory on
  `PdfRenderer`. *Mitigation:* render lazily per page, scale to screen width, recycle
  bitmaps.
- **R3 — Dev backend instability.** PDF fetch may time out. *Mitigation:* streaming +
  bounded retry + clear failed/retry UI; download path independent of preview.
- **OQ1 — `FLAG_SECURE`?** Should the 1099 detail screen block screenshots given PII?
  Product/security to decide.
- **OQ2 — PDF delivery (PARTIALLY RESOLVED).** Verified: `/download` returns a JSON
  `download_url` pointing at a (server-rendered) PDF; the API does not return structured
  form fields for client rendering. **Unverified:** whether `download_url` is a presigned
  S3-style link or a same-host authenticated path, and its expiry/TTL — treat as expiring
  and re-fetch on retry (see §16 open assumptions).
- **OQ4 — Expose creator "Generate 1099" in-app?** The web page offers a Generate button
  (`POST /ui/tax-forms/1099s/{tax_year}/generate`). The ticket AC is view/download only;
  product to decide whether Android surfaces generation.
- **OQ3 — Corrected-form chaining.** *(Reframed — no `supersedesFormId` exists.)* The wire
  exposes `correction_count` and a free-string `status`, but no link to a superseded form.
  Assume a corrected 1099 simply replaces the prior year-row in the list; render a
  "Corrected" chip when `correction_count > 0`. No cross-form chaining is possible from the
  available data.

## 14. Acceptance Criteria

- **AC-1 (renders):** Opening a 1099 from the tax list displays an inline PDF preview of
  the official form; verified by an instrumented test asserting a rendered preview (not a
  `Failed` state) for a fixture PDF. *(maps to ticket "1099 renders")*
- **AC-2 (downloads):** The Download action writes a valid `%PDF` file to the device
  Downloads collection named per FR-6 and surfaces a Share sheet; verified by an
  instrumented test asserting `DownloadState.Done` and a readable PDF URI. *(maps to
  "1099 downloads")*
- **AC-3:** The tax screen lists all of the user's 1099-NEC forms ordered by tax year
  newest first, with USD earnings (`total_earnings_cents`), issue date (from
  `generated_at`), and a status/corrected chip (from `status` + `correction_count`).
  *(Corrected: no NEC/K/MISC type badge and no `voided` status exist on the wire.)*
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and an exact SOURCE pointer. Sources: OpenAPI
index `reference/openapi.index.txt`, OpenAPI schemas in `reference/openapi.pretty.json`
(`components.schemas.<Name>`), and frontend files under `reference/src/`.

1. **List endpoint is `GET /ui/tax-forms/1099s` returning `{items:[...]}`.** VERDICT:
   Corrected (spec said `GET /ui/billing/tax/1099` → `{forms:[...]}`). SOURCE: OpenAPI
   `GET /ui/tax-forms/1099s` (op `list_my_1099s_ui_tax_forms_1099s_get`, resp
   `200: TaxForm1099ListOut`); `src/api/endpoints/taxForm1099.ts: listMy1099s`;
   `TaxForm1099ListOut` (field `items`).
2. **Form detail is `GET /ui/tax-forms/1099s/{tax_year}` (keyed by tax year).** VERDICT:
   Corrected (spec said `/ui/billing/tax/1099/{formId}`). SOURCE: OpenAPI
   `GET /ui/tax-forms/1099s/{tax_year}` (op `get_my_1099_...`, params `tax_year`);
   `src/api/endpoints/taxForm1099.ts: getMy1099(taxYear)`.
3. **Download endpoint is `GET /ui/tax-forms/1099s/{tax_year}/download` returning JSON
   `{download_url}` — NOT raw `application/pdf` bytes.** VERDICT: Corrected (spec said
   `/{formId}/pdf` returning `application/pdf` with `Content-Disposition: attachment`).
   SOURCE: OpenAPI `GET /ui/tax-forms/1099s/{tax_year}/download` (resp
   `200: TaxForm1099DownloadOut`); `TaxForm1099DownloadOut` (single field `download_url`,
   string); `src/api/endpoints/taxForm1099.ts: downloadMy1099`; usage in
   `src/pages/billing/TaxForm1099Page.tsx` (`window.open(res.download_url)`).
4. **Backend issues 1099-NEC only; no NEC/K/MISC type discriminator and no `type` field.**
   VERDICT: Corrected. SOURCE: `TaxForm1099Out` has no `type` property;
   `src/pages/billing/TaxForm1099Page.tsx` title "Tax Forms (1099-NEC)" and copy
   "1099-NEC nonemployee compensation forms."
5. **Earnings field is `total_earnings_cents` (integer minor units), not
   `gross_amount_cents`; no `currency` field (USD implied).** VERDICT: Corrected. SOURCE:
   `TaxForm1099Out.total_earnings_cents`; `src/api/types.ts: TaxForm1099`;
   `TaxForm1099Page.tsx: fmtCents` uses a literal `$`.
6. **TIN exposure is `payer_tin_last4` only; no `recipient_tin_masked` and no full/masked
   TIN.** VERDICT: Corrected (spec listed `payer_tin_masked` + `recipient_tin_masked`).
   SOURCE: `TaxForm1099Out.payer_tin_last4`; `src/api/types.ts: TaxForm1099`.
7. **Timestamps `generated_at`/`updated_at` are epoch integers (seconds), not an ISO
   `issued_at`.** VERDICT: Corrected. SOURCE: `TaxForm1099Out.generated_at`/`updated_at`
   (`type: integer`); no `issued_at` property exists.
8. **Status is a free string (default `"generated"`) plus `correction_count` (int); there
   is no `voided` status and no `supersedes_form_id`/`pdf_url_path`/`page_count`.** VERDICT:
   Corrected. SOURCE: `TaxForm1099Out` properties (`status` default `"generated"`,
   `correction_count` default 0); absence of `voided`/`supersedes_form_id`/`pdf_url_path`/
   `page_count` in the schema and in `src/api/types.ts: TaxForm1099`.
9. **`form_id` may be empty (default `""`); not a reliable row key.** VERDICT: Verified.
   SOURCE: `TaxForm1099Out.form_id` (`default: ""`); `TaxForm1099Page.tsx` keys rows by
   `f.form_id || f.tax_year`.
10. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT: Verified. SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **Auth also sends `Authorization: Bearer <accessToken>` in addition to the cookie
    session.** VERDICT: Corrected/augmented (spec described cookie + CSRF only). SOURCE:
    `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`,
    `credentials: "include"`).
12. **401 handling: single `POST /ui/session/refresh`, then retry once; second 401 →
    logout.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession()` posts
    `/ui/session/refresh`; retried request; on retry 401 `logout("session_expired")`).
13. **FastAPI `detail` mapping supports string | `[{msg}]` | `{code,...}` shapes.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError`.
14. **Documented error response for these endpoints is `422 HTTPValidationError`.**
    VERDICT: Verified. SOURCE: OpenAPI index lines for all four `1099s` ops
    (`resp=...;422:HTTPValidationError`). (Generic 4xx/5xx still handled by the shared
    client per claim 13, but only 422 is declared in the spec.)
15. **A creator-triggered generate endpoint exists:
    `POST /ui/tax-forms/1099s/{tax_year}/generate` → `TaxForm1099Out`.** VERDICT: Corrected
    (spec said "No write/POST endpoints"). SOURCE: OpenAPI
    `POST /ui/tax-forms/1099s/{tax_year}/generate` (op `generate_my_1099_...`);
    `src/api/endpoints/taxForm1099.ts: generateMy1099`; "Generate 1099" button in
    `src/pages/billing/TaxForm1099Page.tsx`.
16. **Admin endpoints exist but are out of scope** (`/ui/tax-forms/admin/1099s/{tax_year}/
    generate`, `.../correct`, `/ui/tax-forms/admin/batch`, `/ui/tax-forms/admin/year/
    {tax_year}`). VERDICT: Verified (informational). SOURCE: OpenAPI index lines for the
    `tax-forms/admin` ops; `src/api/endpoints/taxForm1099.ts` admin section.
17. **`android.graphics.pdf.PdfRenderer` for in-app PDF preview (no third-party dep).**
    VERDICT: Verified (framework ref). SOURCE (framework ref):
    https://developer.android.com/reference/android/graphics/pdf/PdfRenderer (available
    since API 21; app minSdk 24).
18. **MediaStore Downloads write needs no broad storage permission on the target API
    range.** VERDICT: Verified (framework ref) — scoped storage; `MediaStore.Downloads`
    via `MediaStore.Downloads.EXTERNAL_CONTENT_URI` requires no `WRITE_EXTERNAL_STORAGE`
    on API 29+. SOURCE (framework ref):
    https://developer.android.com/training/data-storage/shared/media . Note minSdk 24:
    on API 24-28 a legacy `WRITE_EXTERNAL_STORAGE` path is required; this is owned by
    AND-246's `TaxFileDownloader` and assumed handled there (see open assumptions).
19. **FileProvider content URI + `FLAG_GRANT_READ_URI_PERMISSION` for share.** VERDICT:
    Verified (framework ref). SOURCE (framework ref):
    https://developer.android.com/reference/androidx/core/content/FileProvider .

### Corrections made

- Path prefix `/ui/billing/tax/1099*` → `/ui/tax-forms/1099s*` (claims 1-3).
- Detail/download/preview re-keyed from `{formId}` to `{tax_year}` throughout (§3 FR-4/5,
  §4 model + ViewModel `savedState` + nav route `tax/1099/{taxYear}`, §5 Retrofit, §6 DAO
  `byYear`/PK `taxYear`, cache path `<taxYear>.pdf`) (claim 2).
- Download redesigned: `/download` returns JSON `{download_url}`; PDF bytes fetched from
  that URL (not a streamed `application/pdf` API response) (§3 FR-5, §5, §7) (claim 3).
- Removed unsupported NEC/K/MISC type model + badge; scope is 1099-NEC only (§1, §3 FR-3,
  §4 enums, §14 AC-3) (claim 4).
- Field renames in `core-model` + DTO: `gross_amount_cents`→`total_earnings_cents`,
  added `qualifies`/`correction_count`/`user_sub`; dropped `currency`,
  `recipient_tin_masked`, `supersedes_form_id`, `pdf_url_path`, `page_count`;
  `payer_tin_masked`→`payer_tin_last4`; `issued_at` (Instant/ISO) → `generated_at` (epoch
  seconds) (§4, §5, §6) (claims 5-8).
- List wrapper `{forms:[]}`→`{items:[]}` (claim 1).
- Filename `TestLogon_1099-<type>_<year>_<last4 formId>.pdf` →
  `TestLogon_1099-NEC_<year>.pdf` (§3 FR-6, §11) (claims 4, 9).
- Corrected/voided handling reframed onto `correction_count`/`status` (§3 FR-9, §9, §13
  OQ3, §14 AC-3) (claim 8).
- Auth note augmented with the `Authorization: Bearer` header (§2, §5, §8) (claim 11).
- Added the `generate` POST endpoint and flagged "no POST" as wrong (§5, §13 OQ4)
  (claim 15).

### Open assumptions

- **`download_url` nature & TTL.** Whether it is a presigned/external link vs a same-host
  authenticated path, and its expiry, are not described in OpenAPI or the frontend (the web
  app only `window.open`s it). Assumed expiring and capability-bearing; mitigation: re-fetch
  on retry, do not persist/log. (Unverifiable from available sources.)
- **PDF `page_count` / multi-page.** No `page_count` on the wire; multi-page handling is
  inferred from `PdfRenderer.getPageCount()` at render time, not from metadata.
- **API 24-28 MediaStore path.** No-permission MediaStore write is guaranteed only on
  API 29+. The minSdk-24 download/share plumbing is owned by AND-246's `TaxFileDownloader`
  and assumed to handle legacy permission; not re-verified here (cross-ticket).
- **`status` value domain.** Only the default `"generated"` is documented; other values
  (e.g., a corrected state) are inferred. Handled defensively via `statusRaw` + `UNKNOWN`.
- **`FLAG_SECURE` policy** for the detail screen (§8/§13 OQ1) — product/security decision,
  not derivable from sources.
- **Currency = USD.** No `currency` field; inferred from the web `$` formatting and the
  US-only nature of IRS 1099-NEC. Treated as a safe assumption.
- **AND-246 / AND-223 internals** (`TaxFileDownloader`, `ApiResult<T>`, `ErrorMapper`,
  cookie jar, retry interceptor) are referenced as established contracts; not in the
  provided sources and not re-verified.

## 17. Test Plan

Test targets (per case): **JVM** = JVM unit/Robolectric (local, no device); **EMU** =
headless emulator AVD `test35` (x86_64, API 35); **DEVICE** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Cases that exercise only Kotlin
logic or MockWebServer run on JVM/EMU; cases that must validate real on-device MediaStore
write + OS Share chooser are noted as preferring the physical DEVICE.

- **TC-AND-247-01 — Happy-path list mapping.** Type: contract/MockWebServer. Target: JVM
  (Robolectric for Moshi). Preconditions: MockWebServer returns `200` `TaxForm1099ListOut`
  with one item (fields per §5). Steps: call `TaxForm1099Api.list()`; map via
  `toDomain()`. Expected: `Form1099` has `taxYear=2025`, `totalEarningsCents=1284500`,
  `payerTinLast4="6789"`, `generatedAt` parsed from epoch seconds, `status=GENERATED`,
  `correctionCount=0`; reads from `items[]`. Traces: AC-3, AC-5.
- **TC-AND-247-02 — Unknown/defaulted fields & forward-compat.** Type: unit. Target: JVM.
  Preconditions: list item with `status:"amended_xyz"`, `correction_count:2`, empty
  `form_id`, missing `download_url`. Steps: map to domain. Expected: `statusRaw` preserved,
  `status=CORRECTED` (because `correction_count>0`) or `UNKNOWN` per mapper rule;
  `downloadUrl=null`; mapping does not throw. Traces: AC-3, AC-5.
- **TC-AND-247-03 — Filename builder.** Type: unit. Target: JVM. Preconditions: form
  `taxYear=2025`. Steps: build download filename. Expected: `TestLogon_1099-NEC_2025.pdf`
  (no type/formId segments). Traces: AC-2.
- **TC-AND-247-04 — Download URL fetch then bytes.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: MockWebServer for `GET /ui/tax-forms/1099s/2025/download` →
  `{"download_url":"<mockserver>/blob"}` and `/blob` → a valid `%PDF` body. Steps:
  repository `download(2025)`. Expected: two requests issued (download-url then blob);
  bytes start with `%PDF`; `DownloadState.Done`. Asserts download is JSON-URL-indirect, not
  a streamed `application/pdf` from the API. Traces: AC-2.
- **TC-AND-247-05 — Validation error (422).** Type: contract/MockWebServer. Target: JVM.
  Preconditions: `GET /ui/tax-forms/1099s/9999` → `422` `HTTPValidationError`
  `{"detail":[{"msg":"value is not a valid integer", ...}]}`. Steps: call `get(9999)`.
  Expected: `ApiResult.Error` with the `msg` surfaced via the shared error mapper; not
  retried (4xx). Traces: AC-5.
- **TC-AND-247-06 — 401 → single refresh → retry.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: first `GET .../1099s` → `401`; `POST /ui/session/refresh` → `200`;
  retried list → `200`. Steps: call list. Expected: exactly one refresh call, list
  succeeds; a second consecutive 401 instead yields a re-auth `Error`. Traces: AC-5.
- **TC-AND-247-07 — Offline list serves Room cache (stale banner).** Type: integration.
  Target: JVM/Robolectric (in-memory Room). Preconditions: Room pre-seeded with one
  `Form1099Entity`; network call fails with connectivity error (ApiError status 0). Steps:
  observe repository flow. Expected: cached row emitted, `isStale=true`; UI state would show
  "Showing saved data". Traces: AC-4.
- **TC-AND-247-08 — Offline preview/download error.** Type: unit (ViewModel). Target: JVM.
  Preconditions: no cached PDF; download-url fetch fails offline. Steps: `vm.download()` /
  open preview. Expected: `DownloadState.Failed` / `PreviewState.Failed` with the offline
  message; `retry()` re-attempts. Traces: AC-4.
- **TC-AND-247-09 — Expired/empty download_url + non-PDF body.** Type: contract/
  MockWebServer. Target: JVM. Preconditions: `/download` → `{"download_url":""}` in one
  variant; in another, `download_url` resolves to a non-PDF (HTML) body. Steps: attempt
  download/preview. Expected: `Failed` state ("Couldn't open this form" for non-PDF);
  retry re-requests a fresh URL; magic-byte check (`%PDF`) gates success. Traces: AC-2, AC-4.
- **TC-AND-247-10 — Compose list renders metadata + corrected chip.** Type: Compose-UI.
  Target: EMU. Preconditions: list state with one 2025 form, `correction_count=1`. Steps:
  render the 1099 section. Expected: row shows tax year, `$12,845.00` USD, issue date from
  `generated_at`, and a "Corrected" chip; no NEC/K/MISC type badge; empty-state row shows
  when list is empty. Traces: AC-3.
- **TC-AND-247-11 — Compose detail renders PDF preview (the "renders" proof).** Type:
  instrumented (Compose-UI). Target: EMU (sufficient; `PdfRenderer` is not hardware-bound),
  also runnable on DEVICE. Preconditions: fixture `sample_1099.pdf` in
  `androidTest/assets`; MockWebServer wires `/download` → fixture. Steps: open
  `Form1099DetailScreen` for 2025. Expected: `Pdf1099Preview` shows a non-empty rendered
  bitmap node (state is `Rendered`, not `Failed`). Traces: AC-1.
- **TC-AND-247-12 — Download writes valid PDF to Downloads + Share sheet (the "downloads"
  proof).** Type: instrumented/e2e. Target: **PHYSICAL DEVICE preferred** (SM-A156U, API 34
  / arm64 — validates real `MediaStore.Downloads` write on the API 24-28-style legacy vs
  29+ boundary and the OS Share chooser via `FileProvider`), also runs on EMU. Steps: tap
  Download; on success, inspect the resulting `MediaStore` URI; trigger Share. Expected:
  `DownloadState.Done`; URI is readable; first bytes `%PDF`; file named per FR-6; Share
  chooser launches with a `content://` FileProvider URI carrying
  `FLAG_GRANT_READ_URI_PERMISSION` (no `file://`). Traces: AC-2, AC-7.
- **TC-AND-247-13 — Security: no PII in logs/telemetry; cache cleared on logout.** Type:
  instrumented. Target: EMU. Preconditions: analytics + log capture in test. Steps: view
  list, open detail, download; then logout. Expected: no TIN, amount, payer name, or raw
  `download_url` in logs/analytics events (only non-PII metadata per §10); cached
  `cacheDir/tax1099/<taxYear>.pdf` deleted after logout; no `file://` exposure. Traces:
  AC-6, AC-7.
- **TC-AND-247-14 — Accessibility (TalkBack/semantics).** Type: Compose-UI (a11y).
  Target: EMU (with Accessibility checks), spot-check on DEVICE with TalkBack. Steps: run
  Compose accessibility assertions on list + detail. Expected: row announces "Form
  1099-NEC, tax year 2025, status generated/corrected"; Download/Share have text labels and
  ≥48dp targets; preview pages labeled "Page n of m"; status conveyed by icon+text (not
  color alone). Traces: AC-3.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (renders preview) | TC-AND-247-11 |
| AC-2 (downloads valid PDF + share) | TC-AND-247-03, -04, -09, -12 |
| AC-3 (list metadata, ordering, status) | TC-AND-247-01, -02, -10, -14 |
| AC-4 (offline cache + offline errors) | TC-AND-247-07, -08, -09 |
| AC-5 (ApiResult, detail mapping, 401 refresh) | TC-AND-247-01, -05, -06 |
| AC-6 (no PII logged; cache cleared on logout) | TC-AND-247-13 |
| AC-7 (package/module reuse; scoped share) | TC-AND-247-12, -13 |
