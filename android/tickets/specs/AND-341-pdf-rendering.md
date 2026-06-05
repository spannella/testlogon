---
id: AND-341
title: PDF rendering
milestone: M7
epic: E44
priority: P1
size: M
status: draft
depends_on: [AND-340]
blocks: [AND-342]
---

# AND-341 — PDF rendering

## 1. Overview & Goal

Render the pages of a document (PDF) packet inside the native Android app so a user can view a multi-page document and scroll smoothly through it. This is the viewing substrate of the e-signature flow: AND-340 (Packet list + detail) opens a packet and routes to a document, and AND-341 turns the document's PDF bytes into pixels on screen. The next ticket, AND-342 (Signature capture + placement), draws signature fields and adopted signatures *on top of* the rendered pages, so this ticket must expose page geometry (size and on-screen rect per page) that an overlay can register against.

The renderer uses the platform `android.graphics.pdf.PdfRenderer` (available from API 21, well within minSdk 24) to rasterize pages to `Bitmap`s on demand, hosted in a vertically scrolling lazy list. No third-party PDF library is added; the platform renderer is sufficient for view-only flat PDFs and avoids licensing/size cost.

Goal acceptance (from backlog): *A multi-page document renders and scrolls.* Success means a packet's PDF downloads (or is read from cache), every page rasterizes correctly at display resolution, the list scrolls fluidly without OOM on large documents, and each visible page reports a stable on-screen rectangle for the AND-342 overlay.

## 2. Functional Requirements

FR-1. Given a document reference from a packet detail (AND-340), the screen resolves the document's PDF source (a download URL or a cached file) and renders it.
FR-2. All pages of the document render in a single vertically scrollable list, top to bottom, in document order, each page labeled with its 1-based index ("Page 3 of 12").
FR-3. Pages render at a resolution matched to the viewport width (fit-width) so text is legible; the bitmap render scale derives from page width in points vs. available pixel width, capped to bound memory.
FR-4. Rendering is lazy and windowed: only pages near the viewport are rasterized; off-screen page bitmaps are released to bound memory for large (50+ page) documents.
FR-5. The list scrolls smoothly (target 60 fps on mid-tier devices); a page that has not finished rasterizing shows a placeholder of the correct aspect ratio (so scroll position and overlay geometry are stable) and swaps in the bitmap when ready.
FR-6. Pinch-to-zoom and double-tap-to-zoom are supported within a bounded range (1.0x–3.0x); zoom re-rasterizes visible pages at the higher scale for crisp text rather than upscaling the existing bitmap (debounced).
FR-7. The screen exposes per-page geometry — page index, page size in PDF points, and current on-screen `Rect` in the scroll content — via a stable callback/state for the AND-342 overlay to consume. This ticket renders no signature UI itself.
FR-8. While the PDF is downloading, a loading state is shown; on failure (host down, corrupt/non-PDF, decrypt-required) a typed error state with retry (for retryable causes) is shown.
FR-9. The document source file is read via a seekable file descriptor (`PdfRenderer` requires `ParcelFileDescriptor` over a local `File`); a streamed/remote PDF is fully downloaded to app cache before rendering.

## 3. Context & References

- Lives in `:feature-packets` (the packet/document feature module introduced by AND-340). AND-340 owns the packet list, packet detail, document selection, and navigation into this viewer; AND-341 adds the `DocumentViewerScreen` and the rendering pipeline behind it.
- **Depends on AND-340** for: the navigation route into the viewer, the document identifiers (packet id + document id), and the document metadata/download surface in the packets API/repository.
- **Blocks AND-342** (Signature capture + placement), which overlays signature fields on the page geometry this ticket exposes. The `PageLayout` contract in §6 is the integration seam.
- Module layering: `:app -> :feature-packets -> :core-network, :core-model, :core-data, :core-ui, :core-testing`. The PDF download helper reuses the authenticated OkHttp client (cookies + `X-CSRF-Token`) from `:core-network`.
- Stack: Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable — design ~20s timeouts, bounded backoff for idempotent GETs, offline/stale states). Cookie-based auth; persistent cookie jar; single `POST /ui/session/refresh` retry on 401. OpenAPI at `/openapi.json` is authoritative; the document/download endpoint path and field names below MUST be reconciled against it and the web reference (`frontend/src/api/endpoints/*`) at kickoff (see §13).
- Namespace / applicationId base: `com.testlogon.android`.

## 4. Technical Design

### Module placement
New code lands in `:feature-packets` under a `document/` package, except the authenticated file-download helper, which lives in `:core-network` so other binary-fetch tickets can reuse it.

### Domain & state types (`:core-model`)
```kotlin
data class DocumentRef(
    val packetId: String,
    val documentId: String,
    val displayName: String,
)

/** Geometry the AND-342 overlay registers against. PDF points = 1/72 inch. */
data class PageLayout(
    val index: Int,            // 0-based page index
    val widthPts: Float,       // page media-box width in PDF points
    val heightPts: Float,      // page media-box height in PDF points
)

sealed interface DocumentUiState {
    data object Loading : DocumentUiState              // resolving + downloading
    data class Ready(
        val ref: DocumentRef,
        val pageCount: Int,
        val pages: List<PageLayout>,
        val isStale: Boolean,                          // served from cache, host unhealthy
    ) : DocumentUiState
    data class Error(val cause: AppError, val retryable: Boolean) : DocumentUiState
}
```

### PDF source acquisition (`:core-network`)
```kotlin
interface FileDownloader {
    /** Streams an authenticated GET to a cache file; verifies content and returns it. */
    suspend fun downloadToCache(
        url: String,
        targetFileName: String,
        expectedContentType: String? = "application/pdf",
        onProgress: (read: Long, total: Long) -> Unit = { _, _ -> },
    ): ApiResult<File>
}
```
`FileDownloaderImpl` uses the normal authenticated `OkHttpClient` (cookies + `X-CSRF-Token`, 401 refresh-once) but with a longer `callTimeout` (60s) for large PDFs, streaming the response body to `cacheDir/documents/{packetId}/{documentId}.pdf`. The download is content-addressed by document id + an ETag/version so a re-open hits the cache.

### Page renderer (`:feature-packets`, `document/`)
```kotlin
interface PdfPageRenderer : Closeable {
    val pageCount: Int
    fun pageLayout(index: Int): PageLayout
    /** Rasterize one page to a Bitmap at the given pixel width (height derived from aspect). */
    suspend fun renderPage(index: Int, targetWidthPx: Int): Bitmap
}
```
`PdfRendererImpl(file: File)` opens a single `PdfRenderer` over a `ParcelFileDescriptor.open(file, MODE_READ_ONLY)`. **`PdfRenderer` is not thread-safe and only one page may be open at a time**, so all `openPage`/render calls funnel through a dedicated single-thread `CoroutineDispatcher` (`Dispatchers.IO.limitedParallelism(1)` or a private `newSingleThreadContext`) guarded by a `Mutex`. `renderPage` computes height from the page aspect ratio, allocates an `ARGB_8888` bitmap pre-filled white, and calls `page.render(bmp, null, null, RENDER_MODE_FOR_DISPLAY)`. A render-scale cap (max bitmap edge ≈ 2048 px, or width-bounded by viewport) prevents OOM on huge pages.

### Bitmap cache
An LRU `BitmapPageCache` sized from `ActivityManager.memoryClass` (e.g., 1/8 of available heap) keyed by `(index, targetWidthPx)`. Eviction recycles bitmaps not currently composed. Renders are deduplicated: a page already in flight returns the same `Deferred<Bitmap>`.

### Compose UI
```kotlin
@Composable
fun DocumentViewerScreen(
    state: DocumentUiState,
    onRetry: () -> Unit,
    onPageLayout: (List<PageOnScreen>) -> Unit,   // feeds AND-342 overlay
)

data class PageOnScreen(val index: Int, val contentRect: Rect) // px in scroll content space
```
A `LazyColumn` with one item per page index. Each item is a `PdfPageItem(index, layout, zoom)` that requests its bitmap from the ViewModel and draws it with `Image`/`drawIntoCanvas`, using a placeholder `Spacer` of the correct aspect ratio until ready. Zoom is a `graphicsLayer`/`pointerInput` transform on the column content with bounds [1.0x, 3.0x]; on settle, visible pages re-render at the zoom-scaled width (debounced ~150ms). Each item reports its `onGloballyPositioned` bounds upward, assembled into `List<PageOnScreen>` and emitted via `onPageLayout` for the overlay.

### ViewModel
```kotlin
@HiltViewModel
class DocumentViewerViewModel @Inject constructor(
    private val packetsRepo: PacketsRepository,     // from AND-340 (resolves download URL)
    private val downloader: FileDownloader,
    private val rendererFactory: PdfRendererFactory,
    private val health: BackendHealthSignal,
    savedState: SavedStateHandle,                   // packetId, documentId from nav args
) : ViewModel() {
    val uiState: StateFlow<DocumentUiState>
    fun bitmapFor(index: Int, widthPx: Int): StateFlow<Bitmap?>
    fun setZoom(scale: Float)
    fun retry()
    override fun onCleared()  // closes PdfRenderer + recycles cache
}
```
`init` resolves the download URL via `PacketsRepository`, downloads to cache (or reuses cache if fresh / host unhealthy → `isStale = true`), opens the `PdfRenderer`, emits `Ready` with `pageCount` and all `PageLayout`s (cheap: open each page only to read size, closing immediately). `onCleared` closes the renderer and the `ParcelFileDescriptor` and recycles cached bitmaps.

## 5. API Contract

This ticket consumes the packets API surface owned by AND-340; it does not define new endpoints, but it does fetch the raw PDF bytes. Path/field names are the working contract and MUST be reconciled against `/openapi.json` and `frontend/src/api/endpoints/*` (§13).

### Resolve document download (via AND-340 repository)
`GET /ui/packets/{packet_id}/documents/{document_id}` (metadata, already modeled by AND-340) is expected to include a download reference:
```json
{
  "document_id": "doc_8f1c",
  "name": "Lease Agreement.pdf",
  "page_count": 12,
  "content_type": "application/pdf",
  "download_url": "/ui/packets/pk_42/documents/doc_8f1c/content",
  "version": 3
}
```

### Fetch PDF bytes
`GET {download_url}` (e.g. `GET /ui/packets/pk_42/documents/doc_8f1c/content`) — authenticated UI GET (session cookie + `X-CSRF-Token`). Response: `200` with `Content-Type: application/pdf` and the raw PDF body (possibly `Content-Length`/ETag for caching). This is an **idempotent GET**, so it participates in bounded-backoff retry and the single 401 → `POST /ui/session/refresh` → retry path. The client streams the body to cache; it never holds the whole PDF in memory as a byte array beyond the OkHttp sink.

### Error envelope
On non-PDF/error responses, FastAPI `detail` may be `string`, `[{ "msg": "...", "loc": [...] }]`, or `{ "code": "...", ... }`; the shared mapper (`:core-network`) normalizes all three into `AppError`. Notable cases: `404` (document missing → non-retryable error), `403`/`401` (session expired → refresh-once then retry; persistent 403 → non-retryable), `415`/unexpected content type (not a PDF → corrupt/unsupported error), `5xx`/timeout (retryable, dev host flakiness).

## 6. Data & State Management

- **Document cache (filesystem):** downloaded PDFs live in `cacheDir/documents/{packetId}/{documentId}.pdf`, keyed for reuse by `version`/ETag. A re-open of the same fresh version skips the network. A startup/`onCleared` sweep removes files older than 7 days or for closed packets.
- **Render cache (memory):** `BitmapPageCache` LRU as described in §4; not persisted. On process death the screen restarts from `Loading` (PDF re-read from file cache, bitmaps re-rasterized) — acceptable because file cache makes this fast.
- **No new Room entities.** Document/packet metadata persistence is owned by AND-340; this ticket reads it. If a small `documents` cache table is desired for offline document lists, that belongs to AND-340, not here.
- **UI state** is a single `StateFlow<DocumentUiState>` in the ViewModel; per-page bitmaps are exposed as independent `StateFlow<Bitmap?>` so each `LazyColumn` item recomposes only when its own page is ready.
- **Page geometry seam (AND-342):** `Ready.pages: List<PageLayout>` gives PDF-point dimensions; the composable emits live on-screen rects via `onPageLayout(List<PageOnScreen>)`. Together these let the overlay map a normalized field position (0..1 within a page) to an on-screen rect and back, independent of zoom/scroll. This contract is the agreed integration boundary with AND-342 and must remain stable.

## 7. Error Handling & Resilience

- **Timeouts:** metadata GET uses the app default ~20s; the content GET uses a 60s call timeout for large PDFs on the flaky dev host.
- **Retry policy:** both GETs are idempotent → bounded exponential backoff (reuse the `:core-network` retry policy from the GET-retry ticket). A user-facing retry button drives `retry()` for retryable `AppError`s.
- **401 handling:** content/metadata GETs use the standard refresh-once-then-retry via the OkHttp authenticator; no custom auth code here.
- **Host down / stale:** if `BackendHealthSignal` is unhealthy but a cached PDF exists, render from cache and set `isStale = true`, surfacing the shared stale/offline affordance from `:core-ui`. If unhealthy and no cache, emit `Error(NetworkUnavailable, retryable = true)`.
- **Corrupt / non-PDF:** `PdfRenderer` construction throwing `IOException` (or a content-type mismatch) → `Error(cause = DocumentCorrupt, retryable = false)`; the bad cache file is deleted so a retry re-downloads.
- **Password-protected PDF:** `PdfRenderer` throws `SecurityException` on encrypted PDFs → `Error(DocumentProtected, retryable = false)` with a clear message (no decrypt UI in this ticket; flag as open question §13).
- **OOM safety:** bitmaps are `ARGB_8888` sized to viewport with a max-edge cap; rendering runs on the single render dispatcher; on `OutOfMemoryError` during a page render, evict the cache, retry that page once at a lower scale, and if it still fails show a per-page "couldn't render this page" placeholder rather than crashing.
- **Lifecycle:** the `PdfRenderer` and its `ParcelFileDescriptor` are closed in `onCleared`; in-flight render jobs cancel with the `viewModelScope`.

## 8. Security & Privacy

- **Transport:** the content GET targets the plaintext dev API host; the network-security config keeps cleartext allowed only for that dev host (no global relaxation). If the backend ever returns an absolute presigned object-store URL, prefer HTTPS for it.
- **Credentials/CSRF:** the content GET carries the session cookie and `X-CSRF-Token` via the shared interceptors. Never log cookies, CSRF token, or full signed URLs.
- **At-rest:** documents may contain sensitive PII (legal docs). They are written to app-internal `cacheDir` (not external storage), never world-readable, and excluded from auto-backup (`android:fullBackupContent`/`dataExtractionRules` exclude `documents/`). The 7-day sweep and packet-close cleanup limit retention.
- **No export:** this ticket does not add share/print/save-to-Downloads; document bytes stay in app-internal storage. Any export is a separate ticket.
- **Screenshots:** consider `FLAG_SECURE` on the viewer if the product requires it; flagged as an open question (§13) since it impacts QA/screenshots.
- **PII in logs:** log document id + packet id + page count only; never document text, file paths with user identifiers, or response bodies.

## 9. Accessibility & i18n

- Each page exposes a `contentDescription` ("Page 3 of 12") so TalkBack can announce position while scrolling; the page image itself is marked decorative beyond that label (the document text is not OCR-exposed in this ticket — note as a known a11y limitation).
- Loading, stale, and error states use the shared accessible `:core-ui` state composables; the retry control is a labeled button with a ≥48 dp touch target.
- Zoom is operable without gestures where feasible: provide accessible zoom in/out actions (custom accessibility actions on the viewer) in addition to pinch.
- All user-facing strings ("Page %1\$d of %2\$d", loading/error/stale/retry/protected messages) live in `strings.xml` with proper plurals/positional args; no hardcoded literals. Layout supports RTL (page chrome mirrors; page bitmaps render as-authored).
- Respect large font scale for page labels and error text (dp/sp, not hardcoded px).

## 10. Telemetry & Logging

- Structured events (no PII): `document_open_started{packetId,documentId}`, `document_download_ok{bytes,ms,fromCache:Boolean}`, `document_render_ready{pageCount,ms}`, `document_page_rendered{index,widthPx,ms}` (sampled), `document_zoom{scale}` (sampled), `document_open_failed{stage,error_code}`, `document_stale_shown`.
- `stage` ∈ `{resolve, download, open, render}` to localize failures on the flaky host.
- Debug-only logs gate behind `BuildConfig.DEBUG`; redact any URLs to `host + pathPrefix`.
- A render-success-rate and median time-to-first-page metric feed perf monitoring; no document content or dimensions beyond page count and bitmap pixel size are recorded.

## 11. Testing Strategy

**Unit (`:core-testing`, JUnit + coroutines test):**
- `FileDownloaderImpl`: MockWebServer streams a small fixture PDF → returns a cache `File`; 404/415 map to expected `AppError`; 401 triggers refresh-once-then-retry; cache reuse skips the network when version unchanged.
- `PdfRendererImpl`: opens a bundled multi-page fixture PDF (in `:core-testing` assets), reports correct `pageCount` and `PageLayout` dimensions; `renderPage` returns a non-blank bitmap of the expected aspect; concurrent `renderPage` calls are serialized (no `PdfRenderer` IllegalState/crash) — assert single-threaded access via the dispatcher/mutex.
- `BitmapPageCache`: LRU eviction recycles correctly; in-flight dedupe returns the same `Deferred`.
- ViewModel state machine: `Loading → Ready(pageCount, pages)`; host-down-with-cache → `Ready(isStale=true)` without a network call; host-down-no-cache and corrupt-PDF → expected `Error`.

**Instrumented / Compose UI:**
- Open the bundled multi-page fixture: assert the `LazyColumn` shows the first page, then **scroll to the last page index and assert it composes/renders** (this is the canonical *multi-page renders + scrolls* check).
- Placeholder of correct aspect shows before a page's bitmap is ready; bitmap swaps in.
- Pinch/double-tap zoom changes scale within [1.0, 3.0] and triggers re-render of visible pages.
- `onPageLayout` emits a `PageOnScreen` rect for visible pages, and the rect updates on scroll (the AND-342 seam).
- Error state renders with a working retry; stale state shows the offline affordance.

**Acceptance (satisfies backlog "multi-page doc renders + scrolls"):** the instrumented test above against a ≥3-page fixture, stubbing the content GET via MockWebServer.

## 12. Dependencies & Sequencing

- **Depends on AND-340** (Packet list + detail): the `:feature-packets` module, the nav route into the viewer with `packetId`/`documentId` args, the `PacketsRepository` method that resolves a document's `download_url`/metadata, and any document-metadata DTOs. AND-341 cannot merge before AND-340's document detail + repository surface exist.
- **Blocks AND-342** (Signature capture + placement): AND-342 builds the signature overlay on the `PageLayout` / `PageOnScreen` geometry seam defined here (§6). Land the geometry contract early and keep it stable.
- Implicitly relies on the established `:core-network` authenticated OkHttp/Retrofit client, CSRF + 401-refresh interceptors, GET retry/backoff, `ApiResult`/error mapper, and `BackendHealthSignal` from earlier networking/resilience tickets.
- Sequencing: bundle a multi-page fixture PDF in `:core-testing` → implement `FileDownloader` in `:core-network` (MockWebServer-tested) → `PdfRendererImpl` + `BitmapPageCache` (unit-tested, headless) → `DocumentViewerViewModel` orchestration → `DocumentViewerScreen` Compose UI + zoom + geometry emit → wire into AND-340 nav → instrumented scroll acceptance test.

## 13. Risks & Open Questions

- **Contract drift:** the document content endpoint path, whether it's a relative `download_url` from metadata vs. a fixed `/content` route, and the content-type/ETag behavior are assumed; reconcile with `/openapi.json` and `frontend/src/api/endpoints/*` before coding. *Owner: implementer at kickoff.*
- **`PdfRenderer` limitations:** flat PDFs only; no AcroForm fields, JavaScript, or interactive elements, and **encrypted/password PDFs throw `SecurityException`**. If packets can be encrypted, a decrypt path (or a different renderer such as PdfBox-Android/PSPDFKit) is a follow-up — confirm packet PDF characteristics with backend. *Open.*
- **Geometry coordinate system for AND-342:** confirm that normalized (0..1) per-page coordinates plus `PageLayout` points + `PageOnScreen` px rects are sufficient for signature placement under zoom/scroll, and agree the exact `Rect` space (content vs. viewport) with the AND-342 owner. *Open.*
- **Performance on very large docs:** 100+ page or high-DPI scanned PDFs may stress memory/scroll; the windowed render + LRU + max-edge cap should hold, but validate on a low-RAM device. Render-scale cap value (2048 px) may need tuning.
- **`FLAG_SECURE` / screenshot policy:** product decision on whether the viewer must block screenshots (impacts QA). *Open.*
- **Zoom approach:** re-rasterizing on zoom (crisp text) vs. bitmap upscaling (cheaper, blurry); spec assumes debounced re-raster within [1.0, 3.0]. Tile-based rendering is out of scope unless perf testing demands it.

## 14. Acceptance Criteria

AC-1. Opening a document from a packet (AND-340) renders all its pages in a vertical scroll list in document order, each labeled "Page N of M". **(backlog: "Multi-page doc renders")**
AC-2. The user can scroll from the first page to the last page of a ≥3-page document and every page rasterizes to a non-blank bitmap of correct aspect ratio. **(automated, canonical "renders + scrolls")**
AC-3. Rendering is windowed: off-screen page bitmaps are released and the renderer never holds more than the configured LRU budget; a 50+ page fixture scrolls without OOM. **(unit + instrumented)**
AC-4. While a page's bitmap is not ready, an aspect-correct placeholder holds its position so scroll offset and geometry stay stable, then the bitmap swaps in. **(instrumented UI)**
AC-5. Pinch and double-tap zoom operate within [1.0x, 3.0x] and re-render visible pages crisply (debounced). **(instrumented UI)**
AC-6. The screen emits per-page geometry (`PageLayout` + on-screen `PageOnScreen` rects) that updates on scroll/zoom, consumable by AND-342. **(instrumented UI assertion)**
AC-7. PDF bytes are fetched via the authenticated, idempotent content GET (cookie + `X-CSRF-Token`, 401 refresh-once, bounded retry) and streamed to app-internal cache. **(unit-tested)**
AC-8. When the host is unhealthy but the PDF is cached, the document renders from cache with a stale indicator; with no cache, a retryable error state shows. **(unit + UI)**
AC-9. Corrupt/non-PDF responses and encrypted PDFs produce clear, non-retryable error states (and corrupt cache is purged) rather than crashing. **(unit-tested)**
AC-10. `PdfRenderer` access is serialized on a single thread with no IllegalState/crash under concurrent page requests; renderer + FD are closed on `onCleared`. **(unit-tested)**
AC-11. All user-facing strings are in `strings.xml`; page labels announce to TalkBack; documents are app-internal and excluded from backup. **(lint + a11y + inspection)**

## 15. Definition of Done

- All Acceptance Criteria met; the canonical multi-page render-and-scroll instrumented test passes in CI on the headless emulator.
- New code in `:feature-packets` (`document/`) and `:core-network` (`FileDownloader`) under `com.testlogon.android`; module layering respected (no `:feature-*` → `:feature-*` deps).
- Unit + instrumented tests added per §11; coverage for `FileDownloaderImpl`, `PdfRendererImpl` (incl. single-thread serialization), `BitmapPageCache` eviction, error/stale mapping, and the ViewModel state machine; a multi-page fixture PDF is bundled in `:core-testing`.
- Document content endpoint path/fields reconciled against `/openapi.json` and the web reference; deviations from §5 documented in the PR.
- No memory leaks: `PdfRenderer`/`ParcelFileDescriptor` closed and bitmaps recycled on `onCleared`, verified in an instrumented test; cache sweep removes stale files.
- The `PageLayout`/`PageOnScreen` geometry seam is reviewed and signed off by the AND-342 owner as sufficient for signature placement.
- No lint regressions; no hardcoded strings; ktlint/detekt clean.
- Telemetry events emit with correct `stage` and no PII; debug logs gated by `BuildConfig.DEBUG`.
- Network-security config still scopes cleartext to the dev host only; documents excluded from auto-backup.
- PR description notes resolved/outstanding §13 items (esp. encrypted-PDF support and `FLAG_SECURE` decision).
