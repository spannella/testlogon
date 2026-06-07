---
id: AND-341
title: PDF rendering
milestone: M7
epic: E44
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Module layering: `:app -> :feature-packets -> :core-network, :core-model, :core-data, :core-ui, :core-testing`. The PDF download helper reuses the authenticated OkHttp client from `:core-network`. **(CORRECTED)** The web reference (`src/api/client.ts`) sends, on every call: `Authorization: Bearer <accessToken>`, session cookies (`credentials: include`), `X-CSRF-Token` (read from the `ui_csrf` cookie), and an optional `X-IMPERSONATION-TOKEN`; the OpenAPI additionally declares optional `X-SESSION-ID` header and `user_sub` query params on these routes. The earlier "cookies + `X-CSRF-Token`" phrasing was incomplete — the Bearer access token is the primary credential. The download helper must reuse all of these interceptors, not just the cookie jar.
- Stack: Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable — design ~20s timeouts, bounded backoff for idempotent GETs, offline/stale states). **(CORRECTED)** Auth is Bearer access token + session cookies + `X-CSRF-Token`; persistent cookie jar; single `POST /ui/session/refresh` retry on 401 — verified in `src/api/client.ts` (`refreshSession`). OpenAPI at `/openapi.json` is authoritative; the endpoint paths and field names below have now been reconciled against it and the web reference (`reference/src/api/endpoints/signaturePackets.ts`) — see §16 for the corrections.
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
`FileDownloaderImpl` uses the normal authenticated `OkHttpClient` (Bearer token + cookies + `X-CSRF-Token`, 401 refresh-once — see §3 correction) but with a longer `callTimeout` (60s) for large PDFs, streaming the response body to `cacheDir/documents/{packetId}/{documentId}.pdf`. **(CORRECTED)** since the server does not return a `version` field on these routes, cache freshness is keyed by `packetId` (+ HTTP `ETag`/`Last-Modified` if the server happens to send them); absent those, treat a cached file as fresh for a short TTL and otherwise re-download. The download verifies the body starts with `%PDF-` rather than trusting `Content-Type`.

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

This ticket consumes the signature-packet API surface owned by AND-340; it does not define new endpoints, but it does fetch the raw PDF bytes.

> **(CORRECTED at review.)** The original draft assumed a per-document model (`GET /ui/packets/{packet_id}/documents/{document_id}` with `document_id`/`page_count`/`download_url`/`content_type`/`version`). **No such endpoint or fields exist.** The authoritative surface is the *signature-packet* API: a packet has a single source PDF identified by `source_path` (a file-path string), plus a list of `fields` carrying page geometry. There is no per-document sub-resource and no server-reported `page_count`. The `DocumentRef.documentId` concept in §4 should be treated as a synonym for `packet_id` (a packet maps 1:1 to one PDF) unless AND-340 introduces a real multi-document model. The Android `PdfRenderer` derives `pageCount` and per-page sizes locally from the rendered file.

### Resolve packet + source PDF (via AND-340 repository)
`GET /v1/signature-packets/{packet_id}` → `200: SignaturePacketDetailOut`. **Verified** against OpenAPI (`op=get_signature_packet_detail_...`) and `src/api/endpoints/signaturePackets.ts: getSignaturePacketDetail`. Shape (verified fields; required ones marked *):
```json
{
  "packet_id": "pk_42",          // * string
  "status": "sent",              // * string (draft|sent|partially_signed|completed|cancelled|expired)
  "owner_user_id": "u_…",        // * string
  "source_path": "/contracts/nda.pdf", // * string — the source PDF reference
  "role": "signer",              // * "sender" | "signer"
  "signers": [ { "signer_id": "…", "status": "pending" } ],   // * array
  "fields":  [ { "field_id": "…", "page": 0, "x": 0.1, "y": 0.2, "width": 0.3, "height": 0.05, "field_type": "signature", "required": true } ], // * array — page geometry for AND-342
  "capabilities": { "can_edit_fields": false, "can_send": false, "can_fill_fields": true }, // * object<string,bool>
  "legal_notice": null,          // optional object|null
  "signer_status": "pending",    // optional
  "created_at": null, "sent_at": null, "completed_at": null,
  "origin_channel": null, "origin_ref": null
}
```
Note: `page_count` is NOT present; pages are discovered locally. The `fields[]` page/x/y/width/height are the geometry seam for AND-342 and are already normalized-style coords per the web client's `SignaturePacketField` type.

### Fetch PDF bytes
**(CORRECTED.)** The only PDF-bytes endpoint in the spec is `GET /v1/signature-packets/{packet_id}/final-pdf` (the *final / completed* PDF), **verified** at OpenAPI `op=get_signature_packet_final_pdf_...` and `src/api/endpoints/signaturePackets.ts: downloadSignaturePacketFinalPdf`. The web client fetches it with a raw `fetch` carrying `Authorization: Bearer <accessToken>` + `credentials: include`, then downloads the blob. This is an **idempotent GET**, so it participates in bounded-backoff retry and the single 401 → `POST /ui/session/refresh` → retry path; stream the body to cache (never buffer the whole PDF as a byte array beyond the OkHttp sink).
- *Caveat:* `final-pdf` returns the SIGNED/flattened PDF and exists only once a packet is far enough along; its OpenAPI `200` content is declared as `application/json: {}` (untyped binary passthrough), so the Android client must treat the body as raw bytes and validate the magic header (`%PDF-`) rather than trusting `Content-Type`.
- **Open assumption (see §16):** how to fetch the *unsigned source* PDF (`source_path`) by packet id is NOT modeled in the current OpenAPI/web reference. AND-340 must surface this (e.g. a packets-repository method, an fs-download/presign route such as the `/v1/fs/presign-upload` family, or a route to be added). Until then this ticket renders whatever PDF bytes AND-340's repository hands back.

### Error envelope
On error responses, FastAPI `detail` may be a `string`, an array of `{ "msg": "...", "loc": [...] }` (the documented `422 HTTPValidationError` → `ValidationError` shape — **verified** in OpenAPI components), or an object with a `code` field; the shared mapper (`:core-network`) normalizes all three into `AppError`, mirroring `normalizeErrorDetail` in `src/api/client.ts`. **(CORRECTED.)** The only response codes these routes *declare* are `200` and `422`. The `404`/`403`/`415` cases in the original draft are **unverified assumptions** about runtime behavior (FastAPI dependencies routinely raise `401`/`403`, and missing packets typically `404`, but the schema does not enumerate them) — keep handling them defensively but do not present them as contract guarantees. Retry semantics: `401` → refresh-once-then-retry; `5xx`/timeout → retryable (dev-host flakiness); a body that is not a PDF (`%PDF-` check fails) → non-retryable corrupt-document error.

## 6. Data & State Management

- **Document cache (filesystem):** downloaded PDFs live in `cacheDir/documents/{packetId}/{documentId}.pdf`, keyed for reuse by HTTP `ETag`/`Last-Modified` when present (**CORRECTED:** there is no server `version` field on these routes). A re-open of the same unchanged file skips the network. A startup/`onCleared` sweep removes files older than 7 days or for closed packets.
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

- **Contract drift (RESOLVED at review, with one open item):** the document model was reconciled against `/openapi.json` and `src/api/endpoints/signaturePackets.ts` (see §16). Corrected: there is no per-document endpoint; the surface is `GET /v1/signature-packets/{packet_id}` (detail) and `GET /v1/signature-packets/{packet_id}/final-pdf` (signed PDF bytes); no `page_count`/`version` fields; auth is Bearer + cookies + CSRF. **Still open:** there is no modeled endpoint to fetch the *unsigned source* PDF (`source_path`) by packet id — AND-340 must surface this. *Owner: AND-340 + implementer at kickoff.*
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** Document metadata is fetched via `GET /ui/packets/{packet_id}/documents/{document_id}` returning `document_id`/`name`/`page_count`/`content_type`/`download_url`/`version`. — **Verdict: Corrected.** No such path or fields exist. — **Source:** OpenAPI index (`reference/openapi.index.txt`) has no `/ui/packets/...` route; the packet detail is `GET /v1/signature-packets/{packet_id}` (`op=get_signature_packet_detail_v1_signature_packets__packet_id__get`).
2. **Claim:** Packet detail shape. — **Verdict: Corrected to verified shape.** Fields are `packet_id, status, owner_user_id, source_path, role, signers[], fields[], capabilities` (required) plus optional `legal_notice, signer_status, created_at, sent_at, completed_at, origin_channel, origin_ref`. No `page_count`. — **Source:** OpenAPI `components.schemas.SignaturePacketDetailOut`; `src/api/endpoints/signaturePackets.ts: SignaturePacketDetail` / `getSignaturePacketDetail`.
3. **Claim:** PDF bytes are fetched from a `…/content` route resolved via `download_url`. — **Verdict: Corrected.** The PDF-bytes route is `GET /v1/signature-packets/{packet_id}/final-pdf` (the SIGNED/final PDF). — **Source:** OpenAPI `op=get_signature_packet_final_pdf_v1_signature_packets__packet_id__final_pdf_get`; `src/api/endpoints/signaturePackets.ts: downloadSignaturePacketFinalPdf`.
4. **Claim:** The content GET returns `Content-Type: application/pdf` with the raw body. — **Verdict: Corrected/Unverified.** OpenAPI declares `final-pdf` `200` content as `application/json: {}` (untyped binary passthrough); the client must validate the `%PDF-` magic header, not `Content-Type`. — **Source:** OpenAPI path object for `/v1/signature-packets/{packet_id}/final-pdf` responses (line ~288302).
5. **Claim:** Fetching the *unsigned source* PDF for view-only rendering. — **Verdict: Unverified-assumption.** Packet detail exposes `source_path` (a file-path string) but no modeled endpoint streams that source PDF by packet id; `final-pdf` is the only PDF-bytes route and is the signed output. — **Source:** absence in `reference/openapi.index.txt` and `src/api/endpoints/signaturePackets.ts` (only `final-pdf`).
6. **Claim:** Auth is "cookie-based / cookies + `X-CSRF-Token`". — **Verdict: Corrected (incomplete).** Every call sends `Authorization: Bearer <accessToken>` (primary), session cookies (`credentials: include`), `X-CSRF-Token` (from the `ui_csrf` cookie), and optional `X-IMPERSONATION-TOKEN`; OpenAPI also declares optional `X-SESSION-ID` header and `user_sub` query. — **Source:** `src/api/client.ts` (lines 156–171); OpenAPI params on these routes (`X-SESSION-ID,X-IMPERSONATION-TOKEN,user_sub`).
7. **Claim:** Single `POST /ui/session/refresh` retry on 401. — **Verdict: Verified.** — **Source:** `src/api/client.ts: refreshSession` / 401 branch (lines 121–237); OpenAPI `op=ui_session_refresh_ui_session_refresh_post`.
8. **Claim:** FastAPI `detail` may be string, `[{msg, loc}]`, or `{code,…}`; mapper normalizes all three. — **Verdict: Verified.** — **Source:** OpenAPI `components.schemas.HTTPValidationError` + `ValidationError` (`{loc, msg, type}`); `src/api/client.ts: normalizeErrorDetail` (lines 66–102).
9. **Claim:** Error responses include `404`/`403`/`415` cases as part of the contract. — **Verdict: Unverified-assumption.** These signature-packet routes declare only `200` and `422` in OpenAPI; 401/403/404 occur at runtime via FastAPI deps but are not schema-enumerated. — **Source:** OpenAPI responses for the two routes (only `200`/`422`).
10. **Claim:** The web client renders the source PDF (basis for the renderer contract). — **Verdict: Corrected.** The web reference does NOT rasterize the PDF; its "PDF editor canvas" is a dashed placeholder div with absolutely-positioned field boxes. Android must implement rendering from scratch. — **Source:** `src/pages/files/SignaturePacketComposer.tsx` (line ~606, `data-testid="signature-canvas"`; no `pdfjs`/`react-pdf` import).
11. **Claim:** Field/page geometry is available for the AND-342 overlay. — **Verdict: Verified.** `fields[]` carry `page, x, y, width, height, field_type, required, assigned_signer_id?`. — **Source:** `src/api/endpoints/signaturePackets.ts: SignaturePacketField` (lines 23–38).
12. **Claim:** `android.graphics.pdf.PdfRenderer` exists from API 21, is not thread-safe, allows one open page at a time, and throws `SecurityException` on encrypted PDFs. — **Verdict: Verified (framework ref).** — **Source:** framework ref — Android docs `https://developer.android.com/reference/android/graphics/pdf/PdfRenderer` and `PdfRenderer.Page`.
13. **Claim:** `PdfRenderer` requires a seekable `ParcelFileDescriptor` over a local `File` (so remote PDFs must be downloaded to cache first). — **Verdict: Verified (framework ref).** — **Source:** framework ref — Android docs `PdfRenderer(ParcelFileDescriptor)` constructor.
14. **Claim:** No new Room entities / no new server endpoints introduced by this ticket. — **Verdict: Verified (by scope).** This ticket only reads AND-340's surface and fetches PDF bytes. — **Source:** ticket scope `specs-src/AND-341.md`; no new ops in `reference/openapi.index.txt` attributable here.

### Corrections made
- §3 / §5 / §4 / §6 / §13: replaced the fictional `GET /ui/packets/{id}/documents/{id}` + `download_url`/`page_count`/`content_type`/`version` model with the real `GET /v1/signature-packets/{packet_id}` (`SignaturePacketDetailOut`) and `GET /v1/signature-packets/{packet_id}/final-pdf` (signed PDF bytes).
- §3: corrected auth from "cookies + `X-CSRF-Token`" to **Bearer access token + cookies + `X-CSRF-Token` (+ optional `X-IMPERSONATION-TOKEN`/`X-SESSION-ID`)**.
- §5: corrected the success `Content-Type` claim — body is treated as raw bytes validated by `%PDF-` magic, since OpenAPI declares `200` as `application/json: {}`; downgraded `404/403/415` from "contract" to defensive runtime handling.
- §4/§6: removed reliance on a server `version` field for cache keying; switched to `ETag`/`Last-Modified` (+ TTL fallback).
- §1/§5: noted the web client does not actually rasterize PDFs (placeholder canvas), so the Android renderer is greenfield.

### Open assumptions
- **Source-PDF fetch by packet id is unmodeled.** Only `final-pdf` (signed) is exposed; how to retrieve the unsigned `source_path` bytes for view-only rendering must come from AND-340 (repository method, fs presign/download route, or a new endpoint). *Why unverifiable:* not present in OpenAPI or the web reference.
- **`DocumentRef.documentId` vs `packet_id`.** The current API is 1 packet → 1 PDF; a true multi-document model is assumed-away. *Why:* no document sub-resource exists; revisit if AND-340 adds one.
- **Encrypted/password-protected packet PDFs.** Whether packets are ever encrypted (would make `PdfRenderer` throw `SecurityException`) is a product/backend question. *Why:* no schema field indicates encryption.
- **`FLAG_SECURE` / screenshot policy.** Product decision, not derivable from sources.
- **ETag/Last-Modified presence on `final-pdf`.** The server may or may not send caching headers; not declared in OpenAPI. *Why:* response headers not enumerated.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric (no device); **emu test35** = headless AVD x86_64 / Android 15 / API 35 (CI); **device A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). For ABI/API-version-sensitive native-codec behavior the physical device is preferred.

- **TC-AND-341-01** — Type: contract/MockWebServer (JVM). Target: JVM. Test target: `FileDownloaderImpl`. Preconditions: MockWebServer enqueues `200` with a small fixture PDF body (starts with `%PDF-`). Steps: call `downloadToCache(url,…)`. Expected: returns `ApiResult.Success(File)`; file exists under `cacheDir/documents/{packetId}/…`, body bytes match fixture, `%PDF-` validated; request carried `Authorization: Bearer …`, cookies, and `X-CSRF-Token`. Traces: AC-7.
- **TC-AND-341-02** — Type: contract/MockWebServer (JVM). Target: JVM. Test target: `FileDownloaderImpl` 401 path. Preconditions: server returns `401` once, then `200` PDF after a `POST /ui/session/refresh` `200`. Steps: download. Expected: exactly one refresh call, then original GET retried, success; on a second persistent `401` → `Error` (auth) with no infinite loop. Traces: AC-7.
- **TC-AND-341-03** — Type: contract/MockWebServer (JVM). Target: JVM. Test target: error mapping. Preconditions: server returns body that is NOT a PDF (e.g. `application/json` `{"detail":[{"msg":"…","loc":["…"]}]}` or a `422`), and separately a `200` whose body fails the `%PDF-` check. Steps: download each. Expected: non-retryable `DocumentCorrupt` (or validation `AppError`) per `normalizeErrorDetail` semantics; bad cache file is deleted. Traces: AC-9.
- **TC-AND-341-04** — Type: contract/MockWebServer (JVM). Target: JVM. Test target: retry/backoff + stale. Preconditions: server returns `5xx`/socket timeout; then a cached fresh file exists; `BackendHealthSignal` unhealthy. Steps: trigger load. Expected: idempotent GET retried with bounded backoff; if cache present → render from cache with `isStale=true` and no further network; if no cache → `Error(NetworkUnavailable, retryable=true)`. Traces: AC-8.
- **TC-AND-341-05** — Type: unit (JVM/Robolectric). Target: JVM. Test target: `PdfRendererImpl` over a bundled ≥3-page fixture PDF in `:core-testing` assets. Preconditions: fixture opened via `ParcelFileDescriptor`. Steps: read `pageCount` and each `pageLayout(i)`; `renderPage(0, targetWidthPx)`. Expected: `pageCount`≥3; `PageLayout.widthPts/heightPts` match fixture media box; bitmap is `ARGB_8888`, non-blank, height matches aspect ratio. Traces: AC-1, AC-2.
- **TC-AND-341-06** — Type: unit (JVM/Robolectric). Target: JVM. Test target: `PdfRendererImpl` single-thread serialization. Preconditions: fixture open. Steps: launch N concurrent `renderPage` calls across pages. Expected: all complete with correct bitmaps; no `IllegalStateException`/crash from concurrent `openPage` (access serialized via single dispatcher + `Mutex`); renderer + FD closed on `close()`. Traces: AC-10.
- **TC-AND-341-07** — Type: unit (JVM). Target: JVM. Test target: `BitmapPageCache`. Preconditions: budget set small. Steps: insert beyond budget; request an in-flight page twice. Expected: LRU evicts least-recent and recycles only bitmaps not currently composed; concurrent request for an in-flight page returns the same `Deferred<Bitmap>` (dedupe). Traces: AC-3.
- **TC-AND-341-08** — Type: unit (JVM). Target: JVM. Test target: `DocumentViewerViewModel` state machine. Preconditions: fakes for repo/downloader/renderer/health. Steps: drive happy path, host-down-with-cache, host-down-no-cache, corrupt PDF, encrypted PDF (renderer throws `SecurityException`). Expected: `Loading → Ready(pageCount,pages)`; cache-only → `Ready(isStale=true)` with zero network; no-cache → `Error(retryable)`; corrupt → `Error(DocumentCorrupt, retryable=false)`; encrypted → `Error(DocumentProtected, retryable=false)`; `onCleared` closes renderer + FD. Traces: AC-8, AC-9, AC-10.
- **TC-AND-341-09** — Type: Compose-UI / instrumented (emu test35). Target: emu test35. Test target: `DocumentViewerScreen` canonical render+scroll. Preconditions: content GET stubbed via MockWebServer with the ≥3-page fixture. Steps: open viewer; assert page 1 composes; `performScrollToIndex(last)`; assert last page composes and shows a non-blank bitmap; each page label reads "Page N of M". Expected: all pages rasterize; smooth scroll to last page. Traces: AC-1, AC-2.
- **TC-AND-341-10** — Type: instrumented (emu test35). Target: emu test35. Test target: windowing/placeholder. Preconditions: 50+ page fixture. Steps: fling through the list; observe placeholders then bitmap swap-in; monitor heap. Expected: aspect-correct placeholder holds position before bitmap ready (scroll offset stable), bitmap swaps in; off-screen bitmaps released, LRU budget never exceeded, no OOM. Traces: AC-3, AC-4.
- **TC-AND-341-11** — Type: instrumented / Compose-UI (emu test35; confirm once on device A15). Target: emu test35 (+ device A15). Test target: zoom + geometry seam. Preconditions: fixture loaded. Steps: pinch and double-tap to zoom; settle; read `onPageLayout(List<PageOnScreen>)`. Expected: zoom clamps to [1.0x, 3.0x]; visible pages re-rasterize crisply (debounced ~150ms); `PageOnScreen.contentRect` emitted per visible page and updates on scroll/zoom. Run once on device A15 to confirm pinch gesture + arm64 raster quality (real-hardware gesture/ABI check). Traces: AC-5, AC-6.
- **TC-AND-341-12** — Type: instrumented (emu test35). Target: emu test35. Test target: error/stale UI + retry. Preconditions: stub host-down (no cache) then host-down (with cache). Steps: load each; tap retry on the error state. Expected: retryable error state shows a labeled retry button (≥48 dp) that re-invokes load; stale state shows the shared offline affordance. Traces: AC-8.
- **TC-AND-341-13** — Type: instrumented a11y + lint (emu test35 + JVM lint). Target: emu test35 / JVM. Test target: accessibility + strings + backup. Preconditions: viewer loaded; TalkBack/`AccessibilityChecks` enabled. Steps: scroll and read page `contentDescription`; run accessibility checks on loading/error/stale states; lint for hardcoded strings; inspect `dataExtractionRules`/`fullBackupContent`. Expected: each page announces "Page N of M"; controls labeled with adequate touch targets; no hardcoded user-facing strings (all in `strings.xml` with positional/plural args); `cacheDir/documents/` excluded from auto-backup. Traces: AC-11.
- **TC-AND-341-14** — Type: integration / security (instrumented, device A15 preferred). Target: device A15. Test target: at-rest + transport + lifecycle leak. Preconditions: real download against a stub host. Steps: download a PDF; inspect file location/permissions; rotate + navigate away to trigger `onCleared`; verify cleartext config; grep logs. Expected: PDF stored in app-internal `cacheDir` (not external, not world-readable); cleartext allowed ONLY for the dev host; `PdfRenderer`/`ParcelFileDescriptor` closed and bitmaps recycled on `onCleared` (no leak); no cookies/CSRF/Bearer/full URLs logged; 7-day sweep removes stale files. Device A15 chosen to validate real on-device file ACLs and arm64/API-34 behavior. Traces: AC-10, AC-11.

### Coverage matrix
| AC | Covered by |
|----|------------|
| AC-1 (renders all pages, labeled) | TC-05, TC-09 |
| AC-2 (scroll first→last, non-blank) | TC-05, TC-09 |
| AC-3 (windowed, LRU, no OOM 50+) | TC-07, TC-10 |
| AC-4 (placeholder holds, swaps in) | TC-10 |
| AC-5 (pinch/double-tap zoom [1,3], re-render) | TC-11 |
| AC-6 (per-page geometry emit on scroll/zoom) | TC-11 |
| AC-7 (authenticated idempotent content GET, cached) | TC-01, TC-02 |
| AC-8 (stale-from-cache / retryable error) | TC-04, TC-08, TC-12 |
| AC-9 (corrupt/non-PDF/encrypted → non-retryable, cache purged) | TC-03, TC-08 |
| AC-10 (serialized renderer, close on onCleared) | TC-06, TC-08, TC-14 |
| AC-11 (strings, TalkBack, app-internal + no backup) | TC-13, TC-14 |
