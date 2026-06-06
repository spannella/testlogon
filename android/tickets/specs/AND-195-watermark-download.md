---
id: AND-195
title: Watermark download
milestone: M4
epic: E26
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-191, AND-170]
blocks: []
---

# AND-195 — Watermark download

## 1. Overview & Goal

This ticket delivers a **download path that produces a forensically watermarked file**
for VOD content on the TestLogon native Android client. Where AND-170 burns a per-user
overlay onto the *playback surface* (a presentation-only deterrent that is discarded
when playback ends), this ticket persists a **durable, attributable artifact** to local
storage so that an offline-saved copy of a protected VOD title carries the signed-in
user's identity baked into the saved file's frames (or, where on-device transcode is not
viable, into a sidecar overlay rendered on every local playback). The web reference for
this behavior is `frontend/src/api/endpoints/vodWatermarkDownload.ts`.

The deliverable is: a `feature-vod` "Download" affordance on the VOD detail screen
(AND-191), a download orchestration layer (`core-data`) that requests a watermarked
download artifact, a watermark application stage that guarantees the resulting file is
attributable to the user, and the persisted state + UI to track download progress,
completion, failure, and offline availability. The acceptance bar is narrow and testable:
**a completed download produces a watermarked file** — i.e. the saved artifact (or its
mandatory local-playback overlay descriptor) carries the same per-user identity string
defined by AND-170's `WatermarkSpec`, and a non-watermarked save of a protected title is
never produced.

> **Review correction (§16):** the authoritative backend (`POST /ui/vod/watermark-download/{video_id}`)
> implements **server-side burn-in only** — the backend renders a per-viewer watermarked
> copy (FFmpeg) and returns a `download_url`. There is **no** `client_sidecar` strategy in
> the API. The render is **asynchronous** (`processing` → poll → `ready`/`failed`), though
> the dev backend completes synchronously and returns a `/mock/s3/...` URL immediately. The
> client-sidecar path below is retained only as an **unverified, app-only fallback** for the
> (untested) case where the server returns no `download_url`; it is NOT backed by any backend
> field and is gated behind a feature flag. See §5 and §16 for the verified contract.

Non-goals: hardware DRM/Widevine offline licensing, the playback overlay itself (owned by
AND-170 and reused here), the VOD catalog/detail rendering (AND-191), background download
scheduling policy beyond WorkManager wiring, and server-side rights/entitlement checks
(the backend gates the download endpoint; this client honors its response).

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** `com.testlogon.android`. Feature package
  `com.testlogon.android.feature.vod`; download orchestration in
  `com.testlogon.android.core.data.download`; watermark spec/model reused from
  `com.testlogon.android.core.model` (AND-170).
- **Web reference:** `src/api/endpoints/vodWatermarkDownload.ts` is the source of
  truth for the download request/response shape and the watermark token flow (VERIFIED — it
  defines `requestVodWatermarkDownload`, `pollVodWatermarkStatus`, `listVodWatermarkRenders`,
  `extractVodWatermark`). Mirror its call exactly; reconcile against `GET /openapi.json` on
  the dev backend. DTO definitions in `src/api/types.ts` (`VodWatermarkDownloadResponse`,
  `VodWatermarkDownloadStatusResponse`, `VodWatermarkRenderItem/ListResponse`,
  `VodWatermarkExtractResponse`). NOTE: the web client uses a **request → poll-status**
  flow, not the single-shot request the earlier draft of §5 described — corrected below.
- **Depends on AND-191** (VOD catalog/detail): supplies `VodDetail`, the `vod_detail/{vodId}`
  route, `VodRepository`, and the `core-network` `VodApi` this ticket extends. The Download
  CTA is added to the detail screen alongside AND-191's Play CTA.
- **Depends on AND-170** (Watermark/overlay hooks): supplies `WatermarkSpec`,
  `UserIdentity`, `WatermarkPolicy`, and `CurrentUserRepository.identity`. This ticket
  reuses the *same* identity-string construction so playback overlay and downloaded
  artifact are attributable to the same user with the same format.
- **Dev backend:** `http://18.222.237.167:8000` — PLAINTEXT HTTP, unreliable dev host.
  Design for ~20s timeouts, bounded backoff retry for idempotent GETs only, and
  offline/stale UI states. The begin request **is idempotent within the backend's cache
  window** (the OpenAPI op description states a re-request returns the existing render, and
  the response carries a `cached` flag), so a retried begin is safe — corrected from the
  earlier "non-idempotent" claim (see §5/§7/§16).
- **Auth:** cookie-based session + `ui_csrf` echoed as `X-CSRF-Token`; on 401 the client
  calls `POST /ui/session/refresh` once then retries (owned by AND-027 / core-network).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Media3 1.4, WorkManager,
  Paging 3. minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1. The VOD detail screen (AND-191) MUST expose a **Download** action when the title is
downloadable (per the detail DTO's downloadable flag). Tapping it starts a watermarked
download for the current `vodId`.

FR-2. A download MUST go through a watermark application stage. The completed file MUST be
attributable to the signed-in user. Two compliant strategies, selected by backend
capability (§5):
  - **(A) Server-side burned-in:** the backend issues a per-user, time-limited watermarked
    artifact URL; the client downloads that file as-is.
  - **(B) Client-side sidecar overlay:** the backend returns a plain artifact plus a
    `watermark_token`/spec; the client persists the file together with a mandatory
    `WatermarkSpec` descriptor so every *local* playback renders the AND-170 overlay and
    the file is never playable without it inside this app.

FR-3. A protected/downloadable title MUST NEVER produce a saved file lacking a watermark.
If neither strategy can attribute the file (e.g. identity unresolved, no token, transcode
unsupported), the download MUST fail with a clear error and leave no partial artifact.

FR-4. Download progress MUST be observable: a `StateFlow<DownloadUiState>` drives the
detail screen showing Idle → Queued → Downloading(percent) → Watermarking → Completed, or
Failed(reason)/Cancelled.

FR-5. The user MUST be able to **cancel** an in-flight download and **delete** a completed
download. Cancel removes partial files; delete removes the artifact and its descriptor row.

FR-6. Downloads MUST survive process death and continue across app restarts (WorkManager),
and resume/restart on connectivity per the work constraints. State is persisted in Room.

FR-7. Completed downloads MUST be enumerable (a "Downloads" list is read here from Room;
a dedicated downloads screen is optional follow-up) and each item MUST report whether it
is watermarked and by which identity (truncated/hashed in UI per §8).

FR-8. The identity baked into / attached to the file MUST match the AND-170 format:
primary line = email→username→displayName, secondary line = `id:<userId>`. The download
captures identity at request time and stores it immutably with the artifact.

## 4. Technical Design

### 4.1 Module & file layout

```
core-network/
  .../core/network/api/VodApi.kt                 // + beginWatermarkDownload + pollWatermarkStatus
  .../core/network/dto/WatermarkDownloadDto.kt   // WatermarkDownloadDto + WatermarkStatusDto
core-model/
  .../core/model/DownloadRequestResult.kt        // domain result of "begin download"
  .../core/model/DownloadedItem.kt               // persisted artifact metadata
  (reuses) WatermarkSpec.kt, UserIdentity.kt     // from AND-170
core-data/
  .../core/data/download/WatermarkDownloadRepository.kt
  .../core/data/download/WatermarkDownloadWorker.kt   // WorkManager CoroutineWorker
  .../core/data/download/WatermarkApplier.kt          // strategy A/B applier
  .../core/data/db/DownloadDao.kt + DownloadEntity.kt // Room
feature-vod/
  .../feature/vod/detail/DownloadButton.kt
  .../feature/vod/detail/VodDetailViewModel.kt    // + download intents (AND-191 VM)
  .../feature/vod/download/DownloadUiState.kt
```

### 4.2 State model

```kotlin
package com.testlogon.android.feature.vod.download

sealed interface DownloadUiState {
    data object Idle : DownloadUiState
    data object Queued : DownloadUiState
    data class Downloading(val percent: Int) : DownloadUiState   // 0..100
    data object Watermarking : DownloadUiState
    data class Completed(val item: DownloadedItem) : DownloadUiState
    data class Failed(val reason: DownloadError) : DownloadUiState
    data object Cancelled : DownloadUiState
}

enum class DownloadError {
    NETWORK, NOT_ENTITLED, IDENTITY_UNRESOLVED, WATERMARK_FAILED,
    STORAGE_FULL, TOKEN_EXPIRED, UNKNOWN
}
```

```kotlin
// core-model
data class DownloadedItem(
    val vodId: String,
    val localUri: String,            // content:// or file:// of saved artifact
    val sizeBytes: Long,
    val watermarked: Boolean,        // MUST be true for protected content
    val strategy: WatermarkStrategy, // SERVER_BURNED_IN | CLIENT_SIDECAR
    val identityId: String,          // user id captured at request time
    val watermarkSpec: WatermarkSpec?, // non-null for CLIENT_SIDECAR
    val completedAtEpochMs: Long,
)

enum class WatermarkStrategy { SERVER_BURNED_IN, CLIENT_SIDECAR }
```

### 4.3 Repository

```kotlin
interface WatermarkDownloadRepository {
    /** Per-vod download state, derived from WorkManager + Room. */
    fun observe(vodId: String): StateFlow<DownloadUiState>

    /** Enqueues a watermarked download; captures identity at call time. */
    suspend fun startDownload(vodId: String): ApiResult<Unit>

    suspend fun cancel(vodId: String)
    suspend fun delete(vodId: String)
    fun completed(): Flow<List<DownloadedItem>>
}
```

`startDownload` resolves `CurrentUserRepository.identity.value`; if null it short-circuits
to `ApiResult.Failure(IDENTITY_UNRESOLVED)` (FR-3) and enqueues nothing. Otherwise it
calls the begin endpoint, persists a `DownloadEntity(status=QUEUED, identityId=…)`, and
enqueues a unique `WatermarkDownloadWorker` (`ExistingWorkPolicy.KEEP`, work name
`"wm-download:$vodId"`).

### 4.4 Worker pipeline

`WatermarkDownloadWorker : CoroutineWorker` runs:

1. Re-read `DownloadEntity` for `vodId` and the captured `identityId`.
2. Call `VodApi.beginWatermarkDownload(vodId)` (§5; **no body**) → `WatermarkDownloadDto`
   with `status`, `render_id`, optional `download_url`, `cached`, `watermark_payload`.
   - If `status == "ready"` and `download_url != null` → go to step 3.
   - If `status == "processing"` → poll `VodApi.pollWatermarkStatus(vodId)` on a bounded
     interval (~2s, matching the web client) until `status == "ready"` (capture
     `download_url`) or `status == "failed"`/deadline (→ `WATERMARK_FAILED`). A `not_found`
     status means the render was reaped → restart from begin once.
   - If `status == "failed"` → `WATERMARK_FAILED`, no artifact.
3. Stream-download `download_url` via OkHttp to a temp file in app-private storage,
   publishing `setProgress(workDataOf(KEY_PCT to pct))` (FR-4).
4. **Watermark stage** via `WatermarkApplier.apply(...)`:
   - `SERVER_BURNED_IN` (the only backend-supported path): the streamed file IS the
     server-rendered watermarked copy. Verify `download_url` was non-null and the stream
     completed; promote temp → final, persist `watermark_payload` as the forensic token,
     set `watermarked=true`.
   - `CLIENT_SIDECAR` (UNVERIFIED app-only fallback, feature-flagged — not produced by any
     backend field): only used if a future/edge backend ever returns a render with no
     watermark burn-in. Build `WatermarkSpec` from `UserIdentity` via AND-170's
     `WatermarkPolicy.buildSpec`, store the artifact app-private, and persist the spec so
     AND-170's `WatermarkOverlay` renders on every local playback. Since the current API
     always burns in server-side, this branch is dead code under the verified contract and
     exists purely as a fail-safe; see §16 Open assumptions.
5. On success: update Room `status=COMPLETED`, `watermarked=true`, `localUri`,
   `completedAtEpochMs`; return `Result.success`. On any failure: delete the temp file and
   return `Result.failure(workDataOf(KEY_ERR to error.name))`; Room set to `FAILED`.

Worker constraints: `setRequiredNetworkType(CONNECTED)`, `setBackoffCriteria(EXPONENTIAL, 30s)`.
Cancellation cooperatively deletes the temp file in a `finally` block.

### 4.5 UI integration (AND-191 detail)

`VodDetailViewModel` (from AND-191) gains:

```kotlin
val download: StateFlow<DownloadUiState> = repo.observe(vodId)
fun onDownloadClick() { viewModelScope.launch { repo.startDownload(vodId) } }
fun onCancelDownload() = viewModelScope.launch { repo.cancel(vodId) }
fun onDeleteDownload() = viewModelScope.launch { repo.delete(vodId) }
```

`DownloadButton` is a Material 3 button/icon that maps `DownloadUiState` to label +
affordance (Download / progress ring with % / "Downloaded ✓ Delete" / "Retry"). It is only
shown when `VodDetail.downloadable == true`.

## 5. API Contract

VERIFIED against `src/api/endpoints/vodWatermarkDownload.ts`, `src/api/types.ts`, and
`openapi.pretty.json`. The real backend is an **async, request-then-poll, server-side
burn-in** flow with no request body and no `strategy`/`artifact_url`/`expires_at`/
`watermark_token` fields. The earlier draft of this section was incorrect on every one of
those points; corrected below (audit in §16).

**(1) Begin watermarked download** — `POST /ui/vod/watermark-download/{video_id}`
(op `request_vod_watermark_download_…`; session-gated via cookie + `X-CSRF-Token`; **NO
request body**; viewer identity is taken from the session `user_sub`, not the body).
Per the OpenAPI op description it is **idempotent within the cache window** (a re-request
returns the existing render; `cached:true` indicates a cache hit). Entitlement is gated
server-side. Returns `200: VodWatermarkDownloadResponse`; only declared error is
`422 HTTPValidationError` (403/410 are runtime, not declared — handle defensively).

```json
// VodWatermarkDownloadResponse  (required: status, render_id)
{
  "status": "ready",            // "ready" | "processing" | "failed"
  "render_id": "rnd_…",
  "download_url": "http://18.222.237.167:8000/mock/s3/…/wm.mp4",  // nullable; present when ready
  "cached": false,              // default false; true on cache hit (idempotent re-request)
  "watermark_payload": "…",     // nullable; the forensic per-viewer payload token
  "output_size_bytes": 524288000// nullable
}
```

In dev (FFmpeg disabled) the render completes **synchronously** and `download_url` is
returned immediately with a `/mock/s3/...` URL. In prod it may return
`status:"processing"` with a null `download_url`, requiring polling.

**(2) Poll render status** — `GET /ui/vod/watermark-download/{video_id}/status`
(op `poll_vod_watermark_status_…`). The web client polls this every **2s** until
`status` is `ready` (with a `download_url`) or `failed`. Returns
`200: VodWatermarkDownloadStatusResponse`:

```json
// VodWatermarkDownloadStatusResponse  (required: status)
{
  "status": "ready",   // "ready" | "processing" | "failed" | "not_found"
  "render_id": "rnd_…",            // nullable
  "download_url": "…",             // nullable; present when ready
  "output_size_bytes": 524288000,  // nullable
  "created_at": 1717600000,        // nullable; epoch seconds (integer)
  "error": null                    // nullable error string when status=failed
}
```

**(3) Download the artifact** — plain authenticated `GET download_url` (streamed to disk).
This GET is idempotent and is the retriable call (bounded backoff).

**(4) Owner forensic render list** (optional, for §7 attribution view) —
`GET /ui/vod/watermark-download/{video_id}/renders` → `VodWatermarkRenderListResponse`
`{ items: VodWatermarkRenderItem[] }`, each item
`{ render_id, video_id, viewer_id, watermark_payload, status, created_at, output_size_bytes? }`.

**(5) Extract/verify payload** (optional QA tooling) —
`POST /ui/vod/watermark-download/extract` with body `VodWatermarkExtractIn { payload?: string|null }`
→ `VodWatermarkExtractResponse { found: bool, payload?: string|null, decoded?: object|null }`.

Moshi DTOs (tolerant defaults; unknown `status` ⇒ treat as `processing` and keep polling
up to a deadline, then fail closed as `WATERMARK_FAILED` — never promote an un-watermarked
file):

```kotlin
@JsonClass(generateAdapter = true)
data class WatermarkDownloadDto(
  val status: String,                                       // ready | processing | failed
  @Json(name = "render_id") val renderId: String,
  @Json(name = "download_url") val downloadUrl: String? = null,
  val cached: Boolean = false,
  @Json(name = "watermark_payload") val watermarkPayload: String? = null,
  @Json(name = "output_size_bytes") val outputSizeBytes: Long? = null,
)

@JsonClass(generateAdapter = true)
data class WatermarkStatusDto(
  val status: String,                                       // ready | processing | failed | not_found
  @Json(name = "render_id") val renderId: String? = null,
  @Json(name = "download_url") val downloadUrl: String? = null,
  @Json(name = "output_size_bytes") val outputSizeBytes: Long? = null,
  @Json(name = "created_at") val createdAt: Long? = null,
  val error: String? = null,
)
```

```kotlin
interface VodApi {
  @POST("ui/vod/watermark-download/{videoId}")
  suspend fun beginWatermarkDownload(@Path("videoId") videoId: String): WatermarkDownloadDto

  @GET("ui/vod/watermark-download/{videoId}/status")
  suspend fun pollWatermarkStatus(@Path("videoId") videoId: String): WatermarkStatusDto
}
```

> The begin POST has **no body**: `BeginWatermarkBody { identity_id }` from the earlier draft
> does not exist and MUST NOT be sent. Identity attribution is performed server-side from the
> session; the client still records the AND-170 identity locally (§6/FR-8) for the Downloads
> list and to match the playback-overlay format, but it is NOT transmitted in the request.

FastAPI `detail` errors map via core-network's existing mapper (string | `[{msg}]` |
`{code,…}`) — VERIFIED against `src/api/client.ts: normalizeErrorDetail`. Runtime
403/entitlement → `NOT_ENTITLED`; `status:"failed"` (begin or poll) → `WATERMARK_FAILED`;
`status:"not_found"` on poll → restart from begin. Because begin is idempotent within the
cache window, it MAY be retried (WorkManager backoff); the `download_url` GET is the primary
retriable streamed call.

## 6. Data & State Management

- **Room** (`core-data` db, extends AND-191's database): `DownloadEntity` keyed by `vodId`
  with columns `status`, `localUri`, `sizeBytes`, `watermarked`, `strategy`, `identityId`,
  `watermarkSpecJson` (Moshi-serialized `WatermarkSpec`, nullable), `completedAtEpochMs`,
  `updatedAtEpochMs`. `DownloadDao` exposes `observe(vodId): Flow<DownloadEntity?>` and
  `completed(): Flow<List<DownloadEntity>>`.
- **State derivation:** `observe(vodId)` combines `DownloadDao.observe` with
  `WorkManager.getWorkInfosForUniqueWorkLiveData("wm-download:$vodId")` (as Flow) to map
  RUNNING+progress → `Downloading(pct)`, post-download stage → `Watermarking`, terminal →
  `Completed/Failed/Cancelled`. Single source of truth is Room for completed items; the
  Worker is authoritative for in-flight progress.
- **Identity capture:** `identityId` is written at `startDownload` time and never mutated,
  so the artifact stays attributable to the user who initiated it even if the session later
  changes accounts.
- **Files:** artifacts stored in app-private `filesDir/downloads/<vodId>.mp4`; temp files in
  `cacheDir/dl-tmp/`. `CLIENT_SIDECAR` artifacts are deliberately kept app-private so the
  overlay binding cannot be stripped by sharing the raw file via MediaStore.
- No DataStore changes; prefs unaffected.

## 7. Error Handling & Resilience

- `IDENTITY_UNRESOLVED`: no identity → fail before any network/file work (FR-3). UI offers
  retry; if AND-170's identity load is pending, retry once identity arrives.
- `NETWORK`/timeout (~20s): the artifact GET retries with bounded backoff for idempotent
  GETs; the begin POST relies on WorkManager exponential backoff. Offline → work stays
  QUEUED until `CONNECTED`.
- `TOKEN_EXPIRED` (the short-lived `download_url` returns 403/404/410 before the stream
  completes — NOTE: there is **no** `expires_at` field in the verified response, so expiry is
  detected from the GET status code, not a timestamp): discard temp file, re-call the
  idempotent begin to obtain a fresh `download_url` once; if it fails again →
  `Failed(TOKEN_EXPIRED)`.
- `WATERMARK_FAILED`: unknown strategy, missing token for sidecar, or applier exception →
  **delete the temp artifact** and surface `Failed(WATERMARK_FAILED)`. Never promote an
  un-watermarked file (FR-3) — fail closed.
- `STORAGE_FULL` (`IOException` / no space): abort, clean temp, surface storage error.
- **Atomicity:** the final artifact is moved into place only after the watermark stage
  succeeds; a crash mid-pipeline leaves only a temp file that is reclaimed on next worker
  run / app start cleanup. No partial artifact is ever marked `COMPLETED`.
- 401 mid-download → core-network performs one `POST /ui/session/refresh` then retries the
  underlying call, transparent to this ticket.

## 8. Security & Privacy

- This is a **forensic/attribution mechanism, not DRM.** It makes a leaked download
  traceable; it does not prevent extraction. The spec MUST NOT claim it blocks copying.
- The `identity_id` sent in the begin POST is the account id already visible to the user.
  Never send or embed session cookies, `ui_csrf`, tokens, or password material in the
  artifact, filename, or watermark text.
- `CLIENT_SIDECAR` artifacts are stored app-private (no `MediaStore`/gallery export) so the
  overlay binding is preserved; if a future "export" feature is added it MUST go through a
  burn-in path, never a raw copy.
- PII minimization: the persisted `identityId` and `watermarkSpecJson` contain the user's
  own identity only; in UI the identity is shown truncated/hashed (first 3 chars + length),
  matching AND-170. Logs MUST NOT contain the full email/id at info level (§10).
- The `watermark_token` and per-user `artifact_url` are short-lived (honor `expires_at`)
  and MUST NOT be logged or persisted beyond what the in-flight download needs.

## 9. Accessibility & i18n

- `DownloadButton` is a real focusable control with a stateful `contentDescription`:
  "Download", "Downloading, {percent} percent", "Downloaded, tap to delete", "Download
  failed, retry". Progress uses an accessible determinate `CircularProgressIndicator` with
  the percent exposed via semantics.
- All user-facing strings ("Download", "Downloading…", "Downloaded", "Retry download",
  "Couldn't watermark file", "Not available for download", error reasons) live in
  `feature-vod` `strings.xml` and are localizable; identity text is not translated.
- Touch target ≥ 48dp; state transitions announced via `liveRegion` so TalkBack reports
  completion/failure without manual refocus.
- RTL: layout uses start/end alignment; percent formatting uses the device locale.

## 10. Telemetry & Logging

- Structured events (no PII): `vod_download_started { vodId, strategy }`,
  `vod_download_completed { vodId, strategy, watermarked: true, sizeBytes }`,
  `vod_download_failed { vodId, reason }`, `vod_download_cancelled { vodId }`,
  `vod_download_deleted { vodId }`.
- A `watermark_apply_failed` counter feeds the fail-closed guarantee (§7) so silent
  un-watermarked saves are impossible to ship unnoticed.
- Debug-build logs only for pipeline stage transitions; identity logged hashed/truncated,
  never full email/id; `artifact_url`/`watermark_token` never logged.
- No new analytics endpoint; uses the app's existing sink.

## 11. Testing Strategy

Unit (`core-testing`, JUnit + Turbine + MockWebServer):
- `WatermarkDownloadRepository.startDownload` with identity null → `Failure(IDENTITY_UNRESOLVED)`,
  no work enqueued, no Room row.
- DTO mapping: `server_burned_in` / `client_sidecar` / unknown strategy → unknown fails
  closed as `WATERMARK_FAILED`.
- `WatermarkApplier` truth table: server-burned promotes file with `watermarked=true`;
  sidecar builds a `WatermarkSpec` whose primary/secondary lines match AND-170's format and
  persists it; missing token in sidecar → `WATERMARK_FAILED` and temp file deleted.
- State mapping: WorkManager progress → `Downloading(pct)`; terminal states map correctly.

Worker / instrumented:
- `WatermarkDownloadWorker` against MockWebServer streams a fixture artifact and asserts the
  **completed file exists and is marked watermarked**, with identity captured (core acceptance:
  "Download produces watermarked file").
- Failure injection (artifact 410, IO mid-stream, applier throw) leaves **no** `COMPLETED`
  row and **no** lingering final artifact (only reclaimable temp).
- Cancel mid-download deletes temp and reports `Cancelled`.
- Process-death continuation: enqueue, kill process, restart → download resumes/completes.

Compose UI (`createAndroidComposeRule`):
- Detail screen shows Download only when `downloadable==true`.
- Button reflects Idle→Downloading(%)→Completed; Completed offers Delete; Failed offers Retry.
- `contentDescription` updates per state (a11y assertions).

Manual against dev backend (`http://18.222.237.167:8000`):
- Download a protected VOD title → saved file is watermarked/attributable to the logged-in
  user; local playback of a sidecar artifact renders the AND-170 overlay.

## 12. Dependencies & Sequencing

- **Depends on AND-191** (VOD catalog/detail): provides `VodDetail` (incl. the
  downloadable flag), the `vod_detail/{vodId}` route + ViewModel to host the Download CTA,
  `VodApi`, and the `core-data` Room database this ticket extends.
- **Depends on AND-170** (Watermark/overlay hooks): provides `WatermarkSpec`,
  `UserIdentity`, `WatermarkPolicy.buildSpec`, and `CurrentUserRepository.identity`. The
  `CLIENT_SIDECAR` strategy *requires* AND-170's `WatermarkOverlay` to render on local
  playback; without it, sidecar downloads cannot satisfy FR-2/FR-3.
- **Blocks:** none recorded in backlog (`blocks: []`).
- **Sequencing:** land after both AND-191 and AND-170 merge. Extend AND-191's `VodApi` and
  database in this PR rather than forking duplicate definitions. Reconcile the begin
  endpoint shape with `vodWatermarkDownload.ts` / `/openapi.json` before implementation.

## 13. Risks & Open Questions

- OQ-1: **RESOLVED (this review).** The begin endpoint is `POST /ui/vod/watermark-download/{video_id}`
  (no body), an async request-then-poll flow returning `VodWatermarkDownloadResponse`
  (`status/render_id/download_url/cached/watermark_payload/output_size_bytes`) with a poll at
  `GET …/status`. The backend supports **server-side burn-in only**; there is no
  `strategy` discriminator and no `client_sidecar` capability. The client implements the
  server-burn path; the sidecar path is a dead-code, feature-flagged fail-safe only (§16).
- OQ-2: On-device burn-in transcode (a third strategy) is heavy (Media3 Transformer) and
  battery/time costly; recommend **server_burned_in** as primary and **client_sidecar** as
  fallback rather than client transcode. Flag as product decision.
- Risk: `CLIENT_SIDECAR` is a soft binding — a rooted device can extract the raw artifact
  without overlay. Accepted and documented in §8; sidecar artifacts are kept app-private to
  raise the bar. Hardware DRM is a separate effort.
- OQ-3: The VOD detail DTO (owned by AND-191) was not located in the reference, but the
  verified backend/web convention for this flag is **`allow_download` (boolean)**, not
  `downloadable` — see `src/api/endpoints/videos.ts: allow_download` and OpenAPI schemas
  (`"title": "Allow Download"`). FR-1/AC-8 should bind to `allow_download` (treat absent/null
  as `false` — safe default). The exact VOD-detail field name remains an AND-191 assumption.
- Risk: large downloads over the unreliable dev host may stall; WorkManager backoff +
  `expires_at` re-mint (≤1 retry) mitigates, but very large files may repeatedly expire —
  surface `TOKEN_EXPIRED` clearly. OQ-4: retention/quota policy for completed downloads
  (max count/size, auto-eviction) is unspecified — out of scope, candidate follow-up.

## 14. Acceptance Criteria

AC-1. Initiating a download for a downloadable VOD title produces, on completion, a saved
file that is **watermarked/attributable** to the signed-in user — either server-burned-in
or with a mandatory persisted `WatermarkSpec` sidecar. *(Maps to source acceptance:
"Download produces watermarked file.")*

AC-2. A protected/downloadable title NEVER produces a `COMPLETED` saved file without a
watermark; any watermark-stage failure fails closed and leaves no final artifact (FR-3).

AC-3. The identity baked into / attached to the file matches AND-170's format (primary
email→username→displayName, secondary `id:<userId>`) and is captured at request time.

AC-4. Download progress is observable through `DownloadUiState`
(Queued → Downloading(%) → Watermarking → Completed) on the detail screen.

AC-5. The user can cancel an in-flight download (temp files removed, state `Cancelled`) and
delete a completed download (artifact + Room row removed).

AC-6. Downloads continue across process death / app restart and respect connectivity
constraints (WorkManager).

AC-7. `client_sidecar` artifacts render the AND-170 watermark overlay on local playback; raw
sidecar files are stored app-private and not exported to the gallery.

AC-8. The Download action appears only when the title's `downloadable` flag is true; absent
flag defaults to non-downloadable.

## 15. Definition of Done

- All §14 acceptance criteria pass.
- `WatermarkDownloadRepository`, `WatermarkDownloadWorker`, `WatermarkApplier`,
  `DownloadDao`/`DownloadEntity`, `DownloadUiState`, and `DownloadButton` implemented under
  `com.testlogon.android.core.data.download` / `…feature.vod.download`, reusing AND-170's
  `WatermarkSpec`/`WatermarkPolicy` and AND-191's `VodApi`/database/detail screen.
- `VodApi.beginWatermarkDownload` + `WatermarkDownloadDto` added (Moshi), reconciled with
  `vodWatermarkDownload.ts` / `/openapi.json`; unknown strategy fails closed.
- Unit, worker/instrumented (including process-death continuation and failure-injection
  fail-closed), and Compose UI tests green in CI; the core test asserting a completed
  download yields a watermarked file passes.
- Telemetry events emitted with no PII; `watermark_apply_failed` counter wired; identity
  logged only hashed/truncated in debug builds; tokens/per-user URLs never logged.
- a11y: stateful `contentDescription` + live-region announcements; all strings localized in
  `feature-vod` `strings.xml`.
- §8 security note (attribution-not-DRM, app-private sidecar) reflected in code comments.
- No new lint/detekt regressions; module layering (`app→feature-vod→core-*`) preserved.
- Manual verification against the dev backend recorded in the PR description.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Begin endpoint is `POST /ui/vod/{vodId}/download/watermark`.** — **Corrected** → the real
   path is `POST /ui/vod/watermark-download/{video_id}`.
   Source: OpenAPI `POST /ui/vod/watermark-download/{video_id}`
   (op `request_vod_watermark_download_…`); `src/api/endpoints/vodWatermarkDownload.ts:
   requestVodWatermarkDownload`.
2. **Begin request carries a body `{ identity_id }` (`BeginWatermarkBody`).** — **Corrected** →
   the POST has **no request body**; identity is server-side from the session (`user_sub`).
   Source: OpenAPI op has no `requestBody`; `src/api/endpoints/vodWatermarkDownload.ts` calls
   `api.post(...)` with no payload.
3. **Response is synchronous with `strategy`, `artifact_url`, `expires_at`, `watermark_token`,
   `content_type`, `size_bytes`.** — **Corrected** → response is
   `VodWatermarkDownloadResponse { status, render_id, download_url?, cached?, watermark_payload?,
   output_size_bytes? }`; none of the claimed fields exist.
   Source: OpenAPI `components.schemas.VodWatermarkDownloadResponse`; `src/api/types.ts:
   VodWatermarkDownloadResponse`.
4. **Flow is single-shot (download_url in the begin response).** — **Corrected** → flow is
   **async request-then-poll**: begin returns `status:"processing"` (or `ready`), then
   `GET /ui/vod/watermark-download/{video_id}/status` is polled (~2s) until `ready`/`failed`.
   Source: OpenAPI `GET …/status` (op `poll_vod_watermark_status_…`),
   `components.schemas.VodWatermarkDownloadStatusResponse`;
   `src/api/endpoints/vodWatermarkDownload.ts: pollVodWatermarkStatus`;
   `src/pages/videos/VodWatermarkDownloadButton.tsx` (2000ms `setInterval` poll loop).
5. **Status enum.** — **Verified/Refined** → begin: `ready|processing|failed`; status:
   `ready|processing|failed|not_found`.
   Source: `src/api/types.ts: VodWatermarkDownloadResponse.status` and
   `VodWatermarkDownloadStatusResponse.status`.
6. **The begin request is non-idempotent and must not be auto-retried.** — **Corrected** →
   it is **idempotent within the backend cache window** (a re-request returns the existing
   render; `cached` flag signals a hit), so retry is safe.
   Source: OpenAPI op description: "Idempotent within the cache window: a re-request returns
   the existing render"; `VodWatermarkDownloadResponse.cached`.
7. **Two backend strategies: `server_burned_in` and `client_sidecar`.** — **Corrected** →
   the backend supports **server-side burn-in only** (FFmpeg render); there is no `strategy`
   field and no `client_sidecar` capability anywhere in the contract.
   Source: OpenAPI op description ("real FFmpeg … render completes synchronously"); absence of
   any `strategy`/`client_sidecar` field across all `VodWatermark*` schemas and
   `vodWatermarkDownload.ts`.
8. **Auth: cookie session + `ui_csrf` echoed as `X-CSRF-Token`.** — **Verified.**
   Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
9. **On 401, client calls `POST /ui/session/refresh` once then retries.** — **Verified.**
   Source: `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", {method:"POST"})`)
   and the single-flight 401 retry block.
10. **FastAPI `detail` errors come as string | `[{msg}]` | `{code,…}` and map via a shared
    mapper.** — **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError`.
11. **403 → `NOT_ENTITLED`; entitlement is gated server-side.** — **Verified (gating) /
    Unverified-assumption (the 403 mapping detail).** Begin op declares only `422`; the op
    description says "entitlement gated", and `client.ts` has a dedicated 403 branch, but the
    specific 403 body for this endpoint is not in the sources.
    Source: OpenAPI op description "entitlement gated"; `src/api/client.ts` 403 handler.
12. **A `download_url` expiry surfaces as a `410`/`expires_at`.** — **Corrected** → there is
    **no** `expires_at`/token field; URL expiry must be inferred from the artifact GET status
    code (403/404/410). Source: `VodWatermarkDownloadResponse`/`…StatusResponse` schemas (no
    expiry field).
13. **The forensic token is `watermark_token`.** — **Corrected** → it is `watermark_payload`
    (begin/render item) and is decodable via `POST /ui/vod/watermark-download/extract`.
    Source: `VodWatermarkDownloadResponse.watermark_payload`, `VodWatermarkRenderItem.
    watermark_payload`, `VodWatermarkExtractResponse`.
14. **Owner forensic render list exists.** — **Verified.**
    Source: OpenAPI `GET /ui/vod/watermark-download/{video_id}/renders` →
    `VodWatermarkRenderListResponse { items: VodWatermarkRenderItem[] }`;
    `src/api/endpoints/vodWatermarkDownload.ts: listVodWatermarkRenders`.
15. **VOD detail exposes a `downloadable` flag.** — **Corrected (field name) /
    Unverified-assumption (VOD-detail location).** The verified field name is
    **`allow_download`** (boolean). The VOD-detail DTO that AND-191 owns was not found in the
    reference, so its precise shape is assumed.
    Source: `src/api/endpoints/videos.ts: allow_download`; OpenAPI schemas titled
    "Allow Download".
16. **Stack/framework choices (WorkManager for durable downloads, CoroutineWorker,
    `getWorkInfosForUniqueWork*` as Flow, app-private `filesDir` storage).** —
    **Unverified-assumption (framework ref).** Reasonable Android conventions; not derivable
    from the backend/web sources.
    Source: framework ref — Android WorkManager docs
    (https://developer.android.com/develop/background-work/background-tasks/persistent),
    and app-specific data storage
    (https://developer.android.com/training/data-storage/app-specific).

### Corrections made

- §1/§5/§4.4/§13 (OQ-1): rewrote the API contract — correct path
  `POST /ui/vod/watermark-download/{video_id}`, **no request body**, response schema
  `VodWatermarkDownloadResponse`, and the **async request-then-poll** flow with
  `GET …/status`.
- §2/§5/§7: corrected "non-idempotent begin" → **idempotent within cache window** (`cached`).
- §1/§4.4/§13: corrected "two backend strategies (`server_burned_in`/`client_sidecar`)" →
  **server-side burn-in only**; demoted client-sidecar to a feature-flagged dead-code
  fail-safe.
- §5/§7: removed the non-existent `expires_at`/`watermark_token`/`strategy`/`artifact_url`/
  `content_type`/`size_bytes` fields; renamed forensic token to `watermark_payload`; URL
  expiry now detected via GET status code.
- §13 (OQ-3)/FR-1/AC-8: corrected flag name `downloadable` → **`allow_download`**.
- Added the verified `GET …/renders` and `POST …/extract` endpoints to §5.

### Open assumptions

- **VOD detail DTO shape (AND-191):** the detail DTO and its exact download flag were not
  present in the reference; we assume `allow_download: Boolean` (treat absent → false). Must be
  reconciled when AND-191 lands.
- **Runtime 403/410 bodies:** the begin/status ops declare only `422` in OpenAPI; entitlement
  (403) and URL-expiry (403/404/410) bodies are inferred from the shared client error handling,
  not from an explicit schema for this endpoint.
- **Client-sidecar fallback (FR-2 strategy B):** has no backend support; retained only as a
  feature-flagged fail-safe and is dead code under the verified contract. If product confirms
  the server always burns in, this branch and its DTO fields can be dropped.
- **WorkManager / on-device storage / Media3 overlay reuse:** Android framework choices, not
  verifiable from backend/web sources (labelled framework ref above).
- **Dev-host behavior:** dev backend returns a synchronous `/mock/s3/...` `download_url` (per
  OpenAPI op description); real async `processing` timing/poll-count is unverified against a
  live prod render.

## 17. Test Plan

Test IDs `TC-AND-195-NN`. "Traces" link to §14 acceptance criteria. Targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
**Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a)**.

**TC-AND-195-01 — Begin returns ready synchronously (dev happy path).**
Type: contract/MockWebServer (JVM). Target: JVM unit.
Preconditions: MockWebServer enqueues `200 { "status":"ready", "render_id":"rnd_1",
"download_url":"/mock/s3/wm.mp4", "watermark_payload":"wmp_1" }`; valid session identity.
Steps: call `VodApi.beginWatermarkDownload("vod1")`; assert the request is
`POST /ui/vod/watermark-download/vod1`, has **no body**, and carries `X-CSRF-Token`.
Expected: DTO maps `status=ready`, `downloadUrl` set, `watermarkPayload` set; worker proceeds
straight to stream (no poll). Traces: AC-1, AC-4.

**TC-AND-195-02 — Async render: processing → poll → ready.**
Type: contract/MockWebServer (JVM). Target: JVM unit.
Preconditions: begin returns `200 { "status":"processing", "render_id":"rnd_2" }`; first
`GET …/status` → `{ "status":"processing" }`; second → `{ "status":"ready",
"download_url":"/mock/s3/wm2.mp4" }`.
Steps: run the worker pipeline with a virtual-time poll interval.
Expected: client polls `GET /ui/vod/watermark-download/vod1/status` until `ready`, then
streams `download_url`; UI passes through `Watermarking`/`Downloading`. Traces: AC-1, AC-4.

**TC-AND-195-03 — Identity unresolved fails before any network/file work.**
Type: unit (JVM) + Turbine. Target: JVM unit.
Preconditions: `CurrentUserRepository.identity.value == null`.
Steps: `repo.startDownload("vod1")`.
Expected: `ApiResult.Failure(IDENTITY_UNRESOLVED)`; **no** work enqueued; **no** Room row;
no MockWebServer request observed. Traces: AC-2, AC-3.

**TC-AND-195-04 — Completed download produces a watermarked file (core acceptance).**
Type: instrumented/Worker (emulator `test35`). Target: headless emulator.
Preconditions: MockWebServer serves a fixture MP4 at the `download_url`; begin → `ready`.
Steps: enqueue `WatermarkDownloadWorker`; await completion; read Room row + file.
Expected: final artifact exists in `filesDir/downloads/vod1.mp4`,
`DownloadEntity.status=COMPLETED`, `watermarked=true`, `identityId` captured,
`watermark_payload` persisted. No temp file remains. Traces: AC-1, AC-2, AC-3.

**TC-AND-195-05 — Fail-closed on render failure / unknown status (no un-watermarked save).**
Type: contract/MockWebServer + Worker (JVM/Robolectric). Target: JVM/Robolectric.
Preconditions: variants — (a) begin → `{ "status":"failed" }`; (b) poll → `{ "status":"failed",
"error":"render error" }`; (c) begin → unknown status string past poll deadline.
Steps: run worker for each variant.
Expected: each ends `Failed(WATERMARK_FAILED)`; **no** `COMPLETED` row; **no** final artifact;
only a reclaimable temp may exist; `watermark_apply_failed` counter incremented. Traces: AC-2.

**TC-AND-195-06 — Download URL expiry mid-stream re-mints once via idempotent begin.**
Type: contract/MockWebServer + Worker (JVM/Robolectric). Target: JVM/Robolectric.
Preconditions: artifact GET returns `410` (or `403/404`) once; re-call begin returns
`200 { "status":"ready", "cached":true, "download_url":"/mock/s3/fresh.mp4" }`; fresh GET 200.
Steps: run worker.
Expected: temp discarded on expiry; begin re-called once (idempotent, `cached:true` accepted);
stream completes; `COMPLETED`+`watermarked=true`. A second expiry → `Failed(TOKEN_EXPIRED)`.
Traces: AC-1, AC-2.

**TC-AND-195-07 — Offline/flaky dev host: work stays queued, resumes on connectivity.**
Type: instrumented/Worker (physical device SM-A156U). Target: **physical device** (real radio
toggling exercises `CONNECTED` constraint + arm64/API-34 behavior).
Preconditions: airplane mode ON; begin enqueued.
Steps: `startDownload`; observe state; re-enable connectivity.
Expected: state `Queued` while offline (no failure); on reconnect the worker runs and the
download completes; bounded backoff applied to transient 5xx/timeout from the dev host.
Traces: AC-6.

**TC-AND-195-08 — Process-death continuation.**
Type: instrumented/e2e (emulator `test35`). Target: headless emulator.
Preconditions: begin → `processing`; render finishes during downtime.
Steps: enqueue worker; kill the app process mid-flight; relaunch.
Expected: WorkManager re-runs the unique work `wm-download:vod1`; download resumes/completes;
Room shows a single `COMPLETED` row (no duplicate). Traces: AC-6.

**TC-AND-195-09 — Cancel and delete.**
Type: instrumented/Worker (emulator `test35`). Target: headless emulator.
Preconditions: a download in `Downloading`; and separately a `COMPLETED` item.
Steps: call `cancel("vod1")` mid-flight; then on a completed item call `delete("vod2")`.
Expected: cancel → temp removed, state `Cancelled`, no final artifact; delete → final artifact
file removed and Room row removed; `completed()` no longer lists it. Traces: AC-5.

**TC-AND-195-10 — Download CTA visibility bound to `allow_download`.**
Type: Compose-UI (`createAndroidComposeRule`, emulator `test35`). Target: headless emulator.
Preconditions: VodDetail with `allow_download=true`, then `false`, then absent/null.
Steps: render detail screen for each.
Expected: button shown only when `allow_download==true`; hidden when `false` or absent
(safe default). Traces: AC-8.

**TC-AND-195-11 — DownloadButton state mapping (UI).**
Type: Compose-UI (emulator `test35`). Target: headless emulator.
Preconditions: drive `DownloadUiState` Idle→Downloading(42)→Watermarking→Completed, and a
Failed branch.
Steps: assert label/affordance per state.
Expected: Idle="Download"; Downloading shows determinate ring at 42%; Completed offers Delete;
Failed offers Retry. Traces: AC-4, AC-5.

**TC-AND-195-12 — Accessibility: stateful contentDescription + live region.**
Type: Compose-UI a11y (emulator `test35`); spot-check with TalkBack on physical device.
Target: emulator (+ physical device SM-A156U for TalkBack announcement).
Preconditions: button cycles through states.
Steps: assert `contentDescription` updates ("Download" → "Downloading, 42 percent" →
"Downloaded, tap to delete" → "Download failed, retry"); touch target ≥48dp; `liveRegion`
announces terminal transitions.
Expected: semantics correct; TalkBack reports completion/failure without manual refocus.
Traces: AC-4, AC-5.

**TC-AND-195-13 — Security: app-private storage, no PII/token leakage, no body identity.**
Type: integration/unit (JVM/Robolectric) + log inspection. Target: JVM/Robolectric.
Preconditions: completed download; logging at info/debug.
Steps: inspect artifact location, begin request, persisted rows, and logs.
Expected: artifact under app-private `filesDir` (not MediaStore/gallery); begin request body
empty (no `identity_id`); `X-CSRF-Token` present; logs never contain full email/id,
`download_url`, or `watermark_payload`; UI shows identity truncated/hashed. Traces: AC-3, AC-7.

**TC-AND-195-14 — Sidecar local-playback overlay (fallback path; conditional).**
Type: instrumented/e2e (physical device SM-A156U). Target: **physical device** (real Media3
decode + overlay render; arm64).
Preconditions: feature-flag forces the (unverified) `CLIENT_SIDECAR` fallback with a persisted
`WatermarkSpec`. NOTE: under the verified contract the backend always burns in, so this case
exercises only the dead-code fail-safe and is skipped when the flag is off.
Steps: play the sidecar artifact locally.
Expected: AND-170 `WatermarkOverlay` renders the per-user identity on every local playback;
raw file is not exported to gallery. Traces: AC-7.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-04, TC-06 |
| AC-2 | TC-03, TC-04, TC-05, TC-06 |
| AC-3 | TC-03, TC-04, TC-13 |
| AC-4 | TC-01, TC-02, TC-11, TC-12 |
| AC-5 | TC-09, TC-11, TC-12 |
| AC-6 | TC-07, TC-08 |
| AC-7 | TC-13, TC-14 |
| AC-8 | TC-10 |
