---
id: AND-195
title: Watermark download
milestone: M4
epic: E26
priority: P2
size: L
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/vodWatermarkDownload.ts` is the source of
  truth for the download request/response shape and the watermark token flow. Mirror its
  call exactly; reconcile against `GET /openapi.json` on the dev backend. VOD type
  definitions in `frontend/src/api/types.ts`.
- **Depends on AND-191** (VOD catalog/detail): supplies `VodDetail`, the `vod_detail/{vodId}`
  route, `VodRepository`, and the `core-network` `VodApi` this ticket extends. The Download
  CTA is added to the detail screen alongside AND-191's Play CTA.
- **Depends on AND-170** (Watermark/overlay hooks): supplies `WatermarkSpec`,
  `UserIdentity`, `WatermarkPolicy`, and `CurrentUserRepository.identity`. This ticket
  reuses the *same* identity-string construction so playback overlay and downloaded
  artifact are attributable to the same user with the same format.
- **Dev backend:** `http://18.222.237.167:8000` — PLAINTEXT HTTP, unreliable dev host.
  Design for ~20s timeouts, bounded backoff retry for idempotent GETs only, and
  offline/stale UI states. The watermarked-download request is **not** retried blindly if
  it is non-idempotent (see §7).
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
  .../core/network/api/VodApi.kt                 // + watermark download endpoints
  .../core/network/dto/WatermarkDownloadDto.kt
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
2. Call `VodApi.beginWatermarkDownload(vodId, BeginBody(identityId))` (§5) → returns
   `WatermarkDownloadDto` indicating `strategy`, `artifact_url`, optional `watermark_token`.
3. Stream-download `artifact_url` via OkHttp to a temp file in app-private storage,
   publishing `setProgress(workDataOf(KEY_PCT to pct))` (FR-4).
4. **Watermark stage** via `WatermarkApplier.apply(...)`:
   - `SERVER_BURNED_IN`: verify the artifact is the per-user URL (the URL is opaque and
     unique to the request); promote temp → final, set `watermarked=true`.
   - `CLIENT_SIDECAR`: build `WatermarkSpec` from `UserIdentity` using AND-170's
     `WatermarkPolicy.buildSpec`, write the artifact to MediaStore/app storage, and persist
     the spec in the `DownloadEntity` so AND-170's `WatermarkOverlay` renders on every local
     playback. The artifact is stored app-private (not shared to the gallery) to keep the
     overlay binding intact.
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

The wire shape MUST be reconciled against `frontend/src/api/endpoints/vodWatermarkDownload.ts`
and `/openapi.json`; the following is the expected contract.

**Begin watermarked download** (session-gated, sends `X-CSRF-Token`; treated as
non-idempotent → POST, not auto-retried):

```
POST /ui/vod/{vodId}/download/watermark
Body: { "identity_id": "usr_9f2c…" }
```

200 response:

```json
{
  "strategy": "server_burned_in",
  "artifact_url": "http://18.222.237.167:8000/dl/wm/usr_9f2c/abc123.mp4",
  "expires_at": "2026-06-05T18:00:00Z",
  "watermark_token": null,
  "content_type": "video/mp4",
  "size_bytes": 524288000
}
```

Client-sidecar variant:

```json
{
  "strategy": "client_sidecar",
  "artifact_url": "http://18.222.237.167:8000/dl/vod/med_123.mp4",
  "expires_at": "2026-06-05T18:00:00Z",
  "watermark_token": "wmt_7af…",
  "content_type": "video/mp4",
  "size_bytes": 524288000
}
```

Moshi DTO (tolerant defaults; unknown `strategy` ⇒ fail closed as `WATERMARK_FAILED`):

```kotlin
@JsonClass(generateAdapter = true)
data class WatermarkDownloadDto(
  val strategy: String,                                  // "server_burned_in" | "client_sidecar"
  @Json(name = "artifact_url") val artifactUrl: String,
  @Json(name = "expires_at") val expiresAt: String? = null,
  @Json(name = "watermark_token") val watermarkToken: String? = null,
  @Json(name = "content_type") val contentType: String? = null,
  @Json(name = "size_bytes") val sizeBytes: Long? = null,
)
```

```kotlin
interface VodApi {
  @POST("ui/vod/{vodId}/download/watermark")
  suspend fun beginWatermarkDownload(
    @Path("vodId") vodId: String,
    @Body body: BeginWatermarkBody,
  ): WatermarkDownloadDto
}
@JsonClass(generateAdapter = true)
data class BeginWatermarkBody(@Json(name = "identity_id") val identityId: String)
```

FastAPI `detail` errors map via core-network's existing mapper (string | `[{msg}]` |
`{code,…}`). 403/entitlement → `NOT_ENTITLED`; 410/expired token → `TOKEN_EXPIRED`. The
`artifact_url` GET is the only retriable (idempotent) call and uses bounded backoff; the
begin POST is enqueued once and retried only via WorkManager backoff, not in-line.

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
- `TOKEN_EXPIRED` (410 / `expires_at` passed before download completes): discard temp file,
  re-call begin to mint a fresh URL/token once; if it fails again → `Failed(TOKEN_EXPIRED)`.
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

- OQ-1: Exact begin endpoint path/shape and whether the backend supports `server_burned_in`,
  `client_sidecar`, or both is unconfirmed. Resolution: inspect
  `frontend/src/api/endpoints/vodWatermarkDownload.ts` and `/openapi.json`. Until confirmed,
  implement both strategies behind the `strategy` discriminator and fail closed on unknown.
- OQ-2: On-device burn-in transcode (a third strategy) is heavy (Media3 Transformer) and
  battery/time costly; recommend **server_burned_in** as primary and **client_sidecar** as
  fallback rather than client transcode. Flag as product decision.
- Risk: `CLIENT_SIDECAR` is a soft binding — a rooted device can extract the raw artifact
  without overlay. Accepted and documented in §8; sidecar artifacts are kept app-private to
  raise the bar. Hardware DRM is a separate effort.
- OQ-3: `downloadable` flag's true field name on `VodDetail` DTO is unconfirmed (mirror from
  `frontend/src/api/types.ts`); default to non-downloadable if absent (safe default).
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
