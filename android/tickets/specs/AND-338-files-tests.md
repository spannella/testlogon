---
id: AND-338
title: Files tests
milestone: M7
epic: E43
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-337, AND-331, AND-332, AND-333, AND-334, AND-335]
blocks: [AND-339]
---

# AND-338 — Files tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the entire Files feature
(epic E43): repository-layer unit tests and Compose UI tests covering browse,
search, sort, presigned upload with progress, download/open-with, share links,
and the ViewModels that drive them. It is a **Test** ticket (Priority P2); it
ships no production behavior. The goal is to lock in the contracts established by
AND-331 (`FilesApi` + DTOs), AND-332 (browse UI), AND-333 (presigned upload),
AND-334 (download/open), AND-335 (share links), and AND-337 (Files ViewModels +
Paging), and to make their regressions visible in CI.

The deliverable is "Pass": a green test run that exercises the success paths,
the documented error/`detail` mappings, the offline/stale states mandated by the
unreliable dev backend, and the Paging 3 flows — all without contacting the live
host `http://18.222.237.167:8000`. Concretely we target:

- `core-data` (files repository) unit tests with MockWebServer + fakes.
- `feature-files` ViewModel unit tests over `StateFlow<UiState>` with a fake
  repository and `PagingData` assertions.
- `feature-files` Compose UI tests (`createAndroidComposeRule`) for the browse,
  upload, and share screens.
- A shared test fixture set (JSON payloads, fakes) added to `core-testing`.

Non-goals: changing any production source under AND-331..AND-337; testing Google
Drive import (AND-336, which has its own acceptance and is not in this ticket's
dependency chain); instrumented end-to-end against the real backend.

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. Test packages mirror
  production: `com.testlogon.android.core.data.files`,
  `com.testlogon.android.feature.files`.
- Module layering under test: `feature-files -> core-network, core-model,
  core-data, core-testing`. This ticket adds code only to test source sets
  (`src/test`, `src/androidTest`) of `core-data` and `feature-files`, plus
  reusable fixtures in `core-testing` (`src/main` of that test-only module).
- Backend: FastAPI + DynamoDB. OpenAPI at `/openapi.json`. Web reference for the
  Files API is `src/api/endpoints/files.ts`,
  `src/api/endpoints/fileShareLinks.ts`, and shared types in
  `src/api/types.ts`. Error envelope `detail` is `string |
  [{msg}] | {code,...}`; tests must assert each shape maps correctly. NOTE
  (verified against `src/api/client.ts: normalizeErrorDetail`): the string shape
  is returned verbatim; the array shape joins each item's `msg` with `", "`; the
  object shape is mapped **only** for known `code` values (via
  `mapAuthorizationError`) and otherwise **falls back to the generic message** —
  an unknown `code` like `quota_exceeded` does NOT surface its fields. Tests must
  encode this fallback, not assume arbitrary code-keyed messages.
- Source tickets under test: AND-331 (Files API + DTOs), AND-332 (browse),
  AND-333 (upload via presign, deps AND-129), AND-334 (download/open), AND-335
  (share links, deps AND-022), AND-337 (Files ViewModels + paging).
- Auth is cookie-based with a persistent cookie jar and `X-CSRF-Token` echoing
  the `ui_csrf` cookie; on 401 the client refreshes once via
  `POST /ui/session/refresh` then retries. Tests run against an authenticated
  fake jar and must verify the CSRF header is attached. CORRECTION (verified
  against `src/api/client.ts`): the web client attaches `X-CSRF-Token` to **every**
  request whenever the `ui_csrf` cookie is present — GET *and* mutations — not only
  to mutating calls. The Android transport should mirror this, so CSRF-presence
  assertions are valid on browse/download as well, and "absent on GETs" is NOT a
  correct expectation. The 401 refresh-once flow is confirmed: a single shared
  `refreshPromise` guards against concurrent refreshes, and a second 401 after
  retry triggers logout (no infinite loop).

## 3. Functional Requirements

The test suite must verify the following observable behaviors of the feature
under test (the requirements are on the *tests*, asserting the *feature*):

1. **Browse mapping & paging.** `FilesRepository.browse(path, cursor)` maps a
   paginated `FileListResp` into domain `FileNode`s; `FilesViewModel` exposes them
   as a `Flow<PagingData<FileNode>>`. Tests assert item count, folder-vs-file
   discrimination (via `type == "folder"`), and that the response **`cursor`**
   field drives the next page request (the API param is `cursor`, key `path`).
2. **Search & sort.** Tests assert that changing the search prefix/query or sort
   key issues the correct request. Sort is on browse via `sort_by`/`sort_dir`
   params; filename search is `GET /v1/fs/search?prefix=` and full-text is
   `GET /v1/fs/search-text?q=` (there is no combined `q/sort/order` on browse).
   A new search/sort resets paging.
3. **Upload via presign.** Two-step flow (request presign -> PUT bytes to the
   returned URL -> confirm) emits monotonic progress `0f..1f` and a terminal
   success; tests assert progress ordering and the confirm call.
4. **Download / open.** Repository writes bytes to the app cache, returns a
   content URI via FileProvider, and is idempotent on a cache hit (no second
   network call). Tests assert both the miss and hit paths.
5. **Share links.** Create (`POST /ui/files/share-links`, body
   `CreateShareLinkIn` keyed by `file_node_id`) returns `201 ShareLinkOut` with
   `share_url` + `link_id`; revoke (`DELETE /ui/files/share-links/{link_id}`)
   returns `200 {ok, link_id}` (not `204`). Tests assert request bodies and that
   revoke surfaces success state.
6. **Error & resilience.** For each call: 4xx with each `detail` shape maps to
   `ApiResult.Error` with a human message; idempotent GETs retry on a transient
   5xx within the bounded budget; a 20s-class timeout surfaces the offline/stale
   UI state. Mutations (upload confirm, share create/revoke) are **not** retried.
7. **CSRF & auth.** A mutating request carries `X-CSRF-Token`; a single 401 ->
   `refresh` -> retry sequence succeeds, and a second consecutive 401 fails.
8. **UI states.** Compose tests assert Loading, Content (list rendered), Empty,
   Error (with retry affordance), and Offline/Stale states render and recover.

All tests must be deterministic, hermetic (no real network/host), and run in CI
on JDK 17.

## 4. Technical Design

### Test source layout

```
core-data/src/test/java/com/testlogon/android/core/data/files/
    FilesRepositoryBrowseTest.kt
    FilesRepositoryUploadTest.kt
    FilesRepositoryDownloadTest.kt
    FilesRepositoryShareTest.kt
    FilesErrorMappingTest.kt
feature-files/src/test/java/com/testlogon/android/feature/files/
    FilesViewModelTest.kt
    FileUploadViewModelTest.kt
    ShareLinkViewModelTest.kt
feature-files/src/androidTest/java/com/testlogon/android/feature/files/
    FileBrowseScreenTest.kt
    FileUploadScreenTest.kt
    ShareLinkSheetTest.kt
core-testing/src/main/java/com/testlogon/android/core/testing/files/
    FakeFilesRepository.kt
    FilesFixtures.kt
    PagingTestExt.kt
```

### Repository-layer harness (JVM unit)

Use OkHttp **MockWebServer** to drive the real Retrofit/Moshi stack so DTO
mapping is genuinely exercised. A `MainDispatcherRule` (JUnit `TestWatcher`)
installs a `StandardTestDispatcher`; all suspend calls run under
`runTest`.

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

private fun filesApi(server: MockWebServer): FilesApi =
    Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient.Builder()
            .addInterceptor(CsrfInterceptor(FakeCookieJar.authenticated()))
            .callTimeout(20, TimeUnit.SECONDS)
            .build())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(FilesApi::class.java)
```

`enqueue(MockResponse())` supplies canned bodies from `FilesFixtures`. Retry and
timeout behavior is verified with `MockResponse().setSocketPolicy(NO_RESPONSE)`
and sequential 503-then-200 enqueues; `server.requestCount` asserts the retry
count.

### ViewModel harness (JVM unit)

ViewModels are tested against `FakeFilesRepository` (no MockWebServer) so we
isolate state logic. `StateFlow<UiState>` is collected with Turbine; Paging
flows are snapshotted with the `cashapp/paging-testing` extension exposed via
`PagingTestExt.kt`:

```kotlin
suspend fun <T : Any> Flow<PagingData<T>>.snapshotItems(): List<T> =
    asSnapshot()   // androidx.paging.testing.asSnapshot
```

### Compose UI harness (instrumented / Robolectric-capable)

`feature-files` UI tests use `createAndroidComposeRule<ComponentActivity>()` and
inject a `FakeFilesRepository` into the screen's ViewModel via a Hilt test
component (`@HiltAndroidTest` + `HiltAndroidRule`) or direct constructor
injection of a fake. Assertions use semantics matchers and stable
`testTag`s (added to production composables only if missing — a permitted,
test-enabling change). Where feasible the UI tests run under Robolectric
(`@RunWith(RobolectricTestRunner::class)` via `robolectric` Compose support) to
keep them in the JVM CI lane; otherwise they run on the connected/emulator lane.

## 5. API Contract

This ticket consumes the contracts owned by AND-331/AND-335; it does not define
new endpoints. The fixtures below pin the shapes the tests assert against. If the
live `/openapi.json` diverges, the owning feature ticket is corrected and these
fixtures updated.

> CORRECTED in review (AND-338): the Files API is **path-based** under `/v1/fs/*`
> (web `src/api/endpoints/files.ts`), not id-based under `/ui/files/*`. Nodes are
> keyed by `path`, not `id`; there is no `folder_id`. Share **links** live under
> `/ui/files/share-links` (`src/api/endpoints/fileShareLinks.ts`). The earlier
> `/ui/files/...` shapes in this section were unverified and have been replaced
> with the verified contracts. (`/v1/fs/share` is a *separate* user-to-user share
> feature — `ShareFileReq {path,to_user,permission}` — and is out of scope here.)

**Browse** `GET /v1/fs/list?path={path}&limit={n}&cursor={c}&sort_by={k}&sort_dir={asc|desc}`
(verified: OpenAPI `GET /v1/fs/list`, params `path,limit,cursor,sort_by,sort_dir`;
web `listFiles`). Response is `FileListResp`:

```json
{
  "path": "/Reports",
  "items": [
    {"name":"Q3.pdf","path":"/Reports/Q3.pdf","type":"file","size":20481,
     "content_type":"application/pdf","updated_at":"2026-05-30T11:02:00Z"},
    {"name":"Archive","path":"/Reports/Archive","type":"folder",
     "updated_at":"2026-05-21T09:00:00Z"}
  ],
  "cursor": "eyJrIjoiL1JlcG9ydHMvUTMucGRmIn0="
}
```

CORRECTIONS vs. prior draft: `FileEntry` has no `id` (path-keyed); folder vs file
is `type: "file"|"folder"` (NOT `is_folder`); MIME is `content_type` (NOT `mime`);
timestamp is `updated_at` (NOT `modified_at`); the page token field is **`cursor`**
(NOT `next_cursor`).

**Search** (no combined browse `q/sort/order` exists): filename search is
`GET /v1/fs/search?prefix={p}&limit={n}` -> `{"prefix":..,"results":FileEntry[]}`;
full-text is `GET /v1/fs/search-text?q={q}&limit={n}` -> `{"query":..,"results":FileEntry[]}`.
Sort is applied on browse via `sort_by`/`sort_dir` query params.

**Presign upload (request)** `POST /v1/fs/presign-upload`, body `PresignUploadIn`:

```json
{"path":"/Reports/Q3.pdf","content_type":"application/pdf"}
```
-> `PresignUploadOut`
`{"upload_url":"https://s3/...","bucket":"b","key":"k","ticket_id":"t_77","path":"/Reports/Q3.pdf","content_type":"application/pdf"}`.

**Confirm** `POST /v1/fs/complete-upload`, body `CompleteUploadIn`
`{"path":"/Reports/Q3.pdf","key":"k","ticket_id":"t_77","content_type":"application/pdf","encrypted":false,"enc_meta":null}`
-> `200 {"ok":true,"path":..,"size":..,"content_type":..}`. (Required body fields:
`path`, `key`, `ticket_id`.)

**Download** `GET /v1/fs/download?path={path}` -> binary stream (tests use a small
byte fixture). NOTE: the web reference also does a simple `POST /v1/fs/upload`
multipart path (`uploadFile`); the presign+complete two-step is the large-file
flow and is what AND-333 implements.

**Create share link** `POST /ui/files/share-links`, body `CreateShareLinkIn`
`{"file_node_id":"/Reports/Q3.pdf","expiry_hours":24,"max_downloads":1,"password":null}`
(only `file_node_id` is required; `expiry_hours` default 24, `max_downloads`
default 1) -> **`201` `ShareLinkOut`**
`{"link_id":"sl_1","file_node_id":..,"file_name":..,"file_size_bytes":..,"content_type":..,"created_at":<int>,"expires_at":<int>,"max_downloads":1,"download_count":0,"has_password":false,"is_revoked":false,"share_url":"http://.../share/sl_1"}`.
`created_at`/`expires_at` are **integer epoch** values, not ISO strings.
**Revoke** `DELETE /ui/files/share-links/{link_id}` -> **`200 {"ok":true,"link_id":..}`**
(NOT `204`, and the path is `/ui/files/share-links/{link_id}`, not
`/ui/files/share/{link_id}`).

**Error envelopes** (each asserted in `FilesErrorMappingTest`):
`{"detail":"Not found"}` (-> verbatim), `{"detail":[{"msg":"name required"}]}`
(-> `msg`s joined with `", "`), `{"detail":{"code":"...",...}}` (-> mapped only
for known codes via `mapAuthorizationError`, else generic fallback). The backend
validation error type is `HTTPValidationError`, whose `detail` is an array of
`{loc, msg, type}` — the array shape above is the realistic 422 body.

## 6. Data & State Management

Tests assert the production `FilesUiState` sealed hierarchy and the domain model
without redefining them:

```kotlin
sealed interface FilesUiState {
    data object Loading : FilesUiState
    data class Content(val pager: Flow<PagingData<FileNode>>,
                       val sort: SortSpec, val query: String,
                       val stale: Boolean = false) : FilesUiState
    data object Empty : FilesUiState
    data class Error(val message: String, val retryable: Boolean) : FilesUiState
    data object Offline : FilesUiState
}
```

State assertions:
- Turbine: `Loading` is the initial emission; first successful page -> `Content`.
- Empty listing (`items: []`) -> `Empty`.
- Timeout/no-connectivity -> `Offline`; a successful payload after a prior
  failure that returned cached rows -> `Content(stale = true)`.
- Upload: `UploadState.InProgress(fraction)` emissions are strictly
  non-decreasing and end at `Succeeded(file)`; cancellation -> `Cancelled`.
- Room cache (download): test verifies a second `download(id)` after a cache hit
  performs zero network calls (`server.requestCount == 1`).

`PagingData` is never asserted via raw `StateFlow` equality (it is not
value-comparable); always via `asSnapshot()` / `TestPager` where applicable.

## 7. Error Handling & Resilience

The suite is the primary guardian of the resilience rules for the unreliable dev
backend. Required cases:

1. **`detail` mapping** — three `FilesErrorMappingTest` cases assert
   `ApiResult.Error.message` for string, `[{msg}]` (joined), and `{code,...}`
   (code-keyed message) shapes.
2. **Bounded retry, idempotent GET only** — `browse`/`download` retry on `503`
   then succeed; assert `server.requestCount == 2` (one retry) and that the
   backoff is bounded (test uses a virtual clock; total attempts capped).
3. **No retry on mutations** — upload `confirm`, share `create`, and `revoke`
   that return `503` produce a single request (`requestCount == 1`) and
   `ApiResult.Error`.
4. **Timeout -> Offline** — `NO_RESPONSE` socket policy surfaces `Offline`
   without hanging the test (call timeout honored; test wall-clock bounded).
5. **401 refresh-once** — first call 401, `POST /ui/session/refresh` 200, retry
   200 -> success; two consecutive 401s -> failure and no infinite loop
   (assert exactly one refresh attempt).

## 8. Security & Privacy

- Tests must never embed real credentials or contact the live host; the
  MockWebServer base URL is the only network endpoint. CI must fail if a test
  references `18.222.237.167`.
- `FakeCookieJar.authenticated()` seeds a synthetic session + `ui_csrf` cookie.
  `FilesRepositoryShareTest` and `FilesRepositoryUploadTest` assert the
  `X-CSRF-Token` request header is present and equals the `ui_csrf` value on
  mutating calls. NOTE (corrected): the web client sends `X-CSRF-Token` on **all**
  requests when the cookie is present (`src/api/client.ts`), so an
  "absent on GETs" assertion would be wrong — at most assert presence on GETs too
  if the Android transport mirrors the web behavior, or scope the assertion to
  mutations only without asserting absence on GETs.
- Download tests write only to a sandboxed temp/cache dir and assert the returned
  URI is a `content://com.testlogon.android.fileprovider/...` (no `file://`
  leakage), validating the FileProvider grant model from AND-334.
- Fixtures contain no PII; payloads use synthetic ids and names.

## 9. Accessibility & i18n

- Compose UI tests assert content descriptions exist for icon-only controls
  (sort, upload FAB, share, overflow) via `onNodeWithContentDescription`, and
  that list rows are individually focusable/clickable nodes — guarding the a11y
  contract from AND-332/AND-335.
- Tests assert user-facing error and empty-state strings are resolved from
  resources (`stringResource`), not hardcoded, by reading expected text from
  `context.getString(...)`. This keeps the suite locale-independent and verifies
  i18n readiness.
- No locale-formatting assertions on dates/sizes beyond presence; exact
  formatting belongs to the feature tickets.

## 10. Telemetry & Logging

This is a test ticket and emits no production telemetry. Where the feature
records analytics events (e.g. `file_upload_succeeded`,
`share_link_created`), the ViewModel tests inject a `FakeAnalytics` (recording
sink) and assert the event name + key params are emitted once on the success
path and not emitted on failure. If a feature ticket did not introduce analytics
hooks, that assertion is skipped and noted; the owning ticket (AND-339, Files
polish/release-readiness) carries any telemetry gap. Test logging uses standard
JUnit output; no logcat scraping.

## 11. Testing Strategy

**Frameworks:** JUnit4, Kotlin Coroutines `kotlinx-coroutines-test` (`runTest`,
`StandardTestDispatcher`), Turbine (Flow), OkHttp MockWebServer (Retrofit
stack), `androidx.paging:paging-testing` (`asSnapshot`, `TestPager`), Truth
assertions, Compose UI test (`createAndroidComposeRule`), Hilt testing, and
Robolectric for JVM-lane Compose where viable. All live in `core-testing` as
shared deps.

**Coverage matrix (must all pass):**

| Area | Test class | Key assertions |
|------|-----------|----------------|
| Browse map/page | `FilesRepositoryBrowseTest` | DTO->`FileNode`, next_cursor paging |
| Search/sort | `FilesViewModelTest` | params, paging reset |
| Upload | `FilesRepositoryUploadTest` / `FileUploadViewModelTest` | presign+PUT+confirm, progress monotonic |
| Download/open | `FilesRepositoryDownloadTest` | cache miss/hit, content URI |
| Share | `FilesRepositoryShareTest` / `ShareLinkViewModelTest` | create body (`file_node_id`) -> 201, revoke -> 200 `{ok,link_id}` |
| Errors | `FilesErrorMappingTest` | 3 detail shapes, retry, no-retry, 401 refresh |
| UI | `FileBrowseScreenTest`, `FileUploadScreenTest`, `ShareLinkSheetTest` | Loading/Content/Empty/Error/Offline, a11y tags |

**Determinism:** virtual time via test dispatcher; no `Thread.sleep`; no real
delays in backoff (inject the delay function or use `advanceUntilIdle`). Each
test enqueues exactly the responses it consumes and asserts `requestCount`.

**Run commands:**
`./gradlew :core-data:testDebugUnitTest :feature-files:testDebugUnitTest`
and `./gradlew :feature-files:connectedDebugAndroidTest` (or the Robolectric
unit lane for UI tests). Acceptance = both green.

## 12. Dependencies & Sequencing

- **Hard deps (must be merged first):** AND-337 (ViewModels + paging) is the
  stated dependency; transitively AND-331 (API+DTOs), AND-332 (browse), AND-333
  (upload), AND-334 (download), AND-335 (share) provide the production code under
  test. This ticket cannot reach "Pass" until those land.
- **Not in scope:** AND-336 (Google Drive) — separate acceptance, excluded here.
- **Shared infra:** adds reusable fakes/fixtures to `core-testing`; coordinate so
  AND-330 (KYC tests) and other M7 test tickets reuse `MainDispatcherRule` and
  `PagingTestExt` rather than duplicating them.
- **Blocks:** AND-339 (next E43 ticket / release-readiness) should not be marked
  done while Files tests are red; treat this as a merge gate for the epic.

## 13. Risks & Open Questions

- **Compose UI lane choice.** Robolectric Compose vs. connected-emulator affects
  CI time/flake. Open question: does CI have an emulator lane? Default to
  Robolectric for browse/share, emulator only for upload progress if needed.
- **Paging assertions** are sensitive to `PagingConfig` (pageSize, prefetch).
  Tests must read the production config, not hardcode, to avoid false failures.
- **Presigned PUT to S3** is an external URL; tests must point the presign
  response at the MockWebServer URL so the PUT is also captured locally.
- **FileProvider authority** must match `com.testlogon.android.fileprovider`;
  if AND-334 used a different authority, the download URI assertion needs
  updating — confirm against the manifest.
- **Analytics presence** (section 10) is unconfirmed for E43; if absent, those
  assertions are omitted and flagged to AND-339.

## 14. Acceptance Criteria

1. `:core-data:testDebugUnitTest` and `:feature-files:testDebugUnitTest` pass
   with the new files-test classes present and executed.
2. Browse test maps a multi-item payload to `FileNode`s (folder/file
   distinguished via `type`) and a second page is fetched via the response
   **`cursor`** field (corrected from `next_cursor` during review).
3. Upload test asserts the presign->PUT->confirm sequence and strictly
   non-decreasing progress ending in `Succeeded`.
4. Download test asserts a `content://com.testlogon.android.fileprovider/...`
   URI on cache miss and **zero** additional network calls on cache hit.
5. Share test asserts create request body (`file_node_id`, `expiry_hours`,
   `max_downloads`) -> `201 ShareLinkOut`, and revoke `200 {ok, link_id}` success
   state (corrected from `204` during review).
6. Error test asserts all three `detail` shapes map to `ApiResult.Error`
   messages; GET retries once on 503; mutations do not retry; one 401 ->
   refresh -> retry succeeds and two 401s fail.
7. UI tests assert Loading, Content, Empty, Error (with retry), and Offline
   states render, and icon-only controls have content descriptions.
8. No test references the live host `18.222.237.167`; suite is hermetic and
   deterministic (no `Thread.sleep`, bounded wall-clock).
9. `X-CSRF-Token` presence asserted on at least one mutating call.

## 15. Definition of Done

- All test classes in section 4 implemented; both unit lanes green locally and in
  CI on JDK 17 / AGP 8.7.3 / Gradle 8.9.
- Shared fixtures/fakes added to `core-testing` and consumed by the suite; no
  duplicated harness code across modules.
- Any production-only changes are limited to additive `testTag`s/content
  descriptions strictly required for testability, reviewed and noted in the PR.
- Coverage matrix (section 11) fully realized; each row has at least one passing
  assertion as listed.
- PR on branch `android-port` references AND-338, links AND-331/332/333/334/335/
  337, and confirms it gates AND-339.
- CI guard (grep for `18.222.237.167` in test sources) is in place or the absence
  is confirmed; no flaky/ignored tests merged.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE. OpenAPI pointers reference
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend pointers
reference `reference/src/...`.

1. **Browse endpoint is `GET /v1/fs/list` with params `path,limit,cursor,sort_by,sort_dir`.**
   VERDICT: Corrected (spec said `GET /ui/files?folder_id&q&sort&order&cursor`).
   SOURCE: OpenAPI `GET /v1/fs/list`; `src/api/endpoints/files.ts: listFiles`.
2. **Browse response is `FileListResp {path, items: FileEntry[], cursor?}`; page token field is `cursor`.**
   VERDICT: Corrected (spec used `next_cursor`).
   SOURCE: `src/api/types.ts: FileListResp`; `src/api/endpoints/files.ts: listFiles`.
3. **`FileEntry` shape: `{name, path, type:"file"|"folder", size?, content_type?, updated_at?, created_at?, ...}` — no `id`; folder flag is `type`; MIME is `content_type`; timestamp is `updated_at`.**
   VERDICT: Corrected (spec used `id`, `is_folder`, `mime`, `modified_at`).
   SOURCE: `src/api/types.ts: FileEntry` (lines 1545-1577).
4. **Search is `GET /v1/fs/search?prefix&limit` (filename) / `GET /v1/fs/search-text?q&limit`; sort is via browse `sort_by`/`sort_dir`.**
   VERDICT: Corrected (spec assumed combined `q/sort/order` on browse).
   SOURCE: OpenAPI `GET /v1/fs/search`, `GET /v1/fs/search-text`, `GET /v1/fs/list`;
   `src/api/endpoints/files.ts: searchFiles, searchText, listFiles`.
5. **Presign request is `POST /v1/fs/presign-upload`, body `PresignUploadIn {path, content_type?}` (only `path` required).**
   VERDICT: Corrected (spec said `POST /ui/files/upload/presign` with `{folder_id,name,size,mime}`).
   SOURCE: OpenAPI `POST /v1/fs/presign-upload` + `components.schemas.PresignUploadIn`;
   `src/api/endpoints/files.ts: fsPresignUpload`.
6. **Presign response is `PresignUploadOut {upload_url, bucket, key, ticket_id, path, content_type}`.**
   VERDICT: Corrected (spec said `{upload_url, file_id, headers}`).
   SOURCE: `components.schemas.PresignUploadOut`; `src/api/endpoints/files.ts: fsPresignUpload`.
7. **Confirm is `POST /v1/fs/complete-upload`, body `CompleteUploadIn {path, key, ticket_id, content_type?, encrypted?, enc_meta?}` (required: path,key,ticket_id).**
   VERDICT: Corrected (spec said `POST /ui/files/upload/confirm {file_id}`).
   SOURCE: OpenAPI `POST /v1/fs/complete-upload` + `components.schemas.CompleteUploadIn`;
   `src/api/endpoints/files.ts: completeUpload`.
8. **Download is `GET /v1/fs/download?path=` (binary stream).**
   VERDICT: Corrected (spec said `GET /ui/files/{id}/content`).
   SOURCE: OpenAPI `GET /v1/fs/download`; `src/api/endpoints/files.ts: downloadUrl`.
9. **Create share link is `POST /ui/files/share-links`, body `CreateShareLinkIn {file_node_id, expiry_hours?=24, max_downloads?=1, password?}` (required: file_node_id) -> `201 ShareLinkOut`.**
   VERDICT: Corrected (spec said `POST /ui/files/{id}/share {expires_in}`).
   SOURCE: OpenAPI `POST /ui/files/share-links` (resp `201:ShareLinkOut`,
   req `CreateShareLinkIn`); `components.schemas.CreateShareLinkIn`;
   `src/api/endpoints/fileShareLinks.ts: createShareLink`; `src/api/types.ts: CreateShareLinkInput`.
10. **`ShareLinkOut` has `link_id, file_node_id, file_name, file_size_bytes, content_type, created_at(int), expires_at(int), max_downloads, download_count, has_password, is_revoked, share_url`.**
    VERDICT: Corrected (spec implied only `{link_id, share_url}`; timestamps are epoch ints).
    SOURCE: `components.schemas.ShareLinkOut`; `src/api/types.ts: ShareLink`.
11. **Revoke is `DELETE /ui/files/share-links/{link_id}` -> `200 {ok, link_id}`.**
    VERDICT: Corrected (spec said `DELETE /ui/files/share/{link_id}` -> `204`).
    SOURCE: OpenAPI `DELETE /ui/files/share-links/{link_id}` (resp `200:`);
    `src/api/endpoints/fileShareLinks.ts: revokeShareLink`.
12. **Error envelope `detail`: string verbatim; array joins each `msg` with `", "`; object mapped only for known `code`s, else generic fallback.**
    VERDICT: Verified (refines spec's "{code,...} -> code-keyed message").
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (lines 66-102);
    `src/api/client.errorMapping.test.ts` (unknown code -> fallback).
13. **422 validation body is `HTTPValidationError` (`detail: [{loc,msg,type}]`).**
    VERDICT: Verified.
    SOURCE: OpenAPI `components.schemas.HTTPValidationError` (referenced by all `422` responses in the index).
14. **`X-CSRF-Token` echoes the `ui_csrf` cookie and is attached to EVERY request (GET + mutations) when the cookie is present.**
    VERDICT: Corrected (spec implied mutations-only / GET-absent).
    SOURCE: `src/api/client.ts` (lines 167-171, header set unconditionally before fetch).
15. **401 handling: single shared `refreshPromise` -> `POST /ui/session/refresh` -> retry once; a second 401 after retry triggers logout (no loop).**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (lines 119-237: `refreshSession`, 401 branch, retry).
16. **`/v1/fs/share` (`ShareFileReq {path,to_user,permission}`) is user-to-user sharing, distinct from public share-links.**
    VERDICT: Verified (clarifies scope; out of this ticket's share-link scope).
    SOURCE: OpenAPI `POST /v1/fs/share`; `src/api/endpoints/files.ts: shareFile`;
    `src/api/types.ts: ShareFileReq`.
17. **Network/transient failures: the web client raises `ApiError(0, "Network error")` on fetch throw; idempotent GET retry/backoff is an Android-side concern.**
    VERDICT: Verified-for-web / Unverified-assumption for Android budget.
    SOURCE: `src/api/client.ts` (lines 185-189). The web client does NOT itself
    retry transient 5xx; bounded-retry-on-503 for GETs (spec §7) is an
    Android-port resilience decision owned by AND-331, not a backend contract.
18. **MockWebServer + Retrofit/Moshi as the repo-test transport; Paging via `androidx.paging:paging-testing` `asSnapshot`.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref https://github.com/square/okhttp/tree/master/mockwebserver
    and https://developer.android.com/reference/kotlin/androidx/paging/testing/package-summary (`asSnapshot`).
19. **FileProvider content URI authority `com.testlogon.android.fileprovider`.**
    VERDICT: Unverified-assumption (no Android manifest in `reference/`).
    SOURCE: framework ref https://developer.android.com/reference/androidx/core/content/FileProvider — authority is set by AND-334's manifest; confirm there.
20. **Analytics events (`file_upload_succeeded`, `share_link_created`).**
    VERDICT: Unverified-assumption (no analytics hooks found in `reference/src` for files).
    SOURCE: absent from `src/api/endpoints/files.ts` / `fileShareLinks.ts`; owned by feature tickets / AND-339.

### Corrections made

- §2: error-envelope mapping clarified (array joins `msg` with `", "`; object
  mapped only for known `code`s, else fallback) per `client.ts: normalizeErrorDetail`.
- §2: CSRF corrected — header sent on ALL requests (not mutations-only).
- §5: entire contract rewritten from the unverified `/ui/files/*` id-based shapes
  to the verified path-based `/v1/fs/*` endpoints (browse/list, search, presign,
  complete-upload, download) and `/ui/files/share-links` for share links; field
  names fixed (`type` not `is_folder`, `content_type` not `mime`, `updated_at`
  not `modified_at`, `cursor` not `next_cursor`, no `id`/`folder_id`); presign
  and confirm bodies/responses fixed; revoke `200 {ok,link_id}` not `204`.
- §3 (items 1, 2, 5), §8 (CSRF), §11 (Share row), §14 (AC2, AC5): aligned to the
  corrected contract.

### Open assumptions

- **FileProvider authority** (`com.testlogon.android.fileprovider`): cannot be
  verified — no Android source/manifest is present in `reference/` (web + OpenAPI
  only). Confirm against AND-334's `AndroidManifest.xml` before asserting the URI.
- **Analytics events for Files**: no analytics hooks exist in the web reference
  for files/share-links; presence in the Android feature is unconfirmed. Tests
  gate these assertions behind the hooks' existence and flag the gap to AND-339.
- **Android bounded-retry/backoff for transient 5xx on GETs**: the web client
  does not retry 5xx; this is an Android-port resilience policy (AND-331), not a
  backend contract — treated as a design decision, not a verified fact.
- **`PagingConfig` (pageSize/prefetch)**: must be read from production at test
  time; not derivable from the web reference. Unverified until AND-337 source.
- **`FilesUiState` / `UploadState` / `ApiResult` sealed shapes (§6)**: these are
  Android-side production types owned by AND-331/AND-337; no Android source is in
  `reference/`, so their exact members are assumed from the spec, not verified.

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric (no device); **emulator** =
headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a) on the build host via adb. Each case names its
target; hardware-dependent cases prefer the physical device.

- **TC-AND-338-01 — Browse maps `FileListResp` and pages via `cursor`.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryBrowseTest`).
  Preconditions: `FakeCookieJar.authenticated()`; MockWebServer enqueues page-1
  (`items` with one `type:"file"` + one `type:"folder"`, `cursor:"c2"`) then page-2.
  Steps: call `browse(path="/Reports")`, then request next page with returned
  `cursor`. Expected: two `FileNode`s mapped with correct folder/file (`type`),
  `content_type`, `size`, `updated_at`; second request carries `cursor=c2` and
  `path=/Reports`; `server.requestCount == 2`. Traces: AC-1, AC-2.

- **TC-AND-338-02 — Search and sort issue correct requests and reset paging.**
  Type: unit (JVM, fake repo) + contract. Target: JVM
  (`FilesViewModelTest` / `FilesRepositoryBrowseTest`). Preconditions: fake repo
  records requests. Steps: set sort -> browse with `sort_by`/`sort_dir`; set a
  prefix -> `GET /v1/fs/search?prefix=`; set full-text -> `GET /v1/fs/search-text?q=`.
  Expected: each request has the documented params; changing sort/query resets the
  pager to page 1. Traces: AC-1.

- **TC-AND-338-03 — Upload presign -> PUT -> complete, monotonic progress.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryUploadTest` /
  `FileUploadViewModelTest`). Preconditions: presign response `upload_url` points
  at the MockWebServer URL so the PUT is captured locally. Steps: presign
  (`PresignUploadIn{path}`), PUT bytes, complete (`CompleteUploadIn{path,key,ticket_id}`).
  Expected: three captured requests in order; `UploadState.InProgress(fraction)`
  emissions strictly non-decreasing in `0f..1f` ending `Succeeded`; complete body
  carries `key`+`ticket_id` from the presign response. Traces: AC-3, AC-9.

- **TC-AND-338-04 — Download cache miss writes FileProvider URI; cache hit = 0 network.**
  Type: integration/Robolectric (JVM) for FileProvider; promote to **device** if
  the FileProvider grant must be exercised on real API 34. Target: JVM/Robolectric
  then device (`FilesRepositoryDownloadTest`). Preconditions: MockWebServer serves
  a small byte fixture for `GET /v1/fs/download?path=`; sandbox cache dir.
  Steps: `download(path)` (miss) then `download(path)` again (hit). Expected: miss
  returns `content://com.testlogon.android.fileprovider/...` (no `file://`);
  `server.requestCount == 1` after the hit (zero extra calls). Traces: AC-4.
  NOTE: authority is an open assumption (§16) — confirm against AND-334 manifest.

- **TC-AND-338-05 — Create share link body + 201 `ShareLinkOut`.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryShareTest` /
  `ShareLinkViewModelTest`). Preconditions: enqueue `201` `ShareLinkOut`. Steps:
  `createShareLink(file_node_id="/Reports/Q3.pdf", expiry_hours=24, max_downloads=1)`.
  Expected: request is `POST /ui/files/share-links` with body keyed by
  `file_node_id`; response parses `link_id` + `share_url`; `created_at`/`expires_at`
  parsed as epoch ints; success state surfaced. Traces: AC-5, AC-9.

- **TC-AND-338-06 — Revoke share link returns 200 {ok, link_id}.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryShareTest`).
  Preconditions: enqueue `200 {"ok":true,"link_id":"sl_1"}`. Steps:
  `revokeShareLink("sl_1")`. Expected: request is
  `DELETE /ui/files/share-links/sl_1`; result maps to success (NOT expecting 204);
  ViewModel surfaces revoked state. Traces: AC-5.

- **TC-AND-338-07 — Error `detail` shapes map to `ApiResult.Error` messages.**
  Type: unit/contract (JVM). Target: JVM (`FilesErrorMappingTest`). Preconditions:
  enqueue three 4xx bodies. Steps/Expected: `{"detail":"Not found"}` -> message
  "Not found"; `{"detail":[{"msg":"name required"},{"msg":"size too big"}]}` ->
  "name required, size too big" (joined with `", "`); `{"detail":{"code":"unknown_x"}}`
  -> generic fallback message (unknown code is NOT surfaced). Traces: AC-6.

- **TC-AND-338-08 — Idempotent GET retries once on 503; mutations do not retry.**
  Type: contract/MockWebServer (JVM). Target: JVM
  (`FilesRepositoryBrowseTest` / `FilesErrorMappingTest`). Preconditions: virtual
  clock / injected delay. Steps: browse enqueues `503` then `200`
  (`requestCount==2`); complete-upload / share-create / revoke enqueue `503`
  (`requestCount==1`, `ApiResult.Error`). Expected: GET retried once within a
  bounded budget; mutations not retried. Traces: AC-6, AC-8.
  NOTE: GET-retry is an Android resilience policy (§16 open assumption), not a
  backend guarantee.

- **TC-AND-338-09 — Timeout/no-connectivity surfaces Offline without hanging.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryBrowseTest` /
  `FilesViewModelTest`). Preconditions: `MockResponse().setSocketPolicy(NO_RESPONSE)`;
  20s call timeout; test wall-clock bounded. Steps: browse against the dead socket.
  Expected: call times out -> `FilesUiState.Offline`; a later success after cached
  rows -> `Content(stale = true)`; test does not hang. Traces: AC-6, AC-7, AC-8.
  (This models the flaky dev host `18.222.237.167` offline path.)

- **TC-AND-338-10 — 401 -> refresh-once -> retry succeeds; two 401s fail.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesErrorMappingTest`).
  Preconditions: authenticated fake jar. Steps: (a) browse `401`, then
  `POST /ui/session/refresh` `200`, then retry `200`; (b) browse `401` twice.
  Expected: (a) succeeds with exactly one refresh attempt; (b) fails, no infinite
  loop, logout signaled. Traces: AC-6.

- **TC-AND-338-11 — `X-CSRF-Token` attached and equals `ui_csrf` on mutating call.**
  Type: contract/MockWebServer (JVM). Target: JVM (`FilesRepositoryShareTest` /
  `FilesRepositoryUploadTest`). Preconditions: jar seeds `ui_csrf=abc`. Steps:
  perform a mutating call (share create / complete-upload). Expected: recorded
  request header `X-CSRF-Token == "abc"`. Do NOT assert absence on GETs (web sends
  it on all requests, §16). Traces: AC-9.

- **TC-AND-338-12 — No test references the live host; suite is hermetic/deterministic.**
  Type: unit/CI-guard (JVM). Target: JVM (build/CI step). Preconditions: test
  sources present. Steps: grep test source sets for `18.222.237.167`; scan for
  `Thread.sleep`. Expected: zero matches for the host; no `Thread.sleep`; all
  network goes to MockWebServer base URL. Traces: AC-8.

- **TC-AND-338-13 — Compose UI renders Loading/Content/Empty/Error/Offline and recovers.**
  Type: Compose-UI (Robolectric on JVM where viable, else **emulator** `test35`).
  Target: JVM/Robolectric or emulator (`FileBrowseScreenTest`). Preconditions:
  `FakeFilesRepository` injected; fixtures for each state. Steps: drive states via
  the fake; tap retry from Error. Expected: each state's nodes assert via semantics;
  Empty for `items:[]`; Error shows a retry affordance that re-requests and
  transitions to Content; Offline renders and recovers. Traces: AC-7.

- **TC-AND-338-14 — Accessibility: icon-only controls have content descriptions; rows focusable; strings from resources.**
  Type: Compose-UI / accessibility (Robolectric on JVM, or **emulator**). Target:
  JVM/Robolectric or emulator (`FileBrowseScreenTest`, `FileUploadScreenTest`,
  `ShareLinkSheetTest`). Preconditions: screens rendered with fixtures. Steps:
  query sort/upload-FAB/share/overflow via `onNodeWithContentDescription`; assert
  list rows are individually focusable/clickable; read expected error/empty text
  via `context.getString(...)`. Expected: all icon-only controls have non-empty
  content descriptions; rows are focusable nodes; user-facing strings resolve from
  resources (not hardcoded). Traces: AC-7.

### Coverage matrix (AC -> TC)

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 unit lanes present & executed; classes run | TC-01, TC-02 (and all JVM TCs execute the classes) |
| AC-2 browse maps multi-item payload + 2nd page via `cursor` | TC-01 |
| AC-3 upload presign->PUT->confirm + monotonic progress | TC-03 |
| AC-4 download content URI on miss + 0 network on hit | TC-04 |
| AC-5 share create body + revoke 200 success | TC-05, TC-06 |
| AC-6 detail shapes, GET retry, no mutation retry, 401 refresh | TC-07, TC-08, TC-09, TC-10 |
| AC-7 UI Loading/Content/Empty/Error/Offline + content descriptions | TC-13, TC-14 |
| AC-8 hermetic & deterministic, no live host | TC-08, TC-09, TC-12 |
| AC-9 `X-CSRF-Token` on a mutating call | TC-03, TC-05, TC-11 |
