---
id: AND-338
title: Files tests
milestone: M7
epic: E43
priority: P2
size: M
status: draft
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
  Files API is `frontend/src/api/endpoints/files.ts`,
  `frontend/src/api/endpoints/fileShareLinks.ts`, and shared types in
  `frontend/src/api/types.ts`. Error envelope `detail` is `string |
  [{msg}] | {code,...}`; tests must assert each shape maps correctly.
- Source tickets under test: AND-331 (Files API + DTOs), AND-332 (browse),
  AND-333 (upload via presign, deps AND-129), AND-334 (download/open), AND-335
  (share links, deps AND-022), AND-337 (Files ViewModels + paging).
- Auth is cookie-based with a persistent cookie jar and `X-CSRF-Token` echoing
  the `ui_csrf` cookie; on 401 the client refreshes once via
  `POST /ui/session/refresh` then retries. Tests run against an authenticated
  fake jar and must verify the CSRF header is attached to mutating file calls.

## 3. Functional Requirements

The test suite must verify the following observable behaviors of the feature
under test (the requirements are on the *tests*, asserting the *feature*):

1. **Browse mapping & paging.** `FilesRepository.browse(folderId, page)` maps a
   paginated listing into domain `FileNode`s; `FilesViewModel` exposes them as a
   `Flow<PagingData<FileNode>>`. Tests assert item count, folder-vs-file
   discrimination, and that `cursor`/`next` paging requests the next page.
2. **Search & sort.** Tests assert that changing the query or sort key issues a
   new request with the correct `q`, `sort`, and `order` params and resets
   paging.
3. **Upload via presign.** Two-step flow (request presign -> PUT bytes to the
   returned URL -> confirm) emits monotonic progress `0f..1f` and a terminal
   success; tests assert progress ordering and the confirm call.
4. **Download / open.** Repository writes bytes to the app cache, returns a
   content URI via FileProvider, and is idempotent on a cache hit (no second
   network call). Tests assert both the miss and hit paths.
5. **Share links.** Create returns a `shareUrl` + `linkId`; revoke removes it.
   Tests assert request bodies and that revoke surfaces success state.
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

**Browse** `GET /ui/files?folder_id={id}&q={q}&sort={name|size|mtime}&order={asc|desc}&cursor={c}`

```json
{
  "items": [
    {"id":"f_01","name":"Q3.pdf","is_folder":false,"size":20481,
     "mime":"application/pdf","modified_at":"2026-05-30T11:02:00Z"},
    {"id":"d_09","name":"Reports","is_folder":true,"size":0,
     "mime":null,"modified_at":"2026-05-21T09:00:00Z"}
  ],
  "next_cursor": "eyJrIjoiZl8wMSJ9"
}
```

**Presign upload (request)** `POST /ui/files/upload/presign`

```json
{"folder_id":"d_09","name":"Q3.pdf","size":20481,"mime":"application/pdf"}
```
-> `{"upload_url":"https://s3/...","file_id":"f_77","headers":{"x-amz-...":"v"}}`

**Confirm** `POST /ui/files/upload/confirm` body `{"file_id":"f_77"}` -> `200 {file...}`.

**Download** `GET /ui/files/{id}/content` -> binary stream (tests use a small byte fixture).

**Create share** `POST /ui/files/{id}/share` body `{"expires_in":86400}` ->
`{"link_id":"sl_1","share_url":"http://.../share/sl_1"}`.
**Revoke** `DELETE /ui/files/share/{link_id}` -> `204`.

**Error envelopes** (each asserted in `FilesErrorMappingTest`):
`{"detail":"Not found"}`, `{"detail":[{"msg":"name required"}]}`,
`{"detail":{"code":"quota_exceeded","limit":5}}`.

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
  mutating calls, and absent assertions are not required on GETs.
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
| Share | `FilesRepositoryShareTest` / `ShareLinkViewModelTest` | create body, revoke 204 |
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
   distinguished) and a second page is fetched via `next_cursor`.
3. Upload test asserts the presign->PUT->confirm sequence and strictly
   non-decreasing progress ending in `Succeeded`.
4. Download test asserts a `content://com.testlogon.android.fileprovider/...`
   URI on cache miss and **zero** additional network calls on cache hit.
5. Share test asserts create request body and revoke `204` success state.
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
