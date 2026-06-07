---
id: AND-156
title: Search/contacts tests
milestone: M3
epic: E21
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-155, AND-153, AND-152]
blocks: []
---

# AND-156 — Search/contacts tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the message-search and contacts
features implemented in the E21 epic. It is a pure **Test** ticket (Type: Test,
Priority: P2): it adds no production behavior and ships only test code, fixtures,
and CI wiring. The unit of work is to lock down the behavior of the search and
contacts repositories (`MessageSearchRepository`, `ContactsRepository`), their
`PagingSource`/`RemoteMediator` implementations, the debounced query
`ViewModel`s (`MessageSearchViewModel`, `ContactsViewModel` from AND-155), and the
Compose screens (`MessageSearchScreen` from AND-152, `ContactsScreen` from
AND-153) against a regression suite.

The goal is twofold: (1) prove the debounce/paging/empty-state logic from AND-155
behaves as specified under fast typing, cancellation, error, and empty-result
conditions; and (2) prove the two Compose screens render loading, content, empty,
and error states and drive the correct query/navigation callbacks. The single
acceptance bar from the backlog is **"Tests pass"** — i.e., the new modules
(`feature-search`, `feature-contacts`, plus repo tests in `core-data`) have green
JVM unit tests and instrumented/Robolectric UI tests in CI, with meaningful
assertions (not trivially-passing stubs) covering the scenarios enumerated in
§3 and §11.

The scope is explicitly **Repo + UI tests**: repository-level unit tests
(including `PagingSource` paging assertions) and Compose UI tests for the two
screens. ViewModel unit tests are owned primarily by AND-155 ("Unit-tested"); this
ticket extends them where coverage of debounce/paging interaction with the repo
layer is required and consolidates the suite.

## 2. Context & References

- **Depends on:** AND-155 (Search/contacts ViewModels + paging — debounced query
  state, paging, empty states), which in turn depends on AND-152 (Global message
  search, `/messaging/messages/search`) and AND-153 (Contacts list + search,
  `/messaging/contacts/search`). All three production tickets must be merged
  before this suite can compile and run.
- **Modules under test:** `feature-search`, `feature-contacts`, and the
  search/contacts code paths in `core-data` and `core-network`. Test utilities
  live in `core-testing`.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json` on the dev host
  `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Tests must **not**
  hit the live host; all network is faked via `MockWebServer` (OkHttp) or
  test-double Retrofit services. Endpoint shapes are taken from the web reference
  app: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
- **Namespace:** all test packages live under `com.testlogon.android.*`
  (e.g., `com.testlogon.android.feature.search`,
  `com.testlogon.android.feature.contacts`,
  `com.testlogon.android.core.data.search`).
- **Stack relevant to tests:** Kotlin 2.0.21, Coroutines/Flow, Paging 3,
  Compose + Material 3, Hilt (KSP), Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room
  2.6. JDK 17, AGP 8.7.3, Gradle 8.9. minSdk 24 / target 35.

## 3. Functional Requirements

The suite must assert the following observable behaviors of the code delivered by
AND-152/153/155:

1. **Debounce:** rapid `onQueryChanged()` calls within the debounce window
   (300 ms) collapse to a single repository search invocation for the final
   value. A `query` shorter than the minimum (2 chars) issues no network call and
   resets results to `Idle`.
2. **Distinct-until-changed:** typing the same value twice (e.g., "ab" → "ab")
   does not re-trigger a search.
3. **Cancellation:** when a new query arrives while a previous search is in
   flight, the in-flight request is cancelled (no stale results overwrite newer
   ones — last-write-wins by query token).
4. **Paging:** CORRECTED — the backend `GET /messaging/messages/search` returns
   a **bare JSON array of `MessageOut`** (no `cursor` query param, no
   `next_cursor`/`total` in the body — verified against OpenAPI). There is no
   server-side cursor pagination to test. The suite therefore asserts a
   **single-page** `PagingSource` (one `Refresh` load returns all items with
   `prevKey == null` and `nextKey == null`) and surfaces `LoadResult.Error` on
   transport failure. Any multi-page/cursor behavior would be a **client-side**
   construct (e.g. windowing by `limit`/`after_ts`) owned by AND-152/155 and is
   an unverified assumption (see §16); the test mirrors whatever the production
   `PagingSource` actually exposes. Page-2/`next_cursor` append assertions from
   the prior draft are removed because the backend exposes no such field.
5. **Empty state:** a 200 response with an **empty array `[]`** (not an
   `items: []` envelope — the response is a bare array) yields the `Empty` UI
   state (distinct from `Idle` and `Error`).
6. **Error state:** non-2xx / timeout / parse failures map to a typed
   `ApiResult.Error` and the `Error` UI state with a user-facing message derived
   from the FastAPI `detail` shape.
7. **Contacts tokenization:** the contacts repo forwards the raw query to
   `GET /messaging/contacts/search?q=&limit=` (the `q` param is **required**,
   1–64 chars; `limit` defaults to 10, max 50 — verified against OpenAPI) and
   returns the parsed contact list. CORRECTED — the response is a **bare JSON
   array of `Contact` objects** (`{user_id, display_name}` only; the web client
   types these as `UserSearchResult` = `{user_id, display_name}`), NOT an
   `{items:[{handle, avatar_url, …}]}` envelope. Server-side tokenization is not
   re-tested client-side; the test only asserts the query reaches the endpoint
   and the array parses.
8. **UI rendering:** each screen renders loading skeleton, content list, empty
   placeholder, and error+retry, and fires `onQueryChange`, `onResultClick`,
   and `onRetry` callbacks with correct arguments.

## 4. Technical Design

### Test source sets & layout

```
feature-search/src/test/java/com/testlogon/android/feature/search/
  MessageSearchViewModelTest.kt        // JVM, Robolectric not required
feature-search/src/test/java/com/testlogon/android/feature/search/
  MessageSearchScreenTest.kt           // Robolectric (RobolectricTestRunner)
feature-contacts/src/test/java/com/testlogon/android/feature/contacts/
  ContactsViewModelTest.kt
  ContactsScreenTest.kt
core-data/src/test/java/com/testlogon/android/core/data/search/
  MessageSearchRepositoryTest.kt
  MessageSearchPagingSourceTest.kt
  ContactsRepositoryTest.kt
core-testing/src/main/java/com/testlogon/android/core/testing/
  MainDispatcherRule.kt
  MockWebServerExtensions.kt
  PagingTestExtensions.kt
  FakeSearchApi.kt
```

Compose UI tests run under **Robolectric** (`robolectric` + `createComposeRule`)
so they execute on the JVM in CI without an emulator; a parallel
`androidTest` smoke variant is allowed but not required for "Tests pass".

### Coroutine/time control

A reusable JUnit rule swaps the main dispatcher for a `TestDispatcher` and gives
tests virtual-time control over debounce:

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

Debounce is verified by advancing virtual time:

```kotlin
@Test
fun debounce_collapses_rapid_input_to_single_search() = runTest {
    val vm = MessageSearchViewModel(repo, savedState)
    vm.onQueryChanged("h"); vm.onQueryChanged("he"); vm.onQueryChanged("hello")
    advanceTimeBy(299); runCurrent()
    coVerify(exactly = 0) { repo.searchMessages(any(), any(), any()) }
    advanceTimeBy(1)
    coVerify(exactly = 1) { repo.searchMessages("hello", null, null) }
}
```

### Repository test doubles

`MockWebServer` backs Retrofit for end-to-end JSON parsing tests; MockK fakes the
repo where only ViewModel logic is under test. JSON fixtures live in
`core-testing/src/main/resources/fixtures/` and are enqueued via a helper:

```kotlin
fun MockWebServer.enqueueJson(@Language("JSON") body: String, code: Int = 200) =
    enqueue(MockResponse().setResponseCode(code)
        .setHeader("Content-Type", "application/json").setBody(body))
```

### Paging assertions

`PagingSource` is exercised directly with `PagingSource.LoadParams.Refresh` /
`.Append` and via Paging's `AsyncPagingDataDiffer` for `Flow<PagingData<T>>`
collection. A `collectDataForTest()` helper snapshots `PagingData` into a `List`.

## 5. API Contract

This ticket defines no new endpoints; it asserts conformance to the contracts
from AND-152/153. Tests pin the exact request/response shapes so a backend or
parser drift fails the build.

**Message search** — `GET /messaging/messages/search` (op
`search_messages_all_conversations_messaging_messages_search_get`). CORRECTED
query params (verified against OpenAPI): `q` (**required**, 1–200 chars),
`limit` (default 50, max 200), `sender_id` (was `sender`), `after_ts`
(**integer epoch ms/s**, was `after` ISO-8601), `kind` (repeatable string
array). **There is no `cursor` query param.** Note: the web reference app does
**not** call this endpoint anywhere (`grep messages/search src/` → no hits), so
its client-side usage is an Android-only contract derived from OpenAPI, not a
verified web behavior (see §16).

```
GET /messaging/messages/search?q=hello&sender_id=u_42&after_ts=1735689600&limit=20&kind=text
Cookies: session=...; ui_csrf=...
Authorization: Bearer <accessToken>      # web client sets this (client.ts)
X-CSRF-Token: <ui_csrf value>
```

CORRECTED 200 response — a **bare JSON array of `MessageOut`**, NOT an envelope
with `items`/`next_cursor`/`total` (verified: response schema is
`type: array, items: $ref MessageOut`). `MessageOut` carries `message_id`,
`conversation_id`, `sender_id`, `text`, and `created_at` (**integer** epoch).
There is no `sender_name`, `snippet`, or `sent_at` field. Fixture
`search_messages.json`:

```json
[
  {"message_id":"m_1","conversation_id":"c_9","sender_id":"u_42",
   "text":"hello there","created_at":1748779200}
]
```

**Contacts search** — `GET /messaging/contacts/search?q=ada&limit=10` (op
`search_contact_messaging_contacts_search_get`; web: `searchUsers()` in
`src/api/endpoints/messaging.ts`). CORRECTED 200 response — a **bare JSON array
of `Contact`** (`{user_id, display_name}`); the web client types it as
`UserSearchResult` = `{user_id, display_name}`. No `items` envelope, no
`handle`/`avatar_url`:

```json
[ {"user_id":"u_42","display_name":"Ada Lovelace"} ]
```

> Note: `GET /messaging/contacts/search` is the **message-user search** endpoint.
> The owned-contacts list is a separate resource — `GET /ui/contacts` returning
> `{contacts: ContactEntry[]}` (`ContactEntry` = `{owner_id, contact_id,
> display_name, is_favorite, is_blocked, added_at, profile_photo_url?}`). The
> tests target whichever the AND-153 `ContactsRepository` actually wraps; both
> shapes are pinned here so a parser drift fails the build.

**Error fixtures** assert FastAPI `detail` mapping in all three forms. The
array form matches the verified `HTTPValidationError`/`ValidationError` schema
(`{detail:[{loc:[str|int], msg, type}]}`); the string and object forms are both
handled by the web client's `normalizeErrorDetail()` (string passthrough; object
mapped via `mapAuthorizationError`/`msg`). VERIFIED against
`src/api/client.ts: normalizeErrorDetail`:

```json
{"detail":"Search temporarily unavailable"}
{"detail":[{"loc":["query","q"],"msg":"ensure this value has at least 1 character","type":"string_too_short"}]}
{"detail":{"code":"rate_limited","retry_after":5}}
```

> Note on the second form: the backend min length for `q` is **1** (not 2) for
> both search endpoints. A client-side 2-char min-length gate (§3.1) is an
> Android UX assumption owned by AND-155, not a backend constraint.

The 401-refresh path (`POST /ui/session/refresh` then single retry) is asserted
via an enqueued `401` followed by `200`, verifying exactly one refresh and one
replay of the original GET. VERIFIED against `src/api/client.ts` (`refreshSession`
POSTs `/ui/session/refresh`; on success the original request is re-fetched once;
a second 401 triggers logout and does not loop). Note the web client refreshes
on 401 only when already authenticated and refreshes are de-duplicated via a
shared `refreshPromise`.

## 6. Data & State Management

Tests assert the `UiState` contract produced by the ViewModels (defined in
AND-155). The canonical shape under test:

```kotlin
sealed interface SearchUiState {
    data object Idle : SearchUiState                     // query < minLen
    data object Loading : SearchUiState
    data class Content(val results: Flow<PagingData<MessageHit>>) : SearchUiState
    data object Empty : SearchUiState                    // 200 + empty array []
    data class Error(val message: String, val retryable: Boolean) : SearchUiState
}
```

> `MessageHit` is the app's domain model mapped from the backend `MessageOut`
> (`message_id`, `conversation_id`, `sender_id`, `text`, `created_at:Long`). It
> is NOT a wire DTO with `snippet`/`sender_name`/`sent_at` — those fields do not
> exist on `MessageOut` (verified). The mapper test asserts this projection.

State transitions verified: `Idle → Loading → Content`, `Idle → Loading → Empty`,
`Idle → Loading → Error`, and `Error → Loading` on retry. The `query` string is
held in `SavedStateHandle`; a test asserts it survives process-death simulation
by constructing a new ViewModel from the same handle and confirming the query and
resulting search are restored. Contacts uses an analogous `ContactsUiState` with
a non-paged `List<Contact>` (or paged if AND-155 paged contacts — the test
mirrors whichever the production type exposes). No Room/DataStore writes are
asserted here beyond confirming the repo's cache read path returns stale data
when offline (one test enqueues a network failure and asserts a cached page is
emitted with a `stale = true` flag if AND-155 exposes one).

## 7. Error Handling & Resilience

Tests cover the resilience requirements baked into the stack:

- **Timeout:** `MockWebServer` with `setBodyDelay(25, SECONDS)` against the
  configured ~20 s client timeout yields `ApiResult.Error` of `kind = Timeout`,
  mapped to a retryable `Error` UI state.
- **Bounded retry (idempotent GET only):** a test enqueues two `503` then `200`
  and asserts the search GET is retried within the bounded backoff and ultimately
  succeeds; a separate test asserts non-idempotent calls are **not** retried.
  ASSUMPTION (unverified): the web reference client (`src/api/client.ts`) does
  **not** implement any 503/timeout retry — it only refreshes once on 401. A
  bounded GET-retry + ~20 s timeout is an Android transport-layer design owned by
  the OkHttp stack (AND-15x networking ticket), not a web-verified contract.
  These tests only pass if that retry interceptor exists in the production app;
  otherwise the case is N/A. See §16.
- **401 refresh-once:** verified per §5 — exactly one `POST /ui/session/refresh`
  and one retry; a second consecutive 401 surfaces an auth `Error` and does not
  loop.
- **Cancellation safety:** superseded queries cancel cleanly without emitting
  their results (asserted by collecting emissions and confirming only the latest
  query's results appear).
- **Parse failure:** malformed JSON yields a typed error, never a crash.

## 8. Security & Privacy

No production security surface changes. Test-specific requirements: fixtures must
contain only synthetic data (no real users/credentials/cookies). Tests assert
that the `X-CSRF-Token` header is populated from the `ui_csrf` cookie on every
search request (read from `RecordedRequest.getHeader("X-CSRF-Token")`), ensuring
the CSRF contract is not silently dropped. VERIFIED: `src/api/client.ts` reads
the `ui_csrf` cookie and sets `X-CSRF-Token` on every request, and additionally
sets `Authorization: Bearer <accessToken>` from the auth store and
`X-IMPERSONATION-TOKEN` when impersonating — a parallel test asserts the Android
client likewise attaches its bearer token to search requests. Tests must not log cookie values; the
persistent cookie jar used in tests is an in-memory test double, never written to
disk. No plaintext production host is contacted from any test.

## 9. Accessibility & i18n

UI tests assert accessibility affordances on the search/contacts screens:

- Each result row, the search field, and the retry button expose a non-empty
  content description / semantics label, asserted via
  `onNodeWithContentDescription` / `assertHasClickAction`.
- The empty and error placeholders expose readable text nodes (asserted by
  resource id, not hardcoded English literals, so localization is honored).
- All user-facing strings are resolved from `stringResource` (test asserts the
  rendered node text equals `context.getString(R.string.…)`), guaranteeing no
  hardcoded copy slipped into the production screens.

## 10. Telemetry & Logging

This ticket adds no telemetry. If AND-152/153/155 emit analytics events
(e.g., `search_performed`, `contact_opened`), a test injects a fake analytics
sink and asserts the event is logged once per committed (post-debounce) search
with the query length bucket but **not** the raw query string (privacy). If no
analytics interface exists in the production code, this section is N/A and owned
by the future analytics ticket; the test suite simply does not assert it.

## 11. Testing Strategy

This is the testing deliverable itself. Required test cases:

**Repository (`core-data`, JVM + MockWebServer):**
- `searchMessages` parses the bare `MessageOut[]` array, sends
  `q/sender_id/after_ts/limit/kind` query params (CORRECTED — no `cursor`), and
  sets the `X-CSRF-Token` + `Authorization` headers.
- `searchMessages` empty array `[]` → repo returns empty page.
- `searchMessages` 503×2 then 200 → bounded retry succeeds.
- `searchMessages` 401 then 200 → one refresh, one retry.
- `searchContacts` parses list; sends `q`.
- Timeout → `ApiResult.Error(Timeout)`.
- All three `detail` shapes map to expected messages.

**PagingSource (`core-data`):** (CORRECTED — backend returns a bare array with no
cursor; assertions reflect single-page loading)
- `load(Refresh)` returns the full array as one page with `prevKey == null` and
  `nextKey == null` (no server cursor exists).
- Transport error → `LoadResult.Error`.
- `AsyncPagingDataDiffer` snapshot of `Flow<PagingData>` equals expected list.
- (If AND-152/155 implement client-side windowing via `limit`+`after_ts`, an
  additional `load(Append)` case asserts the next window is fetched with the
  correct `after_ts`; this is conditional on that production behavior existing —
  see §16. The prior `next_cursor`-based append assertion is removed because no
  `next_cursor`/`cursor` field exists on the wire.)

**ViewModel (`feature-*`, virtual time):**
- Debounce collapse; min-length gate; distinct-until-changed; cancellation
  (last-write-wins); SavedStateHandle restore; retry transitions.

**Compose UI (Robolectric, `createComposeRule`):**
- `MessageSearchScreen`: loading skeleton shown; content list shows N rows;
  empty placeholder; error + retry click fires `onRetry`; typing fires
  `onQueryChange`; row click fires `onResultClick(messageId)`; a11y labels present.
- `ContactsScreen`: analogous content/empty/error + `onContactClick(userId)`.

**Coverage target:** ≥ 80% line coverage on the search/contacts production
packages (advisory, enforced via Jacoco report; build does not fail on coverage
but the report is published). Flakiness budget: zero — virtual time and
`MockWebServer` eliminate real delays. Run command:
`./gradlew :feature-search:testDebugUnitTest :feature-contacts:testDebugUnitTest
:core-data:testDebugUnitTest`.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-155 (ViewModels + paging) must be merged; transitively
  AND-152 and AND-153. This ticket cannot compile before those land.
- **Test libs (add to version catalog / `core-testing`):** `junit:4.13.2`,
  `org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.x`, `io.mockk:mockk:1.13.x`,
  `com.squareup.okhttp3:mockwebserver:4.12.0`, `app.cash.turbine:turbine:1.x`
  (Flow assertions), `androidx.paging:paging-testing:3.3.x`,
  `org.robolectric:robolectric:4.13`, `androidx.compose.ui:ui-test-junit4`,
  `androidx.compose.ui:ui-test-manifest`, `androidx.arch.core:core-testing`.
- **Sequencing:** lands after AND-155; **blocks** nothing functional but is a
  gate for the M3 release sign-off (search/contacts cannot be marked Done without
  a green suite). CI must add the three `testDebugUnitTest` tasks to the PR check.

## 13. Risks & Open Questions

- **Production type drift:** exact `UiState`/`PagingData` types are owned by
  AND-155; if their shapes differ from §6, tests mirror the production types (the
  signatures here are the expected contract, to be reconciled at integration).
- **Contacts paging:** unclear whether AND-155 paged contacts or returns a flat
  list. Open question for AND-155 owner; the suite adapts to whichever is shipped.
- **Robolectric vs. instrumented:** Compose UI tests run on Robolectric for CI
  speed; if a Compose+Robolectric incompatibility appears on AGP 8.7.3, fall back
  to `androidTest` on an emulator runner (slower CI but unblocks "Tests pass").
- **Stale/offline flag:** the `stale` cache flag (§6) is only testable if AND-155
  exposes it; otherwise that single test is dropped.
- **Debounce window value:** assumed 300 ms / min-length 2; confirm against
  AND-155 constants and reference them rather than hardcoding.

## 14. Acceptance Criteria

1. `./gradlew :feature-search:testDebugUnitTest :feature-contacts:testDebugUnitTest
   :core-data:testDebugUnitTest` passes locally and in CI with zero failures and
   zero flakes across 3 consecutive runs.
2. All test cases enumerated in §11 exist and assert real behavior (no
   `@Ignore`, no assertion-free tests; reviewed for meaningful assertions).
3. Debounce, min-length gate, distinct-until-changed, cancellation/last-write-wins,
   empty-state, error-state, and SavedStateHandle-restore are each covered by at
   least one passing ViewModel test.
4. PagingSource refresh/append/error and a `Flow<PagingData>` snapshot are covered
   and pass.
5. Repository tests verify request params, `X-CSRF-Token` header, all three
   FastAPI `detail` mappings, timeout, bounded GET retry, and 401-refresh-once.
6. Compose UI tests for both screens cover loading/content/empty/error+retry and
   the `onQueryChange`/`onResultClick`/`onContactClick`/`onRetry` callbacks, plus
   a11y label presence, and pass.
7. No test contacts the live dev host `18.222.237.167`; all network is mocked.
8. Jacoco coverage report is produced for the search/contacts packages (≥ 80%
   advisory).

## 15. Definition of Done

- All §14 criteria met; suite green on the `android-port` branch CI.
- New test dependencies added to the Gradle version catalog; `core-testing`
  exposes the shared rules/helpers (`MainDispatcherRule`,
  `enqueueJson`, paging/turbine extensions, `FakeSearchApi`).
- CI PR check updated to run the three unit-test tasks; build fails on test
  failure.
- Fixtures committed under `core-testing/src/main/resources/fixtures/` with
  synthetic-only data.
- No production code changed (or, if a minimal testability hook was unavoidable —
  e.g., exposing a constructor-injected dispatcher — it is documented in the PR
  and approved by the AND-155 owner).
- Code reviewed and merged; M3 search/contacts features can be signed off as
  regression-protected.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Message search endpoint is `GET /messaging/messages/search`.** VERIFIED.
   OpenAPI `GET /messaging/messages/search`
   (op `search_messages_all_conversations_messaging_messages_search_get`).
2. **Message search query params are `q,sender_id,after_ts,limit,kind`.** CORRECTED
   (was `q,sender,after(ISO),limit,cursor`). OpenAPI `GET /messaging/messages/search`
   params: `q` (required, 1–200), `limit` (default 50, max 200), `sender_id`,
   `after_ts` (integer epoch), `kind` (string array). No `cursor` param exists.
3. **Message search 200 body is a bare `MessageOut[]` array (no
   `items`/`next_cursor`/`total`).** CORRECTED (was an envelope with
   `items/next_cursor/total`). OpenAPI `GET /messaging/messages/search`
   `responses.200` → `{type: array, items: $ref MessageOut}`.
4. **`MessageOut` fields used by the suite: `message_id`, `conversation_id`,
   `sender_id`, `text`, `created_at` (integer epoch).** CORRECTED (spec previously
   used `sender_name`, `snippet`, `sent_at` which do not exist). Schema
   `components.schemas.MessageOut` (`created_at` is `type: integer`).
5. **Contacts search endpoint is `GET /messaging/contacts/search` with `q` (req,
   1–64) and `limit` (default 10, max 50).** VERIFIED. OpenAPI
   `GET /messaging/contacts/search`
   (op `search_contact_messaging_contacts_search_get`); web call
   `src/api/endpoints/messaging.ts: searchUsers` (`api.get(.../contacts/search, {q, limit})`).
6. **Contacts search 200 body is a bare array of `Contact`
   (`{user_id, display_name}`).** CORRECTED (was `{items:[{...handle, avatar_url}]}`).
   OpenAPI response `{type: array, items: $ref Contact}`; schema
   `components.schemas.Contact` = `{user_id, display_name}`; web DTO
   `src/api/types.ts: UserSearchResult` = `{user_id, display_name}`.
7. **Owned-contacts list (distinct from search) is `GET /ui/contacts` returning
   `{contacts: ContactEntry[]}`.** VERIFIED. `src/api/endpoints/contacts.ts:
   getContacts`; schema `components.schemas.ContactEntry`
   (`owner_id, contact_id, display_name, is_favorite, is_blocked, added_at,
   profile_photo_url?`).
8. **CSRF: `X-CSRF-Token` header is set from the `ui_csrf` cookie on every
   request.** VERIFIED. `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).
9. **Auth: client also sends `Authorization: Bearer <accessToken>` (and
   `X-IMPERSONATION-TOKEN` when impersonating).** VERIFIED (added; spec had only
   mentioned cookies/CSRF). `src/api/client.ts`. OpenAPI search ops also expose
   `authorization` + `X-SESSION-ID` headers.
10. **401 → single `POST /ui/session/refresh` then one replay of the original
    request; second consecutive 401 logs out and does not loop.** VERIFIED.
    `src/api/client.ts` (`refreshSession` POSTs `/ui/session/refresh`; retry once;
    on retry 401 → `logout("session_expired")`); OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`).
11. **FastAPI `detail` shapes (string, array-of-`{loc,msg,type}`, object) all map
    to user messages.** VERIFIED. Array form matches schemas
    `HTTPValidationError`/`ValidationError` (`{loc:[str|int], msg, type}`); all
    three handled by `src/api/client.ts: normalizeErrorDetail`
    (+ `mapAuthorizationError` for object `code`s).
12. **Backend min length for `q` is 1 (both endpoints), not 2.** VERIFIED/CORRECTED
    fixture text. OpenAPI param `q` `minLength: 1`. The 2-char min-length gate is
    an Android UX rule (see assumption below), not a backend constraint.
13. **Robolectric + `createComposeRule` runs Compose UI tests on the JVM.**
    VERIFIED (framework ref): https://robolectric.org/ and
    https://developer.android.com/develop/ui/compose/testing.
14. **Paging 3 `PagingSource`/`AsyncPagingDataDiffer`/`paging-testing` APIs.**
    VERIFIED (framework ref):
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data
    and https://developer.android.com/reference/kotlin/androidx/paging/testing/package-summary.
15. **`kotlinx-coroutines-test` virtual time (`StandardTestDispatcher`,
    `advanceTimeBy`, `runTest`) drives debounce.** VERIFIED (framework ref):
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/.
16. **OkHttp `MockWebServer` for contract tests.** VERIFIED (framework ref):
    https://square.github.io/okhttp/features/https/ and
    https://github.com/square/okhttp/tree/master/mockwebserver.

### Corrections made

- §3.4 / §5 / §6 / §11 / §17: removed the cursor-pagination premise. The message
  search response is a **bare `MessageOut[]` array** with no `cursor` param and no
  `next_cursor`/`total` body fields; `PagingSource` is asserted as single-page.
- §5 query params: `sender`→`sender_id`, `after`(ISO)→`after_ts`(integer epoch),
  dropped `cursor`, added `kind`; marked `q` required (1–200).
- §5 message fields: dropped non-existent `sender_name`/`snippet`/`sent_at`;
  message body field is `text`, timestamp is `created_at` (integer epoch).
- §5 / §3.7: contacts search returns a **bare `Contact[]` array**
  (`{user_id, display_name}`), not an `{items:[{handle, avatar_url}]}` envelope;
  added `limit` param; clarified `/ui/contacts` is the separate owned-list.
- §5 / §3.5 / §6: "empty `items: []`" → "empty array `[]`".
- §5 fixture: validation `msg`/`type` and min-length corrected to backend reality
  (min length 1, `string_too_short`).
- §8: added that the web client attaches `Authorization: Bearer` (+ impersonation
  header), not only the CSRF cookie.

### Open assumptions

- **Client-side windowing/append.** The backend exposes no pagination cursor, so
  any multi-page message-search behavior would be an Android client construct
  (windowing via `limit`+`after_ts`). Unverifiable from the sources because the
  web app does not call `/messaging/messages/search` at all and AND-152/155 are
  not yet merged. Tests mirror the shipped `PagingSource`; the append case is
  conditional.
- **Bounded 503/timeout retry + ~20 s client timeout (§7).** The web client
  (`src/api/client.ts`) implements **no** 503/timeout retry — only 401 refresh.
  This is an Android transport-layer (OkHttp interceptor) assumption owned by the
  networking ticket; tests pass only if that interceptor exists.
- **Debounce 300 ms / min-length 2 (§3.1).** Not in the backend (min length is 1)
  or the web client; these are AND-155 ViewModel constants to be referenced, not
  hardcoded. Unverifiable until AND-155 lands.
- **`stale`/offline cache flag (§6) and analytics events (§10).** Only assertable
  if AND-155/152/153 expose them; not present in the reference sources.
- **`UiState`/`MessageHit` domain shapes (§6).** Owned by AND-155; the signatures
  here are the expected contract, reconciled at integration.
- **Contacts paged vs. flat list.** Backend returns a flat array; whether AND-155
  wraps contacts in Paging is an open question. The suite adapts.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric, local (no device); **CW** =
contract test on JVM with OkHttp `MockWebServer`; **Robolectric-UI** = Compose UI
on JVM via `createComposeRule`; **emu(test35)** = headless AVD API 35 x86_64;
**device(SM-A156U)** = physical Samsung Galaxy A15 5G, API 34 arm64
(serial R5CX821TA9R). No test ever contacts the live host `18.222.237.167`.

- **TC-AND-156-01 — Debounce collapses rapid input (happy path).**
  Type: unit (JVM, virtual time). Target: `MessageSearchViewModel`.
  Preconditions: `MainDispatcherRule` with `StandardTestDispatcher`; MockK repo.
  Steps: call `onQueryChanged("h"/"he"/"hello")`; `advanceTimeBy(debounceMs-1)`;
  assert 0 repo calls; `advanceTimeBy(1)`. Expected: exactly one
  `repo.searchMessages("hello", …)` invocation. Traces: AC-3.
- **TC-AND-156-02 — Min-length gate & distinct-until-changed.**
  Type: unit (JVM). Target: `MessageSearchViewModel`. Preconditions: as 01.
  Steps: (a) type a sub-min query → assert state `Idle`, 0 repo calls; (b) type
  "ab" then "ab" again past debounce → assert exactly one search. Expected: no
  network for too-short input; repeated identical value does not re-trigger.
  Traces: AC-3.
- **TC-AND-156-03 — Cancellation / last-write-wins.**
  Type: unit (JVM, virtual time). Target: `MessageSearchViewModel`.
  Preconditions: repo with a suspendable/controllable first response.
  Steps: issue "old" (in flight), then "new"; complete both; collect emissions
  via Turbine. Expected: only "new" results surface; the superseded "old" search
  is cancelled and never overwrites state. Traces: AC-3.
- **TC-AND-156-04 — SavedStateHandle restore (process death).**
  Type: unit (JVM). Target: `MessageSearchViewModel` + `SavedStateHandle`.
  Steps: set query, let search commit; construct a new ViewModel from the same
  handle. Expected: query restored and the search re-runs/results restored.
  Traces: AC-3.
- **TC-AND-156-05 — Error→Loading on retry.**
  Type: unit (JVM). Target: `MessageSearchViewModel`. Steps: drive repo to error
  → assert `Error(retryable=true)`; call `onRetry()`. Expected:
  `Error → Loading → Content/Empty`. Traces: AC-3, AC-6.
- **TC-AND-156-06 — `searchMessages` request shape & headers (contract).**
  Type: contract/MockWebServer (CW). Target: `MessageSearchRepository` + Retrofit
  service. Preconditions: MockWebServer enqueues fixture `search_messages.json`
  (bare `MessageOut[]`); cookie jar has `ui_csrf`; auth store has a bearer token.
  Steps: call `searchMessages(q="hello", senderId="u_42", afterTs=1735689600,
  limit=20)`; read `RecordedRequest`. Expected: path `/messaging/messages/search`,
  query `q=hello&sender_id=u_42&after_ts=1735689600&limit=20` (NO `cursor`),
  header `X-CSRF-Token` == cookie value, `Authorization: Bearer …` present;
  parsed list maps `message_id/conversation_id/sender_id/text/created_at(Long)`.
  Traces: AC-5.
- **TC-AND-156-07 — Empty result → `Empty` state (validation/edge).**
  Type: contract/MockWebServer (CW). Target: `MessageSearchRepository` →
  ViewModel. Steps: enqueue `200` with body `[]`. Expected: repo returns an empty
  page; ViewModel emits `Empty` (distinct from `Idle`/`Error`). Traces: AC-3, AC-6.
- **TC-AND-156-08 — FastAPI `detail` mapping, all three forms + parse failure.**
  Type: contract/MockWebServer (CW). Target: repo error mapper.
  Steps: enqueue in turn `{"detail":"…"}` (500/503), the 422
  `{"detail":[{loc,msg,type}]}`, the object `{"detail":{"code":"rate_limited",
  "retry_after":5}}`, and a malformed-JSON body. Expected: each maps to a typed
  `ApiResult.Error` with the user-facing message derived per
  `normalizeErrorDetail`; malformed JSON yields a typed parse error, never a
  crash. Traces: AC-5.
- **TC-AND-156-09 — Timeout → `ApiResult.Error(Timeout)`.**
  Type: contract/MockWebServer (CW). Target: repo/transport. Preconditions:
  `MockResponse().setBodyDelay(25, SECONDS)` against the ~20 s client timeout.
  Steps: call `searchMessages`. Expected: `ApiResult.Error(kind=Timeout)` mapped
  to a retryable `Error` UI state. (Assumption: ~20 s timeout configured — see
  §16; skip if not.) Traces: AC-5.
- **TC-AND-156-10 — Bounded GET retry (503×2 → 200) and no-retry for writes.**
  Type: contract/MockWebServer (CW). Target: OkHttp retry interceptor + repo.
  Steps: enqueue `503,503,200`; call the idempotent search GET; separately assert
  a non-idempotent call is not retried. Expected: GET retried within bounded
  backoff and ultimately succeeds; writes not retried. (Conditional on the retry
  interceptor existing — §16.) Traces: AC-5.
- **TC-AND-156-11 — 401 refresh-once then replay.**
  Type: contract/MockWebServer (CW). Target: auth interceptor + repo.
  Steps: enqueue `401` then `200` for the search GET; assert exactly one
  `POST /ui/session/refresh` and exactly one replay of the original GET; then a
  second test enqueues `401,401` and asserts auth `Error` with no loop.
  Expected: single refresh + single replay; consecutive 401 surfaces auth error.
  Traces: AC-5.
- **TC-AND-156-12 — `searchContacts` request & bare-array parse (contract).**
  Type: contract/MockWebServer (CW). Target: `ContactsRepository`.
  Steps: enqueue `[{"user_id":"u_42","display_name":"Ada Lovelace"}]`; call
  `searchContacts(q="ada")`; read `RecordedRequest`. Expected: path
  `/messaging/contacts/search`, query contains `q=ada` (and `limit` if sent);
  parsed list = one `Contact(user_id="u_42", display_name="Ada Lovelace")`; no
  `handle`/`avatar_url` expected. Traces: AC-5.
- **TC-AND-156-13 — `PagingSource` single-page refresh & error.**
  Type: unit (JVM) + `paging-testing`. Target: message-search `PagingSource`.
  Steps: (a) MockWebServer returns a fixture array → `load(Refresh)` returns one
  page with `prevKey==null`, `nextKey==null`; (b) transport failure →
  `LoadResult.Error`; (c) `AsyncPagingDataDiffer` snapshot of
  `Flow<PagingData>` equals the expected list. Expected: as stated. Traces: AC-4.
- **TC-AND-156-14 — `MessageSearchScreen` states & callbacks + a11y.**
  Type: Compose-UI (Robolectric-UI). Target: `MessageSearchScreen`.
  Steps: render loading (skeleton shown), content (N rows), empty placeholder,
  error+retry; type text → assert `onQueryChange` fired; click a row → assert
  `onResultClick(messageId)`; click retry → `onRetry`; assert each row, the
  search field, and the retry button expose non-empty content
  description/semantics, and placeholder/error text comes from
  `stringResource` (`assertTextEquals(context.getString(R.string.…))`, not
  hardcoded literals). Expected: all states/callbacks/a11y assertions pass.
  Traces: AC-6.
- **TC-AND-156-15 — `ContactsScreen` states, `onContactClick`, a11y.**
  Type: Compose-UI (Robolectric-UI). Target: `ContactsScreen`. Steps: render
  content/empty/error+retry; click a contact → assert `onContactClick(userId)`;
  assert a11y labels and localized (resource-resolved) text. Expected: pass.
  Traces: AC-6.
- **TC-AND-156-16 — No live-host egress (security).**
  Type: integration (JVM/CI). Target: full test classpath. Steps: run the suite
  with a network guard (deny socket connections to `18.222.237.167` / any
  non-loopback host). Expected: zero connections to the dev host; all traffic
  hits `MockWebServer` on loopback. Traces: AC-7.
- **TC-AND-156-17 — CSRF/cookie not leaked to logs; in-memory cookie jar
  (security/privacy).** Type: unit (JVM). Target: test cookie jar + log capture.
  Steps: run a search; capture logs; assert no `ui_csrf`/`session` value appears
  and the cookie jar is never written to disk. Expected: no secret material in
  logs; jar is the in-memory test double. Traces: AC-7 (supports §8).
- **TC-AND-156-18 — Real-device instrumented smoke (offline/flaky-host path).**
  Type: instrumented/e2e — **MUST run on device(SM-A156U)** (arm64, API 34) to
  validate ABI/API-level behavior vs the emulator. Steps: install the debug APK;
  with airplane mode ON, open search, type a query. Expected: the offline/error
  state renders with a working retry (no crash, no live-host hit); on restoring a
  pointed-at `MockWebServer`, retry succeeds. Rationale for device: API-34/arm64
  differs from AVD `test35` (API-35/x86_64); offline transport + Compose render
  on real hardware. Traces: AC-1, AC-6, AC-7.

> CI default: TC-01–17 run on **JVM** (`testDebugUnitTest`) — no device needed,
> satisfying AC-1's "Tests pass" gate. If a Compose+Robolectric incompatibility
> appears on AGP 8.7.3, TC-14/15 fall back to **emu(test35)** as `androidTest`.
> TC-18 is the only physical-device case.

### Coverage matrix (AC → TC)

| §14 AC | Covered by |
| --- | --- |
| AC-1 (suite green, no flakes) | TC-01…TC-18 (whole suite); device smoke TC-18 |
| AC-2 (cases exist, real assertions) | TC-01…TC-17 (each asserts behavior) |
| AC-3 (debounce/min-len/distinct/cancel/empty/error/restore) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-07 |
| AC-4 (PagingSource refresh/error + snapshot) | TC-13 |
| AC-5 (request params, CSRF header, 3 detail maps, timeout, retry, 401-once) | TC-06, TC-08, TC-09, TC-10, TC-11, TC-12 |
| AC-6 (Compose states/callbacks + a11y) | TC-05, TC-14, TC-15, TC-18 |
| AC-7 (no live-host; all mocked) | TC-16, TC-17, TC-18 |
| AC-8 (Jacoco ≥80% advisory) | Emergent from TC-01…TC-15 coverage; report published in CI |
