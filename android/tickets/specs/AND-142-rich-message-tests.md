---
id: AND-142
title: Rich message tests
milestone: M3
epic: E19
priority: P1
size: M
status: draft
depends_on: [AND-130, AND-140]
blocks: []
---

# AND-142 — Rich message tests

## 1. Overview & Goal

AND-142 delivers the automated test coverage for the "rich message" surface of
the TestLogon Android port: the non-plain-text message types that combine a
binary upload step, a typed render in the thread, and one or more post-send
actions. The feature work itself lands in AND-130 (image messages: presign +
upload + thumbnail + full-screen viewer) and AND-140 (reactions, pins, edits,
delete/revoke, hide). This ticket does **not** add product behavior; it makes
that behavior verifiable and keeps it verifiable in CI.

The goal is a deterministic, headless test suite that proves, end to end within
the app boundary, that for each key rich-message type the **upload** path
produces a correctly-shaped request, the **render** path maps the API DTO to the
right Compose UI, and the **actions** (react / pin / edit / delete / revoke /
hide, plus image open/view) mutate thread state and persist. "Tests pass
headlessly" is the literal acceptance bar: the entire suite must run on the JVM
(Robolectric / unit) or on a headless emulator (instrumented) with no manual
interaction, no real network, and no flake, gating the `android-port` branch.

Out of scope: implementing the message types themselves; tips/paid/unlockable
(AND-139) and calendar event/share (AND-138) message types — those ship their
own tests with their own tickets. This ticket owns image messages and the
AND-140 action set only.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base `com.testlogon.android`.
- Module layering: `app -> feature-* -> core-*`. Rich-message UI lives in
  `feature-messaging`; DTOs and domain models in `core-model`; Retrofit
  services + cookie/CSRF plumbing in `core-network`; Room cache + repositories
  in `core-data`; shared test fixtures in `core-testing`.
- Upstream specs: **AND-130** (`/messages/image`, `images/presign`, pick/capture,
  compress, thumbnail, viewer) and **AND-140** (reactions(+details),
  pin/unpin(+pins list), edits history, delete/revoke, hide).
- Web reference for request/response shapes: `frontend/src/api/endpoints/*.ts`
  and `frontend/src/api/types.ts`; backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json`. The dev backend is **not** used by
  this suite (it is plaintext and unreliable); all HTTP is mocked.
- Stack baseline: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, Media3
  1.4, Paging 3. minSdk 24, compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.

## 3. Functional Requirements

This ticket's "functional requirements" are the behaviors the suite must assert.

FR-1 **Image upload request shape.** Sending an image must (a) call
`POST /messages/images/presign` with the declared `content_type` and
`byte_size`, (b) PUT the (compressed) bytes to the returned `upload_url`, and
(c) call `POST /messages/image` with the `upload_id`/`key`, `thread_id`,
optional `caption`, and generated `width`/`height`/`thumbnail`. Tests assert the
exact JSON body and header set of each call and the ordering.

FR-2 **Image compression & thumbnail.** Given a known input bitmap, the
compressor must emit JPEG/WEBP under the configured max dimension and quality,
and a thumbnail under the thumbnail dimension. Tests assert output dimensions,
mime, and that compressed `byte_size` matches the value sent in presign.

FR-3 **Image render & viewer.** An `ImageMessage` DTO must render a thumbnail
node in the thread; tapping it opens the full-screen viewer; back/dismiss
returns. Tests assert the thumbnail Coil model URL, the viewer route argument,
and that a `loading`/`error`/`loaded` viewer state is reflected.

FR-4 **Action: reactions.** Adding/removing a reaction calls the correct
endpoint, optimistically updates the message's reaction summary in the thread
`StateFlow`, and persists to Room; reaction details load on demand. Tests assert
optimistic update, server confirmation reconciliation, and rollback on error.

FR-5 **Action: pin/unpin.** Pin/unpin toggles message `is_pinned`, updates the
thread's pins list, and persists. Tests assert thread state + pins list + Room.

FR-6 **Action: edit (+history).** Editing replaces body, sets `edited_at`, and
appends an edit-history entry. Tests assert the new body in state, the history
entry, and persistence.

FR-7 **Action: delete / revoke / hide.** Delete removes the message (or marks
tombstone), revoke marks it revoked for all, hide marks it hidden locally only.
Tests assert each distinct end state in the thread `StateFlow` and Room, and
that hide is not sent to the server.

FR-8 **Headless determinism.** Every test runs with `StandardTestDispatcher` /
`runTest`, MockWebServer, an in-memory Room DB, and a fake clock; no test
touches the network, the real filesystem outside a temp dir, or wall-clock time.

## 4. Technical Design

### Test tiers

The suite spans three tiers, each with a defined home:

1. **Unit (JVM, `test/`)** — repositories, mappers, the image compressor,
   ViewModels. Use `kotlinx-coroutines-test` `runTest`, `MainDispatcherRule`,
   Turbine for `StateFlow`, MockWebServer for the Retrofit services, and an
   in-memory Room DB via `Room.inMemoryDatabaseBuilder`. Bitmap-dependent
   compressor tests use Robolectric (`@RunWith(RobolectricTestRunner::class)`,
   `@Config(sdk = [34])`).
2. **Compose UI (Robolectric, `test/`)** — render and tap behavior for
   thumbnail/viewer and the action menu, using `createComposeRule()` under
   Robolectric so they run on the JVM headlessly. No emulator required.
3. **Instrumented (`androidTest/`, headless emulator)** — a thin smoke layer
   for Coil image loading and Media3-free image viewer navigation that cannot be
   faithfully Robolectric'd. Kept minimal; runs on a headless AVD in CI.

### Shared fixtures (in `core-testing`)

```kotlin
object RichMessageFixtures {
    fun imageMessage(id: String = "m_img_1", caption: String? = null): MessageDto
    fun reaction(emoji: String = "👍", count: Int = 1, byMe: Boolean = false): ReactionDto
    fun presignResponse(uploadId: String = "up_1"): PresignResponseDto
    fun editHistory(vararg bodies: String): List<EditHistoryEntryDto>
    val SAMPLE_BITMAP_4000x3000: Bitmap            // Robolectric-backed
}

class MainDispatcherRule(
    private val dispatcher: TestDispatcher = StandardTestDispatcher()
) : TestWatcher() { /* sets/resets Dispatchers.Main */ }

fun mockMessagingApi(server: MockWebServer): MessagingApi   // Retrofit + Moshi wired to server.url("/")

fun inMemoryDb(): TestLogonDatabase =
    Room.inMemoryDatabaseBuilder(ctx, TestLogonDatabase::class.java)
        .allowMainThreadQueries().build()
```

A `FakeClock : Clock` and a `RecordingCookieJar` (verifies the persistent jar +
`X-CSRF-Token` echo without real persistence) are reused across tiers.

### Representative test classes

```kotlin
class ImageUploadRepositoryTest {              // FR-1, FR-2
    @get:Rule val main = MainDispatcherRule()
    private val server = MockWebServer()

    @Test fun presign_then_put_then_send_in_order()
    @Test fun presign_body_carries_content_type_and_byte_size()
    @Test fun send_image_body_includes_dimensions_and_thumbnail()
}

class ImageCompressorTest {                     // FR-2 (Robolectric)
    @Test fun downscales_to_max_dimension_preserving_aspect()
    @Test fun thumbnail_under_thumb_dimension()
    @Test fun reported_byte_size_matches_presign_input()
}

class MessageActionsViewModelTest {             // FR-4..FR-7
    @get:Rule val main = MainDispatcherRule()

    @Test fun addReaction_optimistic_then_confirmed() = runTest {
        vm.uiState.test {
            awaitItem()                          // initial
            vm.addReaction("m1", "👍")
            assertThat(awaitItem().message("m1").myReaction).isEqualTo("👍")  // optimistic
            // server 200 -> reconciled (no rollback)
            expectNoEvents()
        }
    }
    @Test fun addReaction_rolls_back_on_error()
    @Test fun pin_updates_thread_and_pins_list_and_room()
    @Test fun edit_appends_history_and_sets_edited_at()
    @Test fun delete_revoke_hide_reach_distinct_end_states()
    @Test fun hide_is_local_only_no_network_call()
}

class ImageMessageRenderTest {                   // FR-3 (Robolectric Compose)
    @get:Rule val compose = createComposeRule()
    @Test fun thumbnail_renders_and_tap_navigates_to_viewer()
    @Test fun viewer_shows_loading_then_loaded_then_dismiss()
}
```

ViewModels under test expose `StateFlow<MessagingUiState>`; tests assert on
emitted immutable snapshots. Persistence assertions read back through the DAO on
the in-memory DB after the coroutine settles (`advanceUntilIdle()`).

## 5. API Contract

This ticket asserts against, but does not define, the following contracts (owned
by AND-130 / AND-140). Tests pin these shapes via MockWebServer fixtures so a
backend or client drift breaks the build.

Presign (AND-130):
```
POST /messages/images/presign
{ "content_type": "image/jpeg", "byte_size": 184320 }
-> 200 { "upload_id": "up_1", "upload_url": "https://s3.../put", "key": "img/up_1.jpg",
         "headers": { "Content-Type": "image/jpeg" } }
```
Binary PUT: `PUT {upload_url}` with body = compressed bytes, `Content-Type`
header from `headers`. Asserted: method, URL, content-type, body length.

Send image (AND-130):
```
POST /messages/image
{ "thread_id": "t1", "upload_id": "up_1", "key": "img/up_1.jpg",
  "caption": "hi", "width": 1600, "height": 1200,
  "thumbnail": { "key": "img/up_1_thumb.jpg", "width": 320, "height": 240 } }
-> 201 MessageDto(type="image", media={url,thumbnail_url,width,height}, ...)
```

Actions (AND-140), all asserted for body + the `X-CSRF-Token` header:
```
POST   /messages/{id}/reactions        { "emoji": "👍" }     -> 200 ReactionSummaryDto
DELETE /messages/{id}/reactions/{emoji}                      -> 204
GET    /messages/{id}/reactions                              -> 200 { "items": [ReactionDetailDto] }
POST   /messages/{id}/pin                                    -> 200 MessageDto
DELETE /messages/{id}/pin                                    -> 200 MessageDto
GET    /threads/{tid}/pins                                   -> 200 { "items": [MessageDto] }
PATCH  /messages/{id}            { "body": "edited" }        -> 200 MessageDto(edited_at, ...)
GET    /messages/{id}/edits                                  -> 200 { "items": [EditHistoryEntryDto] }
DELETE /messages/{id}                                        -> 204
POST   /messages/{id}/revoke                                 -> 200 MessageDto(revoked=true)
```
`hide` has **no** endpoint; a test asserts `server.requestCount` does not
increase when hiding. Error fixtures use FastAPI `detail` in all three shapes
(string | `[{msg}]` | `{code,...}`) to verify the mapper feeds `ApiResult.Error`
and triggers rollback.

## 6. Data & State Management

Tests exercise the real `core-data` layer against an in-memory `TestLogonDatabase`.

- **Thread state:** `MessagingUiState(messages: List<MessageUi>, pins: List<MessageUi>, viewer: ViewerState)` exposed as `StateFlow`. Action tests assert
  on the post-mutation snapshot and, for optimistic actions, on the intermediate
  snapshot via Turbine.
- **Persistence:** after each action, the DAO is queried directly:
  `messageDao.getById("m1")`, `reactionDao.forMessage("m1")`,
  `messageDao.pinsForThread("t1")`, `editHistoryDao.forMessage("m1")`. Hide sets
  a local `hidden=true` column; delete writes a tombstone or removes per the
  AND-140 design; revoke sets `revoked=true`. Each is asserted distinctly.
- **Optimistic/reconcile:** the repository applies the mutation to Room and emits
  immediately, then patches with the server DTO on success or restores the
  captured prior row on failure. Tests assert both branches, including that a
  failed reaction leaves Room byte-identical to the pre-call snapshot.
- **No DataStore writes** are exercised here; cookie/CSRF persistence is verified
  via `RecordingCookieJar` rather than the real DataStore-backed jar.
- **Paging:** thread paging is not re-tested here (owned by the thread ticket);
  action tests operate on a pre-seeded in-memory page.

## 7. Error Handling & Resilience

The suite is itself the resilience guarantee for this surface, and asserts the
app's error behavior:

- **Upload failures:** presign 500, PUT 403 (expired URL), and send-image 422
  each map to `ApiResult.Error` with the FastAPI `detail` reason surfaced; no
  partial message is left in Room. A presign success followed by PUT failure must
  **not** call `POST /messages/image`.
- **Action failures:** every optimistic action rolls back to the prior Room +
  state snapshot on non-2xx; tests cover 401 (see below), 409 (e.g. edit on a
  revoked message), and 5xx.
- **401 refresh-once:** a 401 on an idempotent GET (e.g. pins/edits/reaction
  details) triggers exactly one `POST /ui/session/refresh` then one retry; a
  second 401 surfaces an auth error and does **not** loop. Asserted via
  MockWebServer dispatcher sequencing and `requestCount`.
- **Timeouts/retry:** GETs use bounded backoff; tests use a `MockWebServer`
  dispatcher that fails N times then succeeds, with `advanceTimeBy` driving the
  virtual clock so no real waiting occurs. Non-idempotent POST/PATCH/DELETE are
  asserted **not** retried.
- **No-flake mandate:** zero `Thread.sleep`, zero real network, fixed seeds for
  any randomized fixture, virtual time only.

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf`
  cookie value on every mutating request (reactions/pin/edit/delete/revoke,
  presign, send). A test omits the cookie and asserts the request is still well
  formed only after the jar is seeded, guarding the CSRF-echo contract.
- The persistent cookie jar contract is verified via `RecordingCookieJar`:
  cookies set by a prior `Set-Cookie` are replayed on subsequent calls within the
  same test; this proves the session rides cookies, not headers.
- No real credentials, tokens, or PII appear in fixtures; the dev backend host is
  never contacted. Bitmap fixtures are synthetic. Temp files created by the
  compressor live under a JUnit `@TempDir` and are deleted after each test.
- Image bytes are never logged; tests assert the upload logger redacts body
  content (see Telemetry).

## 9. Accessibility & i18n

Limited but non-zero for the Compose render tier:

- `ImageMessageRenderTest` asserts the thumbnail node exposes a non-empty
  `contentDescription` (caption or a localized "Image message" fallback) and the
  viewer's dismiss control has an accessible label, using
  `onNodeWithContentDescription`.
- The action menu items (react/pin/edit/delete/revoke/hide) are asserted to carry
  content descriptions and to be reachable as distinct semantics nodes.
- i18n: tests assert user-facing fallbacks resolve through string resources
  (e.g. via `composeRule.activity.getString(R.string.image_message_a11y)`) rather
  than hardcoded literals, so no untranslated string regresses. Full
  locale-matrix testing is out of scope.

## 10. Telemetry & Logging

- Tests use a `RecordingAnalytics` fake injected via Hilt test module and assert
  that the documented events fire once with the right params: `image_send`
  (with `byte_size`, `compressed`), `message_action` (with `action` ∈
  {react,pin,unpin,edit,delete,revoke,hide}), and `image_view_open`. Duplicate or
  missing events fail the test.
- A test installs a recording OkHttp logging interceptor and asserts the image
  PUT/POST bodies are **not** emitted to logs (redaction), satisfying the privacy
  requirement in §8.
- No telemetry endpoint is hit; analytics are recorded in-memory only.

## 11. Testing Strategy

- **Frameworks:** JUnit4, `kotlinx-coroutines-test`, Turbine, Truth/AssertK,
  MockWebServer, Robolectric (Compose + Bitmap), Hilt testing
  (`@HiltAndroidTest` + `HiltTestRule`) for instrumented smoke, Compose UI test
  (`createComposeRule`). All declared in the version catalog under `core-testing`.
- **Coverage matrix (each cell = a named test):**
  | Type | Upload | Render | Action |
  |---|---|---|---|
  | Image (AND-130) | presign+put+send order/body; compression/thumbnail | thumbnail render; tap→viewer; viewer states | open/view event |
  | Reaction (AND-140) | n/a | reaction summary render | add/remove optimistic+rollback; details load |
  | Pin (AND-140) | n/a | pinned badge | pin/unpin → state+pins list+Room |
  | Edit (AND-140) | n/a | edited marker | edit → body+edited_at+history |
  | Delete/Revoke/Hide (AND-140) | n/a | tombstone/revoked/hidden render | distinct end states; hide local-only |
- **Determinism:** `StandardTestDispatcher`, virtual time, in-memory DB, fixed
  fixture seeds, MockWebServer dispatchers. CI runs `./gradlew :feature-messaging:testDebugUnitTest :core-data:testDebugUnitTest`
  plus the headless `connectedDebugAndroidTest` (or Robolectric-only on the
  default PR gate) — all non-interactive.
- **Targets:** ≥90% line coverage on the rich-message repositories, mappers, and
  ViewModel action paths (JaCoCo); 100% of FR-1..FR-7 represented by ≥1 assertion.
- **Anti-flake gate:** the unit suite must pass 50 consecutive local runs
  (`--rerun-tasks`) before merge.

## 12. Dependencies & Sequencing

- **depends_on AND-130** — image messages (presign/upload/compress/thumbnail/
  viewer) must exist before their tests; this ticket cannot complete until
  AND-130's public APIs are stable.
- **depends_on AND-140** — the action set (reactions/pins/edits/delete/revoke/
  hide) and its repository surface must be in place.
- Implicitly relies on `core-testing` test utilities and `core-network`
  MockWebServer plumbing; if `core-testing` lacks `MainDispatcherRule`,
  `mockMessagingApi`, or `RecordingCookieJar`, add them here (they are reused by
  AND-138/AND-139 test tickets).
- **Sequencing:** land after AND-130 and AND-140 merge; run in the same milestone
  (M3, epic E19). Does not block other tickets (`blocks: []`) but is a P1 gate on
  the rich-message feature being declared done.

## 13. Risks & Open Questions

- **R1 Robolectric Bitmap fidelity.** Compression/thumbnail dimensions under
  Robolectric shadows may not match a real device. Mitigation: assert
  dimension/mime/byte-size invariants, not pixel content; keep one instrumented
  smoke for true bitmap encoding.
- **R2 Coil in headless tests.** Coil image loading is hard to assert on JVM.
  Mitigation: inject a fake `ImageLoader` that resolves a test drawable
  synchronously; assert the requested model URL, not pixels.
- **R3 Delete semantics.** AND-140 may model delete as hard-remove or tombstone;
  the test must follow whatever AND-140 ships. **Open:** confirm the exact end
  state with AND-140 before finalizing FR-7 assertions.
- **R4 hide endpoint.** Assumed local-only (no network). **Open:** verify
  against AND-140 / OpenAPI that no `hide` endpoint exists.
- **R5 Optimistic-update contract.** Whether reactions are optimistic is an
  AND-140 design choice; if non-optimistic, drop the intermediate-snapshot
  assertion and keep only confirmed-state + rollback-on-error.

## 14. Acceptance Criteria

1. The suite runs fully headlessly — JVM unit + Robolectric on the PR gate, and
   the instrumented smoke on a headless emulator — with **zero** manual steps and
   **zero** real-network calls.
2. Every functional requirement FR-1..FR-7 has at least one passing, named test,
   per the §11 matrix.
3. Image flow tests prove presign→PUT→send ordering, exact request bodies, and
   that a PUT failure prevents the send call.
4. Each AND-140 action test proves: thread `StateFlow` mutation, Room
   persistence, and (for optimistic actions) rollback on error; hide makes no
   network call.
5. `X-CSRF-Token`/cookie contract and the single-retry 401→refresh behavior are
   asserted.
6. The suite is flake-free across 50 consecutive runs and meets the ≥90% coverage
   target on rich-message repositories/mappers/ViewModels.
7. `./gradlew testDebugUnitTest` (and the headless instrumented task) is green on
   `android-port` CI.

## 15. Definition of Done

- All §14 criteria met and verified in CI on `android-port`.
- New tests live in `feature-messaging/src/test`, `core-data/src/test`, and a
  minimal `feature-messaging/src/androidTest`; shared fixtures/rules added to
  `core-testing` and reused, not duplicated.
- No production code changed except additive test hooks (e.g. `@VisibleForTesting`
  constructors, Hilt test modules); no behavioral change to AND-130/AND-140.
- Version-catalog test dependencies (Turbine, MockWebServer, Robolectric,
  coroutines-test, Hilt testing, Compose UI test) declared and pinned.
- JaCoCo coverage report generated and the rich-message threshold enforced in the
  Gradle build.
- Open questions R3/R4/R5 resolved with AND-140 owner and assertions finalized
  accordingly; PR reviewed and merged.
