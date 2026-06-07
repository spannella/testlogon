---
id: AND-142
title: Rich message tests
milestone: M3
epic: E19
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
`POST /messaging/conversations/{conversation_id}/images/presign` with the
declared `content_type` and `filename`, (b) PUT the (compressed) bytes to the
returned `upload_url` (response also carries `bucket`/`key`/`content_type`), and
(c) call `POST /messaging/conversations/{conversation_id}/messages/image` with
the `bucket`/`key` (both required), plus `content_type`, `filename`, `filesize`,
`kind` ("image"/"video"/"file"), optional `caption`, and generated
`width`/`height`. Tests assert the exact JSON body and header set of each call
and the ordering.
[Corrected — verified against OpenAPI `POST /messaging/conversations/{conversation_id}/images/presign` (req=`SendImagePresignIn` `{content_type,filename}`, resp=`PresignOut` `{upload_url,bucket,key,content_type}`) and `POST /messaging/conversations/{conversation_id}/messages/image` (req=`CreateImageMessageIn`, required `bucket,key`). The original spec's `/messages/images/presign`, `/messages/image`, `byte_size`, `upload_id`, `thread_id`, and `thumbnail` object do not exist; the API is conversation-scoped and uses `bucket`/`key`/`filesize`/`kind`. The server derives the thumbnail; the client does not send a `thumbnail` object — see frontend `src/api/endpoints/messaging.ts: sendImageMessage`.]

FR-2 **Image compression & thumbnail.** Given a known input bitmap, the
compressor must emit JPEG/WEBP under the configured max dimension and quality,
and a thumbnail under the thumbnail dimension. Tests assert output dimensions,
mime, and that the compressed byte count matches the `filesize` value sent in
the `messages/image` request body.
[Corrected — `byte_size` is not sent at presign (presign carries only
`content_type`/`filename`); the compressed size rides as `filesize` in
`CreateImageMessageIn`. Thumbnail generation is a client display concern only —
the upload contract has no thumbnail field; the backend derives media URLs.]

FR-3 **Image render & viewer.** An `ImageMessage` DTO must render a thumbnail
node in the thread; tapping it opens the full-screen viewer; back/dismiss
returns. Tests assert the thumbnail Coil model URL, the viewer route argument,
and that a `loading`/`error`/`loaded` viewer state is reflected.

FR-4 **Action: reactions.** Adding **and** removing a reaction both call the
**same** endpoint `POST /messaging/conversations/{conversation_id}/messages/{message_id}/reactions`
with body `{ "emoji": "...", "action": "add" | "remove" }` — there is no
per-emoji DELETE route. The call optimistically updates the message's reaction
summary in the thread `StateFlow` and persists to Room; reaction details load on
demand via `GET .../messages/{message_id}/reactions/details` (resp
`ReactionDetailsOut`, an object keyed by emoji). Tests assert optimistic update,
server confirmation reconciliation, and rollback on error.
[Corrected — verified against OpenAPI `POST .../reactions` (req=`ReactIn`
`{emoji (required), action}`) and `GET .../reactions/details`
(resp=`ReactionDetailsOut` `{reactions: object}`), and frontend
`src/api/endpoints/messaging.ts: reactToMessage` / `getReactionDetails`. The
original `DELETE /messages/{id}/reactions/{emoji}` and the
`GET /messages/{id}/reactions -> {items:[ReactionDetailDto]}` shapes do not
exist.]

FR-5 **Action: pin/unpin.** Pin is `POST .../messages/{message_id}/pin`, unpin is
`DELETE .../messages/{message_id}/pin`; both return `MessageControlActionOut`
(`{ok, conversation_id, message_id, action, updated_at}`), **not** a full
`MessageDto`. The client toggles the local pinned flag and refreshes the pins
list via `GET .../conversations/{conversation_id}/pins` (resp
`ConversationPinsPageOut` `{items, next_cursor}`), then persists. Tests assert
thread state + pins list + Room.
[Corrected — verified against OpenAPI `POST`/`DELETE .../{message_id}/pin`
(resp=`MessageControlActionOut`) and `GET .../conversations/{conversation_id}/pins`
(resp=`ConversationPinsPageOut`); frontend `pinMessage`/`unpinMessage`/
`getPinnedMessages`. The pins endpoint is `/conversations/{id}/pins`, not the
spec's `/threads/{tid}/pins`, and the pin response is a control-action ack, not
a `MessageDto`.]

FR-6 **Action: edit (+history).** Editing is `PATCH
.../conversations/{conversation_id}/messages/{message_id}` with body
`{ "text": "edited" }` (the field is `text`, **not** `body`), returns
`MessageOut` with `edited_at` set, and the prior content becomes an edit-history
entry retrievable via `GET .../messages/{message_id}/edits`. Tests assert the new
text in state, the history entry, and persistence.
[Corrected — verified against OpenAPI `PATCH .../messages/{message_id}`
(req=`EditMessageIn`, required field `text`; a deprecated `body` alias exists but
the client sends `text`) and frontend `editMessage` (`body: { text }`). Original
`{ "body": "edited" }` field name was wrong.]

FR-7 **Action: delete / revoke / hide.** Delete-for-me is `DELETE
.../messages/{message_id}`; revoke-for-all is `DELETE
.../messages/{message_id}/revoke` (resp `MessageOut`, **not** a `POST`); hide-for-me
is `POST .../messages/{message_id}/hide` and unhide is `DELETE
.../messages/{message_id}/hide`, both returning `MessageControlActionOut`. Tests
assert each distinct end state in the thread `StateFlow` and Room.
[Corrected — major fix. Hide is **not** local-only: a real server endpoint
exists (`POST`/`DELETE .../{message_id}/hide`, resp=`MessageControlActionOut`,
errors=`MessageControlsErrorOut`), with a companion `GET
.../conversations/{conversation_id}/hidden-messages` list. Revoke is a `DELETE`
verb (`DELETE .../{message_id}/revoke`), not the spec's `POST
/messages/{id}/revoke`, and returns `MessageOut` (no `revoked=true` boolean is
guaranteed by the schema — assert via the returned `MessageOut` shape/`message_id`).
Verified against OpenAPI and frontend `deleteMessage`/`revokeMessage` *(see note
in §16: a `revokeMessage` wrapper is not present in `messaging.ts`; the
revoke route itself is confirmed in OpenAPI)* / `hideMessage`/`unhideMessage`.]

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
    @Test fun hide_calls_server_and_reconciles()   // corrected: hide IS a network call (POST .../hide)
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

> **NOTE (review correction):** the entire contract below was rewritten to match
> the authoritative OpenAPI index/spec and the frontend `src/api/endpoints/messaging.ts`.
> All real message routes are **conversation-scoped** under
> `/messaging/conversations/{conversation_id}/...`; the original spec's bare
> `/messages/...` and `/threads/...` paths do not exist. Auth/CSRF: web sends
> `Authorization: Bearer <token>` + `X-CSRF-Token` (= `ui_csrf` cookie) +
> `credentials: include`; the Android client mirrors this with its cookie jar +
> CSRF echo (see §8). Validation errors are FastAPI `422 HTTPValidationError`;
> message-control routes (pin/hide/report) use `MessageControlsErrorOut`
> (`{detail, error_code?}`) on 401/403/404/422/429.

Presign (AND-130) — `POST /messaging/conversations/{conversation_id}/images/presign`:
```
req  SendImagePresignIn  { "content_type": "image/jpeg", "filename": "image.jpg" }
-> 200 PresignOut { "upload_url": "https://s3.../put", "bucket": "...",
                    "key": "img/up_1.jpg", "content_type": "image/jpeg" }
```
Binary PUT: `PUT {upload_url}` with body = compressed bytes and `Content-Type`
header = `presign.content_type`. Asserted: method, URL, content-type, body length.

Send image (AND-130) — `POST /messaging/conversations/{conversation_id}/messages/image`:
```
req  CreateImageMessageIn  (required: bucket, key)
{ "bucket": "...", "key": "img/up_1.jpg", "content_type": "image/jpeg",
  "filename": "image.jpg", "filesize": 184320, "kind": "image",
  "caption": "hi", "width": 1600, "height": 1200 }
-> 200 MessageOut   (server derives media URLs incl. thumbnail; client sends NO thumbnail object)
```

Actions (AND-140) — all conversation-scoped; mutating calls asserted for body +
`X-CSRF-Token` header:
```
POST   .../messages/{message_id}/reactions   { "emoji":"👍", "action":"add" }    -> 200   (ReactIn; same route for "remove")
GET    .../messages/{message_id}/reactions/details                               -> 200 ReactionDetailsOut { "reactions": {…} }
POST   .../messages/{message_id}/pin                                             -> 200 MessageControlActionOut
DELETE .../messages/{message_id}/pin                                             -> 200 MessageControlActionOut
GET    .../conversations/{conversation_id}/pins                                  -> 200 ConversationPinsPageOut { items, next_cursor }
PATCH  .../messages/{message_id}             { "text":"edited" }                 -> 200 MessageOut (edited_at set; EditMessageIn)
GET    .../messages/{message_id}/edits                                           -> 200 (edit-history list)
DELETE .../messages/{message_id}                                                 -> 200   (delete-for-me)
DELETE .../messages/{message_id}/revoke                                          -> 200 MessageOut (revoke-for-all)
POST   .../messages/{message_id}/hide                                            -> 200 MessageControlActionOut (hide-for-me)
DELETE .../messages/{message_id}/hide                                            -> 200 MessageControlActionOut (unhide)
```
`hide` **does** have a server endpoint (corrected; it is **not** local-only) — a
hidden-messages list exists at `GET .../conversations/{conversation_id}/hidden-messages`.
Tests must assert the hide network call is made and reconciled, not that it is
suppressed. Error fixtures use FastAPI `detail` in all three shapes
(string | `[{msg}]` | `{code,...}`) — verified against frontend
`src/api/client.ts: normalizeErrorDetail`/`mapAuthorizationError` — to confirm
the mapper feeds `ApiResult.Error` and triggers rollback; message-control routes
additionally return `MessageControlsErrorOut`.

## 6. Data & State Management

Tests exercise the real `core-data` layer against an in-memory `TestLogonDatabase`.

- **Thread state:** `MessagingUiState(messages: List<MessageUi>, pins: List<MessageUi>, viewer: ViewerState)` exposed as `StateFlow`. Action tests assert
  on the post-mutation snapshot and, for optimistic actions, on the intermediate
  snapshot via Turbine.
- **Persistence:** after each action, the DAO is queried directly:
  `messageDao.getById("m1")`, `reactionDao.forMessage("m1")`,
  `messageDao.pinsForThread("t1")`, `editHistoryDao.forMessage("m1")`. Hide sets
  a local `hidden=true` column **after** the server `POST .../hide` acks (hide is
  a server action, corrected from the original "local-only" assumption); delete
  writes a tombstone or removes per the AND-140 design; revoke sets a revoked
  marker reflecting the `MessageOut` returned by `DELETE .../revoke`. Each is
  asserted distinctly.
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
  **not** call `POST .../conversations/{conversation_id}/messages/image`.
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
  cookie value on every mutating request (reactions/pin/hide/edit/delete/revoke,
  presign, send). A test omits the cookie and asserts the request is still well
  formed only after the jar is seeded, guarding the CSRF-echo contract.
  [Verified — frontend `src/api/client.ts` reads `getCookie("ui_csrf")` and sets
  `X-CSRF-Token`; `credentials: "include"` carries the session cookie.]
- The persistent cookie jar contract is verified via `RecordingCookieJar`:
  cookies set by a prior `Set-Cookie` are replayed on subsequent calls within the
  same test; this proves the session cookie is carried across calls. (Note: the
  web client also sends `Authorization: Bearer <accessToken>` from its auth store
  alongside the cookie — see `client.ts`; the Android client carries the
  equivalent token, so "cookies, not headers" is imprecise: it is cookie + bearer
  + CSRF echo.)
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
  | Edit (AND-140) | n/a | edited marker | edit (`text` field) → text+edited_at+history |
  | Delete/Revoke/Hide (AND-140) | n/a | tombstone/revoked/hidden render | distinct end states; hide IS a server call (POST .../hide) |
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
- **R4 hide endpoint.** ~~Assumed local-only (no network).~~ **RESOLVED (this
  review):** a real `hide` endpoint **exists** — `POST .../messages/{message_id}/hide`
  and `DELETE .../messages/{message_id}/hide` (resp `MessageControlActionOut`,
  errors `MessageControlsErrorOut`), plus `GET
  .../conversations/{conversation_id}/hidden-messages`. FR-7 and §11 updated:
  hide IS a network action; assert the call is made and reconciled, not
  suppressed.
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
   persistence, and (for optimistic actions) rollback on error; hide performs its
   server call (`POST .../messages/{message_id}/hide`) and reconciles the local
   `hidden` flag from the `MessageControlActionOut` ack (corrected — hide is not
   local-only).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI
pointers are `METHOD /path` from `reference/openapi.index.txt` and/or a
`components.schemas.<Name>` from `reference/openapi.pretty.json`. Frontend
pointers are `reference/src/api/...`. Framework choices are labeled
"framework ref".

1. **Image presign endpoint & request shape.** VERDICT: **Corrected.** Real:
   `POST /messaging/conversations/{conversation_id}/images/presign`,
   req=`SendImagePresignIn` `{content_type, filename}`, resp=`PresignOut`
   `{upload_url, bucket, key, content_type}`. Source: OpenAPI
   `POST /messaging/conversations/{conversation_id}/images/presign`; schemas
   `SendImagePresignIn`, `PresignOut`; `src/api/endpoints/messaging.ts: sendImageMessage`
   (presign call). Original `/messages/images/presign` with `byte_size` and a
   `{upload_id, headers}` response is wrong.

2. **Send-image endpoint & body.** VERDICT: **Corrected.** Real:
   `POST /messaging/conversations/{conversation_id}/messages/image`,
   req=`CreateImageMessageIn` (required `bucket, key`; plus `content_type`,
   `filename`, `filesize`, `kind`, `caption`, `width`, `height`). Resp
   `MessageOut`. Source: OpenAPI path above; schema `CreateImageMessageIn`;
   `src/api/endpoints/messaging.ts: sendImageMessage` (payload). Original
   `/messages/image` with `upload_id`, `thread_id`, and a `thumbnail` object is
   wrong; the client sends no thumbnail (server derives media URLs).

3. **Binary PUT.** VERDICT: **Verified.** PUT to `presign.upload_url` with
   `Content-Type: presign.content_type`. Source:
   `src/api/endpoints/messaging.ts` (`fetch(presign.upload_url, {method:"PUT", ...})`
   / `uploadToPresignedUrl`).

4. **Reactions add/remove endpoint.** VERDICT: **Corrected.** Single route
   `POST .../messages/{message_id}/reactions`, req=`ReactIn`
   `{emoji (required), action: "add"|"remove"}`; no per-emoji DELETE. Source:
   OpenAPI `POST .../{message_id}/reactions`; schema `ReactIn`;
   `src/api/endpoints/messaging.ts: reactToMessage`. Original
   `DELETE /messages/{id}/reactions/{emoji}` is wrong.

5. **Reaction details endpoint.** VERDICT: **Corrected.**
   `GET .../messages/{message_id}/reactions/details`, resp=`ReactionDetailsOut`
   `{reactions: object}`. Source: OpenAPI
   `GET .../{message_id}/reactions/details`; schema `ReactionDetailsOut`;
   `src/api/endpoints/messaging.ts: getReactionDetails`. Original
   `GET /messages/{id}/reactions -> {items:[ReactionDetailDto]}` is wrong (path
   and shape).

6. **Pin / unpin endpoints & response.** VERDICT: **Corrected.**
   `POST .../{message_id}/pin` and `DELETE .../{message_id}/pin`, both resp
   `MessageControlActionOut` `{ok, conversation_id, message_id, action,
   updated_at}` — not `MessageDto`. Source: OpenAPI those two paths; schema
   `MessageControlActionOut`; `src/api/endpoints/messaging.ts: pinMessage`/`unpinMessage`.

7. **Pins list endpoint.** VERDICT: **Corrected.**
   `GET /messaging/conversations/{conversation_id}/pins`, resp
   `ConversationPinsPageOut` `{items, next_cursor}`. Source: OpenAPI that path;
   schema `ConversationPinsPageOut`; `src/api/endpoints/messaging.ts: getPinnedMessages`.
   Original `GET /threads/{tid}/pins` is wrong.

8. **Edit endpoint & field name.** VERDICT: **Corrected.**
   `PATCH .../messages/{message_id}`, req=`EditMessageIn` with required field
   **`text`** (deprecated `body` alias exists), resp `MessageOut` (`edited_at`).
   Source: OpenAPI `PATCH .../{message_id}`; schema `EditMessageIn`;
   `src/api/endpoints/messaging.ts: editMessage` (`body: { text }`). Original
   `{ "body": "edited" }` field name is wrong.

9. **Edit history endpoint.** VERDICT: **Verified.**
   `GET .../messages/{message_id}/edits`. Source: OpenAPI
   `GET .../{message_id}/edits`.

10. **Delete (for me).** VERDICT: **Corrected (verb/path).**
    `DELETE .../messages/{message_id}`. Source: OpenAPI
    `DELETE /messaging/conversations/{conversation_id}/messages/{message_id}`;
    `src/api/endpoints/messaging.ts: deleteMessage`. Original bare
    `/messages/{id}` path is wrong (missing conversation scope).

11. **Revoke (for all) endpoint & verb.** VERDICT: **Corrected.**
    `DELETE .../messages/{message_id}/revoke`, resp `MessageOut`. Source: OpenAPI
    `DELETE .../{message_id}/revoke`. Original `POST /messages/{id}/revoke ->
    MessageDto(revoked=true)` is wrong (verb + path; the schema does not
    guarantee a `revoked=true` boolean — `MessageOut` is returned).

12. **Hide / unhide endpoints exist.** VERDICT: **Corrected (major).** Real:
    `POST .../{message_id}/hide` and `DELETE .../{message_id}/hide`, resp
    `MessageControlActionOut`, errors `MessageControlsErrorOut`; list at
    `GET .../conversations/{conversation_id}/hidden-messages`. Source: OpenAPI
    those paths; `src/api/endpoints/messaging.ts: hideMessage`/`unhideMessage`/
    `getHiddenMessages`. Original "hide has no endpoint / local-only" is wrong.

13. **All message routes are conversation-scoped.** VERDICT: **Corrected.**
    Every route lives under `/messaging/conversations/{conversation_id}/...`.
    Source: OpenAPI index (lines 327, 342, 349, 353, 356–361, 372).
    Spec's bare `/messages/...` and `/threads/...` namespace is wrong throughout.

14. **CSRF echo: `X-CSRF-Token` == `ui_csrf` cookie.** VERDICT: **Verified.**
    Source: `src/api/client.ts` (`getCookie("ui_csrf")` then
    `headers.set("X-CSRF-Token", csrf)`).

15. **Auth transport includes a bearer token (not cookies alone).** VERDICT:
    **Corrected (nuance).** Web sends `Authorization: Bearer <accessToken>` +
    `X-CSRF-Token` + `credentials:"include"`. Source: `src/api/client.ts`
    (Authorization + CSRF + credentials). The spec's "session rides cookies, not
    headers" understated the bearer header; clarified in §8.

16. **401 → refresh once → single retry.** VERDICT: **Verified.** A single
    `POST /ui/session/refresh` (deduped via `refreshPromise`), one retry, and a
    second 401 logs out — no loop. Source: OpenAPI `POST /ui/session/refresh`
    (line 1847); `src/api/client.ts` 401 block (lines ~194–237).

17. **FastAPI error `detail` in three shapes (string | `[{msg}]` |
    `{code,...}`).** VERDICT: **Verified.** Source:
    `src/api/client.ts: normalizeErrorDetail` (string / array-of-`{msg}` /
    object) and `mapAuthorizationError` (`{code,...}`). Message-control routes
    also return `MessageControlsErrorOut` `{detail, error_code?}` (schema).

18. **Validation errors are `422 HTTPValidationError`.** VERDICT: **Verified.**
    Source: OpenAPI responses on the messaging routes (`422:HTTPValidationError`).

19. **Test stack (Robolectric Compose/Bitmap on JVM, MockWebServer, in-memory
    Room, coroutines-test, Turbine).** VERDICT: **Verified (framework ref).**
    Robolectric runs Android unit tests on the JVM:
    https://robolectric.org/ ; in-memory Room via
    `Room.inMemoryDatabaseBuilder`:
    https://developer.android.com/training/data-storage/room/testing-db ;
    Compose test rule `createComposeRule`:
    https://developer.android.com/develop/ui/compose/testing ;
    coroutines `runTest`/`StandardTestDispatcher`:
    https://kotlin.github.io/kotlinx.coroutines/kotlinx-coroutines-test/ .

20. **Instrumented smoke on a headless emulator / `connectedDebugAndroidTest`.**
    VERDICT: **Verified (framework ref).**
    https://developer.android.com/studio/test/command-line and
    https://developer.android.com/studio/run/emulator-commandline (headless
    `-no-window`).

### Corrections made

- §3 FR-1, FR-2, FR-4, FR-5, FR-6, FR-7 — endpoints, request/response field
  names, and the hide-is-local-only assumption all corrected to the real,
  conversation-scoped contract (citations 1–13).
- §5 API Contract — rewritten end-to-end: real presign/send shapes, single
  reactions toggle route, `reactions/details`, pin/unpin/hide/unhide returning
  `MessageControlActionOut`, `/conversations/{id}/pins`, edit field `text`,
  revoke as `DELETE .../revoke`, and the added `hidden-messages` list.
- §6 — hide column now set after the server ack; revoke marker derives from the
  returned `MessageOut`.
- §7 — corrected the "must not call send" reference to the conversation-scoped
  `messages/image` path; the 401-refresh-once flow confirmed accurate.
- §8 — CSRF echo confirmed; clarified that auth also carries a bearer token
  ("cookies, not headers" was imprecise); added hide to the mutating-request set.
- §4 / §11 — renamed `hide_is_local_only_no_network_call` to
  `hide_calls_server_and_reconciles`; matrix cells updated (edit `text`, hide is
  a server call).
- §13 R4 — resolved: hide endpoint exists.
- §14 AC-4 — corrected to require the hide server call + reconciliation.
- Frontmatter — `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Reactions POST response body.** OpenAPI lists `resp=200` for
  `POST .../reactions` with **no named schema**, and the frontend
  `reactToMessage` ignores the body. Whether the server returns an updated
  reaction summary is **unverifiable** from the sources; the optimistic-update +
  reconcile assertion in FR-4 assumes the client recomputes the summary locally
  (or refetches via `reactions/details`). Confirm with AND-140.
- **Edit-history & hidden-messages list item schemas.** `GET .../edits` and
  `GET .../hidden-messages` have no named response schema in the index; the
  exact item DTO (`EditHistoryEntryDto`, hidden-message item) is an
  **unverified assumption** — pin the fixture shape against AND-140's
  implementation, not the OpenAPI index.
- **Optimistic reactions / delete-as-tombstone-vs-hard-remove (R3, R5).**
  Client-side behavior choices owned by AND-140; not expressible from the
  backend contract. Remain open per §13.
- **`revoked`/`is_pinned`/`edited_at` fields on `MessageOut`.** The render-state
  flags the tests assert (revoked badge, pinned badge, edited marker) depend on
  `MessageOut` carrying those fields; `MessageOut` was not field-audited in this
  review. **Unverified-assumption** — confirm against schema `MessageOut` before
  finalizing render assertions.
- **Dev backend host `http://18.222.237.167:8000/openapi.json`.** Not reachable
  from / not present in the provided sources. **Unverified-assumption** (and
  irrelevant to the suite, which mocks all HTTP).

## 17. Test Plan

All cases run headlessly unless noted. Test targets: **JVM** = Robolectric/unit,
no device; **emulator** = headless AVD `test35` (API 35, x86_64);
**device** = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) for real
hardware behavior. "Traces" links to §14 Acceptance Criteria.

- **TC-AND-142-01 — Image happy path: presign → PUT → send, in order with exact
  bodies.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  MockWebServer with a 3-response dispatcher (presign 200 `PresignOut`, PUT 200,
  send 200 `MessageOut`); seeded conversation `c1`; CSRF cookie seeded. Steps:
  call `sendImage(c1, bitmap, caption="hi")`; `advanceUntilIdle()`. Expected:
  request 1 = `POST /messaging/conversations/c1/images/presign` body
  `{content_type, filename}`; request 2 = `PUT {upload_url}` with
  `Content-Type` = presign content_type and body length = compressed size;
  request 3 = `POST /messaging/conversations/c1/messages/image` body containing
  `bucket`, `key`, `filesize`, `kind:"image"`, `caption:"hi"`, `width`,
  `height`; ordering presign→PUT→send. Traces: AC-2, AC-3.

- **TC-AND-142-02 — PUT failure aborts send.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: presign 200, PUT 403 (expired URL). Steps:
  call `sendImage`; `advanceUntilIdle()`. Expected: result is `ApiResult.Error`
  with the surfaced `detail`; `POST .../messages/image` is **never** sent
  (assert via `requestCount`/recorded paths); no partial message row in Room.
  Traces: AC-3.

- **TC-AND-142-03 — Compressor invariants (real bitmap encode).** Type:
  instrumented. Target: **physical device** (true JPEG/WEBP encoding differs from
  Robolectric shadows — R1). Preconditions: a 4000×3000 source bitmap.
  Steps: compress at configured max dimension + thumbnail dimension. Expected:
  longest side ≤ max dim, thumbnail longest side ≤ thumb dim, output mime ∈
  {jpeg, webp}, and the reported byte count equals the `filesize` later sent.
  Note: MUST run on the physical device for encoder fidelity; a JVM/Robolectric
  variant asserts only dimension/mime invariants. Traces: AC-2.

- **TC-AND-142-04 — Image render + tap-to-viewer + viewer states.** Type:
  Compose-UI (Robolectric). Target: JVM. Preconditions: `createComposeRule`,
  fake `ImageLoader` resolving a test drawable synchronously (R2), an
  `ImageMessage` DTO. Steps: render thread; assert thumbnail node; click it;
  drive loading→loaded; press back. Expected: thumbnail node present with the
  expected Coil model URL; tap navigates to viewer route with the correct media
  arg; viewer reflects loading→loaded; back dismisses. Traces: AC-2.

- **TC-AND-142-05 — Reaction add: optimistic then confirmed (single toggle
  route).** Type: unit (JVM). Target: JVM. Preconditions: MainDispatcherRule,
  Turbine on `uiState`, MockWebServer `POST .../reactions` → 200. Steps:
  `addReaction(c1,m1,"👍")`. Expected: intermediate snapshot shows my reaction
  optimistically; the single request is `POST
  /messaging/conversations/c1/messages/m1/reactions` body
  `{emoji:"👍", action:"add"}`; no `DELETE` route is used; confirmed state
  persists; Room reflects it. Traces: AC-2, AC-4.

- **TC-AND-142-06 — Reaction remove uses same route with action:"remove".**
  Type: unit (JVM). Target: JVM. Preconditions: a pre-seeded reaction by me.
  Steps: `removeReaction(c1,m1,"👍")`. Expected: request is `POST .../reactions`
  body `{emoji:"👍", action:"remove"}` (NOT a per-emoji DELETE); summary updates;
  Room updated. Traces: AC-2, AC-4.

- **TC-AND-142-07 — Reaction rollback on error (Room byte-identical).** Type:
  unit (JVM). Target: JVM. Preconditions: `POST .../reactions` → 500 with
  FastAPI `detail` string. Steps: `addReaction`; `advanceUntilIdle()`. Expected:
  optimistic snapshot appears then rolls back; final `uiState` == pre-call;
  Room row byte-identical to the captured snapshot; `ApiResult.Error` surfaced.
  Traces: AC-4.

- **TC-AND-142-08 — Pin/unpin → state + pins list + Room.** Type: unit (JVM).
  Target: JVM. Preconditions: MockWebServer: `POST .../pin` →
  `MessageControlActionOut`, then `GET .../conversations/c1/pins` →
  `ConversationPinsPageOut{items:[…]}`. Steps: `pin(c1,m1)` then `unpin(c1,m1)`.
  Expected: pin issues `POST .../m1/pin`, response parsed as
  `MessageControlActionOut` (not MessageDto); pins list refreshed from
  `/conversations/c1/pins`; local pinned flag + Room toggle on; unpin issues
  `DELETE .../m1/pin` and reverses. Traces: AC-2, AC-4.

- **TC-AND-142-09 — Edit uses `text` field; sets edited_at; appends history.**
  Type: unit (JVM). Target: JVM. Preconditions: `PATCH .../m1` →
  `MessageOut{edited_at}`, `GET .../m1/edits` → history list. Steps:
  `edit(c1,m1,"edited")`. Expected: request body is `{ "text":"edited" }` (NOT
  `body`); state shows new text + `edited_at`; history entry retrievable; Room
  persists. Traces: AC-2, AC-4.

- **TC-AND-142-10 — Delete / revoke / hide reach distinct end states (correct
  verbs).** Type: unit (JVM). Target: JVM. Preconditions: dispatcher mapping
  `DELETE .../m1` (delete-for-me) → 200, `DELETE .../m1/revoke` → `MessageOut`,
  `POST .../m1/hide` → `MessageControlActionOut`. Steps: run each against a
  distinct seeded message. Expected: delete → tombstone/removed per AND-140;
  revoke uses **DELETE .../revoke** and sets the revoked marker from the returned
  `MessageOut`; hide uses **POST .../hide** and sets `hidden=true` after the ack;
  three distinct Room/state end states. Traces: AC-2, AC-4.

- **TC-AND-142-11 — Hide IS a server call (regression for the corrected
  assumption).** Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `POST .../m1/hide` → `MessageControlActionOut`. Steps:
  `hide(c1,m1)`; `advanceUntilIdle()`. Expected: exactly one network request,
  `POST /messaging/conversations/c1/messages/m1/hide`; `requestCount`
  increments by 1; local `hidden` flag reconciled from the ack. (Explicitly
  asserts hide is NOT suppressed.) Traces: AC-4.

- **TC-AND-142-12 — CSRF echo + bearer on every mutating call.** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: `RecordingCookieJar`
  seeded with `ui_csrf=abc` and a session cookie; auth store with a bearer
  token. Steps: perform react / pin / hide / edit / delete / revoke / presign /
  send. Expected: each mutating request carries `X-CSRF-Token: abc` (==
  `ui_csrf`) and `Authorization: Bearer …`; the session cookie is replayed from
  the jar. Traces: AC-5.

- **TC-AND-142-13 — 401 → single refresh → one retry; second 401 surfaces auth
  error (no loop).** Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: dispatcher: idempotent `GET .../pins` → 401, then
  `POST /ui/session/refresh` → 200, then retry → 200; a separate sequence where
  the retry also 401s. Steps: trigger the GET in each sequence. Expected: exactly
  one `POST /ui/session/refresh` then one retry; first sequence succeeds; second
  surfaces an auth error and does **not** loop (`requestCount` bounded).
  Non-idempotent POST/PATCH/DELETE asserted **not** retried. Traces: AC-5.

- **TC-AND-142-14 — FastAPI error shapes map to ApiResult.Error + rollback.**
  Type: unit (JVM). Target: JVM. Preconditions: three error fixtures —
  `detail` string, `detail:[{msg}]`, `detail:{code:"role_required",…}` /
  `MessageControlsErrorOut` for a pin 403. Steps: drive a reaction and a pin
  against each. Expected: every shape is normalized to a non-empty message,
  yields `ApiResult.Error`, and triggers optimistic rollback. Traces: AC-4,
  AC-5.

- **TC-AND-142-15 — Flaky-dev-host / offline path.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: dispatcher that drops the connection / 503s
  N times then 200 for an idempotent GET, plus a hard offline (`SocketPolicy`
  disconnect) case; virtual time via `advanceTimeBy`. Steps: trigger a pins/edits
  GET. Expected: bounded backoff retries succeed without real waiting (no
  `Thread.sleep`); offline surfaces a network `ApiResult.Error`; no partial Room
  writes. Traces: AC-1, AC-4.

- **TC-AND-142-16 — Accessibility of thumbnail, viewer, and action menu.** Type:
  Compose-UI (Robolectric). Target: JVM. Preconditions: `createComposeRule`,
  string resources loaded. Steps: render an image message + open the action
  menu. Expected: thumbnail exposes a non-empty `contentDescription` (caption or
  localized "Image message" fallback via `R.string.image_message_a11y`); viewer
  dismiss control has an accessible label; react/pin/edit/delete/revoke/hide menu
  items are distinct semantics nodes with content descriptions. Traces: AC-1,
  AC-2.

- **TC-AND-142-17 — Telemetry redaction + event correctness.** Type: unit (JVM).
  Target: JVM. Preconditions: `RecordingAnalytics` + recording OkHttp logging
  interceptor. Steps: send an image, react, hide, open viewer. Expected:
  `image_send` (with `filesize`/`compressed`), `message_action`
  (`action ∈ {react,pin,unpin,edit,delete,revoke,hide}`), and `image_view_open`
  each fire exactly once; image PUT/POST bodies are NOT present in logs
  (redaction). Traces: AC-1.

- **TC-AND-142-18 — ABI / API-level smoke (arm64 API 34 vs x86_64 API 35).**
  Type: instrumented/e2e. Target: **physical device** (arm64-v8a, API 34) AND
  emulator `test35` (x86_64, API 35). Preconditions: a minimal Coil-load +
  viewer-navigation instrumented test. Steps: run on both targets. Expected:
  identical pass; flags any arm64-vs-x86 or API-34-vs-35 image-decode/render
  divergence. Note: the device leg MUST run on hardware to catch ABI-specific
  decode behavior. Traces: AC-1.

### Coverage matrix (§14 AC → covering TCs)

| Acceptance Criterion | Covered by |
|---|---|
| AC-1 fully headless, zero manual / zero real-network | TC-01..02, 04..17 (mocked); TC-15 (offline), TC-16 (a11y), TC-17 (telemetry), TC-18 (CI device/emu legs) |
| AC-2 every FR-1..FR-7 has ≥1 named test | TC-01 (FR-1), TC-03 (FR-2), TC-04 (FR-3), TC-05/06/07 (FR-4), TC-08 (FR-5), TC-09 (FR-6), TC-10/11 (FR-7) |
| AC-3 presign→PUT→send order, bodies, PUT-failure aborts send | TC-01, TC-02 |
| AC-4 each action: StateFlow + Room + rollback; hide is a server call | TC-05, TC-06, TC-07, TC-08, TC-09, TC-10, TC-11, TC-14 |
| AC-5 CSRF/cookie + single-retry 401→refresh | TC-12, TC-13, TC-14 |
| AC-6 flake-free + ≥90% coverage | TC-15 (no-flake/virtual time); coverage met cumulatively by TC-01..17 (JaCoCo gate) |
| AC-7 `testDebugUnitTest` + headless instrumented green on CI | TC-01..17 (unit/Robolectric), TC-03/TC-18 (instrumented on emulator `test35` + device) |
