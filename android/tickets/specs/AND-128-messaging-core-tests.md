---
id: AND-128
title: Messaging core tests
milestone: M3
epic: E18
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-124, AND-126]
blocks: []
---

# AND-128 — Messaging core tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the messaging core: conversation list, thread (message list) history, and message send (composer + optimistic reconciliation). It is a **Test** ticket (P1); it produces no shipping UI or runtime behavior of its own. Its goal is to convert the acceptance bullets of the messaging feature tickets — AND-122 (list ViewModel + paging), AND-123 (thread screen), AND-124 (send text message), and AND-126 (message domain model + mappers) — into deterministic, headless, repeatable verification.

Concretely, this ticket adds:

- **Repository / ViewModel unit tests** for `MessagingRepository`, `ConversationListViewModel`, and `ThreadViewModel` using fake APIs, fake `MessageDao`, and a `TestDispatcher`.
- **Mapper/round-trip tests** validating the sealed `Message` model defined in AND-126 against captured JSON fixtures.
- **Compose UI tests** (Robolectric host, JVM/headless) for the conversation list, thread list, and composer send-and-reconcile flow.
- A **CI wiring check** so the suite runs in `./gradlew test` with no connected device and no live backend.

The single backlog acceptance criterion — *"Tests pass headlessly"* — is the binding success measure: the full suite must execute and pass under `./gradlew :feature-messaging:test :core-data:test` (and the Robolectric `testDebugUnitTest` variant) on a CI runner with no emulator, no ADB, and no network egress.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app rooted at `android/`, branch `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Modules under test:** `feature-messaging` (ViewModels, Compose screens, composer) and `core-data` (`MessagingRepository`, `MessageDao`, mappers), depending on `core-network` (`MessagingApi`, DTOs), `core-model` (sealed `Message`), and `core-testing` (shared fakes/rules).
- **Upstream tickets (authoritative requirements being verified):**
  - **AND-120** — `MessagingApi` + DTOs for `/messaging/conversations`, `/messaging/conversations/{conversation_id}`, `/messaging/conversations/{conversation_id}/messages`, `/messaging/config`. *(Corrected: every messaging route is under the `/messaging` prefix; the earlier shorthand `/conversations/...` and `/config` were inaccurate — verified against OpenAPI index lines 312–333 and `src/api/endpoints/messaging.ts`.)*
  - **AND-122** — `ConversationListViewModel`, Paging 3 source, unread aggregation, sort.
  - **AND-123** — Thread screen: reverse-paged history, date separators, sender grouping, scroll-to-bottom.
  - **AND-124** *(dependency)* — Composer; `POST /conversations/{id}/messages`; optimistic send + failure retry.
  - **AND-126** *(dependency)* — sealed message model + mappers. The backend `kind` discriminator has 16 values (`text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail, countdown, gif, sticker, find_datetime`); AND-126 may collapse some into a smaller sealed set, but there is **no `poll` or `system` wire kind** (the spec prose elsewhere previously implied these — corrected).
- **Web reference (fixture source of truth):** `frontend/src/api/endpoints/*.ts` and shared types in `frontend/src/api/types.ts`; backend OpenAPI at `http://18.222.237.167:8000/openapi.json`. Fixtures are captured once and committed; tests never hit the live dev host.
- **Shared test infra:** `core-testing` provides `MainDispatcherRule`, `TurbineExt`, JSON fixture loaders, and base fakes. This ticket extends those with messaging-specific fakes.

This is a test-only ticket. No new production source is authored here except, where a seam is missing, small **test-visibility** refactors (e.g. constructor-injecting a `MessageIdGenerator` or `Clock`) coordinated with the owning feature ticket.

## 3. Functional Requirements

**FR-1 — Repository tests (`core-data`).** Cover `MessagingRepository`:
- `conversations(): Flow<PagingData<Conversation>>` emits mapped, sorted conversations with correct unread aggregation (AND-122).
- `messages(conversationId): Flow<PagingData<Message>>` returns reverse-chronological pages; cursor pagination advances; cache (Room) and network are reconciled (AND-123).
- `sendText(conversationId, text): ApiResult<Message>` inserts an optimistic `Message` with client-side `SendStatus.Sending`, issues `POST /messaging/conversations/{conversation_id}/messages` with `{ "text": ... }`, and on success (HTTP 200, `MessageOut`) updates the row to the server message (client-side `Sent`, server `message_id`/`created_at`); on failure marks it `Failed` and the row remains retryable (AND-124). *(Corrected field names: request field is `text` not `body`; server identifier is `message_id` not `id`; `SendStatus` is client-side only — see §6.)*
- `retry(localId)` re-sends a `Failed` message.

**FR-2 — Mapper tests (`core-data`/`core-model`).** Every sealed `Message` subtype from AND-126 maps from its DTO without loss, and an unknown `kind` falls back to a safe `Message.Unknown` placeholder rather than throwing. *(Correction: the wire discriminator is `MessageOut.kind`, not `type`. The backend enum has 16 members — `text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail, countdown, gif, sticker, find_datetime`. The previously listed `Poll`/`System` do not exist as wire kinds — `Poll` corresponds to `meeting_poll`, and there is no `system` kind. AND-126's sealed model may collapse some of these, but the mapper test must cover every kind the model claims to support and is bounded by these 16 source values.)*

**FR-3 — Conversation list ViewModel tests.** `ConversationListViewModel` exposes `StateFlow<ConversationListUiState>`. Tests assert: initial `Loading`; `Content` with sorted items + aggregated unread counts; `Empty`; and `Error` on `ApiResult.Failure`.

**FR-4 — Thread ViewModel tests.** `ThreadViewModel` exposes `StateFlow<ThreadUiState>` plus paged messages. Tests assert history load, append of newly sent messages, presence of date-separator and sender-group markers in the derived list, and `scrollToBottom` signalling on send.

**FR-5 — Composer / send UI test.** A Compose test types text, taps send, observes the optimistic bubble (sending indicator), then observes reconciliation to a sent bubble after the fake API acks; and the failure path showing a retry affordance.

**FR-6 — Headless execution.** All of the above run under JVM unit tests (`test` source set). Compose tests use Robolectric so they need no device. The whole suite is green via Gradle with no network and no connected hardware.

## 4. Technical Design

**Source layout (test source sets only):**

```
feature-messaging/src/test/kotlin/com/testlogon/android/feature/messaging/
  ConversationListViewModelTest.kt
  ThreadViewModelTest.kt
  ComposerSendUiTest.kt           // Robolectric + Compose
  ThreadScreenUiTest.kt           // Robolectric + Compose
core-data/src/test/kotlin/com/testlogon/android/core/data/messaging/
  MessagingRepositoryTest.kt
  MessageMapperTest.kt
core-testing/src/main/kotlin/com/testlogon/android/core/testing/messaging/
  FakeMessagingApi.kt
  FakeMessageDao.kt
  MessagingFixtures.kt
core-data/src/test/resources/fixtures/messaging/   // committed JSON
```

**Fakes.** `FakeMessagingApi : MessagingApi` is a deterministic in-memory implementation with programmable behavior:

```kotlin
class FakeMessagingApi(
    private val clock: Clock = Clock.fixed(Instant.parse("2026-06-05T00:00:00Z"), ZoneOffset.UTC),
) : MessagingApi {
    var sendBehavior: (SendMessageRequest) -> ApiResult<MessageDto> = { ok(it) }
    val sent = mutableListOf<SendMessageRequest>()

    fun seedConversations(vararg c: ConversationDto)
    fun seedMessages(conversationId: String, page: List<MessageDto>, nextCursor: String?)

    override suspend fun getConversations(cursor: String?, limit: Int): ApiResult<ConversationPageDto>
    override suspend fun getMessages(id: String, cursor: String?, limit: Int): ApiResult<MessagePageDto>
    override suspend fun sendMessage(id: String, body: SendMessageRequest): ApiResult<MessageDto>
}
```

`sendBehavior` lets a single test force success, delayed success, or `ApiResult.Failure(NetworkError.Timeout)`. `FakeMessageDao` is a `MutableStateFlow`-backed map honoring the real `MessageDao` query contract (reverse order, upsert-by-localId).

**Coroutine/time control.** All ViewModel and repository tests use `MainDispatcherRule(StandardTestDispatcher())` from `core-testing` and `runTest {}`. `advanceUntilIdle()` drives optimistic→ack transitions deterministically. A fixed `Clock` removes wall-clock flakiness in date-separator and timestamp assertions.

**Flow assertions.** Turbine (`flow.test { }`) asserts ordered `UiState` emissions. Paging output is collected via `AsyncPagingDataDiffer` (Paging 3 testing artifact) or `Pager.flow.asSnapshot { }` to materialize the list snapshot headlessly.

**Compose tests.** Run with `@RunWith(RobolectricTestRunner::class)` and `@Config(sdk = [34])` against `createComposeRule()`. The screen composables are driven with a ViewModel wired to fakes; assertions use `onNodeWithText`, `onNodeWithTag`, `performTextInput`, and `performClick`. Robolectric keeps these in the JVM `test` source set so no emulator is required.

**Test-seam adjustments.** If `sendText` generates IDs/timestamps internally, inject `MessageIdGenerator` and `Clock` via Hilt with test overrides; this small change lands in the owning feature module behind the existing constructor.

## 5. API Contract

This ticket consumes the AND-120 contract through fakes; it defines no new endpoints. The fixtures encode the real shapes the fakes and mappers are validated against. **The shapes below were corrected during review against the OpenAPI spec (`ConversationOut`, `MessageOut`, `SendTextMessageIn`) and `src/api/endpoints/messaging.ts` / `src/api/types.ts`.**

> Reconciliation note: the backend `MessageOut` contract carries **no `client_token` and no `status` field**, and the `SendTextMessageIn` request has **no `client_token` and no `type`**. Optimistic-send identity and delivery state are therefore **client-side concerns only** (mirroring the web client's `Message.__offline.status` of `"pending" | "sending" | "failed"`). The Android tests must assert the optimistic state machine and dedupe in the *repository/Room* layer keyed by a locally generated id — NOT by a server-returned `client_token`. See §13 open question and §16 corrections.

`GET /messaging/conversations?cursor=` — the web client (`getConversations`) tolerates **either** a bare JSON array of `ConversationOut` **or** `{ "conversations": [...], "next_cursor": "..." }` (note: key is `conversations`, **not** `items`). `ConversationOut` uses `conversation_id`, `unread_count`, `title`, `last_message`/`last_message_preview`/`last_message_at`, and integer (epoch-second) timestamps:
```json
{
  "conversations": [
    {"conversation_id": "c_1", "type": "dm", "title": "Alice", "unread_count": 3,
     "status": "active", "created_at": 1749061320, "created_by": "u_2",
     "participant_count": 2, "last_read_at": 0, "muted_until": 0,
     "last_message_at": 1749061320, "last_message_preview": "hey",
     "last_message": {"message_id": "m_9", "conversation_id": "c_1", "kind": "text",
                      "sender_id": "u_2", "text": "hey", "created_at": 1749061320}}
  ],
  "next_cursor": "eyJrIjoiYyJ9"
}
```

`GET /messaging/conversations/{conversation_id}/messages?before=` (reverse-chronological page; the cursor is passed as the **`before`** query param, and the response is a bare array **or** `{ "messages": [...], "next_cursor": "..." }` — key `messages`, **not** `items`):
```json
{
  "messages": [
    {"message_id": "m_9", "conversation_id": "c_1", "kind": "text",
     "sender_id": "u_2", "text": "hey", "created_at": 1749061320}
  ],
  "next_cursor": null
}
```

`POST /messaging/conversations/{conversation_id}/messages` — request (`SendTextMessageIn`) / **200** response (`MessageOut`; the index shows `resp=200:MessageOut`, **not 201**):
```json
{ "text": "hello" }
```
```json
{ "message_id": "m_10", "conversation_id": "c_1", "kind": "text",
  "sender_id": "u_self", "text": "hello", "created_at": 1749080401 }
```
The request's primary text field is **`text`** (max 4000 chars); a legacy nullable `body` alias also exists but `text` is canonical and is what the web client sends. `MessageOut` required fields are exactly `conversation_id`, `message_id`, `sender_id`, `created_at`, `kind`.

Mapper fixtures include one file per backend `kind` value. The real `MessageOut.kind` enum has **16 members** (not the 11 the prose elsewhere lists): `text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail, countdown, gif, sticker, find_datetime` — there is **no `poll` or `system` kind** in the backend contract (poll ≈ `meeting_poll`; "system" is not a wire `kind`). Add `message_unknown_kind.json` for the fallback path. Error fixtures cover the response shapes the messaging layer must tolerate. The canonical FastAPI 422 is `HTTPValidationError` = `{"detail":[{"loc":["body","text"],"msg":"...","type":"..."}]}` (each item **requires** `loc`, `msg`, `type`). The messaging endpoints also advertise bare `400/401/403/429` with **no documented body schema**, so the mapper must additionally tolerate the non-FastAPI-default variants `{"detail":"Not found"}` (string) and `{"detail":{"code":"rate_limited"}}` (object). These are exercised against the AND-120 DTO/error mapping, not re-implemented here.

## 6. Data & State Management

**UI state shapes asserted by tests** (owned upstream; reproduced for the assertions):

```kotlin
sealed interface ConversationListUiState {
    data object Loading : ConversationListUiState
    data class Content(val totalUnread: Int) : ConversationListUiState  // items via PagingData flow
    data object Empty : ConversationListUiState
    data class Error(val message: String, val retryable: Boolean) : ConversationListUiState
}

sealed interface ThreadUiState {
    data object Loading : ThreadUiState
    data class Content(val title: String, val canSend: Boolean) : ThreadUiState
    data class Error(val message: String, val retryable: Boolean) : ThreadUiState
}

enum class SendStatus { Sending, Sent, Failed }
```

**Optimistic send state machine (core assertion target).** Tests pin every transition: `(absent) → Sending` on `sendText`; `Sending → Sent` after fake ack updating the row to the server `message_id`/`created_at`; `Sending → Failed` on `ApiResult.Failure`; `Failed → Sending → Sent` on `retry`. **Correction (verified):** the backend response (`MessageOut`) returns **no `client_token` and no `status`**, and the request (`SendTextMessageIn`) carries **no `client_token`** — so reconciliation cannot key off a round-tripped server token. The local Room row must be keyed by a client-generated `localId`; on ack the repository replaces that row with the server message (matching by `localId`, since the server send returns exactly the one created message). The dedupe test asserts that applying the ack — and then a subsequent network page that includes the same server `message_id` — leaves exactly one row (no duplicate bubble), keyed by `localId → message_id` association held client-side.

**Paging/cache assertions.** `FakeMessageDao` is the source of truth for `RemoteMediator`-style reconciliation; tests assert that a network page upserts without duplicating cached rows and that reverse order is preserved. Date separators and sender grouping are verified as derived properties computed from the message list against the fixed `Clock`, not as persisted fields.

## 7. Error Handling & Resilience

Although this is a test ticket, its primary value is proving the messaging layer's resilience behavior:

- **Send failure → Failed + retry.** Force `sendBehavior` to return `NetworkError.Timeout`; assert row becomes `Failed`, the optimistic bubble persists (not dropped), and `retry(localId)` re-issues exactly one `POST` and resolves to `Sent`.
- **List/thread load failure.** `getConversations`/`getMessages` returning `Failure` yields `UiState.Error(retryable = true)`; a subsequent successful call transitions to `Content`.
- **Backoff/timeout policy is GET-only.** Tests assert idempotent GETs may be retried by the network layer but that `POST /messages` is **never** auto-retried by the repository (only via explicit user `retry`) — guarded by asserting `FakeMessagingApi.sent.size == 1` after a single failed send.
- **Stale/offline.** With network `Failure` but seeded `FakeMessageDao`, the thread test asserts cached messages still render (stale content) rather than an empty error screen.
- **Malformed `detail`.** Error-mapping tests confirm each `detail` variant produces a non-crashing, human-readable message string.

Determinism is enforced by `StandardTestDispatcher` + fixed `Clock`; no real delays, no real timeouts, no `Thread.sleep`.

## 8. Security & Privacy

No production security surface is added. Test-specific concerns:

- **No secrets / no live calls.** Fixtures are synthetic; no real cookies, `ui_csrf` tokens, credentials, or PII appear in committed JSON. Tests must not read environment auth or contact `18.222.237.167`. A CI guard fails the build if any messaging test opens a socket (no network permission in the JVM test sandbox; assert via fakes only).
- **Cookie/CSRF auth out of scope here.** Cookie-jar and `X-CSRF-Token` / `/ui/session/refresh` behavior is owned and tested by the auth/network tickets; messaging tests assume an authenticated `MessagingApi` and do not duplicate that coverage.
- **Log hygiene assertion.** A test verifies that message `body` text is not emitted into any telemetry payload captured by the fake logger (see §10), protecting message content as private.

## 9. Accessibility & i18n

No new shipping UI, so no new a11y or localized surface is introduced. However, the Compose UI tests **assert existing a11y contracts** so regressions are caught headlessly:

- Send button exposes a non-empty `contentDescription`; located by `onNodeWithContentDescription("Send")` (string from resources, not hardcoded English literals — tests resolve via `context.getString`).
- Failed-message retry control is reachable by content description and is a focusable, clickable node.
- Message list items expose merged semantics (sender + body + timestamp) for screen readers; a test asserts the merged semantics node exists.

No new strings are added; tests reference existing `R.string` ids so i18n coverage stays with the feature tickets.

## 10. Telemetry & Logging

This ticket introduces a `FakeAnalyticsLogger`/`FakeEventSink` in `core-testing` and uses it to assert (not produce) telemetry from the messaging layer:

- `message_sent` event is recorded once per successful send, with `conversation_id` and `message_type` but **without** `body` (privacy assertion from §8).
- `message_send_failed` recorded once on failure with an error category, not raw exception text.
- No duplicate analytics on reconciliation (ack must not double-count).

Test logging itself uses Robolectric's `ShadowLog`/JUnit output; failures print the captured `UiState` emission list and the `FakeMessagingApi.sent` log to make CI failures diagnosable.

## 11. Testing Strategy

**Frameworks:** JUnit4, Robolectric (Compose-on-JVM), Truth/AssertK assertions, Turbine for Flow, Coroutines `kotlinx-coroutines-test`, Paging 3 `androidx.paging:paging-testing`, MockK only where a fake is impractical. All in the `test` source set — **no `androidTest`**, so no instrumentation/emulator.

**Representative cases:**

| Area | Test | Asserts |
|---|---|---|
| Mappers | `mapsEverySubtypeWithoutLoss` | every modelled subtype round-trips from fixtures (bounded by the 16 backend `kind` values) |
| Mappers | `unknownKindFallsBackSafely` | unknown `kind` → `Message.Unknown` placeholder, no throw |
| Repo | `sendText_optimisticThenReconcile` | `Sending`→`Sent`, single row by `client_token` |
| Repo | `sendText_failure_marksFailed` | `Failed`, `sent.size == 1` |
| Repo | `retry_resendsFailed` | one new POST, resolves `Sent` |
| Repo | `messages_reverseOrderAndPaging` | order + cursor advance + dedupe |
| Repo | `staleCacheRendersOnNetworkFailure` | cached rows survive `Failure` |
| List VM | `emitsLoadingContentEmptyError` | full state sequence + unread sum |
| Thread VM | `historyLoadsAppendsAndGroups` | append + date/sender markers + scrollToBottom |
| UI | `composer_sendShowsOptimisticThenSent` | sending indicator → sent bubble |
| UI | `composer_failureShowsRetry` | retry control visible & clickable |

**Coverage gate:** target ≥ 85% line coverage on `MessagingRepository` and the two ViewModels (JaCoCo, reported in CI, advisory not blocking for this ticket).

**Headless command:** `./gradlew :core-data:testDebugUnitTest :feature-messaging:testDebugUnitTest` must pass on a runner with no emulator, ADB, or network.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** **AND-124** (send/optimistic/retry behavior) and **AND-126** (sealed model + mappers) — both are the direct subjects of this suite.
- **Transitive deps:** AND-120 (`MessagingApi` + DTOs), AND-122 (list VM + paging), AND-123 (thread screen) — their public types and UI must exist for tests to compile. Practically this ticket sequences after the whole E18 messaging-core slice (AND-120, AND-122, AND-123, AND-124, AND-126) is code-complete.
- **Shared infra:** `core-testing` `MainDispatcherRule`, fixture loader, and the new messaging fakes/`FakeAnalyticsLogger` introduced here. These fakes become reusable by later messaging tickets (media messages, reactions).
- **Blocks:** none listed; serves as a quality gate before subsequent M3 messaging features build on the core.

## 13. Risks & Open Questions

- **Robolectric Compose flakiness / SDK config.** Risk that Compose-on-Robolectric is unstable for the composer test. Mitigation: pin `@Config(sdk=[34])`, `qualifiers`, and a known-good Robolectric version; if a specific interaction can't run on Robolectric, isolate it as a thin `androidTest` smoke test gated out of the headless requirement (with sign-off).
- **Reconciliation key.** **Resolved during review:** the backend contract has no `client_token` (neither `SendTextMessageIn` nor `MessageOut` defines one) and the web `Message` model treats send/queue state as a purely client-side field (`__offline.status`). AND-124 must therefore use a **locally generated id** as the dedupe key and associate it with the returned `message_id` on ack; the optimistic-dedupe test is written against that. (Confirm AND-124 implements exactly this association rather than a server token.) **Open question narrowed for AND-124 owner.**
- **Unknown-kind fallback shape.** AND-126 must define the concrete fallback (`Message.Unknown` placeholder) for a `kind` outside the 16 known wire values; the mapper test asserts whichever is canonical. Note the discriminator is `kind`, not `type`. **Open question for AND-126 owner.**
- **Paging test API.** `Pager.flow.asSnapshot` requires `paging-testing`; ensure it's added to `core-testing`/test classpaths.
- **Clock injection.** If send-path time isn't injectable, date/timestamp assertions become flaky; resolve via the §4 test-seam refactor.

## 14. Acceptance Criteria

1. **Headless pass (binding backlog criterion).** `./gradlew :core-data:testDebugUnitTest :feature-messaging:testDebugUnitTest` completes green on a CI runner with no emulator, no ADB, and no network egress.
2. **Repo coverage.** Optimistic send, ack reconciliation (single row via `client_token`), failure→`Failed`, explicit `retry`, reverse-order paging with dedupe, and stale-cache-on-failure are each tested and passing.
3. **Mapper coverage.** Every modelled `Message` subtype maps losslessly from committed fixtures (one fixture per supported backend `kind`, drawn from the 16-member wire enum); unknown `kind` falls back to `Message.Unknown` without throwing.
4. **ViewModel coverage.** `ConversationListViewModel` asserts Loading/Content(+unread)/Empty/Error; `ThreadViewModel` asserts history load, append, date-separator + sender-group markers, and scroll-to-bottom signalling.
5. **Composer UI.** Compose (Robolectric) test shows optimistic sending bubble → reconciled sent bubble, and the failure→retry affordance.
6. **No-network guarantee.** No messaging test contacts `18.222.237.167` or opens a socket; all behavior is driven by `FakeMessagingApi`/`FakeMessageDao`.
7. **Telemetry/privacy.** Tests assert `message_sent`/`message_send_failed` fire correctly and that message `body` never appears in telemetry.
8. **Determinism.** Suite uses `StandardTestDispatcher` + fixed `Clock`; runs with no `Thread.sleep`/real delays and is stable across 10 consecutive CI runs.

## 15. Definition of Done

- All §14 criteria met; suite green in CI on `android-port`.
- New fakes/fixtures live in `core-testing` and `core-data/src/test/resources/fixtures/messaging/`, reusable by downstream messaging tickets.
- Any required test-seam refactors (Clock/`MessageIdGenerator` injection) merged with the owning feature tickets, with no behavior change to production code paths.
- Test names are descriptive and failures print diagnostic state (emission list + `sent` log).
- No new production strings, endpoints, or security surfaces introduced; sections genuinely N/A (new shipping UI/i18n strings) are explicitly delegated to AND-122/AND-123/AND-124.
- CI config runs the messaging tests as part of the standard `test` job with no device/emulator; documented in the module README test section.
- Code reviewed and merged; open questions in §13 resolved or tracked against AND-124/AND-126.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and the authoritative SOURCE. Sources are exact pointers: OpenAPI `METHOD /path` (and/or schema), frontend file path, or a framework ref URL.

1. **Conversation list endpoint is `GET /messaging/conversations` (cursor pagination).** VERIFIED. Source: OpenAPI `GET /messaging/conversations` (index line 312, op=`list_conversations`); `src/api/endpoints/messaging.ts: getConversations` (passes `{ cursor }`).
2. **Conversation list response key is `conversations` (or a bare array), NOT `items`; `next_cursor` for the wrapped shape.** CORRECTED. Source: `src/api/endpoints/messaging.ts: getConversations` (`res.conversations ?? []`, handles array-or-object). OpenAPI lists `resp=200:` with no named schema for this route (index line 312), so the array/object duality comes from the frontend contract.
3. **`ConversationOut` identifier is `conversation_id` (not `id`); has `title`, `unread_count`, `last_message`, `last_message_preview`, `last_message_at`, integer-epoch `created_at`.** CORRECTED. Source: OpenAPI schema `ConversationOut` (`components.schemas.ConversationOut`, properties `conversation_id`, `title`, `unread_count`, `last_message`, `last_message_at`, `created_at: integer`); `src/api/types.ts: Conversation` (lines 775–806).
4. **Thread/messages history is `GET /messaging/conversations/{conversation_id}/messages`, cursor passed as the `before` query param.** CORRECTED (spec used `cursor` and a `/conversations/...` path without the `/messaging` prefix). Source: OpenAPI `GET /messaging/conversations/{conversation_id}/messages` (index line 332, `params=conversation_id,limit,before,...`); `src/api/endpoints/messaging.ts: getMessages` (sends `{ before: cursor }`).
5. **Messages list response key is `messages` (or a bare array), NOT `items`.** CORRECTED. Source: `src/api/endpoints/messaging.ts: getMessages` (`res.messages ?? []`).
6. **Send text message is `POST /messaging/conversations/{conversation_id}/messages`, request `SendTextMessageIn`, response HTTP 200 `MessageOut`.** CORRECTED (spec claimed 201 and an unprefixed path). Source: OpenAPI `POST /messaging/conversations/{conversation_id}/messages` (index line 333, op=`send_text_message`, `resp=200:MessageOut`); `src/api/endpoints/messaging.ts: sendTextMessage`.
7. **Send request primary text field is `text` (max 4000), NOT `body`; there is no `type` and no `client_token` in the request.** CORRECTED. Source: OpenAPI schema `SendTextMessageIn` (`text` with maxLength 4000; a nullable legacy `body` also exists; no `type`/`client_token` properties); `src/api/types.ts: SendTextMessageReq` (lines 1249–1264 — `text?`, no `type`/`client_token`).
8. **`MessageOut` identifier is `message_id` (not `id`); required fields are `conversation_id, message_id, sender_id, created_at, kind`; `created_at` is integer epoch (not ISO string).** CORRECTED. Source: OpenAPI schema `MessageOut` (`required: [conversation_id, message_id, sender_id, created_at, kind]`, `created_at: integer`); `src/api/types.ts: Message` (lines 1098–1103, `message_id`, `created_at: number`).
9. **Message type discriminator is `kind` (not `type`), a 16-member enum: text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail, countdown, gif, sticker, find_datetime. No `poll` or `system` wire kind.** CORRECTED (spec listed 11 subtypes incl. `poll`/`system`). Source: OpenAPI schema `MessageOut.kind` enum; `src/api/types.ts: Message.kind` (line 1102).
10. **`MessageOut` carries no server `status` and no `client_token`; send/queue state is client-side only.** CORRECTED. Source: OpenAPI `MessageOut` (no `status`/`client_token` properties — confirmed by full-property scan of the schema); `src/api/types.ts: Message.__offline.status: "pending"|"sending"|"failed"` (lines 1226–1232) is a client-only field. This invalidates the spec's prior assumption that ack reconciliation keys off a round-tripped `client_token`.
11. **Messaging config is `GET /messaging/config` (not `/config`).** CORRECTED. Source: `src/api/endpoints/messaging.ts: getMessagingConfig` (`api.get("/messaging/config")`).
12. **Auth/CSRF: cookie-based session with `ui_csrf` cookie echoed as `X-CSRF-Token`, `credentials: "include"`, refresh via `/ui/session/refresh`.** VERIFIED (spec correctly scopes this out to auth/network tickets). Source: `src/api/client.ts` (getCookie `ui_csrf` → `headers.set("X-CSRF-Token", ...)` lines 167–170; `credentials: "include"` lines 183/220; `/ui/session/refresh` line 122).
13. **422 validation error shape is FastAPI `HTTPValidationError` = `{"detail":[{"loc":[...],"msg":...,"type":...}]}` with `loc/msg/type` all required.** VERIFIED (spec's fixture was structurally close but omitted the required `type` and likely uses `loc: ["body","text"]`). Source: OpenAPI schemas `HTTPValidationError` + `ValidationError` (`required: [loc, msg, type]`).
14. **Messaging endpoints also advertise bare `400/401/403/429` with no documented body schema, so the mapper must tolerate non-default `detail` shapes (string and object).** VERIFIED for the status codes; the specific `{"detail":"Not found"}` / `{"detail":{"code":"rate_limited"}}` bodies are UNVERIFIED-ASSUMPTION (no body schema is published for those codes). Source: OpenAPI index lines 312/332/333 (`resp=...;400;401;403;429`).
15. **Offline/cache behavior: the web client wraps list + thread reads in an offline cache (`withOfflineCache`) keyed by user + URL, and queues sends offline.** VERIFIED as the web contract that motivates the Android stale-cache test. Source: `src/api/endpoints/messaging.ts: getConversations`/`getMessages` (`withOfflineCache(...)`); `src/api/types.ts: Message.__offline` queue metadata.
16. **Robolectric runs Compose UI tests on the JVM with no device, configured via `@Config(sdk=[...])`.** VERIFIED (framework ref). Source: Robolectric docs https://robolectric.org/ and AndroidX Compose testing https://developer.android.com/develop/ui/compose/testing (framework ref).
17. **Paging 3 list snapshots are materialized headlessly via `androidx.paging:paging-testing` (`asSnapshot { }` / `AsyncPagingDataDiffer`).** VERIFIED (framework ref). Source: https://developer.android.com/reference/kotlin/androidx/paging/testing/package-summary (framework ref).
18. **Coroutine determinism via `kotlinx-coroutines-test` `StandardTestDispatcher` + `runTest` + `advanceUntilIdle()`.** VERIFIED (framework ref). Source: https://github.com/Kotlin/kotlinx.coroutines/blob/master/kotlinx-coroutines-test/README.md (framework ref).

### Corrections made

- **§2 / §5:** prefixed all messaging routes with `/messaging` (was `/conversations/...`, `/config`).
- **§5:** send response status corrected to **200** (was 201).
- **§5:** request text field corrected to `text` (was `body`); removed nonexistent request `type`/`client_token`.
- **§5 / §6 / §1 / §FR-1:** server message identifier corrected to `message_id` (was `id`); timestamps are integer epoch (was ISO-8601 strings).
- **§5:** list-response wrapper keys corrected to `conversations` / `messages` (was `items`); thread cursor param is `before` (was `cursor`).
- **§FR-2 / §11 / §14.3 / §2 / §1:** message discriminator corrected to `kind`; subtype count corrected from 11 to the real 16-member backend enum; removed nonexistent `poll`/`system` wire kinds.
- **§6 / §7 / §13 / §FR-1:** removed the false premise that `client_token` round-trips through the API; reconciliation re-specified as client-side `localId → message_id`. `SendStatus` clarified as client-side only.
- **§5:** FastAPI 422 fixture corrected to include the required `type` field and `loc: ["body","text"]`.

### Open assumptions

- **Array-vs-object response duality.** The exact production shape of the list endpoints (bare array vs `{conversations|messages, next_cursor}`) is not pinned by OpenAPI (those routes publish `resp=200:` with no schema); we rely on the frontend handling both. Fakes/fixtures must cover both shapes. (Why unverifiable: no response schema in the OpenAPI for these two routes.)
- **`AND-120 MessagingApi` Kotlin surface.** The Android `MessagingApi`/DTO names (`ConversationPageDto`, `MessagePageDto`, `SendMessageRequest`, etc.) used in §4 are this ticket's projected naming; they must match whatever AND-120 actually defines. Unverifiable here (AND-120 source not in this repo snapshot).
- **AND-126 sealed-model member set.** Whether AND-126 collapses the 16 wire kinds into fewer sealed subtypes (and the exact `Message.Unknown` fallback name) is owned by AND-126; the mapper test binds to whatever it defines. (Why unverifiable: AND-126 model not in snapshot.)
- **Error bodies for 400/401/403/429.** Concrete bodies for these codes are not published; the `{"detail": "..."}` / `{"detail": {...}}` tolerant fixtures are assumptions about defensive parsing, not documented contracts.
- **`MessageOut` lacks a server `status`/read-receipt-on-send.** Delivery/read state on individual messages is expressed via separate fields/endpoints (`read_by_user_ids`, `markRead`, `markViewed`), not a single `status` enum; the optimistic `SendStatus` is purely a local UI concept.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device); **Emulator(test35)** = headless AVD, x86_64, API 35; **Device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), Android 14 / API 34, arm64-v8a. This is a headless test ticket, so the great majority run on **JVM**; instrumented variants are noted only where they add value.

- **TC-AND-128-01 — Mapper round-trips every supported `kind`.** Type: unit. Target: JVM. Preconditions: one committed fixture per supported backend `kind` under `core-data/src/test/resources/fixtures/messaging/`. Steps: load each fixture, run `MessageMapper.fromDto`, re-serialize/assert field equality. Expected: every fixture maps without loss; `message_id`/`kind`/`created_at`(epoch)/`sender_id`/`text` and kind-specific payloads preserved. Traces: AC-3.
- **TC-AND-128-02 — Unknown `kind` falls back safely.** Type: unit. Target: JVM. Preconditions: `message_unknown_kind.json` with `kind:"__future__"`. Steps: map it. Expected: returns `Message.Unknown` placeholder, no exception. Traces: AC-3.
- **TC-AND-128-03 — Optimistic send then reconcile.** Type: unit (repository). Target: JVM. Preconditions: `FakeMessagingApi.sendBehavior = success(MessageOut)`, `FakeMessageDao` empty, fixed `Clock`, `StandardTestDispatcher`. Steps: `sendText(c_1,"hello")`; collect row states; `advanceUntilIdle()`. Expected: row appears `Sending` keyed by `localId`, then becomes `Sent` carrying server `message_id`/`created_at`; request body sent was `{"text":"hello"}`; exactly one row. Traces: AC-2.
- **TC-AND-128-04 — Ack + subsequent page does not duplicate.** Type: unit (repository). Target: JVM. Preconditions: after TC-03 ack, seed a network page from `getMessages` that includes the same `message_id`. Steps: load page, reconcile into Room. Expected: exactly one row for that message (dedupe via `localId → message_id` association); no duplicate bubble. Traces: AC-2.
- **TC-AND-128-05 — Send failure marks Failed and is not auto-retried.** Type: unit (repository). Target: JVM. Preconditions: `sendBehavior = Failure(NetworkError.Timeout)`. Steps: `sendText`; `advanceUntilIdle()`. Expected: row becomes `Failed`, optimistic bubble persists (not dropped), `FakeMessagingApi.sent.size == 1` (POST never auto-retried). Traces: AC-2, AC-6.
- **TC-AND-128-06 — Explicit retry re-sends exactly once and resolves Sent.** Type: unit (repository). Target: JVM. Preconditions: a `Failed` row from TC-05, then `sendBehavior = success`. Steps: `retry(localId)`; `advanceUntilIdle()`. Expected: one new POST (`sent.size == 2` total), row resolves to `Sent` with server `message_id`. Traces: AC-2.
- **TC-AND-128-07 — Reverse-order paging with `before` cursor + dedupe.** Type: unit (repository). Target: JVM. Preconditions: `FakeMessagingApi` seeded with two overlapping pages keyed by `before`. Steps: load page 1, then page 2 using returned `next_cursor` as `before`. Expected: messages in reverse-chronological order, cursor advances, overlapping `message_id` rows upsert without duplication. Traces: AC-2.
- **TC-AND-128-08 — Stale cache renders on network failure (offline path).** Type: unit (repository). Target: JVM. Preconditions: `FakeMessageDao` seeded with cached messages; `getMessages` returns `Failure`. Steps: open thread. Expected: cached rows render (stale content), not an empty/error screen; UI state is not a hard `Error` when cache is non-empty. Traces: AC-2.
- **TC-AND-128-09 — Conversation list ViewModel state sequence.** Type: unit (ViewModel). Target: JVM. Preconditions: `FakeMessagingApi` programmable; Turbine on `StateFlow`. Steps: drive empty → seeded → failure cases. Expected: emits `Loading` → `Content(totalUnread = Σ unread_count)` with sorted items; `Empty` when none; `Error(retryable=true)` on `Failure`, recovering to `Content` after a successful retry. Traces: AC-4.
- **TC-AND-128-10 — Thread ViewModel: history, append, derived markers, scroll-to-bottom.** Type: unit (ViewModel). Target: JVM. Preconditions: seeded history + fixed `Clock`. Steps: load history; send a message; inspect derived list + `scrollToBottom` signal. Expected: history loads reverse-paged; newly sent message appends; date-separator and sender-group markers present (computed against fixed `Clock`); `scrollToBottom` emitted once on send. Traces: AC-4.
- **TC-AND-128-11 — Composer UI: optimistic bubble then sent (Compose).** Type: Compose-UI (Robolectric). Target: JVM (Robolectric, `@Config(sdk=[34])`). Preconditions: screen wired to fakes; `sendBehavior` = delayed success. Steps: `performTextInput("hello")`, click send. Expected: sending indicator bubble shows, then reconciles to a sent bubble after ack; input cleared. Traces: AC-5.
- **TC-AND-128-12 — Composer UI: failure shows retry affordance (Compose).** Type: Compose-UI (Robolectric). Target: JVM. Preconditions: `sendBehavior = Failure`. Steps: type + send. Expected: bubble shows failed state with a retry control that is visible, focusable, and clickable; clicking it re-issues the send. Traces: AC-5, AC-2.
- **TC-AND-128-13 — Error-body tolerance (string/object/422 detail).** Type: contract/MockWebServer. Target: JVM (MockWebServer; no real host). Preconditions: enqueue `422 {"detail":[{"loc":["body","text"],"msg":"...","type":"..."}]}`, `404 {"detail":"Not found"}`, `429 {"detail":{"code":"rate_limited"}}`. Steps: drive the error mapper for each. Expected: each produces a non-crashing, human-readable message; `retryable` flags set appropriately (429 retryable, 422 not). Traces: AC-2, AC-7.
- **TC-AND-128-14 — Telemetry + privacy + no-network guarantee.** Type: unit. Target: JVM. Preconditions: `FakeAnalyticsLogger`; a CI/socket guard asserting no socket is opened. Steps: perform a successful send and a failed send. Expected: `message_sent` recorded once (with `conversation_id`, `message_type`, **without** `body`/`text`); `message_send_failed` once with an error category; no analytics double-count on reconcile; no test contacts `18.222.237.167` / opens a socket. Traces: AC-6, AC-7.
- **TC-AND-128-15 — Accessibility semantics of messaging UI (Compose).** Type: Compose-UI/accessibility (Robolectric). Target: JVM. Preconditions: thread + composer rendered. Steps: query semantics tree. Expected: Send button has non-empty `contentDescription` resolved from `R.string` (via `context.getString`, not a hardcoded literal); failed-retry control reachable by content description and clickable; a list item exposes merged semantics (sender + body + timestamp). Traces: AC-5.
- **TC-AND-128-16 — Headless suite green with no device/network (gate).** Type: integration (Gradle). Target: JVM (CI runner, no emulator/ADB/network). Steps: run `./gradlew :core-data:testDebugUnitTest :feature-messaging:testDebugUnitTest`. Expected: all of the above pass; suite stable across 10 consecutive runs (determinism). Traces: AC-1, AC-8.
- **TC-AND-128-17 — (Optional, hardware sanity) Composer smoke on real device.** Type: instrumented/e2e. Target: **Device(A15)** — MUST run on the physical device (real input method + arm64-v8a / API-34 vs the API-35 emulator). Preconditions: only used if a composer interaction proves unstable under Robolectric (see §13 risk). Steps: type + send against `FakeMessagingApi` in an instrumented harness. Expected: optimistic→sent transition behaves identically to TC-11; confirms no arm64/API-34 regression. Note: NOT part of the headless gate; gated out with sign-off. Traces: AC-5.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 Headless pass (gate) | TC-16 |
| AC-2 Repo coverage (optimistic/ack/fail/retry/paging/stale) | TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-12, TC-13 |
| AC-3 Mapper coverage | TC-01, TC-02 |
| AC-4 ViewModel coverage | TC-09, TC-10 |
| AC-5 Composer UI | TC-11, TC-12, TC-15, TC-17 |
| AC-6 No-network guarantee | TC-05, TC-14 |
| AC-7 Telemetry/privacy | TC-13, TC-14 |
| AC-8 Determinism (10× stable) | TC-16 (all unit/Compose TCs run under `StandardTestDispatcher` + fixed `Clock`) |
