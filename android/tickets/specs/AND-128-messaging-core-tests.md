---
id: AND-128
title: Messaging core tests
milestone: M3
epic: E18
priority: P1
size: M
status: draft
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
  - **AND-120** — `MessagingApi` + DTOs for `/messaging/conversations`, `/conversations/{id}`, `/conversations/{id}/messages`, `/config`.
  - **AND-122** — `ConversationListViewModel`, Paging 3 source, unread aggregation, sort.
  - **AND-123** — Thread screen: reverse-paged history, date separators, sender grouping, scroll-to-bottom.
  - **AND-124** *(dependency)* — Composer; `POST /conversations/{id}/messages`; optimistic send + failure retry.
  - **AND-126** *(dependency)* — sealed message model (text/image/video/file/voice/gif/sticker/poll/countdown/calendar/system) + mappers.
- **Web reference (fixture source of truth):** `frontend/src/api/endpoints/*.ts` and shared types in `frontend/src/api/types.ts`; backend OpenAPI at `http://18.222.237.167:8000/openapi.json`. Fixtures are captured once and committed; tests never hit the live dev host.
- **Shared test infra:** `core-testing` provides `MainDispatcherRule`, `TurbineExt`, JSON fixture loaders, and base fakes. This ticket extends those with messaging-specific fakes.

This is a test-only ticket. No new production source is authored here except, where a seam is missing, small **test-visibility** refactors (e.g. constructor-injecting a `MessageIdGenerator` or `Clock`) coordinated with the owning feature ticket.

## 3. Functional Requirements

**FR-1 — Repository tests (`core-data`).** Cover `MessagingRepository`:
- `conversations(): Flow<PagingData<Conversation>>` emits mapped, sorted conversations with correct unread aggregation (AND-122).
- `messages(conversationId): Flow<PagingData<Message>>` returns reverse-chronological pages; cursor pagination advances; cache (Room) and network are reconciled (AND-123).
- `sendText(conversationId, body): ApiResult<Message>` inserts an optimistic `Message` with `status = Sending`, issues `POST`, and on success updates the row to the server message (`status = Sent`, server `id`/`createdAt`); on failure marks it `Failed` and the row remains retryable (AND-124).
- `retry(localId)` re-sends a `Failed` message.

**FR-2 — Mapper tests (`core-data`/`core-model`).** Every sealed `Message` subtype from AND-126 — `Text`, `Image`, `Video`, `File`, `Voice`, `Gif`, `Sticker`, `Poll`, `Countdown`, `Calendar`, `System` — maps from its DTO without loss, and an unknown `type` falls back to a safe `Message.Unknown`/`System` placeholder rather than throwing.

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

This ticket consumes the AND-120 contract through fakes; it defines no new endpoints. The fixtures encode the real shapes the fakes and mappers are validated against.

`GET /messaging/conversations?cursor=&limit=20`
```json
{
  "items": [
    {"id": "c_1", "title": "Alice", "unread_count": 3,
     "last_message": {"id": "m_9", "type": "text", "preview": "hey",
                      "created_at": "2026-06-04T18:22:00Z"},
     "updated_at": "2026-06-04T18:22:00Z"}
  ],
  "next_cursor": "eyJrIjoiYyJ9"
}
```

`GET /conversations/{id}/messages?cursor=&limit=30` (reverse-chronological page):
```json
{
  "items": [
    {"id": "m_9", "conversation_id": "c_1", "type": "text",
     "sender_id": "u_2", "body": "hey", "created_at": "2026-06-04T18:22:00Z",
     "status": "sent"}
  ],
  "next_cursor": null
}
```

`POST /conversations/{id}/messages` — request / 201 response:
```json
{ "type": "text", "client_token": "loc_a1b2", "body": "hello" }
```
```json
{ "id": "m_10", "conversation_id": "c_1", "type": "text", "sender_id": "u_self",
  "body": "hello", "client_token": "loc_a1b2", "created_at": "2026-06-05T00:00:01Z",
  "status": "sent" }
```

Mapper fixtures include one file per `Message` subtype (`message_text.json` … `message_system.json`) plus `message_unknown_type.json`. Error fixtures cover the FastAPI `detail` variants the messaging layer must tolerate: `{"detail":"Not found"}`, `{"detail":[{"msg":"field required","loc":["body","body"]}]}`, and `{"detail":{"code":"rate_limited"}}`. These are exercised against the AND-120 DTO/error mapping, not re-implemented here.

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

**Optimistic send state machine (core assertion target).** Tests pin every transition: `(absent) → Sending` on `sendText`; `Sending → Sent` after fake ack updating row to server `id`/`createdAt`; `Sending → Failed` on `ApiResult.Failure`; `Failed → Sending → Sent` on `retry`. The `client_token` (local id) must be the reconciliation key so no duplicate bubble appears after ack — a dedicated test seeds the server message carrying the same `client_token` and asserts exactly one row remains.

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
| Mappers | `mapsEverySubtypeWithoutLoss` | all 11 subtypes round-trip from fixtures |
| Mappers | `unknownTypeFallsBackSafely` | unknown `type` → placeholder, no throw |
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
- **Reconciliation key.** Confirm AND-124 actually uses `client_token` (vs. local UUID) as the dedupe key; the optimistic-dedupe test depends on it. **Open question for AND-124 owner.**
- **Unknown-type fallback shape.** AND-126 must define the concrete fallback (`Message.Unknown` vs. coerced `System`); the mapper test asserts whichever is canonical. **Open question for AND-126 owner.**
- **Paging test API.** `Pager.flow.asSnapshot` requires `paging-testing`; ensure it's added to `core-testing`/test classpaths.
- **Clock injection.** If send-path time isn't injectable, date/timestamp assertions become flaky; resolve via the §4 test-seam refactor.

## 14. Acceptance Criteria

1. **Headless pass (binding backlog criterion).** `./gradlew :core-data:testDebugUnitTest :feature-messaging:testDebugUnitTest` completes green on a CI runner with no emulator, no ADB, and no network egress.
2. **Repo coverage.** Optimistic send, ack reconciliation (single row via `client_token`), failure→`Failed`, explicit `retry`, reverse-order paging with dedupe, and stale-cache-on-failure are each tested and passing.
3. **Mapper coverage.** All 11 `Message` subtypes map losslessly from committed fixtures; unknown `type` falls back without throwing.
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
