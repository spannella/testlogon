---
id: AND-165
title: Groups/helpdesk tests
milestone: M3
epic: E22
priority: P2
size: M
status: draft
depends_on: [AND-158, AND-162]
blocks: []
---

# AND-165 — Groups/helpdesk tests

## 1. Overview & Goal

This ticket delivers the automated test coverage for the two M3/E22 feature
slices that ship the group-participant management flow (AND-158) and the
helpdesk claim+reply flow (AND-162). It is a **Test** ticket: no production
behavior changes. The deliverable is a set of fast, deterministic JVM unit/
repository tests plus Compose UI (instrumentation-style, Robolectric-backed)
tests that lock in the contracts already implemented upstream and guard them
against regression.

Goal: prove that (a) the group participants repository correctly performs
`PATCH`/`DELETE` membership mutations and that membership changes persist and
re-emit through the cached `StateFlow`, and (b) the helpdesk repository and
screen correctly drive the `claim → reply` happy path and surface
claim/assignee error codes to the UI. Success is defined narrowly by the
source acceptance bullet — **"Tests pass"** — interpreted as: the new test
suites compile, run green in CI on the `android-port` branch, and assert the
behaviors enumerated in §3 with meaningful (not trivially-passing) assertions.

## 2. Context & References

- Source ticket: AND-165 — Type: Test · Priority: P2 · Deps: AND-158, AND-162.
  Scope: "Repo + UI tests." Acceptance: "Tests pass."
- AND-158 (Group participants management): participants add/remove/role via
  `PATCH`/`DELETE`; acceptance "Membership changes persist + reflect."
- AND-162 (Helpdesk claim + reply): `POST /helpdesk/conversations/{id}/claim`
  + reply; "handle claim/assignee error codes"; acceptance "Claim→reply works;
  claim errors surface correctly."
- Module layering under test: `feature-groups`, `feature-helpdesk` →
  `core-data` (repositories), `core-network` (Retrofit services, `ApiResult`),
  `core-model`, `core-ui`. Test utilities live in `core-testing`.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT,
  unreliable). Tests MUST NOT hit the live host; all network is faked via
  MockWebServer or fake services. OpenAPI at `/openapi.json` is the contract
  reference for fixture JSON.
- Auth/CSRF (`X-CSRF-Token`, cookie jar, 401→refresh→retry) is owned by the
  network layer and exercised by its own tests; this ticket only asserts that
  group/helpdesk repos propagate the typed results, not the transport itself.

## 3. Functional Requirements

The test code itself is the requirement. The suites MUST assert:

**Group participants (repo + UI):**
1. `addParticipant` issues the correct write call and, on `2xx`, the new member
   appears in the next `participants(groupId)` `StateFlow` emission.
2. `updateParticipantRole` (PATCH) changes a member's role; the change is
   reflected in cache and re-emitted.
3. `removeParticipant` (DELETE) removes the member; subsequent emission no
   longer contains it; Room cache row is deleted.
4. Mutations are optimistic-safe: on a non-2xx response the cached list is
   restored to its pre-mutation state (no phantom member) and an error
   `ApiResult` is returned.
5. UI: the participants screen renders the member list, role chips, and an
   add/remove affordance; performing an add updates the rendered list.

**Helpdesk (repo + UI):**
6. `claim(conversationId)` issues `POST /helpdesk/conversations/{id}/claim`,
   and on success the conversation's `assignee`/`status` reflects the current
   agent.
7. `reply(conversationId, body)` after a successful claim appends the message
   and re-emits the thread.
8. Claim error codes (`already_claimed`, `claimed_by_other`, `not_assignable`)
   map to distinct, asserted `HelpdeskError` values surfaced in `UiState`.
9. UI: claiming a conversation transitions the reply composer from
   disabled→enabled; a claim conflict shows the mapped error message and keeps
   the composer disabled.

Out of scope: changing any production logic in AND-158/AND-162; backend tests;
end-to-end tests against the live dev host.

## 4. Technical Design

Tests are split by tier and module, all run from the `android-port` branch.

**Test source sets**
- JVM unit/repository tests: `feature-groups/src/test`,
  `feature-helpdesk/src/test`, `core-data/src/test`.
- Compose UI tests (Robolectric, `@RunWith(RobolectricTestRunner)` via the
  `robolectric` Gradle test option `unitTests.includeAndroidResources = true`):
  `feature-groups/src/test` and `feature-helpdesk/src/test` UI packages, so
  they execute on the JVM in CI without a device. Heavier flows that need a
  real device may additionally be placed in `src/androidTest` but are NOT
  required for "Tests pass" in CI.

**Shared harness (`core-testing`)**
```kotlin
// core-testing: deterministic dispatcher rule
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

// MockWebServer wiring that mirrors core-network's Retrofit/Moshi config
object TestApi {
    fun <T> service(klass: Class<T>, server: MockWebServer): T =
        Retrofit.Builder()
            .baseUrl(server.url("/"))
            .addConverterFactory(MoshiConverterFactory.create(TestMoshi.instance))
            .client(OkHttpClient.Builder().build())
            .build()
            .create(klass)
}

fun enqueueJson(server: MockWebServer, code: Int, body: String) =
    server.enqueue(MockResponse().setResponseCode(code).setBody(body))
```

**Room under test** uses `Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`
seeded per-test; flows collected with Turbine.

**Service interfaces exercised (already defined upstream):**
```kotlin
interface GroupService {
    @POST("groups/{id}/participants")
    suspend fun addParticipant(
        @Path("id") groupId: String,
        @Body req: AddParticipantRequest,
    ): Response<ParticipantDto>

    @PATCH("groups/{id}/participants/{userId}")
    suspend fun updateParticipant(
        @Path("id") groupId: String,
        @Path("userId") userId: String,
        @Body req: UpdateRoleRequest,
    ): Response<ParticipantDto>

    @DELETE("groups/{id}/participants/{userId}")
    suspend fun removeParticipant(
        @Path("id") groupId: String,
        @Path("userId") userId: String,
    ): Response<Unit>
}

interface HelpdeskService {
    @POST("helpdesk/conversations/{id}/claim")
    suspend fun claim(@Path("id") id: String): Response<ConversationDto>

    @POST("helpdesk/conversations/{id}/messages")
    suspend fun reply(
        @Path("id") id: String,
        @Body req: ReplyRequest,
    ): Response<MessageDto>
}
```

**Repository signatures under test:**
```kotlin
class GroupParticipantsRepository @Inject constructor(
    private val service: GroupService,
    private val dao: ParticipantDao,
) {
    fun participants(groupId: String): Flow<List<Participant>>
    suspend fun addParticipant(groupId: String, userId: String, role: Role): ApiResult<Participant>
    suspend fun updateRole(groupId: String, userId: String, role: Role): ApiResult<Participant>
    suspend fun removeParticipant(groupId: String, userId: String): ApiResult<Unit>
}

class HelpdeskRepository @Inject constructor(
    private val service: HelpdeskService,
    private val dao: ConversationDao,
) {
    suspend fun claim(id: String): ApiResult<Conversation>
    suspend fun reply(id: String, body: String): ApiResult<Message>
}
```

Tests assert against these contracts; if a signature differs at implementation
time the test mirrors the actual upstream symbol (the repo build is the source
of truth — these are the expected shapes from AND-158/AND-162).

## 5. API Contract

No new endpoints are introduced; this ticket only **asserts** the existing
contracts. Canonical fixtures (validated against `/openapi.json`) used by the
suites:

Add participant — `POST /groups/{id}/participants`:
```json
// request
{ "user_id": "u_42", "role": "member" }
// 201 response
{ "user_id": "u_42", "display_name": "Ada L.", "role": "member", "joined_at": "2026-06-05T12:00:00Z" }
```

Update role — `PATCH /groups/{id}/participants/{userId}`:
```json
{ "role": "admin" }
// 200 -> { "user_id": "u_42", "display_name": "Ada L.", "role": "admin", ... }
```

Remove — `DELETE /groups/{id}/participants/{userId}` → `204` empty body.

Claim — `POST /helpdesk/conversations/{id}/claim`:
```json
// 200 success
{ "id": "c_7", "status": "open", "assignee_id": "agent_self", "subject": "Cannot log in" }
```
Claim error envelope (FastAPI `detail`, mapped per the project's
`string | [{msg}] | {code,...}` rule):
```json
// 409 -> already claimed by self
{ "detail": { "code": "already_claimed" } }
// 409 -> claimed by another agent
{ "detail": { "code": "claimed_by_other", "assignee_id": "agent_99" } }
// 422 -> not assignable
{ "detail": [{ "msg": "conversation not assignable", "type": "not_assignable" }] }
```

Reply — `POST /helpdesk/conversations/{id}/messages`:
```json
{ "body": "Try resetting your password." }
// 201 -> { "id": "m_3", "conversation_id": "c_7", "author_id": "agent_self", "body": "...", "created_at": "..." }
```

The suite includes one `detail`-parsing test per shape (plain string, list-of-
objects, single object) to confirm the shared error mapper resolves the
expected `HelpdeskError`/generic message.

## 6. Data & State Management

- **Persistence assertions:** group tests verify Room rows in
  `participant` table after each mutation (insert on add, update on role
  change, delete on remove) by querying the in-memory `ParticipantDao`
  directly, satisfying AND-158's "persist + reflect."
- **Flow re-emission:** Turbine collects `participants(groupId)` and asserts
  the ordered emissions: initial → post-mutation. `awaitItem()` count and
  contents are asserted; `cancelAndIgnoreRemainingEvents()` closes the flow.
- **ViewModel state:** UI tests drive real ViewModels with fake repos and
  assert successive `StateFlow<UiState>` values:
  `Loading → Content(...) → Content(updated)` for groups, and
  `Content(canReply=false) → Content(canReply=true)` after claim for helpdesk.
- **Determinism:** `StandardTestDispatcher` + `runTest`/`advanceUntilIdle()`
  control coroutine scheduling; no real clocks (timestamps come from fixtures);
  no `Thread.sleep`.
- **Cache seeding:** each repository test seeds the in-memory Room DB with a
  known baseline (e.g. a two-member group, or a single unclaimed conversation)
  via the DAO before invoking the repo, so that the pre-mutation `StateFlow`
  emission is well-defined and the post-mutation delta is unambiguous. Seeding
  goes through the same DAO insert paths the production sync uses, not raw SQL,
  to keep the fixture realistic.
- **State identity:** UI-state assertions compare against fully-constructed
  expected `UiState` instances (data classes with value equality) rather than
  field-by-field probing, which keeps the assertion resilient to field reorders
  and makes a regression report the entire offending state.

## 7. Error Handling & Resilience

This is a test ticket; resilience is what we assert, not implement:
- Non-2xx mutation responses (`409`, `422`, `500`) are enqueued and the suite
  asserts an `ApiResult.Error` (or domain error) is returned and the cache is
  unchanged / rolled back (FR-4).
- A simulated socket timeout (`MockResponse().setSocketPolicy(NO_RESPONSE)`
  with a short OkHttp read timeout in the test client) asserts the repo maps to
  a timeout/`NetworkError` rather than throwing — guarding the ~20s-timeout
  posture without waiting 20s in CI.
- Retry behavior is owned by `core-network` and is NOT re-tested here beyond
  confirming idempotent GET refresh isn't triggered by these write paths.

## 8. Security & Privacy

No new security surface. Tests MUST NOT embed real credentials, cookies, or the
dev host URL as a network target; MockWebServer uses an ephemeral localhost
port. A regression assertion confirms write requests carry the
`X-CSRF-Token` header when the test client is configured with a seeded
`ui_csrf` cookie (validating CSRF echo without contacting the backend). No PII
is logged by tests; fixture identities are synthetic (`u_42`, `agent_self`).

## 9. Accessibility & i18n

UI tests use `onNodeWithContentDescription` / `onNodeWithText` resolved through
string resources rather than hardcoded literals where practical, which
incidentally guards that interactive controls (add/remove buttons, reply send,
claim button) expose accessible labels and merged semantics. A focused test
asserts the claim button and reply composer have non-empty content
descriptions and correct `enabled` semantics. Full a11y audit is owned by the
respective feature tickets, not this one.

## 10. Telemetry & Logging

N/A for production telemetry — owned by the feature tickets. Test-side: failing
assertions emit descriptive messages (`assertThat(...).isEqualTo(...)` via
Truth) so CI logs pinpoint the contract that broke. No analytics events are
emitted or asserted.

## 11. Testing Strategy

**Frameworks:** JUnit4, Truth, Turbine, kotlinx-coroutines-test, MockWebServer,
MockK (for service/repo doubles where MockWebServer is overkill), Robolectric +
Compose `createComposeRule()`/`createAndroidComposeRule()`. All added as
`testImplementation` in the two feature modules and `core-data`.

**Representative cases:**

`GroupParticipantsRepositoryTest`
- `addParticipant_success_insertsRow_andReEmits`
- `updateRole_success_updatesRow_andReEmits`
- `removeParticipant_success_deletesRow_andReEmits`
- `addParticipant_serverError_rollsBackCache_returnsError`
- `removeParticipant_timeout_returnsNetworkError`

`HelpdeskRepositoryTest`
- `claim_success_setsAssigneeToSelf`
- `claim_alreadyClaimed_returnsAlreadyClaimedError`
- `claim_claimedByOther_returnsClaimedByOtherWithAssignee`
- `claim_notAssignable_returnsNotAssignable`
- `reply_afterClaim_appendsMessage`
- `detail_mapping_string_list_object_resolveCorrectly`

`GroupParticipantsScreenTest`
- `rendersMembers_withRoleChips`
- `addMember_updatesRenderedList`
- `removeMember_removesRow`

`HelpdeskConversationScreenTest`
- `unclaimed_composerDisabled`
- `claim_enablesComposer_andSendsReply`
- `claimConflict_showsMappedError_keepsComposerDisabled`

Sketch:
```kotlin
@Test
fun claim_alreadyClaimed_returnsAlreadyClaimedError() = runTest {
    enqueueJson(server, 409, """{"detail":{"code":"already_claimed"}}""")
    val result = repo.claim("c_7")
    assertThat(result).isInstanceOf(ApiResult.Error::class.java)
    assertThat((result as ApiResult.Error).error)
        .isEqualTo(HelpdeskError.AlreadyClaimed)
}

@Test
fun addMember_updatesRenderedList() {
    composeRule.setContent { GroupParticipantsScreen(state = contentState, on = noopActions) }
    composeRule.onNodeWithText("Ada L.").assertIsDisplayed()
    composeRule.onNodeWithContentDescription("Add participant").performClick()
    composeRule.onNodeWithText("Grace H.").assertIsDisplayed()
}
```

**Coverage target:** every public function on the two repositories and each
documented claim error code has at least one asserting test. CI gate: the new
modules' `test` task passes; no flaky-by-design constructs (no real time, no
network, fixed dispatcher).

**Negative/edge cases worth one test each:** empty group (participants flow
emits an empty list, screen shows the empty-state composable); duplicate add
(server `409 duplicate` → error, no second row); reply attempted before claim
in the repo layer (should still issue the request — gating is a UI concern —
but the UI test confirms the composer is disabled so no such call is made);
malformed `detail` (e.g. `{"detail": 123}`) falls back to a generic error
message rather than crashing the mapper.

**What is deliberately not tested here:** the cookie/CSRF transport, the
401→refresh→retry interceptor, Retrofit/Moshi wiring, and navigation graph
routing. Those belong to `core-network` and the host-app navigation tickets and
are covered by their own suites; duplicating them here would couple this gate to
unrelated changes.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-158 (group participants repo + screen) and AND-162
  (helpdesk claim/reply repo + screen) must be merged to `android-port`; their
  public symbols are the test targets. If either symbol set changes, this
  ticket's tests are updated in lockstep.
- **Transitive:** AND-157 (groups list/detail), AND-161 (helpdesk inbox) and
  the `core-network`/`core-testing` harness must exist.
- **Blocks:** nothing functional; this ticket is a CI quality gate and may
  block the M3 sign-off checklist for E22.
- **Sequencing:** land after both feature PRs; can be authored in parallel
  using the published signatures and merged once they're green.

## 13. Risks & Open Questions

- **Contract drift:** assumed DTO field names (`assignee_id`, `joined_at`,
  error `code` values) are derived from the project's FastAPI conventions and
  the web reference; verify against `/openapi.json` and the actual upstream
  DTOs when AND-158/AND-162 land. Adjust fixtures if names differ.
- **Robolectric vs androidTest:** if any Compose interaction (e.g. media or
  paging-backed list) doesn't run reliably under Robolectric, move that single
  case to `androidTest`; keep the CI-required suite on the JVM.
- **Open question:** does `claim` of an already-self-claimed conversation
  return `200` (idempotent) or `409 already_claimed`? Test encodes `409` per
  the assumed contract; confirm with backend/AND-162 author.
- **Optimistic rollback (FR-4):** depends on AND-158 actually implementing
  optimistic updates; if it does straight write-through instead, the rollback
  test becomes a plain "cache unchanged on error" assertion.

## 14. Acceptance Criteria

1. New test suites exist in `feature-groups`, `feature-helpdesk`, and (as
   needed) `core-data`, covering all cases in §11.
2. `./gradlew :feature-groups:test :feature-helpdesk:test :core-data:test`
   passes on the `android-port` branch, locally and in CI.
3. Group tests prove membership add/role-change/remove persist in Room and
   re-emit through the participants flow (AND-158 "persist + reflect").
4. Helpdesk tests prove claim→reply succeeds and that `already_claimed`,
   `claimed_by_other`, and `not_assignable` map to distinct surfaced errors
   (AND-162 "claim errors surface correctly").
5. No test contacts the live dev host; all network is via MockWebServer/fakes.
6. Tests are deterministic: no real sleeps/clocks, fixed test dispatcher; the
   suite passes on three consecutive CI runs with no flakes.
7. Assertions are meaningful (each would fail if the asserted behavior
   regressed) — verified by a reviewer spot-check or mutation-style sanity
   check on at least the claim-error mapping.

## 15. Definition of Done

- All §14 criteria met and the new test tasks are wired into the project's
  default CI `check` aggregation for the `android-port` branch.
- Code reviewed and merged; uses `core-testing` shared harness (no duplicated
  MockWebServer/dispatcher boilerplate).
- Package names use `com.testlogon.android.*` throughout (e.g.
  `com.testlogon.android.feature.groups`, `...feature.helpdesk`).
- No `@Ignore`d or commented-out tests left behind; no TODOs other than tracked
  follow-ups for any confirmed contract-drift open question in §13.
- Test execution time for the JVM suites is reasonable (timeout-simulation
  cases use short OkHttp timeouts, not real 20s waits).
