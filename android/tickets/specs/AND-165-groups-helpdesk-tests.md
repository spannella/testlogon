---
id: AND-165
title: Groups/helpdesk tests
milestone: M3
epic: E22
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- AND-158 (Group membership management): role change + remove via the group
  members API — `PATCH /ui/groups/{group_id}/members/{user_id}/role` and
  `DELETE /ui/groups/{group_id}/members/{user_id}`; acceptance "Membership
  changes persist + reflect." [CORRECTED] The original draft said members are
  *added* via `POST /groups/{id}/participants`; verified against the OpenAPI
  index and the web client (`src/api/endpoints/groups.ts`), groups have **no
  add-member POST** — members are added through join/invite/review flows
  (`/ui/groups/{group_id}/join|invite|requests/{user_id}/review`). The
  `add participant` shape applies to **conversation** participants
  (`POST /messaging/conversations/{conversation_id}/participants`), a different
  feature. This ticket tests the group-membership role/remove mutations.
- AND-162 (Helpdesk claim + reply): claim via
  `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (returns
  `HelpdeskClaimOut`); reply via the ordinary message-send path
  `POST /messaging/conversations/{conversation_id}/messages`. [CORRECTED] The
  original draft used `POST /helpdesk/conversations/{id}/claim` (missing the
  `/messaging/` prefix) and a non-existent
  `/helpdesk/conversations/{id}/messages` reply route. "handle
  claim/assignee error codes"; acceptance "Claim→reply works; claim errors
  surface correctly."
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

**Group membership (repo + UI):**
1. [CORRECTED — groups have no add-member POST] Membership *gain* is asserted
   via the join/invite/review path the group exposes (the member already present
   after sync). The original "addParticipant" FR is reframed: assert that a
   newly-synced member appears in the next `members(groupId)`/`participants(...)`
   `StateFlow` emission once inserted via the DAO sync path. The dedicated
   *add* write under `/groups/{id}/participants` does not exist for groups; if an
   add-write test is desired it must target conversation participants
   (`POST /messaging/conversations/{conversation_id}/participants`), which is a
   different feature outside AND-158.
2. `updateRole` issues `PATCH /ui/groups/{group_id}/members/{user_id}/role`
   with body `{ "role": "moderator" | "member" }` (`GroupUpdateRoleIn` enum) and,
   on `2xx`, the change is reflected in cache and re-emitted.
3. `removeMember` issues `DELETE /ui/groups/{group_id}/members/{user_id}`,
   removes the member; subsequent emission no longer contains it; Room cache
   row is deleted.
4. Mutations are optimistic-safe: on a non-2xx response the cached list is
   restored to its pre-mutation state (no phantom change) and an error
   `ApiResult` is returned.
5. UI: the group members screen renders the member list, role chips, and a
   role-change/remove affordance; performing a role change updates the rendered
   list.

**Helpdesk (repo + UI):**
6. `claim(conversationId)` issues
   `POST /messaging/helpdesk/conversations/{conversation_id}/claim` and, on
   success, the `HelpdeskClaimOut` response
   (`{ ok, conversation_id, state, assigned_agent_user_id, assignment_version,
   idempotent }`) is mapped so the conversation's `routing_state` becomes
   `assigned` and `active_agent_user_id` is the current agent. [CORRECTED] The
   original draft expected `{ id, status, assignee_id, subject }`; that shape is
   not what the endpoint returns.
7. `reply(conversationId, body)` after a successful claim sends via
   `POST /messaging/conversations/{conversation_id}/messages` (`sendTextMessage`,
   body `{ "body": ... }`), appends the message and re-emits the thread.
   [CORRECTED] No `/helpdesk/.../messages` reply endpoint exists.
8. Claim-is-idempotent: re-claiming a conversation already self-assigned returns
   `200` with `idempotent: true` (NOT a `409`). [CORRECTED] Resolves the §13
   open question. Authorization/assignee error codes surfaced by the shared
   error mapper are `helpdesk_claim_required`, `helpdesk_assignee_required`, and
   `helpdesk_claim_not_available` (carried in `detail.code`), each mapping to a
   distinct asserted `HelpdeskError`/message in `UiState`. [CORRECTED] The
   original invented codes (`already_claimed`, `claimed_by_other`,
   `not_assignable`) do not exist in the backend or web client.
9. UI: claiming a conversation in `awaiting_agent` state transitions the banner
   to "You are handling this conversation" and enables the reply composer; a
   reply attempted without claim surfaces the `helpdesk_claim_required` message
   ("Claim this helpdesk conversation before replying.") and the composer stays
   gated.

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

**Service interfaces exercised (paths corrected to the verified backend/web
contract):**
```kotlin
interface GroupService {
    // [CORRECTED] groups have no add-member POST; members join/invite/review.
    // Role change: PATCH /ui/groups/{group_id}/members/{user_id}/role {role}
    @PATCH("ui/groups/{id}/members/{userId}/role")
    suspend fun updateMemberRole(
        @Path("id") groupId: String,
        @Path("userId") userId: String,
        @Body req: UpdateRoleRequest,   // { "role": "moderator" | "member" }  (GroupUpdateRoleIn)
    ): Response<Unit>                    // resp body unspecified in OpenAPI (200, empty schema)

    @DELETE("ui/groups/{id}/members/{userId}")
    suspend fun removeMember(
        @Path("id") groupId: String,
        @Path("userId") userId: String,
    ): Response<Unit>                    // 200 (not 204) per OpenAPI index
}

interface HelpdeskService {
    // [CORRECTED] /messaging/ prefix; returns HelpdeskClaimOut, not a Conversation
    @POST("messaging/helpdesk/conversations/{id}/claim")
    suspend fun claim(@Path("id") id: String): Response<HelpdeskClaimOut>

    // [CORRECTED] reply uses the ordinary message-send route, not a helpdesk one
    @POST("messaging/conversations/{id}/messages")
    suspend fun reply(
        @Path("id") id: String,
        @Body req: SendTextMessageRequest,  // { "body": ... }
    ): Response<MessageDto>
}

// HelpdeskClaimOut (OpenAPI components.schemas.HelpdeskClaimOut):
//   ok: Boolean, conversation_id: String, state: String,
//   assigned_agent_user_id: String, assignment_version: Int,
//   idempotent: Boolean = false
```

**Repository signatures under test:**
```kotlin
class GroupParticipantsRepository @Inject constructor(
    private val service: GroupService,
    private val dao: ParticipantDao,
) {
    fun members(groupId: String): Flow<List<Participant>>   // group members cache flow
    // [CORRECTED] no addParticipant for groups; role enum is moderator|member
    suspend fun updateRole(groupId: String, userId: String, role: Role): ApiResult<Participant>
    suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit>
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

[CORRECTED — all fixtures below replace the original draft, which used
nonexistent paths/fields. Verified against the OpenAPI index/schemas and the
web client.]

Group member listing — `GET /ui/groups/{group_id}/members` →
`{ "members": GroupMember[], "count": N }`. A `GroupMember` is:
```json
{ "user_id": "u_42", "role": "member", "status": "active",
  "display_name": "Ada L.", "joined_at": 1749124800, "promoted_at": 1749200000 }
```
Note: `role` ∈ `admin | moderator | member`; `joined_at`/`promoted_at` are
**epoch seconds (integers)**, not ISO strings.

Update role — `PATCH /ui/groups/{group_id}/members/{user_id}/role`:
```json
// request body (GroupUpdateRoleIn) — enum is moderator | member
{ "role": "moderator" }
// 200 -> response schema unspecified in OpenAPI (empty); the repo re-syncs the
// members list. Tests assert the cached/emitted member now has role "moderator".
```

Remove — `DELETE /ui/groups/{group_id}/members/{user_id}` → `200` (per OpenAPI;
**not** `204`), body unspecified.

Claim — `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (empty
request body `{}`):
```json
// 200 success (HelpdeskClaimOut)
{ "ok": true, "conversation_id": "c_7", "state": "assigned",
  "assigned_agent_user_id": "agent_self", "assignment_version": 3,
  "idempotent": false }
// 200 idempotent re-claim by the same agent
{ "ok": true, "conversation_id": "c_7", "state": "assigned",
  "assigned_agent_user_id": "agent_self", "assignment_version": 3,
  "idempotent": true }
```
Claim/assignee error envelope (FastAPI `detail`, normalized by the shared
`normalizeErrorDetail`/`mapAuthorizationError` rule
`string | [{msg}] | {code,...}`). The real `detail.code` values are:
```json
// claim required before replying
{ "detail": { "code": "helpdesk_claim_required" } }
// only the assigned agent may reply
{ "detail": { "code": "helpdesk_assignee_required" } }
// agent not online/available to claim
{ "detail": { "code": "helpdesk_claim_not_available" } }
// generic 422 validation envelope (HTTPValidationError)
{ "detail": [{ "loc": ["body"], "msg": "field required", "type": "value_error" }] }
```
The OpenAPI only documents `200:HelpdeskClaimOut` and `422:HTTPValidationError`
for the claim route; the `detail.code` strings above are confirmed from the web
client's error mapper (`src/api/client.ts: mapAuthorizationError`) and are the
codes the Android repo must map. There is no documented `409` for claim
(re-claim is idempotent, see above).

Reply — `POST /messaging/conversations/{conversation_id}/messages`
(`sendTextMessage`), request `{ "body": "Try resetting your password." }`,
returns a `Message`. Exact message DTO field set is owned by AND-161/messaging;
tests assert the returned message body and that it appends to the thread flow.

The suite includes one `detail`-parsing test per shape (plain string, list-of-
objects with `msg`, single object with `code`) to confirm the shared error
mapper resolves the expected `HelpdeskError`/generic message.

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

`GroupMembersRepositoryTest`
- `updateRole_success_updatesRow_andReEmits`            // PATCH .../members/{id}/role {moderator|member}
- `removeMember_success_deletesRow_andReEmits`          // DELETE .../members/{id}
- `updateRole_serverError_rollsBackCache_returnsError`
- `removeMember_timeout_returnsNetworkError`
- `syncedMember_appears_inNextEmission`                 // gain-of-member via DAO sync (no add POST)

`HelpdeskRepositoryTest`
- `claim_success_setsStateAssigned_andSelfAsAgent`      // maps HelpdeskClaimOut
- `claim_reclaimBySelf_isIdempotent_noError`            // 200 idempotent:true
- `claim_claimRequired_returnsClaimRequiredError`       // detail.code helpdesk_claim_required
- `claim_assigneeRequired_returnsAssigneeRequiredError` // detail.code helpdesk_assignee_required
- `claim_notAvailable_returnsNotAvailableError`         // detail.code helpdesk_claim_not_available
- `reply_afterClaim_appendsMessage`                     // POST .../conversations/{id}/messages
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
fun claim_claimRequired_returnsClaimRequiredError() = runTest {
    // [CORRECTED] real code is helpdesk_claim_required, surfaced (e.g.) as 403
    enqueueJson(server, 403, """{"detail":{"code":"helpdesk_claim_required"}}""")
    val result = repo.claim("c_7")
    assertThat(result).isInstanceOf(ApiResult.Error::class.java)
    assertThat((result as ApiResult.Error).error)
        .isEqualTo(HelpdeskError.ClaimRequired)
}

@Test
fun claim_reclaimBySelf_isIdempotent() = runTest {
    enqueueJson(server, 200, """{"ok":true,"conversation_id":"c_7","state":"assigned","assigned_agent_user_id":"agent_self","assignment_version":3,"idempotent":true}""")
    val result = repo.claim("c_7")
    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    assertThat((result as ApiResult.Success).data.routingState).isEqualTo("assigned")
}

@Test
fun roleChange_updatesRenderedList() {
    composeRule.setContent { GroupMembersScreen(state = contentState, on = noopActions) }
    composeRule.onNodeWithText("Ada L.").assertIsDisplayed()
    composeRule.onNodeWithContentDescription("Change role for Ada L.").performClick()
    composeRule.onNodeWithText("Moderator").assertIsDisplayed()
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

- **Contract drift [RESOLVED in this review]:** DTO field names verified against
  `openapi.pretty.json` and the web reference. Corrections applied: claim
  response is `HelpdeskClaimOut` (`assigned_agent_user_id`/`state`, not
  `assignee_id`/`status`); `joined_at` is epoch-seconds integer, not ISO; group
  role enum is `moderator|member` (`GroupUpdateRoleIn`); helpdesk error codes are
  `helpdesk_claim_required|helpdesk_assignee_required|helpdesk_claim_not_available`.
  Re-verify only if AND-158/AND-162 land with different upstream symbols.
- **Robolectric vs androidTest:** if any Compose interaction (e.g. media or
  paging-backed list) doesn't run reliably under Robolectric, move that single
  case to `androidTest`; keep the CI-required suite on the JVM.
- **Open question [RESOLVED]:** `claim` of an already-self-claimed conversation
  returns `200` with `idempotent: true` (`HelpdeskClaimOut.idempotent`), NOT a
  `409`. Tests now encode the idempotent-200 path. The unverified item that
  remains is the *HTTP status* the backend uses to carry the `detail.code`
  authorization errors (403 vs 409) — see §16 Open assumptions.
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
4. Helpdesk tests prove claim→reply succeeds (claim returns `HelpdeskClaimOut`,
   reply via `POST /messaging/conversations/{id}/messages`) and that the real
   error codes `helpdesk_claim_required`, `helpdesk_assignee_required`, and
   `helpdesk_claim_not_available` map to distinct surfaced errors, and that a
   self re-claim is idempotent (AND-162 "claim errors surface correctly").
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Group role change endpoint is `PATCH /ui/groups/{group_id}/members/{user_id}/role`.**
   VERDICT: Corrected (draft said `PATCH /groups/{id}/participants/{userId}`).
   SOURCE: OpenAPI `PATCH /ui/groups/{group_id}/members/{user_id}/role`
   (op `update_member_role...`, req `GroupUpdateRoleIn`); frontend
   `src/api/endpoints/groups.ts: updateMemberRole`.
2. **Group role request body is `{ "role": "moderator" | "member" }`.**
   VERDICT: Corrected (draft used `admin`).
   SOURCE: OpenAPI `components.schemas.GroupUpdateRoleIn` (enum
   `moderator`, `member`).
3. **Group member remove endpoint is `DELETE /ui/groups/{group_id}/members/{user_id}`, returns `200`.**
   VERDICT: Corrected (draft said `DELETE /groups/{id}/participants/{userId}` → `204`).
   SOURCE: OpenAPI `DELETE /ui/groups/{group_id}/members/{user_id}`
   (resp `200`); frontend `src/api/endpoints/groups.ts: removeMember`.
4. **Groups have no add-member POST; membership is gained via join/invite/review.**
   VERDICT: Corrected (draft asserted `POST /groups/{id}/participants`).
   SOURCE: OpenAPI group routes (`POST /ui/groups/{group_id}/join`, `/invite`,
   `/requests/{user_id}/review`); frontend `src/api/endpoints/groups.ts`
   (`joinGroup`, `inviteToGroup`, `reviewJoinRequest`; no add-member export).
5. **`POST /messaging/conversations/{conversation_id}/participants` (req `AddParticipantsIn`, body `{ "participant_ids": [...] }`) is the *conversation* participant-add, a different feature.**
   VERDICT: Verified.
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/participants`
   + `components.schemas.AddParticipantsIn`; frontend
   `src/api/endpoints/messaging.ts: addParticipants`,
   `src/api/types.ts: AddParticipantsReq`.
6. **`GroupMember.joined_at`/`promoted_at` are epoch-seconds integers; `role` ∈ `admin|moderator|member`.**
   VERDICT: Corrected (draft fixture used ISO timestamp `joined_at` and `admin` only).
   SOURCE: `src/api/types.ts: GroupMember`.
7. **Helpdesk claim endpoint is `POST /messaging/helpdesk/conversations/{conversation_id}/claim`, returns `HelpdeskClaimOut`.**
   VERDICT: Corrected (draft said `POST /helpdesk/conversations/{id}/claim` →
   conversation object).
   SOURCE: OpenAPI `POST /messaging/helpdesk/conversations/{conversation_id}/claim`
   (resp `200:HelpdeskClaimOut`); frontend
   `src/api/endpoints/messaging.ts: claimHelpdeskConversation`.
8. **`HelpdeskClaimOut` = `{ ok, conversation_id, state, assigned_agent_user_id, assignment_version, idempotent }`.**
   VERDICT: Corrected (draft expected `{ id, status, assignee_id, subject }`).
   SOURCE: OpenAPI `components.schemas.HelpdeskClaimOut`; consumed in
   `src/pages/messages/ConversationView.tsx: claimMutation.onSuccess`
   (`data.state`, `data.assigned_agent_user_id`).
9. **Self re-claim is idempotent (200 + `idempotent: true`), not `409`.**
   VERDICT: Corrected (draft §13 assumed 409 `already_claimed`).
   SOURCE: OpenAPI `HelpdeskClaimOut.idempotent` (default false); claim route
   documents only `200`/`422`, no `409`.
10. **Helpdesk error codes are `helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available` (in `detail.code`).**
    VERDICT: Corrected (draft invented `already_claimed`, `claimed_by_other`,
    `not_assignable`).
    SOURCE: `src/api/client.ts: mapAuthorizationError` (exact `code` strings and
    their user messages).
11. **FastAPI `detail` normalization handles `string | [{msg}] | {code,...}`.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`;
    `src/api/client.errorMapping.test.ts`.
12. **Helpdesk reply uses `POST /messaging/conversations/{conversation_id}/messages` (body `{ "body": ... }`), not a helpdesk-specific route.**
    VERDICT: Corrected (draft said `POST /helpdesk/conversations/{id}/messages`).
    SOURCE: frontend `src/api/endpoints/messaging.ts: sendTextMessage`; no
    `/helpdesk/.../messages` path exists in the OpenAPI index.
13. **Write requests carry `X-CSRF-Token` from the `ui_csrf` cookie; auth is `Authorization: Bearer` + `credentials: include`.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (lines reading `getCookie("ui_csrf")` →
    `X-CSRF-Token`; `Authorization` Bearer; `credentials: "include"`).
14. **Claim UI: only `awaiting_agent` state shows a "Claim" button; after claim the banner reads "You are handling this conversation"; the Claim button has `aria-label="Claim this helpdesk conversation"`.**
    VERDICT: Verified.
    SOURCE: `src/pages/messages/ConversationView.tsx: HelpdeskRoutingBanner`
    (`showClaim` only when `state === "awaiting_agent"`; assigned-to-self text;
    aria-label).
15. **Conversation routing fields are `routing_state` and `active_agent_user_id`; helpdesk conversations have `routing_mode === "helpdesk_bridge"`.**
    VERDICT: Verified.
    SOURCE: `src/api/types.ts: Conversation` (`routing_state`,
    `active_agent_user_id`); `src/pages/helpdesk/HelpdeskPage.tsx`
    (`routing_mode === "helpdesk_bridge"`).
16. **Helpdesk queue is `GET /messaging/helpdesk/queue?group_id=...`; agents get 403 if not authorized.**
    VERDICT: Verified.
    SOURCE: OpenAPI `GET /messaging/helpdesk/queue`; frontend
    `src/api/endpoints/messaging.ts: getHelpdeskQueue` and
    `src/pages/helpdesk/HelpdeskPage.tsx` (403 → non-agent).
17. **Robolectric runs Compose UI on the JVM via `unitTests.includeAndroidResources = true`.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — Robolectric Compose testing,
    https://robolectric.org/ and
    https://developer.android.com/develop/ui/compose/testing.
18. **MockWebServer + `SocketPolicy.NO_RESPONSE` simulates timeout deterministically.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — OkHttp MockWebServer,
    https://github.com/square/okhttp/tree/master/mockwebserver.

### Corrections made

- §2, §3, §4, §5, §11, §13, §14 endpoints/paths: group membership uses the
  `/ui/groups/{group_id}/members[/{user_id}[/role]]` family (PATCH role, DELETE
  remove); the `/groups/{id}/participants` route in the draft was wrong for
  groups (it is the messaging-conversation participant API).
- Removed the nonexistent group **add-member POST**; reframed FR-1 as
  member-gain via sync/join.
- Group role enum corrected to `moderator|member` (was `admin`).
- `joined_at` corrected to epoch-seconds integer (was ISO string).
- Helpdesk claim path corrected to include `/messaging/` prefix; response type
  corrected to `HelpdeskClaimOut` (was an invented conversation object with
  `id/status/assignee_id/subject`).
- Helpdesk reply path corrected to the ordinary message-send route (the
  `/helpdesk/.../messages` route does not exist).
- Helpdesk error codes corrected to the real
  `helpdesk_claim_required|helpdesk_assignee_required|helpdesk_claim_not_available`
  (invented codes removed).
- §13 open question on re-claim resolved: idempotent `200`, not `409`.

### Open assumptions

- **HTTP status carrying `detail.code` auth errors (403 vs 409 vs 400).** The
  web mapper keys on `detail.code` regardless of status, and the OpenAPI claim
  route documents only `200`/`422`. The exact status the backend returns for
  `helpdesk_claim_required`/`helpdesk_assignee_required`/`helpdesk_claim_not_available`
  is not pinned by the sources (the mapper handles them under 401/403 handling).
  Tests therefore assert on the mapped `HelpdeskError`, and enqueue `403` as the
  representative status; revisit if AND-162 specifies otherwise.
- **Exact `Message` reply DTO field set.** Owned by messaging/AND-161; the
  `MessageOut` schema is large and its precise fields are not re-pinned here.
  Tests assert body round-trip + thread append, not every field.
- **`updateRole`/`removeMember` 200 response bodies.** OpenAPI marks these
  responses with an empty schema; the repo is assumed to re-sync the members
  list rather than parse a body. Treated as `Response<Unit>`.
- **Android repository/DAO/service symbol names** (`GroupMembersRepository`,
  `members(...)`, `HelpdeskError.*`) are the *expected* upstream shapes from
  AND-158/AND-162; the merged code is the source of truth and tests mirror the
  actual symbols if they differ. Unverifiable until those tickets land.

## 17. Test Plan

Test IDs `TC-AND-165-NN`. "Traces" links to §14 Acceptance Criteria.
Target legend: JVM = JVM/Robolectric unit (no device); MWS =
contract test with MockWebServer (JVM); CUI = Compose-UI (Robolectric, JVM);
EMU = headless emulator AVD `test35` (API 35); DEV = physical Samsung Galaxy
A15 5G (API 34). None of these cases need real hardware, so all run on JVM/EMU;
the one device note explains why DEV is not required here.

- **TC-AND-165-01 — Group role change happy path.** Type: contract/MWS
  (JVM). Target: `GroupMembersRepository.updateRole`. Preconditions: in-memory
  Room seeded with member `u_42` role `member`; MockWebServer enqueues `200`.
  Steps: call `updateRole("g_1","u_42", Role.MODERATOR)`; collect `members("g_1")`
  with Turbine. Expected: request is `PATCH /ui/groups/g_1/members/u_42/role`
  with body `{"role":"moderator"}`; `ApiResult.Success`; next emission shows
  `u_42` role `moderator`; Room row updated. Traces: AC-3.
- **TC-AND-165-02 — Group member remove happy path.** Type: contract/MWS
  (JVM). Target: `GroupMembersRepository.removeMember`. Preconditions: Room
  seeded with two members; MWS enqueues `200`. Steps: call
  `removeMember("g_1","u_42")`; collect flow. Expected: request is
  `DELETE /ui/groups/g_1/members/u_42`; `ApiResult.Success`; next emission omits
  `u_42`; Room row deleted. Traces: AC-3.
- **TC-AND-165-03 — Member-gain reflects after sync.** Type: unit (JVM).
  Target: `GroupMembersRepository.members` + DAO sync. Preconditions: empty
  members cache. Steps: insert a member via the DAO sync path; collect flow.
  Expected: initial empty emission then an emission containing the new member
  (covers FR-1 without an add-POST). Traces: AC-3.
- **TC-AND-165-04 — Role-change server error rolls back / leaves cache
  unchanged.** Type: contract/MWS (JVM). Target: `updateRole`. Preconditions:
  Room seeded `u_42=member`; MWS enqueues `409`/`422`. Steps: call `updateRole`.
  Expected: `ApiResult.Error`; cache/flow still shows `u_42=member` (no phantom
  change). Traces: AC-3, AC-7.
- **TC-AND-165-05 — Remove on socket timeout maps to NetworkError.** Type:
  contract/MWS (JVM). Target: `removeMember`. Preconditions: MWS
  `MockResponse().setSocketPolicy(NO_RESPONSE)`; short OkHttp read timeout on the
  test client. Steps: call `removeMember`. Expected: returns a timeout/
  `NetworkError` `ApiResult.Error` (does not throw); cache unchanged; completes
  well under 20s. Traces: AC-5, AC-6.
- **TC-AND-165-06 — Helpdesk claim happy path maps HelpdeskClaimOut.** Type:
  contract/MWS (JVM). Target: `HelpdeskRepository.claim`. Preconditions: Room
  seeded with conversation `c_7` in `awaiting_agent`; MWS enqueues the success
  `HelpdeskClaimOut` (`idempotent:false`). Steps: call `claim("c_7")`. Expected:
  request is `POST /messaging/helpdesk/conversations/c_7/claim`; `ApiResult.Success`;
  mapped conversation has `routingState="assigned"`,
  `activeAgentUserId="agent_self"`. Traces: AC-4.
- **TC-AND-165-07 — Self re-claim is idempotent.** Type: contract/MWS (JVM).
  Target: `claim`. Preconditions: MWS enqueues success with `idempotent:true`,
  same `assignment_version`. Steps: call `claim("c_7")`. Expected:
  `ApiResult.Success` (no error); state remains `assigned`; no duplicate
  side-effect. Traces: AC-4.
- **TC-AND-165-08 — Claim/assignee error codes map to distinct errors.** Type:
  contract/MWS (JVM). Target: `claim`/`reply` error mapping. Preconditions: MWS
  enqueues, across sub-cases, `{"detail":{"code":"helpdesk_claim_required"}}`,
  `...helpdesk_assignee_required`, `...helpdesk_claim_not_available` (status
  403). Steps: invoke the relevant call per code. Expected: each yields a
  distinct `HelpdeskError` (`ClaimRequired` / `AssigneeRequired` /
  `NotAvailable`) surfaced in `UiState`. Traces: AC-4, AC-7.
- **TC-AND-165-09 — `detail` shape normalization.** Type: unit (JVM). Target:
  shared error mapper. Preconditions: three payloads — plain string
  `{"detail":"nope"}`, list `{"detail":[{"msg":"field required"}]}`, object
  `{"detail":{"code":"helpdesk_claim_required"}}`, plus malformed
  `{"detail":123}`. Steps: run each through the mapper. Expected: string/list →
  generic surfaced message; object code → mapped `HelpdeskError`; malformed →
  generic fallback without crashing. Traces: AC-4, AC-7.
- **TC-AND-165-10 — Reply after claim appends message.** Type: contract/MWS
  (JVM). Target: `HelpdeskRepository.reply`. Preconditions: `c_7` claimed by
  self; MWS enqueues a `Message`. Steps: call `reply("c_7","Try resetting…")`.
  Expected: request is `POST /messaging/conversations/c_7/messages` with body
  `{"body":"Try resetting…"}`; `ApiResult.Success`; thread flow re-emits with the
  appended message. Traces: AC-4.
- **TC-AND-165-11 — No test hits the live dev host + CSRF header echo.** Type:
  contract/MWS (JVM). Target: test client transport assertions. Preconditions:
  MWS on ephemeral localhost; test client seeded with a `ui_csrf` cookie. Steps:
  perform any write (e.g. `updateRole`); inspect the recorded request. Expected:
  base URL is the MWS localhost port (never `18.222.237.167`); request carries
  `X-CSRF-Token` matching the cookie. Traces: AC-5.
- **TC-AND-165-12 — Group members screen renders + role change updates list.**
  Type: Compose-UI (CUI, Robolectric/JVM; runnable on EMU). Target:
  `GroupMembersScreen` + ViewModel with fake repo. Preconditions: content state
  with members incl. "Ada L." (member). Steps: render; assert "Ada L." and role
  chip displayed; perform role change to Moderator. Expected: list re-renders
  with "Moderator"; `StateFlow<UiState>` goes `Content → Content(updated)`.
  Traces: AC-3.
- **TC-AND-165-13 — Helpdesk claim enables composer; unclaimed reply gated &
  shows mapped error.** Type: Compose-UI (CUI/JVM; runnable on EMU). Target:
  `HelpdeskConversationScreen` + ViewModel. Preconditions: conversation in
  `awaiting_agent`. Steps: assert composer disabled and "Claim" button shown;
  click Claim (fake repo returns success → `assigned`/self); assert composer
  enabled and banner "You are handling this conversation"; in a sibling sub-case
  attempt reply pre-claim and have repo surface `helpdesk_claim_required`.
  Expected: post-claim composer enabled; pre-claim path shows "Claim this
  helpdesk conversation before replying." and composer stays gated. Traces:
  AC-4.
- **TC-AND-165-14 — Accessibility semantics for claim/reply/role controls.**
  Type: Compose-UI (CUI/JVM; runnable on EMU). Target: members + helpdesk
  screens. Preconditions: rendered content states. Steps: query by content
  description — Claim button (`"Claim this helpdesk conversation"`), reply send,
  and role-change affordance; assert non-empty content descriptions and correct
  `enabled`/`disabled` semantics for claimed vs unclaimed. Expected: all
  interactive controls expose accessible labels and correct enabled-state
  semantics. Traces: AC-1, AC-7.
- **TC-AND-165-15 — CI determinism / no-flake gate.** Type: integration
  (JVM CI). Target: the full new suites. Preconditions: `StandardTestDispatcher`,
  fixture clocks, short timeouts. Steps: run
  `:feature-groups:test :feature-helpdesk:test :core-data:test` three times.
  Expected: green all three runs; no real sleeps/clocks/network. Traces: AC-2,
  AC-6.

Device note: every case above is deterministic JVM/Robolectric or emulator
work (no camera, biometrics, FCM, WebRTC, Telecom, or ABI-specific behavior),
so the **physical Galaxy A15 (DEV) is NOT required** for AND-165. If any Compose
interaction proves unreliable under Robolectric (per §13), promote that single
case to `androidTest` on the headless `test35` emulator (EMU); the physical
device is reserved for the hardware-dependent feature tickets, not this test
gate.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (suites exist, cover §11) | TC-01..TC-14, TC-15 |
| AC-2 (gradle test tasks pass) | TC-15 |
| AC-3 (group persist + re-emit) | TC-01, TC-02, TC-03, TC-04, TC-12 |
| AC-4 (claim→reply + error codes + idempotent) | TC-06, TC-07, TC-08, TC-09, TC-10, TC-13 |
| AC-5 (no live host; MWS/fakes) | TC-05, TC-11 |
| AC-6 (deterministic, no flakes) | TC-05, TC-15 |
| AC-7 (meaningful assertions) | TC-04, TC-08, TC-09, TC-14 |
