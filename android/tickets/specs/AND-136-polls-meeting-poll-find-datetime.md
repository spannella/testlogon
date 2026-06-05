---
id: AND-136
title: Polls, meeting-poll, find-datetime
milestone: M3
epic: E19
priority: P2
size: L
status: draft
depends_on: [AND-124]
blocks: []
---

# AND-136 — Polls, meeting-poll, find-datetime

## 1. Overview & Goal

Add interactive **poll** and **meeting-poll (find-datetime)** support to the conversation
experience of the TestLogon native Android app. A user must be able to (a) create a poll —
either a simple multiple-choice poll or a date/time availability poll — from the message
composer, (b) cast or change a vote on an existing poll rendered inline in the message
thread, (c) close a poll (creator only), and (d) for meeting-polls, confirm a winning
time slot. Poll state (options, vote tallies, the caller's own vote, open/closed status, and
the confirmed slot) must render inline in the thread and update reactively after each
mutation.

This ticket builds directly on the messaging composer and thread surface delivered in
**AND-124 (Send text message)**. It does not introduce a new screen; polls are a message
*type* that lives inside the existing conversation thread (`feature-messaging`) plus a
modal creation sheet. The goal is feature-complete create/vote/close/confirm flows with
correct optimistic-then-reconciled rendering of results.

Out of scope: real-time push of other participants' votes (polls reconcile on thread refresh
/ pull-to-refresh; live websocket updates are owned by a later realtime ticket), ranked-choice
voting, and calendar-system integration of confirmed slots.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-messaging` (host of the conversation thread from AND-124). Poll
  models live in `core-model`; the polls API service lives in `core-network`; repository and
  cache in `core-data`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24,
  compile/target 35, JDK 17.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`; poll/meeting shapes are authoritative there and in the web
  reference under `frontend/src/api/endpoints/*.ts` + `frontend/src/api/types.ts`. Confirm
  field names against `/openapi.json` before freezing the Moshi DTOs (see §13).
- Auth is cookie-based with `X-CSRF-Token` echoed from the `ui_csrf` cookie; all mutating
  poll calls (create/vote/close/confirm) are POSTs and MUST carry the CSRF header via the
  shared OkHttp interceptor (delivered by the auth/network core tickets). On `401` the client
  performs a single `POST /ui/session/refresh` then retries (handled centrally).

## 3. Functional Requirements

FR-1 **Create a poll.** From the composer, an "Attach poll" affordance opens a modal bottom
sheet (`PollComposerSheet`) with two modes: *Choice poll* (question + 2–10 free-text options,
toggle "allow multiple selections") and *Meeting poll* (title + 2–10 candidate datetime slots,
each a start/end instant). Submitting posts to `POST /messages/meeting-poll` and inserts the
resulting poll message into the thread.

FR-2 **Render inline.** A poll message renders as `PollCard` inside the thread list. It shows
the question/title, each option with its current vote count and a proportion bar, the caller's
own selection(s) highlighted, total voters, open/closed badge, and (meeting-poll) the confirmed
slot when present.

FR-3 **Vote.** Tapping an option (when the poll is open) casts/changes the caller's vote via
`POST /polls/{id}/vote`. For single-select polls a second tap on the same option clears the
vote; multi-select toggles each option independently. The tally updates optimistically and
reconciles against the server response.

FR-4 **Close.** The poll *creator* sees a "Close poll" action that calls
`POST /polls/{id}/confirm` with no selected slot for choice polls (closes voting). Once closed,
options are read-only and the closed badge shows.

FR-5 **Confirm slot (meeting-poll).** The creator of a meeting-poll can pick a winning slot and
call `POST /polls/{id}/confirm` with the chosen `option_id`; the confirmed slot renders with a
distinct "Confirmed" treatment for all viewers after refresh.

FR-6 **Permissions.** Non-creators never see Close/Confirm. Voting is disabled on closed polls.

FR-7 **Resilience.** Find-datetime availability is fetched lazily via the availability/close
endpoint described in §5; failure renders a non-blocking inline retry on the card without
discarding the poll itself.

## 4. Technical Design

### Module placement

```
core-model/      Poll, PollOption, PollKind, PollVote, MeetingSlot, ConfirmedSlot
core-network/    PollsApi (Retrofit), Poll*Dto + mappers
core-data/       PollRepository (+ impl), PollEntity/PollOptionEntity (Room), PollDao
feature-messaging/ PollComposerSheet, PollCard, PollViewModel (or extend MessagingViewModel)
```

### Domain models (`core-model`)

```kotlin
enum class PollKind { CHOICE, MEETING }

data class Poll(
    val id: String,
    val messageId: String,
    val conversationId: String,
    val kind: PollKind,
    val title: String,
    val options: List<PollOption>,
    val allowMultiple: Boolean,
    val isClosed: Boolean,
    val createdBy: String,
    val totalVoters: Int,
    val myVotes: Set<String>,          // option ids the caller selected
    val confirmedOptionId: String?,    // meeting-poll winner, null otherwise
)

data class PollOption(
    val id: String,
    val label: String,                 // free text (CHOICE) or formatted slot (MEETING)
    val slot: MeetingSlot?,            // non-null only for MEETING kind
    val voteCount: Int,
)

data class MeetingSlot(val startUtc: Instant, val endUtc: Instant)
```

### Repository (`core-data`)

```kotlin
interface PollRepository {
    fun observePoll(pollId: String): Flow<Poll?>                       // Room-backed
    suspend fun createPoll(req: CreatePollRequest): ApiResult<Poll>
    suspend fun vote(pollId: String, optionIds: Set<String>): ApiResult<Poll>
    suspend fun close(pollId: String): ApiResult<Poll>
    suspend fun confirmSlot(pollId: String, optionId: String): ApiResult<Poll>
    suspend fun refresh(pollId: String): ApiResult<Poll>              // idempotent GET
}
```

`ApiResult<T>` is the shared sealed type (`Success<T>` / `Error(detail, httpCode)` /
`NetworkError`). All four mutations write the server-returned `Poll` into Room on success so
`observePoll` re-emits and every visible `PollCard` updates.

### ViewModel (`feature-messaging`)

Poll interactions are surfaced through the existing thread ViewModel to keep a single
`StateFlow<MessagingUiState>`, with poll-specific intents:

```kotlin
sealed interface PollIntent {
    data class ToggleVote(val pollId: String, val optionId: String) : PollIntent
    data class Close(val pollId: String) : PollIntent
    data class Confirm(val pollId: String, val optionId: String) : PollIntent
    data class Create(val draft: PollDraft) : PollIntent
}

data class PollCardUiState(
    val poll: Poll,
    val isMutating: Boolean,
    val inlineError: String?,
    val canManage: Boolean,            // createdBy == currentUserId && !isClosed
)
```

`ToggleVote` applies an **optimistic** in-memory mutation (adjust `myVotes` and the affected
`voteCount`/`totalVoters`) before the network call, sets `isMutating = true`, then on
`ApiResult.Success` overwrites with the canonical server poll, and on error reverts to the
pre-mutation snapshot and sets `inlineError`. Optimistic edits are keyed by `pollId` so two
rapid taps coalesce (latest-wins; previous in-flight job is cancelled).

### Compose UI

```kotlin
@Composable fun PollCard(state: PollCardUiState, onIntent: (PollIntent) -> Unit, modifier: Modifier = Modifier)

@Composable fun PollComposerSheet(
    initial: PollDraft = PollDraft.choice(),
    onSubmit: (PollDraft) -> Unit,
    onDismiss: () -> Unit,
)
```

`PollComposerSheet` is a Material 3 `ModalBottomSheet`. Mode is a `SegmentedButton` row.
Option rows are an editable list (add/remove, min 2 / max 10); meeting-poll slots use a
date+time picker (`rememberDatePickerState` + a time picker dialog) producing `MeetingSlot`
in device tz, serialized to UTC. Submit is disabled until validation passes (non-blank title,
≥2 non-blank/distinct options, end>start for slots).

`PollCard` renders each option with an animated `LinearProgressIndicator`-style proportion bar
(`voteCount / totalVoters`), the count, and a check icon for `myVotes`. A trailing overflow
menu hosts Close / Confirm when `canManage`.

## 5. API Contract

All paths are relative to the dev base. All POSTs require cookies + `X-CSRF-Token`.

**Create** — `POST /messages/meeting-poll`

Request:
```json
{
  "conversation_id": "conv_123",
  "kind": "meeting",
  "title": "Sprint sync time?",
  "allow_multiple": false,
  "options": [
    { "label": "Mon AM", "start_utc": "2026-06-08T15:00:00Z", "end_utc": "2026-06-08T15:30:00Z" },
    { "label": "Tue PM", "start_utc": "2026-06-09T21:00:00Z", "end_utc": "2026-06-09T21:30:00Z" }
  ]
}
```
For `kind:"choice"`, omit `start_utc`/`end_utc`. Response: `201` with the full `Poll` DTO
(also embedded in the inserted message so the thread can render immediately).

**Vote** — `POST /polls/{id}/vote`
```json
{ "option_ids": ["opt_2"] }   // [] clears vote; multiple ids when allow_multiple
```
Response `200`: updated `Poll` DTO (authoritative tallies + `my_votes`).

**Close** — `POST /polls/{id}/confirm`  (choice poll, no winner)
```json
{ "close_only": true }
```
Response `200`: `Poll` DTO with `is_closed:true`.

**Confirm slot (meeting)** — `POST /polls/{id}/confirm`
```json
{ "option_id": "opt_1" }
```
Response `200`: `Poll` DTO with `confirmed_option_id` set and `is_closed:true`.

**Availability / refresh** — `GET /polls/{id}`  (idempotent; used by find-datetime to pull
current availability and reconcile). Returns the same `Poll` DTO.

Representative `Poll` DTO:
```json
{
  "id": "poll_9", "message_id": "msg_77", "conversation_id": "conv_123",
  "kind": "meeting", "title": "Sprint sync time?", "allow_multiple": false,
  "is_closed": false, "created_by": "user_1", "total_voters": 3,
  "confirmed_option_id": null, "my_votes": ["opt_2"],
  "options": [
    { "id": "opt_1", "label": "Mon AM", "start_utc": "2026-06-08T15:00:00Z", "end_utc": "2026-06-08T15:30:00Z", "vote_count": 1 },
    { "id": "opt_2", "label": "Tue PM", "start_utc": "2026-06-09T21:00:00Z", "end_utc": "2026-06-09T21:30:00Z", "vote_count": 2 }
  ]
}
```

Errors follow the FastAPI `detail` convention (string | `[{msg}]` | `{code,...}`) mapped by
the shared error mapper into `ApiResult.Error`. Field names above are provisional pending
`/openapi.json` verification (§13).

## 6. Data & State Management

- **Room** (`core-data`): `PollEntity` (PK `id`, indexed `message_id`, `conversation_id`) +
  `PollOptionEntity` (PK `id`, FK `poll_id`, ordered by `position`). `my_votes` stored as a
  `@TypeConverter` JSON string of option ids. A single suspend `upsertPoll(poll)` writes the
  poll and replaces its options transactionally (`@Transaction`). `PollDao.observePoll(id)`
  returns `Flow<PollWithOptions?>`; the mapper builds the domain `Poll`.
- **Single source of truth:** `PollCard` always renders from Room via `observePoll`. Network
  responses only write to Room; UI never binds directly to a network result. This guarantees
  every card showing the same poll (e.g., the message and a future "polls in this chat" view)
  stays consistent.
- **Optimistic layer:** transient optimistic vote state lives in the ViewModel as an
  `optimisticVotes: MutableStateFlow<Map<String, OptimisticPoll>>` overlay merged over the
  Room flow with `combine`. Cleared per-poll once the server response is persisted.
- **No DataStore** usage for this ticket (no user prefs introduced).
- **Paging:** poll messages flow through the existing thread `Pager` from AND-124; poll
  payloads are hydrated into Room as messages page in.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global ~20s OkHttp timeout. The unreliable dev host means vote
  taps can hang; `isMutating` disables the tapped option and shows a small inline spinner.
- **Idempotent GET retry:** `GET /polls/{id}` (refresh/availability) uses the shared bounded
  backoff retry (e.g., 3 tries, exponential w/ jitter). Mutating POSTs are **not** retried
  automatically to avoid double-votes/double-creates.
- **Optimistic revert:** on any mutation `ApiResult.Error`/`NetworkError`, restore the
  pre-mutation snapshot and set `PollCardUiState.inlineError` (e.g., "Couldn't save your vote —
  tap to retry"). The card remains interactive.
- **Stale/offline:** if Room has a cached poll but the network is down, render the cached poll
  with a subtle "offline — votes may be out of date" caption; voting is allowed and queued as a
  single optimistic attempt that surfaces an error if it fails (no durable offline queue in
  this ticket).
- **Validation errors (422):** map FastAPI list-form `detail` to a field error inside
  `PollComposerSheet` (e.g., duplicate option labels) rather than dismissing the sheet.
- **Closed-poll race:** if a vote returns an error indicating the poll closed, persist the
  returned/refetched poll so the card flips to closed.

## 8. Security & Privacy

- All mutations are POSTs carrying the `X-CSRF-Token` header sourced from the `ui_csrf` cookie
  via the shared interceptor; do not hand-roll CSRF handling in this feature.
- Session `401` → single `POST /ui/session/refresh` then retry is handled centrally; poll code
  treats a post-refresh failure as a normal `ApiResult.Error`.
- No poll content is logged at info level (titles/options may contain meeting details / PII).
- No new permissions, no secrets stored. The dev host is plaintext HTTP; cleartext is allowed
  only for the dev base URL via the existing network-security config — this ticket adds nothing
  to that surface.
- Creator-only actions (Close/Confirm) are gated in UI by `createdBy == currentUserId`, but the
  server remains the authority; UI gating is convenience, not enforcement.

## 9. Accessibility & i18n

- Every option row exposes a `Modifier.semantics` with `role = RadioButton` (single-select) or
  `Checkbox` (multi-select), `stateDescription` = selected/not, and a `contentDescription`
  combining label + "X of Y votes". Proportion bars are decorative (`clearAndSetSemantics {}`).
- Close/Confirm overflow items have text labels; touch targets ≥48dp.
- Meeting slots are formatted with `java.time` + the device locale/zone (e.g.,
  `DateTimeFormatter.ofLocalizedDateTime(SHORT)`); stored/transmitted strictly in UTC.
- All strings (labels, errors, "Closed", "Confirmed", composer hints) live in
  `feature-messaging` `strings.xml`; no concatenated sentences — use plurals
  (`<plurals name="poll_vote_count">`) for vote counts.
- Color is never the sole signal: confirmed/closed states pair an icon with text.

## 10. Telemetry & Logging

- Emit analytics events via the shared analytics interface (no PII; ids only):
  `poll_created {kind, option_count}`, `poll_voted {poll_id, multi}`, `poll_closed {poll_id}`,
  `poll_confirmed {poll_id}`, `poll_vote_failed {http_code}`.
- Network failures log at `WARN` with endpoint + http code, never request/response bodies.
- Optimistic revert logs a `DEBUG` breadcrumb with `poll_id` only.

## 11. Testing Strategy

- **Unit (core-data):** `PollRepositoryImpl` against a fake `PollsApi` + in-memory Room —
  verify each mutation persists the server poll, `observePoll` re-emits, and errors leave Room
  untouched. Test mappers (DTO↔domain↔entity) including null `slot` for choice polls and UTC
  parsing.
- **Unit (ViewModel):** optimistic toggle applies then reconciles on success; reverts on error
  and sets `inlineError`; rapid double-tap coalesces (previous job cancelled); creator gating
  (`canManage`) for creator vs non-creator and open vs closed.
- **Compose UI tests** (`core-testing` harness): `PollCard` renders counts/bars/selection/closed/
  confirmed states; tapping an option emits `ToggleVote`; Close/Confirm hidden for non-creators.
  `PollComposerSheet` validation (min/max options, end>start, duplicate labels) gates submit.
- **Repository contract test** against recorded JSON fixtures derived from `/openapi.json` for
  create/vote/close/confirm responses.
- **Acceptance (instrumented or fixture-backed):** end-to-end create → vote → close, asserting
  results render — satisfies the ticket's "tested" intent.

## 12. Dependencies & Sequencing

- **Depends on AND-124** (Send text message): provides the composer entry point, the thread
  list, the message Pager, and the `MessagingViewModel`/UiState this ticket extends. Poll cards
  are inserted as a message subtype into the same list.
- Transitively depends on the network/auth core (cookie jar + CSRF interceptor + `ApiResult`
  + FastAPI error mapper) and `core-data` Room infrastructure already established earlier in M3.
- **Blocks:** none currently tracked.
- Sequencing within this ticket: (1) core-model + DTOs/mappers, (2) `PollsApi` + repository +
  Room, (3) `PollCard` read-only render, (4) vote optimism, (5) composer sheet + create,
  (6) close/confirm + creator gating.

## 13. Risks & Open Questions

- **OpenAPI field-name drift (high):** the JSON shapes in §5 are inferred. Before freezing
  Moshi DTOs, verify against `/openapi.json` whether create is truly `POST /messages/meeting-poll`
  for *both* kinds (or only meeting) and whether vote/confirm use `option_ids`/`option_id`/
  `close_only` as named. Resolve before coding the network layer.
- **Single confirm endpoint overloaded:** §5 assumes `POST /polls/{id}/confirm` serves both
  "close choice poll" and "confirm meeting slot". If the backend splits these, add a
  `closePoll` repository method and a distinct endpoint.
- **Who may close/confirm:** assumed creator-only. Confirm against backend authz.
- **Concurrent votes / live updates:** no realtime push here; tallies can be stale until
  refresh. Acceptable for P2; flag the future realtime ticket as owner of live reconciliation.
- **`total_voters` semantics** for multi-select polls (distinct voters vs total selections) —
  confirm so the proportion bar denominator is correct.

## 14. Acceptance Criteria

- AC-1: From the composer a user can create a **choice** poll and a **meeting** poll; the new
  poll appears inline in the thread immediately on success. *(maps to ticket: Create a poll)*
- AC-2: Tapping an option on an open poll casts/changes the vote via `POST /polls/{id}/vote`;
  the tally updates optimistically and matches the server response after reconciliation.
- AC-3: A second tap clears the vote in single-select; multi-select toggles each option
  independently.
- AC-4: The creator can **close** a choice poll and **confirm** a winning slot on a meeting
  poll; non-creators never see those actions.
- AC-5: Results render correctly — per-option counts, proportion bars, total voters, the
  caller's selection, and open/closed/confirmed badges — bound to Room as the single source of
  truth. *(maps to ticket: results render)*
- AC-6: A failed vote reverts the optimistic change and shows an inline retry without losing
  the poll.
- AC-7: All four flows (create/vote/close/confirm) send `X-CSRF-Token`; a `401` is transparently
  retried once via session refresh.
- AC-8: An end-to-end create → vote → close test passes (satisfies "tested").

## 15. Definition of Done

- All AC met; code merged to `android-port` under `feature-messaging` + supporting core modules.
- `PollRepository`, `PollsApi`, Room entities/DAO, `PollCard`, and `PollComposerSheet`
  implemented with real `com.testlogon.android.*` packages.
- DTO field names verified against `/openapi.json` (§13 resolved or explicitly deferred with a
  follow-up note).
- Unit + Compose + repository contract tests green in CI; ktlint/detekt clean; no new
  cleartext-traffic surface beyond the dev base URL.
- Strings externalized with plurals; accessibility semantics present and verified with TalkBack
  smoke check.
- No poll content logged; telemetry events emit ids only.
- Spec reviewers (messaging owner) sign off; open questions either resolved or tracked as
  follow-up tickets.
