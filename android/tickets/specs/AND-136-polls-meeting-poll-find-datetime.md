---
id: AND-136
title: Polls, meeting-poll, find-datetime
milestone: M3
epic: E19
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-124]
blocks: []
---

# AND-136 — Polls, meeting-poll, find-datetime

## 1. Overview & Goal

Add interactive **meeting-poll** and **find-datetime** support to the conversation
experience of the TestLogon native Android app. A user must be able to (a) create a
**meeting poll** (a date/time *availability* poll over 2–5 candidate slots) and a
**find-datetime poll** (a window/range availability finder) from the message composer,
(b) cast or change an availability response on an existing meeting poll rendered inline in
the message thread, (c) for find-datetime, submit free/busy availability, and (d) for
meeting-polls, confirm a winning time slot (creator only). Poll state (slots, per-slot
yes/maybe/no tallies, the caller's own response, open/confirmed/cancelled status, and the
confirmed slot) must render inline in the thread and update reactively after each mutation.

> **Review correction (2026-06-06):** The original draft assumed a generic free-text
> *multiple-choice* poll on the messaging surface. The authoritative backend has **no such
> endpoint under `/messaging`** — the meeting-poll endpoint is strictly a **yes/maybe/no
> availability poll over datetime slots** (`CreateMeetingPollMessageIn`,
> `PollVoteIn.votes = {slot_id: "yes"|"no"|"maybe"}`). A free-text choice poll exists only on
> the *newsfeed* surface (`POST /posts/{post_id}/vote`, `VoteIn`) and is out of scope for this
> messaging ticket. All "choice poll" framing below has been corrected accordingly.

This ticket builds directly on the messaging composer and thread surface delivered in
**AND-124 (Send text message)**. It does not introduce a new screen; polls are a message
*type* that lives inside the existing conversation thread (`feature-messaging`) plus a
modal creation sheet. The goal is feature-complete create/vote/close/confirm flows with
correct optimistic-then-reconciled rendering of results.

Out of scope: real-time push of other participants' votes (polls reconcile on thread refresh
/ pull-to-refresh; live SSE updates via `GET /messaging/events/stream` are owned by a later
realtime ticket), ranked-choice or free-text multiple-choice voting (newsfeed-only surface),
and ranked-choice voting. Note that `PollConfirmIn` accepts an optional `calendar_id`, i.e.
confirming a slot *can* create a calendar event server-side; surfacing that calendar
integration in the Android UI is out of scope for this ticket (we send `slot_id` only).

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

FR-1 **Create a meeting poll.** From the composer, an "Attach meeting poll" affordance opens a
modal bottom sheet (`MeetingPollComposerSheet`) with: a *title* (1–200 chars), a *duration*
(`duration_minutes`, default 30, range 15–1440), and **2–5 candidate datetime slots** each with
a start/end instant. Submitting posts to
`POST /messaging/conversations/{conversation_id}/messages/meeting-poll`
(req `CreateMeetingPollMessageIn`, resp **200** `MessageOut`) and inserts the resulting poll
message into the thread.
*Corrected:* slot range is **2–5** (was "2–10"); the create endpoint is the **conversation-scoped**
path (was the flat `/messages/meeting-poll`); response is **200** (was 201);
`conversation_id` is a **path param**, not a body field; there is **no** `kind`,
`allow_multiple`, free-text `options`, nor per-option `label` field. Web reference:
`src/pages/messages/MeetingPollComposer.tsx` (enforces min 2 / max 5 slots).

FR-1b **Create a find-datetime poll.** A separate composer (`FindDateTimeComposerSheet`) posts
`POST /messaging/conversations/{conversation_id}/messages/find-datetime`
(req `CreateFindDateTimeMessageIn` = `title`, `from_date`/`to_date` (`YYYY-MM-DD`),
`start_hour` (0–23), `end_hour` (1–24), `slot_duration_minutes` (default 30),
`deadline_hours` (default 48, 1–336), optional `text`; resp **201**). This is a window/range
availability finder, distinct from the slot-list meeting poll.

FR-2 **Render inline.** A meeting-poll message renders as `MeetingPollCard` inside the thread
list. It shows the title, and for **each slot**: the formatted start/end, the three counts
(`yes_count` / `maybe_count` / `no_count`), the caller's own response (`my_vote` ∈
yes/maybe/no/null) highlighted, an open/confirmed/cancelled badge, and the confirmed slot when
`confirmed_slot_id` is set. *Corrected:* the model is per-slot yes/maybe/no, **not** a single
`vote_count` per option; there is **no** `total_voters` field — derive a denominator from the
slot counts if a proportion bar is desired.

FR-3 **Vote (availability).** Tapping a slot (when status is `open`) sets/changes the caller's
response for that slot via
`POST /messaging/conversations/{conversation_id}/polls/{poll_id}/vote` with body
`{ "votes": { "<slot_id>": "yes" | "no" | "maybe" } }` (`PollVoteIn`). The response is
`{ "ok": true }` (**not** a full poll DTO), so the client must re-fetch via
`GET /messaging/conversations/{conversation_id}/polls/{poll_id}` (`MeetingPollState`) to
reconcile authoritative counts. Tapping cycles the per-slot response (e.g. yes→maybe→no→clear,
clear = omit that slot from the `votes` map). *Corrected:* request shape is a
`{slot_id: state}` map, **not** `option_ids`; there is no single-select vs multi-select
concept — each slot carries its own yes/maybe/no independently. Web reference:
`src/api/endpoints/messaging.ts: voteMeetingPoll`.

FR-4 **Cancel/close.** There is **no** dedicated "close" endpoint or `close_only` body for the
*meeting* poll on the messaging surface (verified against the OpenAPI index). The lifecycle is
open → confirmed (via confirm) or → cancelled (server-driven status). The Android UI therefore
exposes **Confirm** (FR-5) as the creator's terminal action; a separate "cancel" affordance is
*not* implemented in this ticket unless a cancel endpoint is added (tracked in §13). *(The
`/messaging/messages/find-datetime/{poll_id}/close` endpoint closes a **find-datetime** poll,
not a meeting poll — see FR-7.)*

FR-5 **Confirm slot (meeting-poll).** The creator can pick a winning slot and call
`POST /messaging/conversations/{conversation_id}/polls/{poll_id}/confirm` with body
`{ "slot_id": "<slot_id>" }` (`PollConfirmIn`; `calendar_id` optional and omitted here). The
response is `{ "ok": true, "event_id?": "..." }`; the client re-fetches `MeetingPollState` so
`status:"confirmed"` and `confirmed_slot_id` render a distinct "Confirmed" treatment for all
viewers after refresh. *Corrected:* the body field is `slot_id` (was `option_id`); response is
not a poll DTO.

FR-6 **Permissions.** Non-creators (`creator_id != currentUserId`) never see Confirm. Voting is
disabled once `status != "open"`.

FR-7 **Find-datetime resilience.** Find-datetime availability is fetched via
`GET /messaging/messages/find-datetime/{poll_id}` (`FindDateTimeFull`), submitted via
`POST /messaging/messages/find-datetime/{poll_id}/availability` (`SubmitAvailabilityIn` =
`{ "slots": ["<iso8601>", ...] }`, 1–500 items), and closed (creator) via
`POST /messaging/messages/find-datetime/{poll_id}/close`. Failure renders a non-blocking inline
retry on the card without discarding the poll itself.

## 4. Technical Design

### Module placement

```
core-model/      MeetingPoll, MeetingPollSlot, MeetingPollStatus, SlotVote, FindDateTime*
core-network/    MeetingPollApi + FindDateTimeApi (Retrofit), *Dto + mappers
core-data/       MeetingPollRepository (+ impl), MeetingPollEntity/MeetingPollSlotEntity (Room), MeetingPollDao
feature-messaging/ MeetingPollComposerSheet, MeetingPollCard, FindDateTimeComposerSheet/Card,
                 poll intents on the existing MessagingViewModel
```

### Domain models (`core-model`)

> **Corrected to match `MeetingPollState` / `MeetingPollSlot`** (`src/api/types.ts`). The
> earlier `PollKind.CHOICE`, `allowMultiple`, `isClosed`, `totalVoters`, `myVotes: Set`,
> `confirmedOptionId`, and per-option `voteCount` do not exist on the backend. Status is a
> tri-state enum; each slot carries three counts + the caller's own response.

```kotlin
enum class MeetingPollStatus { OPEN, CONFIRMED, CANCELLED }   // status: "open"|"confirmed"|"cancelled"
enum class SlotVote { YES, MAYBE, NO }                        // "yes"|"maybe"|"no"

data class MeetingPoll(
    val pollId: String,                 // poll_id
    val title: String,
    val durationMinutes: Int,           // duration_minutes
    val creatorId: String,              // creator_id
    val status: MeetingPollStatus,      // status
    val confirmedSlotId: String?,       // confirmed_slot_id (null until confirmed)
    val slots: List<MeetingPollSlot>,
)

data class MeetingPollSlot(
    val slotId: String,                 // slot_id
    val startUtc: Instant,              // start_utc (ISO-8601)
    val endUtc: Instant,                // end_utc
    val yesCount: Int,                  // yes_count
    val maybeCount: Int,                // maybe_count
    val noCount: Int,                   // no_count
    val myVote: SlotVote?,              // my_vote (null = no response)
)
```

> Find-datetime uses a separate domain model (`FindDateTimeFull` → `meta`/`availabilities`/
> `result`); it is window-based, not slot-list-based, and is modeled independently.

### Repository (`core-data`)

```kotlin
interface MeetingPollRepository {
    fun observePoll(pollId: String): Flow<MeetingPoll?>                              // Room-backed
    // conversationId is required by every endpoint (path param).
    suspend fun createMeetingPoll(conversationId: String, req: CreateMeetingPollRequest): ApiResult<MeetingPoll>
    suspend fun vote(conversationId: String, pollId: String, slotId: String, vote: SlotVote?): ApiResult<MeetingPoll>
    suspend fun confirmSlot(conversationId: String, pollId: String, slotId: String): ApiResult<MeetingPoll>
    suspend fun refresh(conversationId: String, pollId: String): ApiResult<MeetingPoll>  // idempotent GET → MeetingPollState
}
```

> **Corrected:** `vote`/`confirm` POSTs return `{ok:true}` (and confirm `{ok, event_id?}`),
> **not** a poll DTO. The repo therefore performs a **vote/confirm POST followed by a GET
> re-fetch** of `MeetingPollState`, then writes that into Room; only `refresh` and the create
> response (`MessageOut` embedding poll state) carry full poll data directly. `vote(..., null)`
> clears the caller's response for that slot (omit the slot from the `votes` map). There is no
> standalone `close()` on the meeting poll (no endpoint — see §13); a find-datetime repository
> handles its own create/getAvailability/submitAvailability/close set.

`ApiResult<T>` is the shared sealed type (`Success<T>` / `Error(detail, httpCode)` /
`NetworkError`). Each mutation, after its follow-up GET, writes the server-returned
`MeetingPollState` into Room on success so `observePoll` re-emits and every visible
`MeetingPollCard` updates.

### ViewModel (`feature-messaging`)

Poll interactions are surfaced through the existing thread ViewModel to keep a single
`StateFlow<MessagingUiState>`, with poll-specific intents:

```kotlin
sealed interface PollIntent {
    // Cycle/set the caller's response for one slot (null = clear).
    data class SetSlotVote(val pollId: String, val slotId: String, val vote: SlotVote?) : PollIntent
    data class Confirm(val pollId: String, val slotId: String) : PollIntent
    data class CreateMeetingPoll(val draft: MeetingPollDraft) : PollIntent
}

data class MeetingPollCardUiState(
    val poll: MeetingPoll,
    val isMutating: Boolean,
    val inlineError: String?,
    val canManage: Boolean,            // creatorId == currentUserId && status == OPEN
)
```

> **Corrected:** intents operate per-slot (`SetSlotVote`/`Confirm(slotId)`); there is no
> `Close` intent (no meeting-poll close endpoint). `canManage` gates on `status == OPEN`, not a
> non-existent `isClosed` flag.

`SetSlotVote` applies an **optimistic** in-memory mutation (adjust that slot's
`yesCount`/`maybeCount`/`noCount` and `myVote`) before the network call, sets
`isMutating = true`, then on `ApiResult.Success` overwrites with the canonical server poll
(from the follow-up GET re-fetch), and on error reverts to the pre-mutation snapshot and sets
`inlineError`. Optimistic edits are keyed by `(pollId, slotId)` so two rapid taps on the same
slot coalesce (latest-wins; previous in-flight job is cancelled).

### Compose UI

```kotlin
@Composable fun MeetingPollCard(state: MeetingPollCardUiState, onIntent: (PollIntent) -> Unit, modifier: Modifier = Modifier)

@Composable fun MeetingPollComposerSheet(
    initial: MeetingPollDraft = MeetingPollDraft.empty(),
    onSubmit: (MeetingPollDraft) -> Unit,
    onDismiss: () -> Unit,
)
```

`MeetingPollComposerSheet` is a Material 3 `ModalBottomSheet` with a title field, a duration
chip row (15–1440 min; default 30), and an editable **slot list (min 2 / max 5)**. Slots use a
date+time picker (`rememberDatePickerState` + a time-picker dialog) producing
`MeetingPollSlot` start/end in device tz, serialized to UTC. Submit is disabled until
validation passes (non-blank title 1–200 chars, **2–5** slots, end>start per slot). *Corrected:*
slot bound is **2–5** (was 2–10); there is no "choice poll" mode and no `SegmentedButton`
toggle for poll type, and no "allow multiple selections" control. (find-datetime gets its own
`FindDateTimeComposerSheet`.)

`MeetingPollCard` renders each slot with the formatted time range, the three counts
(yes/maybe/no), an optional proportion bar (denominator = sum of the slot's three counts; there
is **no** `total_voters` field), and a check/indicator reflecting `myVote`. A trailing overflow
menu hosts **Confirm** (per-slot, or a chooser) when `canManage`; there is no "Close" item.

## 5. API Contract

All paths are relative to the dev base. All POSTs require cookies + `X-CSRF-Token` (plus the
`Authorization: Bearer` header and `X-SESSION-ID` the shared client already attaches — see
`src/api/client.ts`). **Every endpoint below was verified against `openapi.index.txt` /
`openapi.pretty.json` and `src/api/endpoints/messaging.ts`.** The prior draft's flat paths,
request shapes, and `Poll` DTO were materially wrong and are replaced here.

### Meeting poll

**Create** — `POST /messaging/conversations/{conversation_id}/messages/meeting-poll`
(op `create_meeting_poll_message...`, req `CreateMeetingPollMessageIn`, **resp 200 `MessageOut`**)
```json
{
  "title": "Sprint sync time?",
  "duration_minutes": 30,
  "slots": [
    { "start_utc": "2026-06-08T15:00:00Z", "end_utc": "2026-06-08T15:30:00Z" },
    { "start_utc": "2026-06-09T21:00:00Z", "end_utc": "2026-06-09T21:30:00Z" }
  ],
  "text": "optional accompanying message"
}
```
`conversation_id` is a **path** param. `title` 1–200, `duration_minutes` default 30 / 15–1440,
`slots` **2–5** items (`MeetingPollSlotIn` = `start_utc`+`end_utc`, both required). Response is a
`MessageOut` (the inserted poll message) — render the thread from it immediately, then GET the
poll for canonical counts.

**Vote (availability)** — `POST /messaging/conversations/{conversation_id}/polls/{poll_id}/vote`
(req `PollVoteIn`, resp 200)
```json
{ "votes": { "<slot_id>": "yes" } }   // values ∈ {"yes","no","maybe"}; omit a slot to clear it
```
Response body is **`{ "ok": true }`** (NOT a poll DTO). Re-fetch the poll (GET below) to
reconcile tallies.

**Get / refresh** — `GET /messaging/conversations/{conversation_id}/polls/{poll_id}`
(idempotent, resp 200 → `MeetingPollState`). Authoritative source of per-slot counts + `my_vote`.

**Confirm slot** — `POST /messaging/conversations/{conversation_id}/polls/{poll_id}/confirm`
(req `PollConfirmIn`, resp 200)
```json
{ "slot_id": "<slot_id>" }            // optional "calendar_id" creates a calendar event server-side; omitted here
```
Response body is **`{ "ok": true, "event_id": "..." }`** (`event_id` optional). Re-fetch to see
`status:"confirmed"` + `confirmed_slot_id`. There is **no** meeting-poll "close" endpoint and no
`close_only` flag.

Representative `MeetingPollState` DTO (the GET response — verified `src/api/types.ts`):
```json
{
  "poll_id": "poll_9", "title": "Sprint sync time?", "duration_minutes": 30,
  "creator_id": "user_1", "status": "open", "confirmed_slot_id": null,
  "slots": [
    { "slot_id": "slot_1", "start_utc": "2026-06-08T15:00:00Z", "end_utc": "2026-06-08T15:30:00Z",
      "yes_count": 1, "maybe_count": 0, "no_count": 0, "my_vote": null },
    { "slot_id": "slot_2", "start_utc": "2026-06-09T21:00:00Z", "end_utc": "2026-06-09T21:30:00Z",
      "yes_count": 2, "maybe_count": 1, "no_count": 0, "my_vote": "yes" }
  ]
}
```

### Find-datetime (separate feature, MSG-009)

- **Create** — `POST /messaging/conversations/{conversation_id}/messages/find-datetime`
  (req `CreateFindDateTimeMessageIn` = `title`, `from_date`/`to_date` `YYYY-MM-DD`,
  `start_hour` 0–23, `end_hour` 1–24, `slot_duration_minutes` default 30,
  `deadline_hours` default 48 / 1–336, optional `text`; **resp 201 `MessageOut`**).
- **Get** — `GET /messaging/messages/find-datetime/{poll_id}` → `FindDateTimeFull`
  (`meta` + `availabilities` + `result`). Note: **not** conversation-scoped.
- **Submit availability** — `POST /messaging/messages/find-datetime/{poll_id}/availability`
  (req `SubmitAvailabilityIn` = `{ "slots": ["<iso8601>", ...] }`, 1–500 items).
- **Close** — `POST /messaging/messages/find-datetime/{poll_id}/close` (creator; no body).

Errors follow the FastAPI `detail` convention (string | `[{loc,msg,type}]` for `422` |
`{code,...}`) mapped by the shared error mapper into `ApiResult.Error`. All listed endpoints
declare `422:HTTPValidationError` in the OpenAPI index.

## 6. Data & State Management

- **Room** (`core-data`): `MeetingPollEntity` (PK `poll_id`, indexed `conversation_id`;
  columns `title`, `duration_minutes`, `creator_id`, `status`, `confirmed_slot_id`) +
  `MeetingPollSlotEntity` (PK `slot_id`, FK `poll_id`, ordered by `position`; columns
  `start_utc`, `end_utc`, `yes_count`, `maybe_count`, `no_count`, `my_vote`). `my_vote` is a
  nullable enum stored via `@TypeConverter`; no `my_votes` list converter is needed (the model
  has no option-id set). `status` stored as a string enum. A single suspend `upsertPoll(poll)`
  writes the poll and replaces its slots transactionally (`@Transaction`).
  `MeetingPollDao.observePoll(pollId)` returns `Flow<MeetingPollWithSlots?>`; the mapper builds
  the domain `MeetingPoll`. *Corrected:* `conversation_id` is a poll/path attribute but is not
  part of the `MeetingPollState` GET body — persist it from the create/thread context.
- **Single source of truth:** `MeetingPollCard` always renders from Room via `observePoll`.
  Network responses only write to Room; UI never binds directly to a network result. Because
  vote/confirm return only `{ok}`, the repo's follow-up GET supplies the canonical
  `MeetingPollState` written to Room.
- **Optimistic layer:** transient optimistic per-slot vote state lives in the ViewModel as an
  `optimisticVotes: MutableStateFlow<Map<Pair<String,String>, SlotVote?>>` (keyed by
  `pollId,slotId`) overlay merged over the Room flow with `combine`. Cleared per `(poll,slot)`
  once the server-reconciled poll is persisted.
- **No DataStore** usage for this ticket (no user prefs introduced).
- **Paging:** poll messages flow through the existing thread `Pager` from AND-124; poll
  payloads are hydrated into Room as messages page in.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global ~20s OkHttp timeout. The unreliable dev host means vote
  taps can hang; `isMutating` disables the tapped option and shows a small inline spinner.
- **Idempotent GET retry:** `GET /messaging/conversations/{conversation_id}/polls/{poll_id}`
  (refresh) and `GET /messaging/messages/find-datetime/{poll_id}` use the shared bounded backoff
  retry (e.g., 3 tries, exponential w/ jitter). Mutating POSTs are **not** retried automatically
  to avoid double-votes/double-creates. (Note: a vote/confirm whose POST succeeds but whose
  follow-up reconcile GET fails should still retry only the GET, since the POST already applied.)
- **Optimistic revert:** on any mutation `ApiResult.Error`/`NetworkError`, restore the
  pre-mutation snapshot and set `PollCardUiState.inlineError` (e.g., "Couldn't save your vote —
  tap to retry"). The card remains interactive.
- **Stale/offline:** if Room has a cached poll but the network is down, render the cached poll
  with a subtle "offline — votes may be out of date" caption; voting is allowed and queued as a
  single optimistic attempt that surfaces an error if it fails (no durable offline queue in
  this ticket).
- **Validation errors (422):** map FastAPI list-form `detail` to a field error inside
  `PollComposerSheet` (e.g., duplicate option labels) rather than dismissing the sheet.
- **Status race:** if a vote returns an error (or a reconcile GET shows `status != "open"`,
  e.g. `confirmed`/`cancelled`), persist the refetched poll so the card flips out of the open
  state and disables voting.

## 8. Security & Privacy

- All mutations are POSTs carrying the `X-CSRF-Token` header sourced from the `ui_csrf` cookie
  via the shared interceptor; do not hand-roll CSRF handling in this feature.
- Session `401` → single `POST /ui/session/refresh` then retry is handled centrally; poll code
  treats a post-refresh failure as a normal `ApiResult.Error`.
- No poll content is logged at info level (titles/options may contain meeting details / PII).
- No new permissions, no secrets stored. The dev host is plaintext HTTP; cleartext is allowed
  only for the dev base URL via the existing network-security config — this ticket adds nothing
  to that surface.
- Creator-only actions (Confirm; find-datetime Close) are gated in UI by
  `creator_id == currentUserId`, but the server remains the authority; UI gating is convenience,
  not enforcement. (Verified: `MeetingPollState.creator_id`, `src/api/types.ts`.)

## 9. Accessibility & i18n

- Each **slot** row exposes a `Modifier.semantics` describing the three-state availability
  response (yes/maybe/no/none) rather than a radio/checkbox; `stateDescription` = the caller's
  current `my_vote` (e.g. "Your response: Yes"), and a `contentDescription` combining the
  formatted time range + "Yes N, Maybe M, No K". *Corrected:* there is no single-select vs
  multi-select model, so `role = RadioButton/Checkbox` does not apply; use buttons/toggles with
  explicit state descriptions. Proportion bars are decorative (`clearAndSetSemantics {}`).
- Confirm (and find-datetime Close) overflow items have text labels; touch targets ≥48dp.
- Meeting slots are formatted with `java.time` + the device locale/zone (e.g.,
  `DateTimeFormatter.ofLocalizedDateTime(SHORT)`); stored/transmitted strictly in UTC.
- All strings (labels, errors, "Closed", "Confirmed", composer hints) live in
  `feature-messaging` `strings.xml`; no concatenated sentences — use plurals
  (`<plurals name="poll_vote_count">`) for vote counts.
- Color is never the sole signal: confirmed/closed states pair an icon with text.

## 10. Telemetry & Logging

- Emit analytics events via the shared analytics interface (no PII; ids only):
  `poll_created {kind, slot_count}`, `poll_voted {poll_id, response}` (response ∈
  yes/maybe/no/clear), `poll_confirmed {poll_id}`, `poll_vote_failed {http_code}`,
  `finddatetime_availability_submitted {poll_id, slot_count}`, `finddatetime_closed {poll_id}`.
  (`poll_closed` was dropped — meeting polls have no close action.)
- Network failures log at `WARN` with endpoint + http code, never request/response bodies.
- Optimistic revert logs a `DEBUG` breadcrumb with `poll_id` only.

## 11. Testing Strategy

- **Unit (core-data):** `MeetingPollRepositoryImpl` against a fake `MeetingPollApi` + in-memory
  Room — verify vote/confirm perform their `{ok}` POST **then** a reconcile GET that persists the
  server poll, `observePoll` re-emits, and errors leave Room untouched. Test mappers
  (DTO↔domain↔entity) including null `my_vote` and UTC `start_utc`/`end_utc` parsing.
- **Unit (ViewModel):** optimistic per-slot toggle applies then reconciles on success; reverts
  on error and sets `inlineError`; rapid double-tap on a slot coalesces (previous job cancelled);
  creator gating (`canManage`) for creator vs non-creator and open vs confirmed/cancelled.
- **Compose UI tests** (`core-testing` harness): `MeetingPollCard` renders
  counts/bars/`my_vote`/confirmed/cancelled states; tapping a slot emits `SetSlotVote`; Confirm
  hidden for non-creators. `MeetingPollComposerSheet` validation (2–5 slots, title 1–200,
  end>start) gates submit.
- **Repository contract test (MockWebServer)** against recorded JSON fixtures derived from
  `openapi.pretty.json` for create (`MessageOut`), vote (`{ok}`), confirm (`{ok,event_id}`), and
  the GET `MeetingPollState`.
- **Acceptance (instrumented or fixture-backed):** end-to-end create → vote → confirm, asserting
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

- **RESOLVED — OpenAPI field-name drift:** verified against `openapi.index.txt` /
  `openapi.pretty.json` (2026-06-06). Create is `POST /messaging/conversations/{conversation_id}
  /messages/meeting-poll` (resp **200**), req `CreateMeetingPollMessageIn`
  (`title`,`slots`,`duration_minutes`,`text`); it serves **meeting/availability polls only** —
  there is no choice-poll variant here. Vote uses `PollVoteIn.votes = {slot_id: "yes|no|maybe"}`
  (not `option_ids`); confirm uses `PollConfirmIn.slot_id` (+ optional `calendar_id`), not
  `option_id`/`close_only`. DTOs may now be frozen from these shapes.
- **RESOLVED — no overloaded confirm:** confirm only confirms a slot; there is **no**
  meeting-poll close endpoint. A separate find-datetime *close* endpoint exists
  (`.../find-datetime/{poll_id}/close`). No `closePoll` method needed for meeting polls.
- **OPEN — who may confirm/close:** UI assumes `creator_id == currentUserId`; backend authz is
  the authority and the 403 shape was not separately inspected. Treat a 403 on confirm as a
  normal `ApiResult.Error`.
- **Concurrent votes / live updates:** no realtime push in this ticket; tallies can be stale
  until a GET refresh (or future `GET /messaging/events/stream` SSE). Acceptable for P2.
- **RESOLVED — counts model:** there is no `total_voters`; each slot has independent
  `yes_count`/`maybe_count`/`no_count`. Any proportion bar must choose its own denominator
  (e.g. per-slot sum, or max across slots); document the choice in the UI PR.

## 14. Acceptance Criteria

- AC-1: From the composer a user can create a **meeting poll** (and, separately, a
  **find-datetime** poll); the new poll appears inline in the thread immediately on success.
  Create posts `CreateMeetingPollMessageIn` to
  `POST /messaging/conversations/{conversation_id}/messages/meeting-poll` (resp 200).
  *(maps to ticket: Create a poll)*
- AC-2: Tapping a slot on an `open` poll sets/changes the caller's availability via
  `POST /messaging/conversations/{conversation_id}/polls/{poll_id}/vote` with body
  `{votes:{slot_id:"yes|no|maybe"}}`; the per-slot tally updates optimistically and matches the
  server state after the reconcile GET (`MeetingPollState`).
- AC-3: A slot's response cycles (yes→maybe→no→clear); clearing omits that slot from the
  `votes` map. Each slot's response is independent.
- AC-4: The creator can **confirm** a winning slot on a meeting poll
  (`POST .../polls/{poll_id}/confirm` with `{slot_id}`); non-creators never see Confirm. (There
  is no meeting-poll "close" action; find-datetime has its own creator-only Close.)
- AC-5: Results render correctly — per-slot yes/maybe/no counts, optional proportion bars, the
  caller's `my_vote`, and open/confirmed/cancelled badges (+ the confirmed slot) — bound to Room
  as the single source of truth. *(maps to ticket: results render)*
- AC-6: A failed vote reverts the optimistic change and shows an inline retry without losing
  the poll.
- AC-7: All mutating flows (create/vote/confirm; find-datetime availability/close) send
  `X-CSRF-Token` (from the `ui_csrf` cookie) with credentialed requests; a `401` is
  transparently retried once via `POST /ui/session/refresh`.
- AC-8: An end-to-end create → vote → confirm test passes (satisfies "tested").

## 15. Definition of Done

- All AC met; code merged to `android-port` under `feature-messaging` + supporting core modules.
- `MeetingPollRepository`, `MeetingPollApi` (+ `FindDateTimeApi`), Room entities/DAO,
  `MeetingPollCard`, and `MeetingPollComposerSheet` implemented with real
  `com.testlogon.android.*` packages.
- DTO field names verified against `openapi.pretty.json` (§13 resolved; remaining open item is
  confirm/close authz only).
- Unit + Compose + repository contract tests green in CI; ktlint/detekt clean; no new
  cleartext-traffic surface beyond the dev base URL.
- Strings externalized with plurals; accessibility semantics present and verified with TalkBack
  smoke check.
- No poll content logged; telemetry events emit ids only.
- Spec reviewers (messaging owner) sign off; open questions either resolved or tracked as
  follow-up tickets.

## 16. Citations & Assumption Audit

Verified 2026-06-06 against `reference/openapi.index.txt`, `reference/openapi.pretty.json`, and
`reference/src/*`. Each numbered claim lists the VERDICT and an exact SOURCE pointer.

1. **Create endpoint = `POST /messaging/conversations/{conversation_id}/messages/meeting-poll`,
   resp 200 `MessageOut`.** VERDICT: Corrected (draft said flat `POST /messages/meeting-poll`,
   resp 201). SOURCE: `openapi.index.txt:343` (`op=create_meeting_poll_message...`,
   `req=CreateMeetingPollMessageIn`, `resp=200:MessageOut`); `src/api/endpoints/messaging.ts:759`
   (`sendMeetingPollMessage`).
2. **Create request = `CreateMeetingPollMessageIn` {title(1–200, req), slots(2–5, req,
   MeetingPollSlotIn{start_utc,end_utc}), duration_minutes(default 30, 15–1440), text(opt ≤2000)}.**
   VERDICT: Corrected (draft had `conversation_id`/`kind`/`allow_multiple`/free-text `options`/
   `label`, and slot range 2–10). SOURCE: `openapi.pretty.json` `components.schemas.
   CreateMeetingPollMessageIn` (lines 22519–22562) + `MeetingPollSlotIn` (50049–50066);
   `src/pages/messages/MeetingPollComposer.tsx` (enforces min 2 / max 5).
3. **There is NO free-text multiple-choice ("choice") poll on the `/messaging` surface.**
   VERDICT: Corrected (draft's dual "Choice poll / Meeting poll" composer). SOURCE: absence in
   `openapi.index.txt` messaging block (lines 339–375); the only free-text choice poll is
   newsfeed (`openapi.index.txt:518` `POST /posts/{post_id}/vote`, `req=VoteIn`), out of scope.
4. **Vote endpoint = `POST /messaging/conversations/{conversation_id}/polls/{poll_id}/vote`,
   req `PollVoteIn` = `{votes: {<slot_id>: "yes"|"no"|"maybe"}}`, resp `{ok:true}`.** VERDICT:
   Corrected (draft used `POST /polls/{id}/vote` with `{option_ids:[...]}` returning a Poll DTO).
   SOURCE: `openapi.index.txt:375`; `openapi.pretty.json` `PollVoteIn` (56088–56108, enum
   yes/no/maybe, additionalProperties map); `src/api/endpoints/messaging.ts:865`
   (`voteMeetingPoll` returns `{ok:boolean}`).
5. **Confirm endpoint = `POST /messaging/conversations/{conversation_id}/polls/{poll_id}/confirm`,
   req `PollConfirmIn` = `{slot_id (req), calendar_id? (opt)}`, resp `{ok, event_id?}`.** VERDICT:
   Corrected (draft used `option_id` and a `{close_only:true}` variant). SOURCE:
   `openapi.index.txt:374`; `openapi.pretty.json` `PollConfirmIn` (55962–55985);
   `src/api/endpoints/messaging.ts:876` (`confirmMeetingPoll`, sends `{slot_id, calendar_id}`,
   returns `{ok, event_id?}`).
6. **No meeting-poll "close" endpoint / `close_only` flag exists.** VERDICT: Corrected (draft FR-4
   called `/polls/{id}/confirm` with `{close_only:true}`). SOURCE: messaging endpoint set
   `openapi.index.txt:339–375` contains only create/get/vote/confirm for meeting polls. The
   `close` endpoint belongs to *find-datetime* (`openapi.index.txt:410`).
7. **Get/refresh = `GET /messaging/conversations/{conversation_id}/polls/{poll_id}` →
   `MeetingPollState`.** VERDICT: Corrected (draft `GET /polls/{id}`). SOURCE:
   `openapi.index.txt:373`; `src/api/endpoints/messaging.ts:856` (`getMeetingPoll`).
8. **Poll DTO = `MeetingPollState` {poll_id, title, duration_minutes, creator_id, status
   (open|confirmed|cancelled), confirmed_slot_id, slots[]} with each slot {slot_id, start_utc,
   end_utc, yes_count, maybe_count, no_count, my_vote(yes|no|maybe|null)}.** VERDICT: Corrected
   (draft had id/message_id/kind/allow_multiple/is_closed/created_by/total_voters/
   confirmed_option_id/my_votes[set] and per-option `vote_count`). SOURCE: `src/api/types.ts:953`
   (`MeetingPollState`) and `:934` (`MeetingPollSlot`).
9. **find-datetime is a separate feature** (window/range finder): create
   `POST /messaging/conversations/{conversation_id}/messages/find-datetime` (req
   `CreateFindDateTimeMessageIn`, resp 201); get `GET /messaging/messages/find-datetime/{poll_id}`
   → `FindDateTimeFull`; availability `POST .../availability` (`SubmitAvailabilityIn` =
   `{slots:[iso8601]}` 1–500); close `POST .../close`. VERDICT: Verified/clarified (draft conflated
   find-datetime availability/close with meeting-poll close). SOURCE: `openapi.index.txt:339,408,
   409,410`; `openapi.pretty.json` `CreateFindDateTimeMessageIn` (21654–21719),
   `SubmitAvailabilityIn` (70674–70692); `src/api/types.ts:997,1044`;
   `src/api/endpoints/messaging.ts:772,783,787,801`.
10. **Auth/CSRF: mutating calls send `X-CSRF-Token` from the `ui_csrf` cookie with credentialed
    requests; 401 → single `POST /ui/session/refresh` then retry.** VERDICT: Verified. SOURCE:
    `src/api/client.ts:168–171` (CSRF header from `getCookie("ui_csrf")`), `:183` & `:220`
    (`credentials:"include"`), `:122` (`/ui/session/refresh`), `:194–221` (one refresh+retry on
    401). Note the client also attaches `Authorization: Bearer` (`:158`) and the endpoints declare
    an `X-SESSION-ID` param (`openapi.index.txt:343` etc.) — both handled by shared transport.
11. **Web composer enforces 2–5 slots and a title.** VERDICT: Verified. SOURCE:
    `src/pages/messages/MeetingPollComposer.tsx:56–58` (`slots.length >= 5` guard), `:95`
    (`canSend = title && slots.length >= 2`).
12. **Stack/framework choices** (Compose Material 3 `ModalBottomSheet`, `SegmentedButton`,
    `rememberDatePickerState`, Room `@Transaction`, Moshi). VERDICT: Unverified-assumption
    (Android-side, not in backend/frontend sources). SOURCE: framework ref —
    Compose Material3 https://developer.android.com/jetpack/compose/components/bottom-sheets ,
    date/time pickers https://developer.android.com/jetpack/compose/components/datepickers ,
    Room transactions https://developer.android.com/training/data-storage/room .

### Corrections made

- **Endpoint paths**: all meeting-poll paths changed to the conversation-scoped
  `/messaging/conversations/{conversation_id}/...` form; get/vote/confirm fixed (claims 1,4,5,7).
- **HTTP/response codes**: create is 200 `MessageOut` (not 201); vote/confirm return `{ok}` /
  `{ok,event_id?}` not poll DTOs — added the mandatory reconcile-GET step (claims 1,4,5).
- **Request shapes**: vote `{votes:{slot_id:state}}` (not `option_ids`); confirm `{slot_id}` (not
  `option_id`/`close_only`); create dropped `conversation_id`/`kind`/`allow_multiple`/`options`/
  `label` and uses `duration_minutes`+`slots` (claims 2,4,5).
- **Conceptual**: removed the non-existent free-text "choice poll" mode; the meeting poll is a
  yes/maybe/no availability poll; removed the non-existent meeting-poll "close" action (claims 3,6).
- **DTO/model**: replaced `Poll`/`PollOption`/`PollKind` with `MeetingPoll`/`MeetingPollSlot`/
  `MeetingPollStatus`/`SlotVote`; slot counts are yes/maybe/no (no `total_voters`); `my_vote`
  replaces `my_votes` set; `status` enum replaces `is_closed` (claim 8). Domain, repo, ViewModel,
  Compose, Room (§4, §6), a11y (§9), telemetry (§10), risks (§13), ACs (§14), DoD (§15) all
  updated to match. Slot bound corrected 2–10 → 2–5 throughout.

### Open assumptions

- **Confirm/find-datetime-close authorization** is assumed creator-only; the backend authz rule
  and exact 403 body were not separately inspected in the sources (the schemas describe request
  bodies, not authz). Treat 403 as a normal `ApiResult.Error` (claim 5; §13).
- **`MessageOut` poll embedding**: we assume the create `MessageOut` carries enough poll state to
  render immediately before the reconcile GET; `MessageOut`'s exact poll-attachment field was not
  exhaustively traced (the web `MeetingPollAttachment` shape in `src/api/types.ts:944` is the
  likely carrier). Safe fallback: GET the poll right after create.
- **Android framework specifics** (claim 12) are standard-library choices, not verifiable from the
  backend/frontend sources; cited as framework refs.
- **Proportion-bar denominator**: no server field defines it (no `total_voters`); the UI must pick
  one (per-slot count sum, or max across slots) — a product/UX choice, not a backend contract.

## 17. Test Plan

Test IDs `TC-AND-136-NN`. Targets: JVM/Robolectric (local), emulator AVD `test35` (API 35,
x86_64), physical device Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Most cases here are
non-hardware and run fastest on JVM or the emulator; the ABI/API-skew case (TC-12) is the only one
that MUST run on the physical device. "Traces" links to §14 Acceptance Criteria.

- **TC-AND-136-01 — Create meeting poll happy path.** Type: contract/MockWebServer. Target:
  JVM/Robolectric. Preconditions: authenticated session; MockWebServer returns 200 `MessageOut`
  for `POST /messaging/conversations/{cid}/messages/meeting-poll`, then a `MeetingPollState` for
  the follow-up GET. Steps: build a `MeetingPollDraft` (title, duration 30, 3 valid slots) →
  `createMeetingPoll`. Expected: request body matches `CreateMeetingPollMessageIn`
  (`title`,`duration_minutes`,`slots[{start_utc,end_utc}]`, **no** `kind`/`option_ids`); the poll
  is upserted into Room; `observePoll` emits a `MeetingPoll` with the 3 slots. Traces: AC-1.

- **TC-AND-136-02 — Composer validation gates submit.** Type: Compose-UI. Target: emulator
  `test35`. Preconditions: `MeetingPollComposerSheet` shown. Steps: leave title blank / add only 1
  slot / add a slot with end ≤ start / add a 6th slot. Expected: Submit disabled for blank title,
  for <2 slots, and for end≤start; the "add slot" affordance is unavailable at 5 slots (2–5 bound).
  Traces: AC-1.

- **TC-AND-136-03 — Vote sets availability and reconciles.** Type: contract/MockWebServer. Target:
  JVM/Robolectric. Preconditions: open poll in Room; MockWebServer returns `{ok:true}` for
  `POST .../polls/{pid}/vote` and an updated `MeetingPollState` for the reconcile GET. Steps:
  `vote(cid, pid, slot_1, YES)`. Expected: POST body == `{"votes":{"slot_1":"yes"}}`; after the
  follow-up GET, Room reflects server `yes_count`/`my_vote`. Traces: AC-2.

- **TC-AND-136-04 — Optimistic update then reconcile (UI).** Type: Compose-UI. Target: emulator
  `test35`. Preconditions: `MeetingPollCard` bound to an open poll. Steps: tap a slot to vote Yes.
  Expected: the slot's Yes indicator and count update immediately (optimistic), `isMutating`
  disables re-tap, then the card settles to the reconciled server counts. Traces: AC-2, AC-5.

- **TC-AND-136-05 — Vote cycle / clear.** Type: unit (ViewModel). Target: JVM. Preconditions: slot
  `my_vote=null`. Steps: dispatch `SetSlotVote` yes→maybe→no→clear. Expected: yes/maybe/no/then a
  vote that omits the slot from the `votes` map (clear); each slot independent of others.
  Traces: AC-3.

- **TC-AND-136-06 — Confirm slot (creator).** Type: contract/MockWebServer. Target:
  JVM/Robolectric. Preconditions: caller is `creator_id`; MockWebServer returns
  `{ok:true,event_id:"evt_1"}` for `POST .../polls/{pid}/confirm`, then a `MeetingPollState` with
  `status:"confirmed"`. Steps: `confirmSlot(cid, pid, slot_2)`. Expected: POST body ==
  `{"slot_id":"slot_2"}` (no `option_id`/`close_only`); after reconcile, Room shows
  `status=CONFIRMED`, `confirmedSlotId=slot_2`. Traces: AC-4.

- **TC-AND-136-07 — Creator-only gating.** Type: Compose-UI + unit (ViewModel). Target: emulator
  `test35`. Preconditions: render once with `creator_id == currentUserId` and once without; once
  with `status=confirmed`. Expected: Confirm action visible only to the creator and only while
  `status==OPEN`; `canManage` false otherwise; voting disabled when `status!=OPEN`.
  Traces: AC-4, AC-6.

- **TC-AND-136-08 — Failed vote reverts + inline retry.** Type: contract/MockWebServer + Compose-UI.
  Target: JVM/Robolectric (logic) and emulator `test35` (UI). Preconditions: open poll; vote POST
  returns 500 (or the reconcile GET fails). Steps: tap a slot to vote. Expected: optimistic change
  reverts to the pre-tap snapshot, `inlineError` set ("Couldn't save your vote — tap to retry"),
  card stays interactive, poll not lost. Traces: AC-6.

- **TC-AND-136-09 — Flaky/offline cached render + retry.** Type: integration. Target:
  JVM/Robolectric (or emulator with airplane mode). Preconditions: poll cached in Room; network
  unreachable (simulate dev-host hang/timeout, no body). Steps: open thread; attempt a vote.
  Expected: cached poll renders with an "offline — votes may be out of date" caption; the GET
  refresh uses bounded backoff (≈3 tries); a vote attempt surfaces `NetworkError` as inline retry
  without crashing; mutating POSTs are NOT auto-retried. Traces: AC-5, AC-6.

- **TC-AND-136-10 — CSRF + 401 refresh-and-retry.** Type: contract/MockWebServer. Target:
  JVM/Robolectric. Preconditions: `ui_csrf` cookie present; MockWebServer returns 401 on the first
  vote, 200 on `POST /ui/session/refresh`, then 200 on the retried vote. Steps: vote. Expected:
  every mutating request carries `X-CSRF-Token` (== cookie value) and credentials; on 401 exactly
  one refresh is issued, then the original request retried once; a post-refresh failure surfaces as
  `ApiResult.Error`. Traces: AC-7.

- **TC-AND-136-11 — 422 validation error mapping.** Type: contract/MockWebServer. Target: JVM.
  Preconditions: create/vote returns `422` with FastAPI list-form `detail`
  (`[{loc,msg,type}]`). Steps: submit an invalid create (e.g. 1 slot bypassing client guard).
  Expected: the shared mapper yields `ApiResult.Error` with a field-level message surfaced inside
  the composer sheet (sheet not dismissed); no crash on the list-form `detail`. Traces: AC-1, AC-6.

- **TC-AND-136-12 — ABI/API-skew smoke (arm64 / API 34).** Type: instrumented/e2e. Target:
  **PHYSICAL DEVICE (SM-A156U, arm64-v8a, API 34) — MUST run here**, not the x86_64 API-35
  emulator. Preconditions: app installed via adb; test conversation seeded. Steps: create a meeting
  poll → vote → confirm against a MockWebServer/dispatcher (or staging). Expected: `java.time`
  UTC↔device-tz slot formatting, Moshi (de)serialization, and Room work identically on arm64/API
  34; no ABI-specific crash; confirms behavior matches the emulator suite. Traces: AC-1, AC-2,
  AC-4, AC-8.

- **TC-AND-136-13 — Accessibility (TalkBack/semantics).** Type: Compose-UI (instrumented). Target:
  emulator `test35` (with a TalkBack smoke pass on the physical device for DoD). Preconditions:
  `MeetingPollCard` rendered with mixed votes. Expected: each slot exposes a `stateDescription`
  for its yes/maybe/no/none response and a `contentDescription` combining the time range + counts;
  proportion bars are `clearAndSetSemantics{}` (decorative); Confirm overflow has a text label;
  touch targets ≥48dp; confirmed/cancelled use icon+text (not color alone). Traces: AC-5.

- **TC-AND-136-14 — End-to-end create → vote → confirm.** Type: instrumented/e2e. Target: emulator
  `test35` (fixture-backed dispatcher), with the same flow re-run on the physical device per TC-12.
  Preconditions: authenticated; dispatcher serves the full meeting-poll contract. Steps: open
  composer → create poll → poll appears inline → vote a slot → (as creator) confirm a slot.
  Expected: each step's results render (slots, counts, my_vote, confirmed badge) bound to Room as
  the single source of truth; satisfies the ticket's "tested" intent. Traces: AC-1, AC-2, AC-4,
  AC-5, AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (create meeting/find-datetime poll, renders inline) | TC-01, TC-02, TC-11, TC-12, TC-14 |
| AC-2 (vote sets/changes availability, optimistic+reconcile) | TC-03, TC-04, TC-12, TC-14 |
| AC-3 (per-slot response cycles/clears, independent slots) | TC-05 |
| AC-4 (creator confirm; non-creators never see it) | TC-06, TC-07, TC-12, TC-14 |
| AC-5 (results render from Room SSoT) | TC-04, TC-09, TC-13, TC-14 |
| AC-6 (failed vote reverts + inline retry) | TC-07, TC-08, TC-09, TC-11 |
| AC-7 (CSRF on mutations; 401 single refresh+retry) | TC-10 |
| AC-8 (e2e create→vote→confirm passes) | TC-12, TC-14 |
