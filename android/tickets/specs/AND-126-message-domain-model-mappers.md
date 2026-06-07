---
id: AND-126
title: Message domain model + mappers
milestone: M3
epic: E18
priority: P0
size: M
depends_on: [AND-120]
blocks: [AND-128]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-126 — Message domain model + mappers

## 1. Overview & Goal

This ticket delivers the **domain-layer representation of a chat message** plus
the pure mapping functions that convert the wire-format DTOs produced by AND-120
into that domain model. It produces no UI, no networking, no persistence, and no
business logic beyond translation. The deliverable is a sealed type `Message`
with a subtype per known kind — see the CORRECTED 17-value `kind` set below —
plus an explicit fallback for unrecognized kinds, and a total, loss-free
`MessageMapper` from the DTO surface.

> **REVIEW CORRECTION (kind value set).** The original spec named twelve types
> `text/image/video/file/voice/gif/sticker/poll/countdown/calendar/system`. The
> authoritative backend `kind` enum (OpenAPI `MessageOut.kind`, mirrored by
> `src/api/types.ts: Message.kind`) is the **17-value** set:
> `text, image, file, audio, video, gallery, file_share, calendar_share,
> calendar_event, meeting_poll, video_share, voice_message, voicemail,
> countdown, gif, sticker, find_datetime`. Concretely: `poll`→`meeting_poll`,
> `calendar`→`calendar_event` (plus a distinct `calendar_share`),
> `voice`→`voice_message`; `audio`, `gallery`, `file_share`, `video_share`,
> `voicemail`, `find_datetime` were **missing**; and **`system` does not exist**
> as a `kind`. The sealed hierarchy in §4.1 and the `when` branches in §4.2 must
> use these exact tokens. See §16 for the full audit.

The DTOs from AND-120 are intentionally permissive: the backend serializes every
message as one envelope object with a discriminator field — **`kind`** (CORRECTED:
the spec originally said `message_type`; the real `MessageOut`/`Message`
discriminator is `kind`. `message_type` exists only inside the optional `lottery`
sub-object with the single value `"lottery_dm"`). Per-type payload fields are
**flattened onto the message object** (e.g. `text`, `image`, `voice_message`,
`countdown_title`, `gif_url`), NOT nested under a single `content` sub-object
(CORRECTED). AND-120 owns the JSON contract; **AND-126 owns the Kotlin domain
shape the rest of the messaging feature (AND-122/123/124) programs against.** A
strongly-typed sealed model lets
Compose UI exhaustively `when`-branch over message kinds and isolates the
brittle, discriminator-driven parsing in one tested place.

Goal: ship the `core-model` sealed `Message` hierarchy and the `core-data`
`MessageMapper` such that **every known message type maps from its DTO without
information loss**, proven by fixture-driven round-trip unit tests, with unknown
types degrading to a safe `Message.Unsupported` rather than crashing or being
silently dropped.

## 2. Context & References

- **Module placement.** The sealed `Message` model and its value objects live in
  `core-model` under package `com.testlogon.android.core.model.messaging`. The
  mapper lives in `core-data` under
  `com.testlogon.android.core.data.messaging.MessageMapper` (kept next to the
  repository tickets that consume it). The mapper depends on both the AND-120
  DTOs and this domain model; neither `core-model` type depends on Moshi or DTOs.
- **Stack.** Kotlin 2.0.21, Coroutines/Flow, Moshi 1.15 (DTO side only). Domain
  model is a plain immutable Kotlin sealed hierarchy with no framework deps so it
  is unit-testable on the JVM. minSdk 24 / compileSdk 35, JDK 17.
- **Dependency (AND-120).** Provides `MessageDto`, `MessageContentDto`,
  `ConversationDto`, the `MessagingApi` Retrofit interface, and committed JSON
  fixtures for `GET /messaging/conversations`,
  `GET /messaging/conversations/{conversation_id}`, and
  `GET /messaging/conversations/{conversation_id}/messages` (CORRECTED full paths;
  all live under the `/messaging/` prefix). AND-126 maps `MessageDto` →
  `Message`; it does **not** add or change endpoints. (NOTE: no `/config` endpoint
  enumerating message kinds was found in the OpenAPI index — UNVERIFIED; treat the
  `kind` set as sourced from `MessageOut.kind` / `types.ts`, not `/config`.)
- **Downstream consumers.** AND-122 (list VM uses last-message preview),
  AND-123 (thread screen renders messages exhaustively), AND-124 (optimistic
  text send constructs a `Message.Text`), AND-128 (messaging core tests, which
  this ticket blocks).
- **Backend.** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference for exact
  field names and the discriminator value set: `src/api/types.ts` (the `Message`
  interface and its `kind` string-union — there is **no** `MessageType` type;
  CORRECTED), `src/api/endpoints/messaging.ts`, and especially
  `src/api/endpoints/messagingAdapter.ts` (`adaptMessage`/`adaptConversation` —
  the exact field-by-field normalization the web client applies, including epoch
  coercion via `toNum`). Mirror snake_case backend names exactly at the DTO
  layer; the domain layer uses idiomatic Kotlin names.
- **Time.** This is the layer that parses ISO-8601 strings carried as `String`
  in the DTOs into `Instant` domain values (deferred from AND-120 by design).

## 3. Functional Requirements

FR-1. Define a sealed interface `Message` with a common header (id, conversation
id, sender, timestamps, delivery/edit flags) shared by every subtype.

FR-2. Define one subtype per known `kind` discriminator (CORRECTED field name
and value set — see Overview/§16). Map the 17 real `kind` values to domain
subtypes, e.g. `Text, Image, File, Audio, Video, Gallery, FileShare,
CalendarShare, CalendarEvent, MeetingPoll, VideoShare, VoiceMessage, Voicemail,
Countdown, Gif, Sticker, FindDateTime`, plus `Unsupported` for any unrecognized
discriminator. (The original `Poll`/`Calendar`/`Voice`/`System` names were wrong;
`System` has no backend `kind` at all.)

FR-3. Each subtype carries the **full** typed payload for its kind (e.g. `Image`
carries url, dimensions, alt text, blurhash; `Poll` carries question + options +
vote tallies; `Voice` carries audio url + duration + waveform). No payload field
present in the DTO for a known type may be dropped during mapping.

FR-4. `MessageMapper.toDomain(dto: MessageDto): Message` is a **total** function:
it never throws for an unknown discriminator and never returns `null`; unknown or
malformed-but-present types map to `Message.Unsupported(rawType, raw)` preserving
the original type token and the raw payload for diagnostics/forward-compat.

FR-5. Provide the reverse mapper `MessageMapper.toDto(message: Message):
MessageDto` for the subtypes that are client-creatable (at minimum `Text`;
others as needed by send tickets) to support optimistic send (AND-124) and
fixture round-tripping.

FR-6. Provide `ConversationMapper.toDomain(dto: ConversationDto): Conversation`
including the mapped `lastMessage: Message?` preview, so the list/VM tickets get
a domain `Conversation` rather than a DTO.

FR-7. Timestamps map to `Instant`. **CORRECTED:** the wire format is **epoch
seconds as an integer** (`MessageOut.created_at`/`edited_at` are OpenAPI
`integer`; the web `adaptMessage` coerces via `toNum`, accepting `number` or
numeric `string`) — NOT ISO-8601 strings. The mapper therefore converts a numeric
epoch (use `Instant.fromEpochSeconds(...)`), guarding a missing/non-numeric value
to `null`/sentinel without throwing. (NOTE: a few *nested attachment* fields ARE
ISO-8601 strings — `CalendarEventAttachment.start_utc`/`end_utc`,
`MeetingPollSlot.start_utc`/`end_utc` — so the mapper needs BOTH an epoch-int path
for top-level message timestamps and an ISO-8601 path for those attachment
fields.)

FR-8. All domain types are immutable, annotated `@Immutable` (Compose stability)
where they enter composition, and expose `List<T>` (never mutable collections).

FR-9. Mapping must be **loss-free for all known types**, verified by a
DTO→domain→DTO round-trip whose re-serialized JSON tree equals the original
(ignoring key order/whitespace) for every committed fixture (the ticket's
acceptance bar).

## 4. Technical Design

> **REVIEW CORRECTION (applies to all code in §4).** The illustrative Kotlin
> below predates verification and still reflects the wrong wire contract: it reads
> `dto.messageType`, a nested `dto.content` sub-object, and parses `Instant` from
> ISO-8601 strings via `toInstantOrNull`, and it enumerates
> `Poll/Calendar/Voice/System` subtypes. Per the audit (§16) the implementation
> MUST instead: (1) branch on `dto.kind` (17 values); (2) read **flattened**
> top-level payload fields/objects (`text`, `image`, `voice_message`,
> `meeting_poll`, `countdown_title`+`target_datetime`, `gif_url`/`sticker_*`,
> etc.) — there is no `content` object; (3) build top-level `Instant`s from
> **epoch integers** (`Instant.fromEpochSeconds`), reserving ISO-8601 parsing for
> nested attachment fields (`*_utc`); and (4) name subtypes after the real kinds
> (`MeetingPoll`, `CalendarEvent`/`CalendarShare`, `VoiceMessage`, `Voicemail`,
> `Audio`, `Gallery`, `FileShare`, `VideoShare`, `FindDateTime`) with no `System`
> subtype. The shapes shown are kept only as design intent for the *domain* side;
> field names that touch the wire are corrected in §16.

### 4.1 Domain model (`core-model`)

```kotlin
package com.testlogon.android.core.model.messaging

import androidx.compose.runtime.Immutable
import kotlin.time.Instant

@Immutable
data class MessageId(val value: String)

@Immutable
data class MessageSender(
    val userId: String,
    val displayName: String?,
    val avatarUrl: String?,
)

/** Fields common to every message regardless of content type. */
@Immutable
data class MessageMeta(
    val id: MessageId,
    val conversationId: String,
    val sender: MessageSender,
    val sentAt: Instant?,
    val editedAt: Instant?,
    val deleted: Boolean = false,
    val replyToId: MessageId? = null,
)

@Immutable
sealed interface Message {
    val meta: MessageMeta

    @Immutable data class Text(
        override val meta: MessageMeta,
        val body: String,
    ) : Message

    @Immutable data class Image(
        override val meta: MessageMeta,
        val url: String,
        val width: Int?,
        val height: Int?,
        val altText: String?,
        val blurhash: String?,
        val caption: String?,
    ) : Message

    @Immutable data class Video(
        override val meta: MessageMeta,
        val url: String,
        val thumbnailUrl: String?,
        val durationMs: Long?,
        val width: Int?,
        val height: Int?,
        val caption: String?,
    ) : Message

    @Immutable data class File(
        override val meta: MessageMeta,
        val url: String,
        val fileName: String,
        val mimeType: String?,
        val sizeBytes: Long?,
    ) : Message

    @Immutable data class Voice(
        override val meta: MessageMeta,
        val url: String,
        val durationMs: Long,
        val waveform: List<Int> = emptyList(),
    ) : Message

    @Immutable data class Gif(
        override val meta: MessageMeta,
        val url: String,
        val previewUrl: String?,
        val width: Int?,
        val height: Int?,
    ) : Message

    @Immutable data class Sticker(
        override val meta: MessageMeta,
        val url: String,
        val packId: String?,
        val stickerId: String?,
    ) : Message

    @Immutable data class Poll(
        override val meta: MessageMeta,
        val question: String,
        val options: List<PollOption>,
        val multipleChoice: Boolean,
        val closesAt: Instant?,
        val myVotes: List<String> = emptyList(),
    ) : Message

    @Immutable data class Countdown(
        override val meta: MessageMeta,
        val title: String,
        val targetAt: Instant,
    ) : Message

    @Immutable data class Calendar(
        override val meta: MessageMeta,
        val title: String,
        val startAt: Instant,
        val endAt: Instant?,
        val location: String?,
        val description: String?,
    ) : Message

    /** Service/system notice (joins, renames, etc.). */
    @Immutable data class System(
        override val meta: MessageMeta,
        val event: String,
        val text: String,
    ) : Message

    /** Forward-compat fallback: unknown discriminator preserved verbatim. */
    @Immutable data class Unsupported(
        override val meta: MessageMeta,
        val rawType: String,
        val rawPayload: Map<String, Any?>,
    ) : Message
}

@Immutable
data class PollOption(
    val id: String,
    val label: String,
    val voteCount: Int,
)

@Immutable
data class Conversation(
    val id: String,
    val title: String?,
    val isDirect: Boolean,
    val avatarUrl: String?,
    val unreadCount: Int,
    val lastMessage: Message?,
    val updatedAt: Instant?,
)
```

### 4.2 Mapper (`core-data`)

```kotlin
package com.testlogon.android.core.data.messaging

import com.testlogon.android.core.model.messaging.*
import com.testlogon.android.core.model.messaging.dto.MessageDto
import com.testlogon.android.core.model.messaging.dto.ConversationDto

object MessageMapper {

    fun toDomain(dto: MessageDto): Message {
        val meta = dto.toMeta()
        val c = dto.content // typed-ish DTO sub-object from AND-120
        return when (dto.messageType.lowercase()) {
            "text"      -> Message.Text(meta, c.text.orEmpty())
            "image"     -> Message.Image(meta, c.url.orThrowMissing("url"), c.width, c.height, c.altText, c.blurhash, c.caption)
            "video"     -> Message.Video(meta, c.url.orThrowMissing("url"), c.thumbnailUrl, c.durationMs, c.width, c.height, c.caption)
            "file"      -> Message.File(meta, c.url.orThrowMissing("url"), c.fileName.orEmpty(), c.mimeType, c.sizeBytes)
            "voice"     -> Message.Voice(meta, c.url.orThrowMissing("url"), c.durationMs ?: 0L, c.waveform.orEmpty())
            "gif"       -> Message.Gif(meta, c.url.orThrowMissing("url"), c.previewUrl, c.width, c.height)
            "sticker"   -> Message.Sticker(meta, c.url.orThrowMissing("url"), c.packId, c.stickerId)
            "poll"      -> Message.Poll(meta, c.question.orEmpty(), c.options.toPollOptions(), c.multipleChoice ?: false, c.closesAt.toInstantOrNull(), c.myVotes.orEmpty())
            "countdown" -> Message.Countdown(meta, c.title.orEmpty(), c.targetAt.toInstantOrNull() ?: Instant.DISTANT_FUTURE)
            "calendar"  -> Message.Calendar(meta, c.title.orEmpty(), c.startAt.toInstantOrNull() ?: Instant.DISTANT_PAST, c.endAt.toInstantOrNull(), c.location, c.description)
            "system"    -> Message.System(meta, c.event.orEmpty(), c.text.orEmpty())
            else        -> Message.Unsupported(meta, dto.messageType, dto.rawPayload())
        }
    }

    fun toDto(message: Message): MessageDto = /* inverse for client-creatable types; see FR-5 */ TODO()
}
```

`orThrowMissing` is used only for fields structurally required for a *known* type
(e.g. an `image` with no `url`); such a DTO is malformed and surfaces a mapping
`IllegalStateException` caught at the repository boundary and converted to
`ApiResult.Error` (AND-018) — it does **not** crash the app. An *unknown
discriminator* never reaches `orThrowMissing`; it routes to `Unsupported`. Helper
extensions (`toInstantOrNull`, `toMeta`, `rawPayload`) are private to the mapper
module; ISO-8601 parsing uses `Instant.parse` in a try/catch returning `null`.

The discriminator string set is the single coupling point to the backend's
`MessageType` union (`frontend/src/api/types.ts`); mirror it as a private `const`
set and cross-check in tests against the AND-120 `/config` fixture if that
endpoint enumerates supported types.

## 5. API Contract

This ticket performs **no network I/O**. Endpoint ownership belongs to AND-120
(`MessagingApi`). The contract relevant here is the shape of the `MessageDto`
this mapper consumes.

> **REVIEW CORRECTION (envelope shape).** The original sample below was
> fabricated and wrong on every structural axis. Verified against OpenAPI
> `GET /messaging/conversations/{conversation_id}/messages` → `MessageOut`
> (the list endpoint returns a plain array of `MessageOut`, not a nested
> `content` envelope) and `src/api/types.ts: Message`:
> - id field is `message_id` (not `id`); sender is a **flat** `sender_id`
>   string (there is no nested `sender { user_id, display_name, avatar_url }`
>   object on the message — display name/avatar come from `Conversation.participants`).
> - timestamp is `created_at`: **epoch integer** (not `sent_at` ISO string);
>   `edited_at` is epoch integer|null.
> - discriminator is `kind` (not `message_type`).
> - per-type payload is **flattened**, not under `content`. A poll is
>   `kind: "meeting_poll"` with a `meeting_poll` object
>   (`{ poll_id, creator_id, title, duration_minutes, status, confirmed_slot_id }`,
>   slots/votes live in the separate `MeetingPollState`), NOT a `content.question`/
>   `options[].vote_count`/`my_votes` shape.
> - required top-level fields (OpenAPI `MessageOut.required`):
>   `message_id, sender_id, created_at, kind`.

Corrected representative envelope (one `MessageOut` from
`GET /messaging/conversations/{conversation_id}/messages`):

```json
{
  "message_id": "msg_01H...",
  "conversation_id": "cnv_42",
  "sender_id": "usr_7",
  "created_at": 1749124800,
  "edited_at": null,
  "kind": "meeting_poll",
  "meeting_poll": {
    "poll_id": "mp_1",
    "creator_id": "usr_7",
    "title": "Lunch?",
    "duration_minutes": 60,
    "status": "open",
    "confirmed_slot_id": null
  }
}
```

Text variant: top-level `{ "kind": "text", "text": "hi" }`. Image variant:
top-level `kind: "image"` with an `image` object
(`MessageImage`: `{ bucket, key, content_type, width, height, url, filename,
filesize, preview_url, ... }` — note `alt_text`/`blurhash`/`caption` do **not**
exist; the adapter synthesizes `url` from `bucket`+`key` when `url` is absent).
The full per-type schemas are frozen by AND-120; this spec encodes the **mapping**
of those keys to domain fields. The `kind` discriminator value set (17 values,
§16) is the authority for the `when` branches in §4.2.

## 6. Data & State Management

No persistent or observable app state is introduced. The domain
`Message`/`Conversation` types are the **output** of the mapper and the **input**
to ViewModels and (later) Room entity mappers; Room/DataStore persistence is
owned by the messaging cache/repository tickets, not here. Domain types are
`@Immutable` so they are stable in Compose and safe to hold in
`StateFlow<UiState>` lists without spurious recomposition. Timestamps are
normalized to `Instant` exactly once, at this boundary, so upstream layers work in
a single time type. `Message.Unsupported.rawPayload` retains the original JSON map
so a future ticket can render or re-serialize an unknown type without data loss.

## 7. Error Handling & Resilience

Mapping-level robustness only (network timeouts, the ~20s budget, bounded GET
retry, and offline/stale UI belong to core-network and the messaging
repository/feature tickets):

- **Unknown discriminator** → `Message.Unsupported`, never throws, original type
  token + raw payload preserved.
- **Missing structurally-required field of a *known* type** (e.g. image without
  `url`) → mapper throws `IllegalStateException`; the repository wraps it as
  `ApiResult.Error` so a single malformed message does not crash the thread. The
  repository should skip/placeholder the bad item rather than fail the whole page
  (recommended: map the page item-by-item, substituting `Unsupported` on a
  per-item map failure — implemented in the repository ticket, contract noted
  here).
- **Malformed timestamp** → `null` (or guarded sentinel for non-null targets like
  `Countdown.targetAt`); never throws.
- **Empty/absent `content`** for a text message → empty body, not crash.
- **Additive backend fields** inside `content` → ignored at the DTO layer
  (Moshi default, AND-120), invisible here.

## 8. Security & Privacy

- The domain model carries no credentials or tokens; auth rides on cookies and
  never reaches this layer.
- Message bodies, media URLs, and poll content are user data: they must **not**
  be logged at this layer. The mapper performs no logging. `Message` subtypes
  rely on default `data class` `toString()`; if any debug `toString()` is added
  for `Unsupported`, it must **not** dump `rawPayload` to logcat in release
  builds (gate behind `BuildConfig.DEBUG`).
- Media URLs may be signed/expiring; the model stores them verbatim and treats
  them as opaque (no parsing, no caching of credentials).
- Test fixtures use synthetic users, ids, and URLs only — no real PII.

## 9. Accessibility & i18n

No UI surface, so no direct a11y obligations and no `strings.xml` entries. This
ticket **enables** accessibility downstream by carrying the fields the thread UI
(AND-123) needs: `Image.altText`/`caption` for content descriptions,
`Voice.durationMs`/`Video.durationMs` for spoken duration labels, and
`System.text`/`Poll.question`/`option.label` as human-readable strings. No
timestamp is pre-formatted here, preserving locale-correct rendering downstream.

## 10. Telemetry & Logging

No analytics events are emitted by the mapper or model. The only diagnostic
allowance is a single **debug-only** counter/log when a message maps to
`Message.Unsupported`, to detect new backend types in the field — emitted via the
shared logger behind `BuildConfig.DEBUG`, with only the `rawType` token (never the
payload). This is optional and must be off in release. No request/response body
logging is introduced (that is core-network's redaction-governed concern).

## 11. Testing Strategy

All tests are JVM unit tests in `core-data` (mapper) referencing `core-model`
types and the AND-120 fixtures; no Android instrumentation required.

- **Per-type happy path.** For each of the twelve known types, a committed
  fixture `core-data/src/test/resources/messaging/message_<type>.json` is
  deserialized via the AND-120 DTO adapter, mapped with `MessageMapper.toDomain`,
  and asserted to produce the correct subtype with every payload field populated.
- **Loss-free round-trip (acceptance bar).** For every fixture,
  `toDto(toDomain(dto))` re-serialized has a parsed JSON tree **equal** to the
  original (compared as Moshi `Map`/`JSONObject`, ignoring key order/whitespace).
  Exact for client-creatable types; for server-only fields a per-type
  field-coverage assertion proves no known field is dropped.
- **Exhaustiveness.** A test enumerates the discriminator set and asserts each
  maps to a non-`Unsupported` subtype, guarding against a forgotten `when` branch.
- **Unknown type.** A fixture with `"message_type": "audio_room"` (or any unknown
  token) maps to `Message.Unsupported` with `rawType == "audio_room"` and a
  non-empty `rawPayload`, and does **not** throw.
- **Malformed known type.** An `image` fixture missing `url` causes
  `toDomain` to throw `IllegalStateException` (asserted), confirming fail-fast for
  malformed-but-known content.
- **Timestamp parsing.** Valid ISO-8601 parses to the expected `Instant`; a
  malformed timestamp yields `null`/sentinel without throwing.
- **Conversation mapping.** `ConversationMapper.toDomain` maps `lastMessage` via
  the same path and preserves `unreadCount`.
- **Test classes.** `com.testlogon.android.core.data.messaging.MessageMapperTest`
  and `ConversationMapperTest`. Coverage target: every Section 4.1 subtype has at
  least one fixture + round-trip assertion (this is the ticket's stated acceptance
  — *all known types map without loss, tested*).

## 12. Dependencies & Sequencing

- **Depends on AND-120** (Messaging API + DTOs): requires `MessageDto`,
  `MessageContentDto`/payload accessors, `ConversationDto`, and the committed
  messaging JSON fixtures the mapper tests reuse. The discriminator value set and
  per-type `content` schemas are frozen by AND-120; if AND-120's `content` is a
  raw `Map<String, Any?>` rather than typed accessors, the mapper reads keys
  defensively from that map (no edit to AND-120 required).
- **Blocks AND-128** (messaging core tests): repo/UI tests assert thread and list
  rendering over the domain `Message`/`Conversation` types this ticket defines.
- **Enables (does not strictly block) AND-122/123/124**: list VM, thread screen,
  and optimistic text send all program against the sealed `Message` model; their
  exhaustive `when` rendering and `Message.Text` construction depend on this
  shape. Sequence AND-126 immediately after AND-120 and before the messaging UI
  tickets.

## 13. Risks & Open Questions

- **R1 — Discriminator drift.** RESOLVED at review (§16): discriminator is `kind`
  with a frozen 17-value enum in OpenAPI `MessageOut.kind` (mirrored by
  `src/api/types.ts: Message.kind`). Canonical tokens are `gif`, `sticker`,
  `voice_message` (and `audio` is a *separate* kind from `voice_message`). Keep a
  fixture per kind to guard against future backend additions (which now route to
  `Unsupported`).
- **R2 — Per-type payload field names.** RESOLVED at review (§16): payload is
  flattened on the message (no `content` object). Voice waveform is
  `voice_message.waveform_data: number[]` (int array, not base64). The poll kind
  is `meeting_poll` with slot-level `yes_count`/`maybe_count`/`no_count`
  (`MeetingPollSlot`), not a `vote_count`/`my_votes` shape. Calendar uses
  `calendar_event.start_utc`/`end_utc` (ISO-8601 strings) + `timezone`/`all_day`.
- **R3 — Loss-free definition for server-only fields.** Server-computed fields
  (e.g. poll tallies, signed URLs) are not echoed on client→server round-trips;
  "loss-free" is therefore defined as *domain retains every DTO field*, and the
  round-trip test scopes exactness to client-creatable types. *Open:* confirm
  with reviewers this interpretation satisfies the acceptance bullet.
- **R4 — `Unsupported` reachability.** A required-but-unknown message type could
  render as a blank/placeholder in the thread. *Mitigation:* preserve
  `rawPayload` and surface a "message not supported, update the app" placeholder
  in AND-123 (noted for that ticket).
- **R5 — Time type.** minSdk 24 requires core library desugaring for
  `java.time.Instant`; `kotlin.time.Instant` (stdlib) avoids it. *Open:* confirm
  the project's standard `Instant` type and align.

## 14. Acceptance Criteria

1. A sealed `Message` hierarchy exists in
   `com.testlogon.android.core.model.messaging` with one immutable subtype for
   each of the twelve known types (`Text, Image, Video, File, Voice, Gif,
   Sticker, Poll, Countdown, Calendar, System`) plus `Unsupported`, all
   `@Immutable`.
2. `MessageMapper.toDomain(MessageDto): Message` is total — it never throws for an
   unknown discriminator and never returns `null`; unknown types map to
   `Message.Unsupported` preserving `rawType` and `rawPayload`.
3. **Every known message type maps from its DTO without loss**, proven by
   `MessageMapperTest` against one committed fixture per type, with a
   DTO→domain→DTO round-trip whose parsed JSON tree equals the original for
   client-creatable types and a field-coverage assertion for all types.
4. A malformed *known* type (e.g. `image` without `url`) throws
   `IllegalStateException`; a malformed timestamp maps to `null`/sentinel without
   throwing.
5. `ConversationMapper.toDomain` maps `lastMessage` and `unreadCount` and is
   tested.
6. The exhaustiveness test confirms every discriminator routes to a
   non-`Unsupported` subtype, guarding the `when`.
7. Modules compile; `core-model` has no Moshi/DTO dependency; the mapper depends
   only on `core-model` + AND-120 DTOs.

## 15. Definition of Done

- Code merged to `android-port`: sealed `Message`/`Conversation` model under
  `core-model` (`com.testlogon.android.core.model.messaging`) and `MessageMapper`
  + `ConversationMapper` under `core-data`
  (`com.testlogon.android.core.data.messaging`).
- `MessageMapperTest` and `ConversationMapperTest` pass in CI; one committed JSON
  fixture per known type plus an unknown-type and a malformed-known fixture under
  `core-data/src/test/resources/messaging/`.
- `./gradlew :core-model:test :core-data:test` green on JDK 17; no new
  lint/detekt violations.
- No UI, persistence, or network-call code introduced (those are downstream
  tickets); no message content logged.
- Open questions R1/R2/R5 (discriminator spelling, per-type `content` field
  names, `Instant` type) resolved against `/openapi.json` and the live dev host
  (or explicitly re-ticketed) before AND-123/124 consume the model.
- Spec reviewed; AND-128 can build its repo/UI tests against the domain model.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and the exact source pointer. "OpenAPI"
refers to the backend index/spec; frontend pointers are repo-relative under
`reference/src/`.

1. **Message discriminator field is `message_type`.** VERDICT: **Corrected** → the
   discriminator is **`kind`**. `message_type` exists only inside the optional
   `lottery` sub-object (value `"lottery_dm"`). SOURCE: OpenAPI
   `components.schemas.MessageOut.kind` (required); `src/api/types.ts: Message`
   (line `kind: "text" | ...`); `src/api/types.ts: Message.lottery.message_type`.

2. **Known message kinds are the 12 values
   `text/image/video/file/voice/gif/sticker/poll/countdown/calendar/system`.**
   VERDICT: **Corrected** → the real enum has **17** values:
   `text, image, file, audio, video, gallery, file_share, calendar_share,
   calendar_event, meeting_poll, video_share, voice_message, voicemail,
   countdown, gif, sticker, find_datetime`. `poll`→`meeting_poll`,
   `calendar`→`calendar_event` (+`calendar_share`), `voice`→`voice_message`;
   `audio/gallery/file_share/video_share/voicemail/find_datetime` were missing;
   `system` does not exist. SOURCE: OpenAPI `MessageOut.kind.enum`;
   `src/api/types.ts: Message.kind`.

3. **Per-type payload lives in a nested `content` sub-object.** VERDICT:
   **Corrected** → payload fields/objects are **flattened** onto the message
   (`text`, `image`, `file`, `voice_message`, `voicemail`, `video_share`,
   `meeting_poll`, `calendar_event`, `calendar_share`, `find_datetime`,
   `gif_url`/`gif_*`, `sticker_*`, `countdown_title`/`target_datetime`,
   `free_images`/`locked_images`). There is no `content` key. SOURCE:
   `src/api/types.ts: Message` (lines ~1098-1217);
   `src/api/endpoints/messagingAdapter.ts: adaptMessage` (field-by-field copy).

4. **Top-level timestamps are ISO-8601 strings parsed with `Instant.parse`.**
   VERDICT: **Corrected** → `created_at`/`edited_at`/`consumed_at`/`revoked_at`
   are **epoch integers**. SOURCE: OpenAPI `MessageOut.created_at` (`type:
   integer`, required), `edited_at` (`integer|null`);
   `src/api/endpoints/messagingAdapter.ts` (`toNum`, `created_at: toNum(raw.created_at)`).

5. **Some nested attachment time fields ARE ISO-8601 strings.** VERDICT:
   **Verified** → `CalendarEventAttachment.start_utc`/`end_utc` and
   `MeetingPollSlot.start_utc`/`end_utc` are ISO-8601 `string`s. SOURCE:
   `src/api/types.ts: CalendarEventAttachment`, `MeetingPollSlot`.

6. **Message id/sender fields are `id` and a nested `sender { user_id,
   display_name, avatar_url }`.** VERDICT: **Corrected** → flat `message_id` and
   `sender_id` (strings); no nested sender object on the message (display
   name/avatar come from `Conversation.participants`, which carry `display_name`,
   `profile_photo_url`). SOURCE: OpenAPI `MessageOut.required = [message_id,
   sender_id, created_at, kind]`; `src/api/types.ts: Message`, `Participant`.

7. **Poll payload is `{ question, options[].vote_count, multiple_choice,
   closes_at, my_votes }`.** VERDICT: **Corrected** → `meeting_poll` is
   `{ poll_id, creator_id, title, duration_minutes, status, confirmed_slot_id }`;
   slot-level tallies (`yes_count`/`maybe_count`/`no_count`, `my_vote`) live in
   `MeetingPollSlot` within `MeetingPollState` (fetched separately). SOURCE:
   `src/api/types.ts: MeetingPollAttachment`, `MeetingPollSlot`, `MeetingPollState`.

8. **Voice payload is `{ url, durationMs, waveform: List<Int> }`.** VERDICT:
   **Corrected** → `voice_message` is `{ audio_url, audio_content_type,
   audio_size_bytes, duration_seconds, waveform_data: number[] }` (duration in
   **seconds**, not ms; waveform key is `waveform_data`). A separate `voicemail`
   object exists for call voicemails. SOURCE: `src/api/types.ts: Message.voice_message`,
   `Message.voicemail`.

9. **Image payload carries `alt_text`, `blurhash`, `caption`.** VERDICT:
   **Corrected** → `MessageImage` is `{ bucket, key, content_type, width, height,
   url, filename, filesize, file_created_at, preview_url }`. No `alt_text`/
   `blurhash`/`caption`. The adapter derives `url` from `bucket`+`key` when absent.
   SOURCE: `src/api/types.ts: MessageImage`;
   `src/api/endpoints/messagingAdapter.ts` (`buildS3ObjectUrl`).

10. **Conversation is `{ id, title, isDirect, avatarUrl, unreadCount,
    lastMessage, updatedAt }`.** VERDICT: **Corrected** (DTO side) → `Conversation`
    is `{ conversation_id, type: "dm"|"group", title, ..., unread_count,
    last_message_at (epoch int), last_message_preview (string), last_message?:
    Message, participants[] }`. Domain renaming is fine, but the DTO field names
    differ (`conversation_id`, `type`, `unread_count`). SOURCE:
    `src/api/types.ts: Conversation`;
    `src/api/endpoints/messagingAdapter.ts: adaptConversation`.

11. **Messaging list/get endpoint paths.** VERDICT: **Corrected/Verified** → all
    under `/messaging/`: `GET /messaging/conversations`,
    `GET /messaging/conversations/{conversation_id}`,
    `GET /messaging/conversations/{conversation_id}/messages`. List endpoints
    return a **plain array** (web client also tolerates `{ messages, next_cursor }`).
    Messages paginate via the `before` query param. SOURCE: OpenAPI index lines
    312/317/332; `src/api/endpoints/messaging.ts: getConversations/getMessages`.

12. **Reverse mapper `toDto` for client-creatable Text.** VERDICT: **Verified
    (with nuance)** → there is no single envelope POST; sends are per-kind
    endpoints. Text send is `POST /messaging/conversations/{conversation_id}/messages`
    with `SendTextMessageIn` whose body field is **`body`** (not `text`); the
    *response* `MessageOut` carries the string in `text`. SOURCE: OpenAPI
    `POST /messaging/conversations/{conversation_id}/messages` (req
    `SendTextMessageIn`, resp `MessageOut`); `SendTextMessageIn.body`.

13. **Other client-creatable kinds have dedicated endpoints.** VERDICT:
    **Verified** → e.g. `.../messages/gif` (`SendGifMessageIn`),
    `.../messages/sticker` (`SendStickerMessageIn`), `.../messages/countdown`
    (`SendCountdownMessageIn`), `.../messages/image` (`CreateImageMessageIn`),
    `.../messages/file` (`CreateFileMessageIn`), `.../messages/calendar-event`,
    `.../messages/meeting-poll`, `.../messages/find-datetime`. SOURCE: OpenAPI
    index lines 333-347.

14. **Auth rides on cookies; no credentials reach this mapper layer.** VERDICT:
    **Verified** → web client uses cookie session (`credentials: "include"`) plus
    `Authorization: Bearer` from the auth store and CSRF `ui_csrf` cookie echoed
    as `X-CSRF-Token`; messaging endpoints also accept `X-SESSION-ID`. None of
    this touches the pure mapper (no network here). SOURCE: `src/api/client.ts`
    (lines ~124, 158-170; `getCookie("ui_csrf")` → `X-CSRF-Token`); OpenAPI
    `params=...,X-SESSION-ID` on messaging routes.

15. **Error/validation response shapes.** VERDICT: **Verified** → request
    validation returns **422 `HTTPValidationError`**; messaging read/send routes
    additionally document `400/401/403/429`. Some message-control routes use
    `MessageControlsErrorOut`. SOURCE: OpenAPI index lines 332-333 (`resp=...;422:
    HTTPValidationError;400;401;403;429`), 326/330 (`MessageControlsErrorOut`).

16. **Web client caches messaging reads for the flaky/offline dev host.**
    VERDICT: **Verified** → `getConversations`/`getMessages` wrap the network call
    in `withOfflineCache` keyed by endpoint + user id. SOURCE:
    `src/api/endpoints/messaging.ts` (`withOfflineCache(networkFn, {endpoint:...})`).

17. **`Instant` type for minSdk 24 (framework choice).** VERDICT:
    **Unverified-assumption** → the spec uses `kotlin.time.Instant` to avoid core
    library desugaring of `java.time.Instant` on minSdk 24. This is a reasonable
    Kotlin-stdlib choice but is a project convention not verifiable from backend/
    frontend sources. framework ref:
    https://developer.android.com/studio/write/java8-support-table (desugaring of
    `java.time`); https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.time/-instant/.

18. **`Message.Unsupported.rawPayload` as `Map<String, Any?>` for forward-compat.**
    VERDICT: **Verified (design-consistent)** → matches how the web client treats
    unknown shapes (additive fields tolerated; lottery carried as an opaque
    sub-object). No backend contract forbids it. SOURCE:
    `src/api/endpoints/messagingAdapter.ts` (spreads unknown nested objects).

### Corrections made

- Discriminator field corrected `message_type` → **`kind`** (Overview, §2, §4, §5,
  FR-2, R1). `message_type` retained only as the `lottery.message_type` token.
- Kind value set corrected from 12 invented tokens to the **17** authoritative
  enum values; `poll`→`meeting_poll`, `calendar`→`calendar_event`/`calendar_share`,
  `voice`→`voice_message`; added `audio/gallery/file_share/video_share/voicemail/
  find_datetime`; removed nonexistent `system` (Overview, FR-2, §4, §13).
- Payload model corrected from a nested `content` object to **flattened** top-level
  fields (Overview, §4, §5).
- Timestamp wire format corrected from ISO-8601 strings to **epoch integers** for
  top-level message times, with ISO-8601 retained only for nested `*_utc`
  attachment fields (FR-7, §4, §5, R2).
- Id/sender shape corrected to flat `message_id`/`sender_id` (no nested `sender`)
  (§5).
- Poll/voice/image payload field names corrected to the real attachment schemas
  (§5, §13, §16 items 7-9).
- Conversation DTO field names corrected (`conversation_id`/`type`/`unread_count`/
  `last_message_*`) (§16 item 10).
- Endpoint paths corrected to the `/messaging/...` prefix; removed the
  unverifiable `/config` kind-enumeration claim (§2).
- Frontend reference paths corrected (`frontend/src/...` → `src/...`; added
  `messagingAdapter.ts`); removed the nonexistent `MessageType` union reference.
- R1/R2 reclassified from open to resolved.

### Open assumptions

- **`Instant` type / desugaring** (item 17): project-level Kotlin convention, not
  derivable from API sources. Confirm against the repo's existing time type.
- **`/config` kind enumeration**: no such endpoint found in the OpenAPI index, so
  the cross-check the spec proposed cannot be implemented; the `kind` set is taken
  from `MessageOut.kind`. If a config/feature endpoint is added later, re-ticket.
- **AND-120 DTO accessor style** (typed accessors vs raw `Map`): owned by AND-120;
  this spec assumes the mapper reads flattened keys defensively. Unverifiable until
  AND-120 lands.
- **`Unsupported.rawPayload` Compose stability**: a `Map<String, Any?>` is not
  `@Immutable`-stable; holding `Unsupported` in composition may need a stability
  wrapper or `@Stable` annotation. Flag for §4.1/AND-123; not contract-derivable.
- **`reply_to_id` / `deleted` domain fields** (in §4.1 `MessageMeta`): the backend
  uses `reply_to_message_id` and `revoked_at`/`revoked_by` (not a boolean
  `deleted`); the domain `deleted: Boolean` should be derived from `revoked_at != null`
  and `replyToId` mapped from `reply_to_message_id`. Confirm naming when wiring.

## 17. Test Plan

All cases target the pure JVM mapper/model unless noted. Test classes:
`MessageMapperTest`, `ConversationMapperTest` (package
`com.testlogon.android.core.data.messaging`). Fixtures live under
`core-data/src/test/resources/messaging/`. "Traces" link to §14 Acceptance
Criteria (AC-1..AC-7). Because this ticket is a pure-Kotlin mapping layer with no
UI/network/hardware, almost everything runs as JVM unit tests; device/emulator
notes are included only where a downstream/contract concern legitimately needs one.

- **TC-AND-126-01 — Per-kind happy-path mapping (parameterized over all 17
  kinds).** Type: unit (JVM). Target: JVM unit/Robolectric (no device).
  Preconditions: one committed fixture per real `kind`
  (`message_text.json`, `message_image.json`, `message_meeting_poll.json`,
  `message_voice_message.json`, `message_voicemail.json`, `message_calendar_event.json`,
  `message_calendar_share.json`, `message_countdown.json`, `message_gif.json`,
  `message_sticker.json`, `message_audio.json`, `message_video.json`,
  `message_video_share.json`, `message_gallery.json`, `message_file.json`,
  `message_file_share.json`, `message_find_datetime.json`), each using the real
  flattened wire shape with epoch-int `created_at`. Steps: deserialize via the
  AND-120 DTO adapter; call `MessageMapper.toDomain`. Expected: each maps to its
  matching (non-`Unsupported`) subtype with every payload field populated and
  non-defaulted. Traces: AC-1, AC-3.

- **TC-AND-126-02 — Loss-free round-trip for client-creatable kinds.** Type:
  unit (JVM). Target: JVM unit. Preconditions: fixtures for client-creatable
  kinds (at least `text`, `gif`, `sticker`, `countdown`, `image`). Steps:
  `toDto(toDomain(dto))`, re-serialize, parse both as Moshi `Map`/`JSONObject`.
  Expected: trees equal ignoring key order/whitespace; for the text round-trip,
  assert the send shape uses `body` while the response shape uses `text` (per §16
  item 12). Traces: AC-3.

- **TC-AND-126-03 — Field-coverage (no dropped field) for server-only kinds.**
  Type: unit (JVM). Target: JVM unit. Preconditions: fixtures for non-creatable
  kinds (`meeting_poll`, `voicemail`, `video_share`, `find_datetime`,
  `calendar_event`). Steps: map to domain; assert every key present in the fixture
  payload has a corresponding populated domain field (reflective key-coverage
  assertion). Expected: zero uncovered keys. Traces: AC-3.

- **TC-AND-126-04 — Exhaustiveness guard over the kind enum.** Type: unit (JVM).
  Target: JVM unit. Preconditions: a hard-coded copy of the 17-value `kind` set
  (the §16 list). Steps: for each token, map a minimal valid fixture/synthetic DTO;
  assert result is not `Message.Unsupported`. Expected: all 17 route to concrete
  subtypes; the test fails if a `when` branch is missing or a token is misspelled.
  Traces: AC-1, AC-6.

- **TC-AND-126-05 — Unknown discriminator → `Unsupported`, total/no-throw.**
  Type: unit (JVM). Target: JVM unit. Preconditions: fixture with
  `"kind": "audio_room"` (a token outside the enum) plus a populated payload.
  Steps: call `toDomain`. Expected: returns `Message.Unsupported` with
  `rawType == "audio_room"` and non-empty `rawPayload`; never throws, never null.
  Traces: AC-2.

- **TC-AND-126-06 — Malformed known kind (image without resolvable url) →
  `IllegalStateException`.** Type: unit (JVM). Target: JVM unit. Preconditions:
  `message_image_missing_url.json` with `kind:"image"` and an `image` object that
  has neither `url` nor `bucket`+`key`. Steps: call `toDomain`; expect throw.
  Expected: `IllegalStateException` naming the missing field; does not crash a
  test harness (caught at repo boundary downstream). Traces: AC-4.

- **TC-AND-126-07 — Timestamp parsing (epoch int → Instant; malformed →
  null/sentinel).** Type: unit (JVM). Target: JVM unit. Preconditions: fixtures
  with (a) valid integer `created_at`, (b) `created_at` as numeric string
  (adapter-tolerated), (c) `edited_at: null`, (d) a non-numeric/garbage
  `created_at`. Steps: map each. Expected: (a)/(b) →
  `Instant.fromEpochSeconds(value)`; (c) → null `editedAt`; (d) → null/sentinel
  without throwing. Additionally assert nested `calendar_event.start_utc` ISO-8601
  parses correctly. Traces: AC-4.

- **TC-AND-126-08 — Conversation mapping incl. lastMessage + unread_count.**
  Type: unit (JVM). Target: JVM unit (`ConversationMapperTest`). Preconditions:
  `conversation.json` with `conversation_id`, `type:"group"`, `unread_count`,
  `last_message_at` (epoch), and a nested `last_message` of `kind:"text"`. Steps:
  `ConversationMapper.toDomain`. Expected: domain `Conversation` with `lastMessage`
  mapped via the same path, `unreadCount` preserved, `updatedAt` from
  `last_message_at`. Traces: AC-5.

- **TC-AND-126-09 — Module/dependency boundary (architecture test).** Type:
  unit (JVM). Target: JVM unit (e.g. Konsist/ArchUnit or a compile-only check).
  Preconditions: `core-model` and `core-data` modules present. Steps: assert no
  `core-model` type imports Moshi/DTO packages; assert the mapper depends only on
  `core-model` + AND-120 DTO package. Expected: assertions pass; build green.
  Traces: AC-7.

- **TC-AND-126-10 — No message content logged (security).** Type: unit (JVM).
  Target: JVM unit. Preconditions: a captured logger/test tree; a `text` and a
  `meeting_poll` fixture. Steps: map both with a spy logger installed. Expected:
  zero log emissions containing `body`/`text`/poll `title`/media URLs; if the
  optional `Unsupported` debug counter fires it logs only `rawType`, gated behind
  `BuildConfig.DEBUG`. Traces: AC-2 (supports §8/§10).

- **TC-AND-126-11 — Lottery sub-object preserved without collapsing to
  Unsupported.** Type: unit (JVM). Target: JVM unit. Preconditions: fixture with
  a known top-level `kind` (e.g. `text`) carrying a `lottery` object whose
  `message_type:"lottery_dm"`. Steps: map. Expected: maps to the normal subtype
  for its `kind` (the inner `message_type` is NOT the discriminator and must not
  reroute to `Unsupported`); lottery data is retained or explicitly carried.
  Traces: AC-1, AC-2.

- **TC-AND-126-12 — Per-item resilience over a real fixture page (contract).**
  Type: contract/MockWebServer. Target: emulator AVD `test35` (API 35) for a fast
  CI instrumented run of the AND-120 Retrofit adapter + this mapper end-to-end;
  the mapper logic itself is JVM-pure, but exercising it through the actual JSON
  adapter and an HTTP boundary belongs on a device/emulator. Preconditions:
  MockWebServer serving a `GET .../messages` page (a plain JSON **array**) mixing
  valid kinds plus one unknown-kind item and one malformed-image item. Steps: call
  the messaging API; map the page item-by-item. Expected: valid items map to their
  subtypes, the unknown maps to `Unsupported`, the malformed item is substituted
  with `Unsupported`/placeholder rather than failing the whole page; 422 responses
  surface as `HTTPValidationError`-derived errors. Note: emulator is sufficient (no
  hardware needed); physical device not required. Traces: AC-2, AC-3, AC-4.

- **TC-AND-126-13 — Flaky/offline dev-host path (cached read maps identically).**
  Type: integration. Target: emulator AVD `test35` (network toggled off in CI);
  the physical Samsung A15 is NOT required (no hardware-specific behavior). 
  Preconditions: a previously cached `/messaging/conversations/{id}/messages`
  payload (mirrors the web `withOfflineCache` behavior); network forced to fail.
  Steps: invoke the read path offline; map the cached payload. Expected: cached
  bytes map to the same domain `Message` list as the online path; no crash on the
  unreliable plaintext dev host. Traces: AC-3 (supports §7).

- **TC-AND-126-14 — Compose stability of domain types (smoke).** Type:
  Compose-UI. Target: emulator AVD `test35`. Preconditions: a tiny test composable
  holding `StateFlow<List<Message>>` including an `Unsupported` whose
  `rawPayload` is a `Map`. Steps: recompose with an unrelated state change;
  assert (via Compose stability tooling/`@Immutable` lint) the `Message` list does
  not force recomposition, and verify the `Unsupported.rawPayload` `Map` does not
  break stability (if it does, this proves the §16 open assumption and requires a
  `@Stable` wrapper). Accessibility note: this case also asserts that
  content-description-bearing fields (`Image` caption-equivalent, durations,
  poll/option labels) are non-null strings available to downstream a11y, since
  AND-126 has no UI of its own. Traces: AC-1 (supports §9 enablement).

### Coverage matrix (§14 AC → TCs)

| Acceptance Criterion | Covered by |
|---|---|
| AC-1 (sealed hierarchy, all kinds, @Immutable) | TC-01, TC-04, TC-11, TC-14 |
| AC-2 (toDomain total; unknown→Unsupported) | TC-05, TC-10, TC-11, TC-12 |
| AC-3 (every kind maps loss-free; round-trip/coverage) | TC-01, TC-02, TC-03, TC-12, TC-13 |
| AC-4 (malformed known throws; bad timestamp→null) | TC-06, TC-07, TC-12 |
| AC-5 (ConversationMapper lastMessage + unreadCount) | TC-08 |
| AC-6 (exhaustiveness guard on the when) | TC-04 |
| AC-7 (module boundaries; core-model no Moshi/DTO) | TC-09 |
