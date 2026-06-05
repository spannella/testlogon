---
id: AND-126
title: Message domain model + mappers
milestone: M3
epic: E18
priority: P0
size: M
status: draft
depends_on: [AND-120]
blocks: [AND-128]
---

# AND-126 — Message domain model + mappers

## 1. Overview & Goal

This ticket delivers the **domain-layer representation of a chat message** plus
the pure mapping functions that convert the wire-format DTOs produced by AND-120
into that domain model. It produces no UI, no networking, no persistence, and no
business logic beyond translation. The deliverable is a sealed type `Message`
with a subtype per known kind — `text, image, video, file, voice, gif, sticker,
poll, countdown, calendar, system` — plus an explicit fallback for unrecognized
kinds, and a total, loss-free `MessageMapper` from the DTO surface.

The DTOs from AND-120 are intentionally permissive: the backend serializes every
message as one envelope object with a discriminator field (`message_type`) and a
loosely-typed `content` sub-object whose keys differ by type. AND-120 owns the
JSON contract; **AND-126 owns the Kotlin domain shape the rest of the messaging
feature (AND-122/123/124) programs against.** A strongly-typed sealed model lets
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
  fixtures for `/messaging/conversations`, `/conversations/{id}`,
  `/conversations/{id}/messages`, and `/config`. AND-126 maps `MessageDto` →
  `Message`; it does **not** add or change endpoints.
- **Downstream consumers.** AND-122 (list VM uses last-message preview),
  AND-123 (thread screen renders messages exhaustively), AND-124 (optimistic
  text send constructs a `Message.Text`), AND-128 (messaging core tests, which
  this ticket blocks).
- **Backend.** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference for exact
  field names and the discriminator value set: `frontend/src/api/types.ts`
  (the `Message`/`MessageType` union) and `frontend/src/api/endpoints/messaging.ts`.
  Mirror snake_case backend names exactly at the DTO layer; the domain layer uses
  idiomatic Kotlin names.
- **Time.** This is the layer that parses ISO-8601 strings carried as `String`
  in the DTOs into `Instant` domain values (deferred from AND-120 by design).

## 3. Functional Requirements

FR-1. Define a sealed interface `Message` with a common header (id, conversation
id, sender, timestamps, delivery/edit flags) shared by every subtype.

FR-2. Define one subtype per known `message_type` discriminator:
`Text, Image, Video, File, Voice, Gif, Sticker, Poll, Countdown, Calendar,
System`, plus `Unsupported` for any unrecognized discriminator.

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

FR-7. Timestamps map from ISO-8601 `String` to `Instant`; a malformed timestamp
maps to a null/`Instant.DISTANT_PAST`-guarded value without throwing (logged once
in tests, never crashes UI).

FR-8. All domain types are immutable, annotated `@Immutable` (Compose stability)
where they enter composition, and expose `List<T>` (never mutable collections).

FR-9. Mapping must be **loss-free for all known types**, verified by a
DTO→domain→DTO round-trip whose re-serialized JSON tree equals the original
(ignoring key order/whitespace) for every committed fixture (the ticket's
acceptance bar).

## 4. Technical Design

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
this mapper consumes. Representative envelope (one message object from
`GET /conversations/{id}/messages`):

```json
{
  "id": "msg_01H...",
  "conversation_id": "cnv_42",
  "sender": { "user_id": "usr_7", "display_name": "Alice", "avatar_url": null },
  "sent_at": "2026-06-05T12:00:00Z",
  "edited_at": null,
  "deleted": false,
  "reply_to_id": null,
  "message_type": "poll",
  "content": {
    "question": "Lunch?",
    "options": [
      { "id": "o1", "label": "Tacos", "vote_count": 3 },
      { "id": "o2", "label": "Sushi", "vote_count": 5 }
    ],
    "multiple_choice": false,
    "closes_at": "2026-06-05T18:00:00Z",
    "my_votes": ["o2"]
  }
}
```

Text variant `content`: `{ "text": "hi" }`. Image variant `content`:
`{ "url": "https://…/a.jpg", "width": 1080, "height": 720, "alt_text": "…",
"blurhash": "L6Pj…", "caption": null }`. The full per-type `content` schemas are
frozen by AND-120; this spec encodes the **mapping** of those keys to domain
fields. The `message_type` discriminator value set is the authority for the
`when` branches in §4.2.

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

- **R1 — Discriminator drift.** The exact `message_type` token spelling
  (`gif` vs `image/gif`, `voice` vs `audio`) must match the live backend.
  *Mitigation:* mirror `frontend/src/api/types.ts` and capture a fixture per type
  from the dev host; cross-check against `/config` if it enumerates types.
  *Open:* confirm the canonical token for sticker/gif/voice.
- **R2 — Per-type `content` field names.** Poll vote tally key (`vote_count` vs
  `votes`), voice waveform encoding (int array vs base64), and calendar
  start/end key names are inferred. *Open:* confirm from `/openapi.json` and a
  real sample of each type before freezing the mapper.
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
