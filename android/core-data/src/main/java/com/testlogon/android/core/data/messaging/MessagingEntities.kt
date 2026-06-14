package com.testlogon.android.core.data.messaging

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * AND-115 / AND-121..124 — Room entities backing the offline messaging cache and the optimistic
 * send outbox.
 *
 * Timestamps are epoch SECONDS (the wire unit). Message bodies live only in the app-private DB and
 * are never logged. The outbox survives process death so a FAILED/pending send is recoverable.
 */

@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey val conversationId: String,
    val title: String,
    val iconUrl: String?,
    val lastMessagePreview: String?,
    val lastActivityEpochSeconds: Long,
    val unreadCount: Int,
)

/**
 * AND-158 — a cached group participant (roster row). Composite PK (conversationId, userId) so a user
 * appears at most once per group; the roster is replaced transactionally on each refresh. Persisted so
 * the roster survives process death and renders before a network round-trip ("persist + reflect").
 */
@Entity(
    tableName = "group_participant",
    primaryKeys = ["conversationId", "userId"],
)
data class ParticipantEntity(
    val conversationId: String,
    val userId: String,
    val displayName: String?,
    val avatarUrl: String?,
    /** "ADMIN" | "MEMBER" | "UNKNOWN" (mirrors GroupRole.name). */
    val role: String,
    /** Epoch SECONDS the member joined; orders the roster. */
    val joinedAtEpochSeconds: Long,
)

@Entity(tableName = "messages")
data class MessageEntity(
    @PrimaryKey val messageId: String,
    val conversationId: String,
    val senderId: String,
    val text: String,
    val createdAtEpochSeconds: Long,
    /** Locally-attached client correlation id (for outbox cleanup); the server never returns it. */
    val clientId: String?,
    // AND-130 / AND-131 — additive media columns (DB schema v2). Default "text"/null for legacy rows.
    val kind: String = "text",
    /** AND-130 — image display url (server url else bucket/key-derived). */
    val imageUrl: String? = null,
    val imageWidth: Int? = null,
    val imageHeight: Int? = null,
    /** AND-131 — shared library video fields. The playback_token is intentionally NOT persisted. */
    val videoId: String? = null,
    val videoTitle: String? = null,
    val videoThumbnailUrl: String? = null,
    val videoDurationSeconds: Int? = null,
    val videoHlsManifestUrl: String? = null,
    val videoDrmEnabled: Boolean = false,
    // AND-132 — file/file_share columns (DB schema v3). Null for non-file kinds.
    val fileName: String? = null,
    val fileSizeBytes: Long? = null,
    val fileMimeType: String? = null,
    val fileIsShare: Boolean = false,
    /** "none" | "view_once" | "listen_once" — gates once-media cache reuse. */
    val consumptionPolicy: String = "none",
    // AND-133 — voice columns (DB schema v3). Null for non-voice kinds.
    val voiceAudioUrl: String? = null,
    val voiceDurationSeconds: Double? = null,
    /** Normalized waveform peaks (0..1) stored as a JSON number[] string. */
    val voiceWaveformJson: String? = null,
    // AND-134 — voicemail columns (DB schema v4). Null for non-voicemail kinds.
    /** Signed audio_url/video_url (short-lived); a play attempt re-fetches the message if expired. */
    val voicemailMediaUrl: String? = null,
    val voicemailIsVideo: Boolean = false,
    val voicemailCallId: String? = null,
    val voicemailCallState: String? = null,
    // AND-135 — gif columns (DB schema v4). Null for non-gif kinds.
    val gifUrl: String? = null,
    val gifAltText: String? = null,
    val gifWidth: Int? = null,
    val gifHeight: Int? = null,
    // AND-135 — sticker columns (DB schema v4). Null for non-sticker kinds.
    val stickerUrl: String? = null,
    val stickerAltText: String? = null,
    val stickerId: String? = null,
    val stickerCollectionId: String? = null,
    // AND-136 — meeting-poll envelope columns (DB schema v4). Null for non-poll kinds.
    val pollId: String? = null,
    val pollTitle: String? = null,
    val pollCreatorId: String? = null,
    val pollStatus: String? = null,
    val pollConfirmedSlotId: String? = null,
    // AND-137 — countdown columns (DB schema v5). Null for non-countdown kinds.
    val countdownTitle: String? = null,
    val countdownTargetEpochSeconds: Long? = null,
    val countdownEventType: String? = null,
    val countdownEventId: String? = null,
    // AND-138 — calendar-event columns (DB schema v5). Null for non-calendar-event kinds.
    val calEventId: String? = null,
    val calEventCalendarId: String? = null,
    val calEventName: String? = null,
    val calEventStartUtc: String? = null,
    val calEventEndUtc: String? = null,
    val calEventAllDay: Boolean = false,
    val calEventAllDayDate: String? = null,
    val calEventTimezone: String? = null,
    val calEventDescription: String? = null,
    val calEventOwner: String? = null,
    // AND-138 — calendar-share columns (DB schema v5). Null for non-calendar-share kinds.
    val calShareCalendarId: String? = null,
    val calShareName: String? = null,
    val calShareOwner: String? = null,
    val calSharePermission: String? = null,
    val calShareBookingUrl: String? = null,
    // AND-139 — monetization columns (DB schema v5). Gated content is NEVER persisted while locked.
    /** "FIXED" | "LOTTERY" (null for non-paid messages). */
    val monetizationType: String? = null,
    val monetizationUnlocked: Boolean = false,
    val lockPriceCents: Long? = null,
    val lockCurrency: String? = null,
    /** Safe teaser caption (lock_description); never the gated body. */
    val lockTeaser: String? = null,
    /** Revealed text written ONLY after a successful unlock/draw. */
    val revealedText: String? = null,
    // AND-140 — reactions / pins / edits / lifecycle / hide columns (DB schema v6).
    /** Moshi-serialized List<Reaction> (emoji+count+reactedByMe) for the chip row. */
    val reactionsJson: String? = null,
    val isPinned: Boolean = false,
    /** "ACTIVE" | "EDITED" | "DELETED" | "REVOKED" (mirrors MessageLifecycle). */
    val lifecycle: String = "ACTIVE",
    val editedAtEpochSeconds: Long? = null,
    /** Per-user hide flag (server-backed; cached for instant/offline UI + cross-restart persistence). */
    val isHidden: Boolean = false,
)

/**
 * AND-141 — per-conversation composer draft (client policy: one ACTIVE draft per conversation,
 * keyed by [conversationId]). Mirrors the server's most-recent draft; [remoteId] holds the server
 * `draft_id` once synced. Draft bodies are user content and live only in the app-private DB.
 */
@Entity(tableName = "drafts")
data class DraftEntity(
    @PrimaryKey val conversationId: String,
    val text: String,
    val updatedAtEpochMs: Long,
    val version: Int = 1,
    /** Server `draft_id`; null while local-only (never PATCHed/DELETEd on the wire). */
    val remoteId: String? = null,
    /** True when a local change has not yet been pushed to the server. */
    val pendingSync: Boolean = false,
)

/**
 * AND-135 — cached workspace custom emoji (single source of truth for the picker grid and inline
 * `:shortcode:` substitution in the message list). Keyed by shortcode. `fetchedAt` gates refresh.
 */
@Entity(tableName = "custom_emoji")
data class CustomEmojiEntity(
    @PrimaryKey val shortcode: String,
    val name: String,
    val imageUrl: String,
    /** Inferred from content_type (image/gif|image/webp); there is no `animated` field on the wire. */
    val animated: Boolean,
    val fetchedAt: Long,
)

/**
 * AND-136 — cached meeting-poll envelope (Room single source of truth for the card). Slots live in
 * [MeetingPollSlotEntity], ordered by [position].
 */
@Entity(tableName = "meeting_polls")
data class MeetingPollEntity(
    @PrimaryKey val pollId: String,
    val conversationId: String,
    val title: String,
    val durationMinutes: Int,
    val creatorId: String,
    /** "open" | "confirmed" | "cancelled". */
    val status: String,
    val confirmedSlotId: String?,
)

@Entity(tableName = "meeting_poll_slots")
data class MeetingPollSlotEntity(
    @PrimaryKey val slotId: String,
    val pollId: String,
    val position: Int,
    val startUtc: String,
    val endUtc: String,
    val yesCount: Int,
    val maybeCount: Int,
    val noCount: Int,
    /** "yes" | "maybe" | "no" | null (caller's own response). */
    val myVote: String?,
)

@Entity(tableName = "outbox_messages")
data class OutboxMessageEntity(
    @PrimaryKey val clientId: String,
    val conversationId: String,
    val text: String,
    val createdAtEpochSeconds: Long,
    /** "SENDING" | "FAILED" (mirrors com.testlogon.android.data.messaging.SendStatus). */
    val status: String,
    val attemptCount: Int = 0,
    // AND-130 — optimistic image send (DB schema v2). kind="text" for legacy/text rows.
    val kind: String = "text",
    /** Local content uri of the picked image, for the optimistic thumbnail. */
    val imageLocalUri: String? = null,
    /** Live upload progress 0..100 (Int avoids a Room Float column). Null when not uploading. */
    val uploadPercent: Int? = null,
    // AND-132 / AND-133 — optimistic file/voice outbox rows (DB schema v3).
    /** Local content uri (file) or local clip path (voice) of the picked/recorded attachment. */
    val attachmentLocalUri: String? = null,
    /** Display name for an optimistic file bubble. */
    val fileName: String? = null,
    val fileSizeBytes: Long? = null,
    val fileMimeType: String? = null,
    /** Voice clip duration (seconds) for the optimistic preview/bubble. */
    val voiceDurationSeconds: Double? = null,
    /** Normalized waveform peaks (0..1) as a JSON number[] string, for the optimistic voice bubble. */
    val voiceWaveformJson: String? = null,
)
