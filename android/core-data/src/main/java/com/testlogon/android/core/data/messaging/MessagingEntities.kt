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
