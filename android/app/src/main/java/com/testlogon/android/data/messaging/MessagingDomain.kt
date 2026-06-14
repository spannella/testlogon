package com.testlogon.android.data.messaging

/**
 * AND-120..AND-124 — domain models for the messaging feature (no Moshi/Room leakage past the
 * data layer's public surface).
 *
 * Timestamps are carried as epoch-SECONDS [Long] (the wire unit). Relative-time formatting is a
 * @Composable concern (minSdk24-safe DateUtils), never done in JVM-unit-tested code.
 */

/** Delivery state of a thread row. History rows are SENT; the outbox produces SENDING/FAILED. */
enum class SendStatus { SENDING, SENT, FAILED }

/**
 * AND-130 / AND-131 — media payload attached to a message. Text messages carry [None]. Outbox rows
 * for an in-flight image carry an [Image] with a local source uri + upload progress so the bubble
 * renders an optimistic thumbnail with progress before the remote url exists.
 */
sealed interface MessageMedia {
    data object None : MessageMedia

    /**
     * @param url remote display url (server `image.url` else bucket/key-derived S3 url); null while
     *            the optimistic row is still uploading.
     * @param localUri local content uri for the optimistic thumbnail; null for received images.
     * @param uploadProgress 0f..1f while uploading; null when not in an upload.
     */
    data class Image(
        val url: String?,
        val localUri: String? = null,
        val width: Int? = null,
        val height: Int? = null,
        val uploadProgress: Float? = null,
    ) : MessageMedia

    /** Shared library video — inline HLS playback (AND-131). */
    data class VideoShare(
        val videoId: String,
        val title: String?,
        val thumbnailUrl: String?,
        val durationSeconds: Int?,
        val hlsManifestUrl: String?,
        val playbackToken: String?,
        val drmEnabled: Boolean,
        val width: Int? = null,
        val height: Int? = null,
    ) : MessageMedia

    /**
     * AND-132 — a generic file attachment (or file_share). Bytes are downloaded on demand via the
     * grant/consume flow keyed by message id; the bubble renders name/size/type + a download/open
     * affordance. [isShare] distinguishes the file_share variant (no re-upload). [localUri] carries
     * the optimistic source uri while an outbox row is still uploading.
     */
    data class File(
        val fileName: String,
        val sizeBytes: Long?,
        val mimeType: String?,
        val consumptionPolicy: String = "none",
        val isShare: Boolean = false,
        val localUri: String? = null,
        val uploadProgress: Float? = null,
    ) : MessageMedia

    /**
     * AND-133 — a voice message. [audioUrl] is the (short-lived) signed url for ExoPlayer playback;
     * null while an optimistic outbox row is still uploading. [localUri] is the local clip path for
     * preview/optimistic playback. [waveform] is the server-provided normalized peaks (0..1).
     */
    data class Voice(
        val audioUrl: String?,
        val durationSeconds: Double,
        val waveform: List<Float>,
        val localUri: String? = null,
        val uploadProgress: Float? = null,
    ) : MessageMedia

    /**
     * AND-134 — a voicemail (call-tied async audio/video drop). [mediaUrl] is the short-lived signed
     * audio_url (audio mode) or video_url (video mode); null while an optimistic outbox row uploads.
     * [callState] ∈ "missed"|"declined"|"busy". [waveform] is the server-provided peaks (0..1).
     */
    data class Voicemail(
        val mediaUrl: String?,
        val isVideo: Boolean,
        val durationSeconds: Double,
        val waveform: List<Float>,
        val callId: String,
        val callState: String?,
        val localUri: String? = null,
        val uploadProgress: Float? = null,
    ) : MessageMedia

    /**
     * AND-135 — an animated GIF. [url] is the provider GIF url (animated via the Coil GIF decoder);
     * [width]/[height] drive the bubble aspect ratio. [altText] is the accessibility label.
     */
    data class Gif(
        val url: String,
        val altText: String?,
        val width: Int?,
        val height: Int?,
        val provider: String? = null,
    ) : MessageMedia

    /** AND-135 — a sticker (fixed-size image). [url] is the sticker image_url; [altText] the label. */
    data class Sticker(
        val url: String,
        val altText: String?,
        val stickerId: String? = null,
        val collectionId: String? = null,
    ) : MessageMedia

    /**
     * AND-136 — a meeting poll. Carries the poll envelope (id/title/status); per-slot counts +
     * my_vote are loaded on demand via the polls GET and surfaced through the ViewModel, not Room.
     */
    data class MeetingPoll(
        val pollId: String,
        val title: String,
        val creatorId: String,
        val status: String,
        val confirmedSlotId: String?,
    ) : MessageMedia

    /**
     * AND-137 — a countdown. [targetEpochSeconds] is UTC; the live remaining time is DERIVED from
     * the device clock at render time (never stored), so it self-corrects after backgrounding.
     */
    data class Countdown(
        val title: String,
        val targetEpochSeconds: Long,
        val associatedEventType: AssociatedEventType = AssociatedEventType.CUSTOM,
        val associatedEventId: String? = null,
    ) : MessageMedia

    /** AND-138 — an inline calendar event (render + add-to-calendar). No title/location/rsvp fields. */
    data class CalendarEvent(
        val eventId: String,
        val calendarId: String,
        val name: String,
        val startUtc: String?,
        val endUtc: String?,
        val allDay: Boolean,
        val allDayDate: String?,
        val timezone: String?,
        val description: String?,
        val owner: String,
    ) : MessageMedia

    /** AND-138 — a shared calendar reference (read-only render + disabled accept). */
    data class CalendarShare(
        val calendarId: String,
        val name: String,
        val owner: String,
        val permission: SharePermission,
        val bookingPublicUrl: String?,
    ) : MessageMedia

    /**
     * AND-139 — a paid/unlockable message. While [monetization.unlocked] is false the bubble renders
     * a locked teaser (price + lock_description ONLY); the gated body/media is NEVER carried here.
     */
    data class Paid(
        val monetization: MessageMonetization,
    ) : MessageMedia
}

/** AND-137 — the kind of item a countdown is associated with (display/pass-through only). */
enum class AssociatedEventType { BROADCAST, CALL, CALENDAR, CUSTOM, UNKNOWN }

/** AND-138 — calendar-share permission ("read"|"write" on the wire). */
enum class SharePermission { READ, WRITE, UNKNOWN }

/**
 * AND-139 — monetization metadata mapped from the flat lock_* fields (FIXED) or the nested `lottery`
 * sub-object (LOTTERY). This is an internal mapping convenience, NOT a wire shape. The gated
 * body/media is never represented here; only the safe teaser caption + price are.
 */
data class MessageMonetization(
    val type: UnlockType,
    val unlocked: Boolean,
    /** Fixed-price amount in minor units (cents); null for a lottery (server resolves the price). */
    val priceMinorUnits: Long?,
    val currency: String,
    /** Safe teaser caption (lock_description); never the gated body. */
    val teaser: String?,
    /** AND-139 — revealed text content after a successful unlock/draw (else null while locked). */
    val revealedText: String? = null,
)

/** AND-139 — fixed-price unlock vs server-resolved lottery unlock. */
enum class UnlockType { FIXED, LOTTERY }

// ---- AND-137/138/139 enum <-> wire mappers (pure / JVM-testable) ----

internal fun String?.toAssociatedEventType(): AssociatedEventType = when (this) {
    "broadcast" -> AssociatedEventType.BROADCAST
    "call" -> AssociatedEventType.CALL
    "calendar" -> AssociatedEventType.CALENDAR
    "custom" -> AssociatedEventType.CUSTOM
    null -> AssociatedEventType.CUSTOM
    else -> AssociatedEventType.UNKNOWN
}

internal fun AssociatedEventType.wire(): String = when (this) {
    AssociatedEventType.BROADCAST -> "broadcast"
    AssociatedEventType.CALL -> "call"
    AssociatedEventType.CALENDAR -> "calendar"
    else -> "custom"
}

internal fun String?.toSharePermission(): SharePermission = when (this) {
    "read" -> SharePermission.READ
    "write" -> SharePermission.WRITE
    else -> SharePermission.UNKNOWN
}

/**
 * AND-140 — a single emoji reaction summary on a message: the emoji, its total count, and whether
 * the current user reacted with it. Derived in the mapper from MessageOut.reactions_counts +
 * my_reactions (there is no per-emoji `reacted_by_me` array on the wire).
 */
data class Reaction(val emoji: String, val count: Int, val reactedByMe: Boolean)

/** AND-140 — a reactor row for the reaction-details sheet (flattened from emoji -> reactor list). */
data class Reactor(
    val userSub: String,
    val displayName: String,
    val profilePhotoUrl: String?,
    val emoji: String,
)

/** AND-140 — one prior revision of an edited message (newest-first in the history sheet). */
data class MessageEdit(val revision: Int, val body: String, val editedAtEpochSeconds: Long?)

/**
 * AND-140 — derived message lifecycle. The wire has no `state` field; REVOKED is signalled by a
 * non-null `revoked_at`, EDITED by a non-null `edited_at`, and DELETED is applied locally after a
 * delete-for-me 200 (no tombstone payload).
 */
enum class MessageLifecycle { ACTIVE, EDITED, DELETED, REVOKED }

/** A single message in a conversation, merged from history + the local outbox at render time. */
data class Message(
    /** Server message id; null until a send is acked (outbox rows have no server id yet). */
    val id: String?,
    /** Stable client-generated correlation id; LOCAL-ONLY (never sent to / echoed by the server). */
    val clientId: String,
    val conversationId: String,
    val senderId: String,
    val text: String,
    /** Epoch SECONDS. Local placeholder for an optimistic row until the server ack replaces it. */
    val createdAtEpochSeconds: Long,
    val sendStatus: SendStatus = SendStatus.SENT,
    /** AND-130/131 — message discriminator: "text" | "image" | "video_share". */
    val kind: String = "text",
    /** AND-130/131 — media payload; [MessageMedia.None] for text. */
    val media: MessageMedia = MessageMedia.None,
    // AND-140 — moderation / engagement state (defaults keep older callers green).
    /** Reaction chips (emoji + count + reactedByMe), derived from the wire summary. */
    val reactions: List<Reaction> = emptyList(),
    /** True when this message is pinned in the conversation. */
    val isPinned: Boolean = false,
    /** Derived lifecycle: ACTIVE / EDITED / DELETED (local) / REVOKED. */
    val lifecycle: MessageLifecycle = MessageLifecycle.ACTIVE,
    /** Epoch SECONDS of the last edit (drives the "edited" marker), null if never edited. */
    val editedAtEpochSeconds: Long? = null,
    /** True when the current user hid this message (server-backed, cached for instant/offline UI). */
    val isHiddenLocal: Boolean = false,
    // AND-147 — delivery/read receipt counts from the message payload (transient; not Room-persisted).
    /** Distinct recipients the message was delivered to (delivered_to_count). 0 when unknown. */
    val deliveredToCount: Int = 0,
    /** Distinct readers excluding self (read_by_count). 0 when unknown. */
    val readByCount: Int = 0,
    /** Reader user ids (read_by_user_ids), for self-exclusion + roster seeding. */
    val readByUserIds: List<String> = emptyList(),
)

/** A conversation summary for the inbox list. */
data class Conversation(
    val id: String,
    val title: String,
    val iconUrl: String?,
    val lastMessagePreview: String?,
    /** Epoch SECONDS of last activity (last_message_at else created_at), 0 if unknown. */
    val lastActivityEpochSeconds: Long,
    val unreadCount: Int,
) {
    val isUnread: Boolean get() = unreadCount > 0
}

/**
 * AND-153 — a contact (people-search) result. Mapped from [ContactDto]; carries only what the
 * `/messaging/contacts/search` endpoint returns ([id] from `user_id`, [displayName] from
 * `display_name`). There is no username / avatar URL / presence on the wire, so the UI renders an
 * initials-only avatar.
 */
data class Contact(
    val id: String,
    val displayName: String,
)

/** AND-153 — wire -> domain for a contact search row. Pure / JVM-testable. */
internal fun ContactDto.toDomain(): Contact = Contact(id = userId, displayName = displayName)

// ---- Mappers ----

internal fun MessageDto.toDomain(
    clientId: String = messageId,
    sendStatus: SendStatus = SendStatus.SENT,
): Message {
    val mappedMedia = toMedia()
    // AND-139 (OQ-3): for a still-locked paid message the wire `text` would be the GATED body.
    // We must not carry it into the domain/cache — the teaser caption lives in the monetization
    // model only. Drop the text for a locked Paid bubble so the gated body can never leak.
    val safeText = if (mappedMedia is MessageMedia.Paid && !mappedMedia.monetization.unlocked) {
        ""
    } else {
        text ?: if (kind == "text") preview ?: "" else ""
    }
    return Message(
        id = messageId,
        clientId = clientId,
        conversationId = conversationId,
        senderId = senderId,
        text = safeText,
        createdAtEpochSeconds = createdAt,
        sendStatus = sendStatus,
        kind = kind,
        media = mappedMedia,
        reactions = toReactions(),
        lifecycle = deriveLifecycle(),
        editedAtEpochSeconds = editedAt,
        // AND-147 — receipt counts ride the message payload (not persisted to Room; recomputed on fetch).
        deliveredToCount = deliveredToCount ?: 0,
        readByCount = readByCount ?: 0,
        readByUserIds = readByUserIds ?: emptyList(),
    )
}

/**
 * AND-140 — derives the reaction chip list by zipping `reactions_counts` (emoji -> count) with
 * `my_reactions` (emojis the current user reacted with). Pure / JVM-testable. Stable order: by
 * descending count then emoji so the chip row does not jitter on reconcile.
 */
internal fun MessageDto.toReactions(): List<Reaction> {
    val counts = reactionsCounts ?: return emptyList()
    val mine = myReactions?.toSet() ?: emptySet()
    return counts
        .filterValues { it > 0 }
        .map { (emoji, count) -> Reaction(emoji, count, reactedByMe = emoji in mine) }
        .sortedWith(compareByDescending<Reaction> { it.count }.thenBy { it.emoji })
}

/**
 * AND-140 — derives [MessageLifecycle] from the wire markers (there is no `state` field): a non-null
 * `revoked_at` wins (REVOKED), else a non-null `edited_at` (EDITED), else ACTIVE. DELETED is applied
 * locally after a delete-for-me 200, never from a wire payload. Pure / JVM-testable.
 */
internal fun MessageDto.deriveLifecycle(): MessageLifecycle = when {
    revokedAt != null -> MessageLifecycle.REVOKED
    editedAt != null -> MessageLifecycle.EDITED
    else -> MessageLifecycle.ACTIVE
}

/** AND-140 — flattens ReactionDetailsOut (emoji -> reactor list) to a flat [Reactor] list. */
internal fun ReactionDetailsOut.toReactors(): List<Reactor> =
    reactions.entries.flatMap { (emoji, users) ->
        users.map { Reactor(it.userSub, it.displayName, it.profilePhotoUrl, emoji) }
    }

/** AND-140 — maps a tolerant edit-history entry to the domain [MessageEdit]; newest-first sorted. */
internal fun List<EditHistoryEntryDto>.toMessageEdits(): List<MessageEdit> =
    mapIndexed { index, dto ->
        MessageEdit(
            revision = dto.revision ?: (size - index),
            body = dto.text ?: dto.body.orEmpty(),
            editedAtEpochSeconds = dto.editedAt ?: dto.createdAt,
        )
    }.sortedByDescending { it.editedAtEpochSeconds ?: it.revision.toLong() }

/** Maps the wire media object to the domain [MessageMedia] (pure; no Android types). */
internal fun MessageDto.toMedia(): MessageMedia = when {
    image != null -> MessageMedia.Image(
        url = image.url?.takeIf { it.isNotBlank() }
            ?: deriveS3Url(image.bucket, image.key),
        width = image.width,
        height = image.height,
    )
    videoShare != null -> MessageMedia.VideoShare(
        videoId = videoShare.videoId,
        title = videoShare.title,
        thumbnailUrl = videoShare.thumbnailUrl,
        durationSeconds = videoShare.durationSeconds,
        hlsManifestUrl = videoShare.hlsManifestUrl,
        playbackToken = videoShare.playbackToken,
        drmEnabled = videoShare.drmEnabled,
        width = videoShare.width,
        height = videoShare.height,
    )
    voiceMessage != null -> MessageMedia.Voice(
        audioUrl = voiceMessage.audioUrl?.takeIf { it.isNotBlank() },
        durationSeconds = voiceMessage.durationSeconds ?: 0.0,
        waveform = voiceMessage.waveformData ?: emptyList(),
    )
    voicemail != null -> MessageMedia.Voicemail(
        mediaUrl = (voicemail.videoUrl ?: voicemail.audioUrl)?.takeIf { it.isNotBlank() },
        isVideo = voicemail.mode == "video",
        durationSeconds = voicemail.durationSeconds ?: 0.0,
        waveform = voicemail.waveformData ?: emptyList(),
        callId = voicemail.callId,
        callState = voicemail.callState,
    )
    gifUrl != null -> MessageMedia.Gif(
        url = gifUrl,
        altText = gifAltText,
        width = gifWidth,
        height = gifHeight,
        provider = gifProvider,
    )
    stickerUrl != null -> MessageMedia.Sticker(
        url = stickerUrl,
        altText = stickerAltText,
        stickerId = stickerId,
        collectionId = stickerCollectionId,
    )
    meetingPoll != null -> MessageMedia.MeetingPoll(
        pollId = meetingPoll.pollId,
        title = meetingPoll.title,
        creatorId = meetingPoll.creatorId,
        status = meetingPoll.status,
        confirmedSlotId = meetingPoll.confirmedSlotId,
    )
    // AND-137 — countdown (flat title + target_datetime).
    kind == "countdown" && countdownTitle != null && targetDatetime != null -> MessageMedia.Countdown(
        title = countdownTitle,
        targetEpochSeconds = targetDatetime,
        associatedEventType = associatedEventType.toAssociatedEventType(),
        associatedEventId = associatedEventId,
    )
    // AND-138 — calendar event / share (nested attachments).
    calendarEvent != null -> MessageMedia.CalendarEvent(
        eventId = calendarEvent.eventId,
        calendarId = calendarEvent.calendarId,
        name = calendarEvent.name,
        startUtc = calendarEvent.startUtc,
        endUtc = calendarEvent.endUtc,
        allDay = calendarEvent.allDay,
        allDayDate = calendarEvent.allDayDate,
        timezone = calendarEvent.timezone,
        description = calendarEvent.description,
        owner = calendarEvent.owner,
    )
    calendarShare != null -> MessageMedia.CalendarShare(
        calendarId = calendarShare.calendarId,
        name = calendarShare.name,
        owner = calendarShare.owner,
        permission = calendarShare.permission.toSharePermission(),
        bookingPublicUrl = calendarShare.bookingPublicUrl,
    )
    // AND-139 — lottery paid message (nested lottery sub-object). Reveal only when unlocked.
    lottery != null -> MessageMedia.Paid(
        MessageMonetization(
            type = UnlockType.LOTTERY,
            unlocked = lottery.lockState == "unlocked",
            priceMinorUnits = null,
            currency = tipCurrency ?: "USD",
            teaser = lockDescription,
            revealedText = lottery.selectedOutcome?.takeIf { lottery.lockState == "unlocked" }?.textContent,
        ),
    )
    // AND-139 — fixed-price locked paid message (flat lock_* fields). Gated body never carried while locked.
    locked == true && isUnlocked != true -> MessageMedia.Paid(
        MessageMonetization(
            type = UnlockType.FIXED,
            unlocked = false,
            priceMinorUnits = lockPriceCents,
            currency = tipCurrency ?: "USD",
            teaser = lockDescription,
            revealedText = null,
        ),
    )
    fileShare != null -> fileShare.toFileMedia(consumptionPolicy ?: "none", isShare = true)
    file != null -> file.toFileMedia(consumptionPolicy ?: "none", isShare = false)
    else -> MessageMedia.None
}

/** Maps a wire file/file_share object to the domain [MessageMedia.File]. */
internal fun MessageFileDto.toFileMedia(policy: String, isShare: Boolean): MessageMedia.File =
    MessageMedia.File(
        fileName = name ?: path?.substringAfterLast('/') ?: "file",
        sizeBytes = size,
        mimeType = contentType,
        consumptionPolicy = policy,
        isShare = isShare,
    )

/**
 * Derives the public S3 object url from bucket+key (mirrors messagingAdapter.ts: buildS3ObjectUrl),
 * keeping the path separators unescaped. Pure / JVM-testable.
 */
internal fun deriveS3Url(bucket: String?, key: String?): String? {
    if (bucket.isNullOrBlank() || key.isNullOrBlank()) return null
    return "https://$bucket.s3.amazonaws.com/$key"
}

internal fun ConversationDto.toDomain(): Conversation = Conversation(
    id = conversationId,
    title = title?.takeIf { it.isNotBlank() } ?: deriveTitle(),
    iconUrl = icon,
    lastMessagePreview = lastMessagePreview ?: lastMessage?.preview ?: lastMessage?.text,
    lastActivityEpochSeconds = lastMessageAt ?: createdAt,
    unreadCount = unreadCount,
)

/** DM title fallback: the other participant's display name, else a generic label. */
private fun ConversationDto.deriveTitle(): String =
    participants.firstNotNullOfOrNull { it.displayName?.takeIf(String::isNotBlank) }
        ?: "Conversation"

/** Newest-activity-first with a stable id tie-break. */
internal fun List<Conversation>.sortedNewestFirst(): List<Conversation> =
    sortedWith(compareByDescending<Conversation> { it.lastActivityEpochSeconds }.thenBy { it.id })
