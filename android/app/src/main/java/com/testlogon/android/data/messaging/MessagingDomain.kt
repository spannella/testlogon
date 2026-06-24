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

    /**
     * C6 — multiple images sent as ONE message (kind="gallery"). Renders as a grid; each item opens
     * full-screen. [images] are the free (always-visible) images projected by the server.
     */
    data class Gallery(
        val images: List<GalleryImage>,
    ) : MessageMedia

    /** C6 — one image inside a [Gallery]. */
    data class GalleryImage(
        val url: String?,
        val width: Int? = null,
        val height: Int? = null,
    )

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
     * MV2 — a SHORT uploaded video clip (kind="video"). Unlike [VideoShare] (HLS library video), this
     * is a single object-URL clip. [playbackUrl] is the server-relative /mock/s3 object url (used as the
     * ExoPlayer source AND the Coil video-frame poster); [localUri] is the optimistic local source while
     * an outbox row is still uploading. Renders a poster + play glyph; tapping plays it in-app.
     */
    data class VideoClip(
        val playbackUrl: String?,
        val localUri: String? = null,
        val durationSeconds: Int? = null,
        val uploadProgress: Float? = null,
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
        /** "none" | "listen_once" — listen-once plays exactly once then is consumed. */
        val consumptionPolicy: String = "none",
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
     * MSG-009 — a Find-a-DateTime poll ("custom poll"). Distinct from [MeetingPoll]; renders a
     * simple "Find a time" card from the create/list response. Availability voting is out of scope
     * for the composer demo (the card is read-mostly).
     */
    data class FindDateTime(
        val pollId: String,
        val title: String,
        val creatorId: String,
        val status: String,
        val fromDate: String? = null,
        val toDate: String? = null,
        val startHour: Int? = null,
        val endHour: Int? = null,
        val slotDurationMinutes: Int? = null,
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
    // #13 — revealed lottery option MEDIA after a draw: a server-relative object url derived from the
    // winning outcome's media_asset_id (image or video). Null for text-only or while locked.
    val revealedMediaUrl: String? = null,
    val revealedMediaIsVideo: Boolean = false,
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

/**
 * MSG — a client-side encryption envelope carried on a message (AES-256-GCM / PBKDF2-SHA256). Mirrors
 * [MessageEncryptionEnvelopeDto] but stays a domain type so the UI can decrypt on passphrase entry.
 * Persisted to Room so the receiver renders the locked state + can unlock after a process restart.
 */
data class MessageEncryption(
    val version: Int,
    val alg: String,
    val kdf: String,
    val iterations: Int,
    val saltB64: String,
    val ivB64: String,
    val ciphertextB64: String?,
)

/** A single message in a conversation, merged from history + the local outbox at render time. */
data class Message(
    /** Server message id; null until a send is acked (outbox rows have no server id yet). */
    val id: String?,
    /** Stable client-generated correlation id; LOCAL-ONLY (never sent to / echoed by the server). */
    val clientId: String,
    val conversationId: String,
    val senderId: String,
    val text: String,
    /** Server id of the message this one replies to (null when not a reply). */
    val replyToMessageId: String? = null,
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
    /** Self-destruct expiry epoch seconds (null = never); [expired] = server-confirmed. */
    val expiresAtEpochSeconds: Long? = null,
    val expired: Boolean = false,
    /** MSG — true when the message is client-side encrypted. */
    val isEncrypted: Boolean = false,
    /** MSG — the encryption envelope (persisted to Room) used to decrypt on the receiver. */
    val encryption: MessageEncryption? = null,
    /** MSG — true when the message is view-once (hidden on the receiver until opened). */
    val viewOnce: Boolean = false,
    /** MSG — true once the view-once message has been consumed (permanently hidden). */
    val consumed: Boolean = false,
    val consumptionPolicy: String = "none",
    /**
     * R2 — pay-to-unlock price in minor units when this message was sent locked (PPV), else null.
     * Carried even for the SENDER's own copy (whose gated media IS present, so it maps to
     * MessageMedia.Image not MessageMedia.Paid) so the sender's own bubble can badge "Locked $X".
     */
    val lockPriceCents: Long? = null,
    /** R2 — ISO-4217 currency for [lockPriceCents] (defaults to USD when the wire omits it). */
    val lockCurrency: String = "USD",
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
        replyToMessageId = replyToMessageId,
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
        expiresAtEpochSeconds = expiresAt,
        expired = expired ?: false,
        // RG22 — a locked+encrypted message has its `is_encrypted` flag/`encryption` envelope
        // WITHHELD by the server while still locked (paywall-first); after the recipient pays,
        // the re-fetch returns the envelope. Treat the presence of an envelope as encrypted even
        // if the flag lags, so the bubble keeps showing the ENCRYPTED teaser (enter passphrase)
        // after unlock instead of falling through to a blank/normal bubble.
        isEncrypted = (isEncrypted ?: false) || encryption != null,
        viewOnce = (viewOnce ?: false) || consumptionPolicy == "view_once",
        consumed = consumptionState == "consumed",
        consumptionPolicy = consumptionPolicy ?: "none",
        // R2 — capture the lock price whenever the message was sent locked (even if it maps to a
        // plain Image for the sender / unlocked viewer) so the bubble can badge "Locked $X".
        lockPriceCents = if (locked == true) lockPriceCents else null,
        lockCurrency = tipCurrency ?: "USD",
        encryption = encryption?.let {
            MessageEncryption(
                version = it.version,
                alg = it.alg,
                kdf = it.kdf,
                iterations = it.iterations,
                saltB64 = it.saltB64,
                ivB64 = it.ivB64,
                ciphertextB64 = it.ciphertextB64,
            )
        },
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
    // C6 — gallery (multi-image) message. Sender + unlocked recipients get free_images here.
    kind == "gallery" && !freeImages.isNullOrEmpty() -> MessageMedia.Gallery(
        images = freeImages.map { gi ->
            MessageMedia.GalleryImage(
                url = gi.url?.takeIf { it.isNotBlank() } ?: deriveS3Url(gi.bucket, gi.key),
            )
        },
    )
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
        consumptionPolicy = consumptionPolicy ?: "none",
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
    // MSG-009 — find-a-datetime poll (nested find_datetime attachment).
    findDatetime != null -> MessageMedia.FindDateTime(
        pollId = findDatetime.pollId,
        title = findDatetime.title,
        creatorId = findDatetime.creatorId,
        status = findDatetime.status ?: "open",
        fromDate = findDatetime.fromDate,
        toDate = findDatetime.toDate,
        startHour = findDatetime.startHour,
        endHour = findDatetime.endHour,
        slotDurationMinutes = findDatetime.slotDurationMinutes,
    )
        // AND-139 — lottery paid message (nested lottery sub-object). Reveal only when unlocked.
    lottery != null -> run {
        val lot = lottery!!
        val revealed = lot.selectedOutcome?.takeIf { lot.lockState == "unlocked" }
        val revealedIsVideo = revealed?.payloadType == "video"
        MessageMedia.Paid(
            MessageMonetization(
                type = UnlockType.LOTTERY,
                unlocked = lot.lockState == "unlocked",
                priceMinorUnits = null,
                currency = tipCurrency ?: "USD",
                teaser = lockDescription,
                revealedText = revealed?.takeIf { it.payloadType == "text" }?.textContent,
                revealedMediaUrl = revealed?.takeIf { it.payloadType == "image" || it.payloadType == "video" }
                    ?.let { deriveMediaAssetUrl(it.mediaAssetId) },
                revealedMediaIsVideo = revealedIsVideo,
            ),
        )
    }
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
    // MV2 — an uploaded short video clip (server stores it as a `file` object with kind="video").
    // Render it as an inline video bubble (poster + play) rather than a plain file bubble. The server
    // populates file.url with the directly-playable /mock/s3 object url (dev) used by ExoPlayer + Coil.
    kind == "video" && file != null -> MessageMedia.VideoClip(
        // RG20 fix — the message-CREATE response omits file.url (only bucket/key), so derive the
        // /mock/s3 object url from bucket/key (same as images' deriveS3Url) instead of rendering a
        // blank, un-tappable bubble until a thread refetch repopulates url.
        playbackUrl = file.url?.takeIf { it.isNotBlank() }
            ?: file.path?.takeIf { it.isNotBlank() }
            ?: deriveS3Url(file.bucket, file.key),
        durationSeconds = file.durationSeconds,
    )
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
    // The backend serves uploaded objects through its storage gateway at /mock/s3/<bucket>/<key> --
    // the same server-relative path the list/get endpoints return as image.url and that presign hands
    // out for upload. The image-CREATE response omits url, so the sender's just-sent bubble must
    // derive it here; Coil's RelativeUrlMapper resolves the leading-"/" path against the API origin.
    // (Without this the sender saw a broken/blank thumbnail until a thread refresh re-fetched url.)
    return "/mock/s3/$bucket/$key"
}

/**
 * #13 — resolve a lottery outcome's media_asset_id to a server-relative object url. The backend
 * persists/echoes media_asset_id as "bucket:key" (or "s3://bucket/key", or a bare key under the image
 * bucket). Coil's RelativeUrlMapper resolves the leading-"/" path against the API origin.
 */
internal fun deriveMediaAssetUrl(mediaAssetId: String?): String? {
    val raw = mediaAssetId?.trim().takeUnless { it.isNullOrEmpty() } ?: return null
    val (bucket, key) = when {
        raw.startsWith("s3://") -> raw.removePrefix("s3://").substringBefore('/', "") to raw.removePrefix("s3://").substringAfter('/', "")
        ':' in raw -> raw.substringBefore(':') to raw.substringAfter(':')
        else -> null to raw
    }
    if (key.isBlank()) return null
    // A bare key (no bucket) is served from the same /mock/s3 gateway; without a bucket we cannot build
    // the path, so fall back to a key-only relative url the gateway also accepts.
    return if (bucket.isNullOrBlank()) "/mock/s3/$key" else "/mock/s3/$bucket/$key"
}

internal fun ConversationDto.toDomain(): Conversation = Conversation(
    id = conversationId,
    title = title?.takeIf { it.isNotBlank() } ?: deriveTitle(),
    // ID15 - prefer a set conversation icon; for a DM (no icon) fall back to a participant's
    // profile photo so the row avatar shows the person instead of an initial.
    iconUrl = icon?.takeIf { it.isNotBlank() } ?: deriveParticipantPhoto(),
    lastMessagePreview = lastMessagePreview ?: lastMessage?.preview ?: lastMessage?.text,
    lastActivityEpochSeconds = lastMessageAt ?: createdAt,
    unreadCount = unreadCount,
)

/** ID15 - first participant with a profile photo (the other party in a DM); null otherwise. */
private fun ConversationDto.deriveParticipantPhoto(): String? =
    participants.firstNotNullOfOrNull { it.profilePhotoUrl?.takeIf(String::isNotBlank) }

/** DM title fallback: the other participant's display name, else a generic label. */
private fun ConversationDto.deriveTitle(): String =
    participants.firstNotNullOfOrNull { it.displayName?.takeIf(String::isNotBlank) }
        ?: "Conversation"

/** Newest-activity-first with a stable id tie-break. */
internal fun List<Conversation>.sortedNewestFirst(): List<Conversation> =
    sortedWith(compareByDescending<Conversation> { it.lastActivityEpochSeconds }.thenBy { it.id })
