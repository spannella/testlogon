package com.testlogon.android.data.messaging

import android.net.Uri
import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.CustomEmojiDao
import com.testlogon.android.core.data.messaging.CustomEmojiEntity
import com.testlogon.android.core.data.messaging.MeetingPollDao
import com.testlogon.android.core.data.messaging.MeetingPollEntity
import com.testlogon.android.core.data.messaging.MeetingPollSlotEntity
import com.testlogon.android.core.data.messaging.MeetingPollWithSlots
import com.testlogon.android.core.data.messaging.MessageDao
import com.testlogon.android.core.data.messaging.MessageEntity
import com.testlogon.android.core.data.messaging.OutboxDao
import com.testlogon.android.core.data.messaging.OutboxMessageEntity
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.upload.AttachmentUploader
import com.testlogon.android.data.upload.UploadProgress
import com.testlogon.android.data.upload.UploadRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-120..AND-124 — messaging data layer over [MessagingApi] + the core-data Room cache/outbox.
 *
 * Responsibilities:
 *  - conversation list: network fetch -> cache upsert -> observable, sorted domain stream.
 *  - thread history: reverse-paged via the `before` cursor (oldest-loaded id), cached for offline.
 *  - send: optimistic outbox insert -> POST -> reconcile (insert MessageEntity, drop outbox row),
 *    or mark FAILED on error; the local `clientId` is the outbox key only (no server idempotency).
 *  - realtime: applies inbound [MessagingEvent.NewMessage] into the message + conversation caches.
 *
 * Failures fold into [ApiResult.Failure] / [ApiResult.NetworkError]; CancellationException is
 * re-thrown, never swallowed. Message content is never logged.
 */
/** #25/#27 — one staged media item for a mixed gallery send (a photo or a short video). */
data class MediaItem(
    val localUri: String,
    val isVideo: Boolean,
)

interface MessagingRepository {

    /** Observable, sorted conversation inbox backed by the Room cache. */
    fun observeConversations(): Flow<List<Conversation>>

    /** Network refresh of the conversation list; upserts the cache on success. */
    suspend fun refreshConversations(): ApiResult<List<Conversation>>

    /** Observable thread (history ∪ outbox) for a conversation, oldest-first. */
    fun observeThread(conversationId: String): Flow<List<Message>>

    /**
     * Fetch one page of older history. [before] is the oldest loaded message id (null = newest page).
     * Returns the fetched page; a short/empty page signals end-of-history. Upserts the cache.
     */
    suspend fun loadHistory(conversationId: String, before: String?, limit: Int): ApiResult<List<Message>>

    /** Enqueue an optimistic SENDING outbox row; returns its clientId. */
    suspend fun enqueueOptimistic(conversationId: String, clientId: String, text: String, nowSeconds: Long)

    /** POST the send and reconcile the outbox row; marks FAILED on error. */
    suspend fun sendOutbox(
        conversationId: String,
        clientId: String,
        text: String,
        replyToMessageId: String? = null,
        viewOnce: Boolean = false,
        lockPriceCents: Long? = null,
        lockDescription: String? = null,
        sendAtEpochSeconds: Long? = null,
        expiresInSeconds: Long? = null,
        // #6 (B-COUNTDOWN3) — attach a countdown to this (any-kind) text message.
        countdownTargetEpochSeconds: Long? = null,
        countdownTitle: String? = null,
        countdownRevealText: String? = null,
        countdownRevealImage: LotteryImageRef? = null,
    ): ApiResult<Message>

    /** Apply an inbound realtime new-message event to the caches. */
    suspend fun applyInboundMessage(event: MessagingEvent.NewMessage)

    /**
     * AND-140 — apply an inbound realtime mutation (reaction/edit/revoke) by re-fetching the affected
     * message and reconciling the cache, so the open thread reflects the change live. Best-effort.
     */
    suspend fun applyMessageMutation(event: MessagingEvent.MessageMutated)

    // ---- AND-140: reactions / pins / edits / delete / revoke / hide ----

    /**
     * AND-140 — toggle a reaction optimistically (chip count + reactedByMe) then POST …/reactions
     * with action add/remove. The endpoint returns an empty 200, so on success we re-fetch the
     * message to reconcile authoritative counts; on error we restore the captured prior entity.
     */
    suspend fun toggleReaction(
        conversationId: String,
        messageId: String,
        emoji: String,
        add: Boolean,
    ): ApiResult<Message>

    /** AND-140 — reactor details grouped by emoji (read-through; not persisted). */
    suspend fun reactionDetails(conversationId: String, messageId: String): ApiResult<List<Reactor>>

    /**
     * AND-140 — pin/unpin a message. POST/DELETE …/pin return a control ack (not a Message); we
     * apply the pinned flag to the cached entity optimistically and reconcile/roll back.
     */
    suspend fun setPinned(conversationId: String, messageId: String, pinned: Boolean): ApiResult<Unit>

    /** AND-140 — pinned messages (resolves pin refs against the cache, fetching any miss). */
    suspend fun pinnedMessages(conversationId: String, cursor: String? = null): ApiResult<List<Message>>

    /**
     * AND-140 / B-MSGEDIT #5 — edit a message (PATCH .../messages/{mid}); reconciles the cached row.
     *
     * In addition to [text], full media control is supported: pass ONE media kind to add/replace it
     * (promoting a text message), or [removeMedia]=true to strip all media back to text:
     *  - [image]                          -> image message (descriptor from [uploadEditImage]).
     *  - [freeImages]+[lockedImages]      -> gallery message (descriptors from [uploadEditImage]).
     *  - [filePath]                       -> file message (server VFS path from [uploadEditFile]).
     *  - [videoId]                        -> video_share message (a library video id).
     * At least one of text/media/removeMedia must be meaningful. Encrypted messages still unsupported.
     */
    suspend fun editMessage(
        conversationId: String,
        messageId: String,
        text: String? = null,
        image: MessageImageDto? = null,
        filePath: String? = null,
        videoId: String? = null,
        freeImages: List<GalleryImageDto>? = null,
        lockedImages: List<GalleryImageDto>? = null,
        removeMedia: Boolean = false,
    ): ApiResult<Message>

    /**
     * B-MSGEDIT #5 — process + presign + PUT a picked image so it can be attached on [editMessage]
     * (reuses the same conversation image-presign flow as the composer / scheduled-edit). Returns the
     * uploaded image descriptor (bucket/key/size). Does NOT mutate the message itself.
     */
    suspend fun uploadEditImage(conversationId: String, localUri: String): ApiResult<MessageImageDto>

    /**
     * B-MSGEDIT #5 / #4 — drive a picked file through the fs upload (presign -> PUT -> complete) so it
     * can be attached on [editMessage] / [rescheduleMessage]. Returns the server VFS path the
     * complete-upload echoed back (the value `file_path` expects). Does NOT mutate the message itself.
     */
    suspend fun uploadEditFile(
        conversationId: String,
        localUri: String,
        fileName: String,
        mimeType: String,
    ): ApiResult<String>

    /** AND-140 — edit history (newest-first; read-through, not persisted). */
    suspend fun editHistory(
        conversationId: String,
        messageId: String,
        limit: Int = 50,
    ): ApiResult<List<MessageEdit>>

    /**
     * AND-140 — delete a message FOR ME. Empty 200 -> mark DELETED locally; a 404 reconciles to the
     * same tombstone rather than rolling back.
     */
    suspend fun deleteMessage(conversationId: String, messageId: String): ApiResult<Unit>

    /** AND-140 — revoke ("unsend") a message FOR ALL; reconciles the cached row to REVOKED. */
    suspend fun revokeMessage(conversationId: String, messageId: String): ApiResult<Message>

    /**
     * #8 — list the caller's still-pending scheduled messages in [conversationId] (sorted by due time
     * ascending). Read-through, not cached (the manager refetches each time it opens).
     */
    suspend fun listScheduledMessages(conversationId: String): ApiResult<List<ScheduledMessage>>

    /**
     * #8 — reschedule / edit a still-pending scheduled message. Pass [text] and/or [sendAtEpochSeconds]
     * (at least one); returns the updated [ScheduledMessage]. Caller maps 400/403 to a user message.
     */
    suspend fun rescheduleMessage(
        conversationId: String,
        messageId: String,
        text: String? = null,
        sendAtEpochSeconds: Long? = null,
        // #7 (B-SCHED3) — attach/replace an image on a still-pending scheduled message. When the
        // message is currently text-only the server promotes its kind to "image" so the photo is
        // honored. Pass the descriptor returned by [uploadRescheduleImage].
        image: MessageImageDto? = null,
        // #4 (B-MSGEDIT) — attach/replace a FILE or a library VIDEO on a still-pending scheduled
        // message (even an originally text-only one; the server promotes its kind on save). [filePath]
        // is the server VFS path from [uploadEditFile]; [videoId] is a library video id.
        filePath: String? = null,
        videoId: String? = null,
    ): ApiResult<ScheduledMessage>

    /**
     * #7 (B-SCHED3) — process + presign + PUT a picked image so it can be attached to a scheduled
     * message via [rescheduleMessage]. Returns the uploaded image descriptor (bucket/key/size), or a
     * failure if processing/upload fails. Does NOT mutate the scheduled message itself.
     */
    suspend fun uploadRescheduleImage(conversationId: String, localUri: String): ApiResult<MessageImageDto>

    /** #8 — cancel/delete a still-pending scheduled message before it delivers. */
    suspend fun cancelScheduledMessage(conversationId: String, messageId: String): ApiResult<Unit>

    /**
     * AND-140 — hide/unhide a message FOR ME (server-backed). Applies the local hide flag
     * optimistically, POSTs/DELETEs …/hide, and rolls back on error. The hide flag is set via a
     * targeted column update so an unrelated MessageOut upsert never clobbers it.
     */
    suspend fun setHidden(conversationId: String, messageId: String, hidden: Boolean): ApiResult<Unit>

    /** AND-140 — the current user's hidden messages for a conversation. */
    suspend fun hiddenMessages(conversationId: String, cursor: String? = null): ApiResult<List<Message>>

    /**
     * AND-125 — mark a conversation read. Optimistically clears the local unread count/badge first,
     * then POSTs the read marker. The web client sends `last_read_at` (the newest loaded message's
     * created_at epoch); we mirror that. Failures keep the optimistic clear (read intent not lost)
     * and are not surfaced as a blocking error. [lastReadMessageId] is sent too when known (the
     * backend MarkReadIn accepts both nullable fields).
     */
    suspend fun markRead(
        conversationId: String,
        lastReadMessageId: String? = null,
        lastReadAtEpochSeconds: Long? = null,
    ): ApiResult<Unit>

    /** AND-125 — reactive total of unread conversations (rows with unreadCount > 0). */
    fun observeTotalUnread(): Flow<Int>

    // ---- AND-147: read receipts / views ----

    /**
     * AND-147 — report that the local user viewed [messageId] (FR-1). Idempotent: a no-op if already
     * reported this process lifetime (in-memory once-guard). Failures are silent (queued for one retry
     * on reconnect); never surfaced as a user error. Skips own messages at the call site.
     */
    suspend fun reportView(conversationId: String, messageId: String): ApiResult<Unit>

    /** Record consumption of a once-media message (grant -> consume) without downloading bytes;
     *  used for listen-once audio whose url is already exposed for direct playback. */
    suspend fun consumeOnceMedia(conversationId: String, messageId: String, trigger: String)

    /**
     * AND-147 — fetch the viewer roster for [messageId] (FR-5). Returns viewers sorted most-recent
     * first with the local user excluded (FR-6). The roster is a single bounded fetch (server has no
     * cursor); name/avatar are resolved by the caller from the participant cache.
     */
    suspend fun getViewers(
        conversationId: String,
        messageId: String,
        limit: Int = 200,
    ): ApiResult<List<com.testlogon.android.data.messaging.realtime.MessageViewer>>

    /**
     * AND-147 — retry any view reports that failed while offline, on SSE reconnect (FR-8 / AC-6).
     * Idempotent and best-effort; drains the in-memory pending queue.
     */
    suspend fun retryPendingViews()

    // ---- AND-151 / AND-152: message search ----

    /**
     * AND-151 — search within a single conversation. Returns matches FLATTENED to one entry per local
     * occurrence (ordered oldest->newest, then occurrenceIndex) so prev/next can step through every hit.
     * Highlight offsets are computed locally (the backend supplies none). Idempotent GET.
     */
    suspend fun searchInConversation(
        conversationId: String,
        query: String,
    ): ApiResult<List<MessageSearchMatch>>

    /**
     * AND-152 — cross-conversation message search. Returns a single bounded list of result items
     * spanning all conversations the user participates in (the endpoint has no pagination). `senderId`
     * and `afterTs` (epoch seconds) are optional filters. Idempotent GET.
     */
    suspend fun searchAllMessages(
        query: String,
        senderId: String? = null,
        afterTs: Long? = null,
    ): ApiResult<List<MessageSearchResultItem>>

    /**
     * AND-127 — find-or-create a 1:1 DM with [peerUserId], resolving to a [Conversation]. Guards
     * against self-DM locally (no network). The returned conversation is upserted into the cache so
     * the list reflects a brand-new DM immediately.
     */
    suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation>

    /**
     * #18 — resolve the conversation's peers for the audio/video-call menu from the CONVERSATION
     * PARTICIPANTS (not message senders), so a brand-new/empty 1:1 DM still exposes the call option.
     * Returns the conversation [ConversationPeers.type] plus the OTHER participants' user subs (self
     * excluded). Default no-op keeps test fakes / other implementers unaffected.
     */
    suspend fun conversationPeers(conversationId: String): ApiResult<ConversationPeers> =
        ApiResult.Success(ConversationPeers(type = "dm", otherUserSubs = emptyList()))

    /**
     * AND-153 — search contacts (people) by display-name token. Returns a single bounded list (the
     * endpoint has no pagination). A blank/whitespace-only query short-circuits to an empty list with
     * NO network request (a blank `q` would 422 server-side). The query is trimmed and capped at 64
     * chars to honour the server `q` maxLength. Idempotent GET.
     */
    suspend fun searchContacts(query: String): ApiResult<List<Contact>>

    /**
     * AND-130 — enqueue an optimistic image outbox row (renders a local-thumbnail bubble with
     * progress immediately).
     */
    suspend fun enqueueOptimisticImage(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    )

    /**
     * AND-130 — drive a picked image through process to presign to PUT to create-message and
     * reconcile the optimistic row. Progress is written to the outbox row so the bubble animates.
     * Marks the row FAILED on any error (manual retry, no server idempotency key).
     */
    suspend fun sendImageOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        caption: String? = null,
        viewOnce: Boolean = false,
        lockPriceCents: Long? = null,
        expiresInSeconds: Long? = null,
        sendAtEpochSeconds: Long? = null,
        encryptionPassphrase: String? = null,
    ): ApiResult<Message>

    /** C6 — enqueue an optimistic gallery (multi-image) outbox row (renders the first thumbnail + a
     * "+N" badge while uploading). */
    suspend fun enqueueOptimisticGallery(
        conversationId: String,
        clientId: String,
        firstLocalUri: String,
        imageCount: Int,
        nowSeconds: Long,
    )

    /**
     * C6 — send MULTIPLE picked images as ONE gallery message: process + presign + PUT each image,
     * collect the refs, then POST messages/gallery once. Reconciles the optimistic row or marks it
     * FAILED. Manual retry (no server idempotency key).
     */
    suspend fun sendGalleryOutbox(
        conversationId: String,
        clientId: String,
        localUris: List<String>,
        caption: String? = null,
        expiresInSeconds: Long? = null,
        sendAtEpochSeconds: Long? = null,
    ): ApiResult<Message>

    /**
     * #25/#27 — send a MIXED set of staged media (photos AND/OR videos) as ONE gallery message. Each
     * [MediaItem] is uploaded via the messaging media presign (images are processed/compressed; videos
     * stream raw) and referenced in free_images with its real content_type, so the server-derived
     * per-item media_kind lets the bubble render a mixed photo+video grid.
     */
    suspend fun sendMixedGalleryOutbox(
        conversationId: String,
        clientId: String,
        media: List<MediaItem>,
        caption: String? = null,
        expiresInSeconds: Long? = null,
        sendAtEpochSeconds: Long? = null,
    ): ApiResult<Message>

    /** C7 — enqueue an optimistic short-video outbox row (renders a file/clip bubble + progress). */
    suspend fun enqueueOptimisticVideoClip(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    )

    /**
     * C7 — send a picked SHORT video inline: stream the raw clip through the messaging images presign
     * (+ PUT, NO image processing/compression) and POST messages/image with kind="video". The server
     * stores it as a file attachment, so it renders as a downloadable/playable video bubble.
     */
    suspend fun sendVideoClipOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        caption: String? = null,
        viewOnce: Boolean = false,
        lockPriceCents: Long? = null,
        expiresInSeconds: Long? = null,
        sendAtEpochSeconds: Long? = null,
    ): ApiResult<Message>

    /** MSG (encrypted media) — GET raw bytes from a media url (encrypted-image ciphertext). */
    suspend fun fetchEncryptedImageBytes(url: String): ByteArray?

    /** AND-131 — list the current user's published videos for the share picker. */
    suspend fun listShareableVideos(): ApiResult<List<ShareableVideo>>

    /** AND-131 — share a library video by id into [conversationId]; returns the created message. */
    suspend fun sendVideoShare(
        conversationId: String,
        videoId: String,
        caption: String?,
    ): ApiResult<Message>

    /** AND-132 — enqueue an optimistic file outbox row (renders a chip with name/size + progress). */
    suspend fun enqueueOptimisticFile(
        conversationId: String,
        clientId: String,
        localUri: String,
        fileName: String,
        sizeBytes: Long,
        mimeType: String,
        nowSeconds: Long,
    )

    /**
     * AND-132 — drive a picked file through the AND-129 fs upload (presign -> PUT -> complete-upload)
     * to obtain a server VFS `path`, then POST messages/file. Reconciles the optimistic row or marks
     * it FAILED. Manual retry (no server idempotency key).
     */
    suspend fun sendFileOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        fileName: String,
        mimeType: String,
        // #10 — optional caption text sent alongside the file (kept with the message).
        caption: String? = null,
        viewOnce: Boolean = false,
        lockPriceCents: Long? = null,
        lockDescription: String? = null,
        expiresInSeconds: Long? = null,
        sendAtEpochSeconds: Long? = null,
    ): ApiResult<Message>

    /** AND-132 — share an existing owned file (by VFS path) into a conversation; returns the message. */
    suspend fun shareFile(
        conversationId: String,
        filePath: String,
        permission: String = "read",
        text: String? = null,
    ): ApiResult<Message>

    /** AND-132 — download a file/voice attachment to app cache (grant -> consume? -> GET bytes). */
    fun downloadAttachment(
        conversationId: String,
        messageId: String,
        fileName: String,
        consumptionPolicy: String,
    ): Flow<DownloadProgress>

    /** AND-133 — enqueue an optimistic voice outbox row (renders a waveform bubble + progress). */
    suspend fun enqueueOptimisticVoice(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        nowSeconds: Long,
    )

    /**
     * AND-133 — send a recorded voice clip: presign -> PUT (AND-129 transport) -> create. Reconciles
     * the optimistic row or marks it FAILED. A retry re-issues create with the same message_id/s3_key.
     */
    suspend fun sendVoiceOutbox(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        consumptionPolicy: String = "none",
        sendAtEpochSeconds: Long? = null,
    ): ApiResult<Message>

    // ---- AND-134: voicemail ----

    /** AND-134 — enqueue an optimistic voicemail outbox row (waveform/duration bubble + progress). */
    suspend fun enqueueOptimisticVoicemail(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        isVideo: Boolean,
        nowSeconds: Long,
    )

    /**
     * AND-134 — send a recorded voicemail clip tied to [callId]: presign -> PUT (AND-129 transport)
     * -> create. Reconciles the optimistic row or marks it FAILED. A retry re-issues create with the
     * same message_id/s3_key.
     */
    suspend fun sendVoicemailOutbox(
        conversationId: String,
        clientId: String,
        callId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        contentType: String,
        isVideo: Boolean,
    ): ApiResult<Message>

    // ---- AND-135: gifs / stickers / custom emoji ----

    /** AND-135 — send a GIF message (optimistic insert -> POST -> reconcile against the MessageOut). */
    suspend fun sendGif(
        conversationId: String,
        clientId: String,
        payload: GifSendPayload,
    ): ApiResult<Message>

    /** AND-135 — send a sticker message (optimistic insert -> POST -> reconcile). */
    suspend fun sendSticker(
        conversationId: String,
        clientId: String,
        sticker: StickerPick,
    ): ApiResult<Message>

    /** AND-135 — GIF search (empty query => trending). Single bounded page; no cursor. */
    suspend fun searchGifs(query: String, limit: Int = 20): ApiResult<List<GifResult>>

    /** AND-135 — sticker collections (with their stickers). */
    suspend fun stickerCollections(): ApiResult<List<StickerCollectionUi>>

    /** AND-135 — Room-backed, stale-first custom-emoji catalog (single source for picker + render). */
    fun observeCustomEmoji(): Flow<List<CustomEmojiUi>>

    /** AND-135 — refresh the custom-emoji catalog from the network into Room. */
    suspend fun refreshCustomEmoji(): ApiResult<Unit>

    // ---- AND-136: meeting poll ----

    /** AND-136 — observe a cached poll (Room single source of truth) by id. */
    fun observeMeetingPoll(pollId: String): Flow<MeetingPoll?>

    /** AND-136 — create a meeting poll message; inserts it into the thread + caches the poll. */
    suspend fun createMeetingPoll(
        conversationId: String,
        draft: MeetingPollDraft,
    ): ApiResult<MeetingPoll>

    /** Send an arbitrary text-option poll message (kind="poll"); inserts it into the thread. */
    suspend fun sendArbitraryPoll(
        conversationId: String,
        question: String,
        options: List<String>,
        multiSelect: Boolean,
        maxSelections: Int?,
        closesAt: Long?,
        text: String?,
    ): ApiResult<Unit>

    /** AND-136 — refresh authoritative poll state (idempotent GET) into Room. */
    suspend fun refreshMeetingPoll(conversationId: String, pollId: String): ApiResult<MeetingPoll>

    /**
     * AND-136 — set/clear the caller's response for [slotId] (null clears it). POSTs the vote then
     * re-fetches the canonical [MeetingPoll] (vote returns only {ok}). Writes the result to Room.
     */
    suspend fun voteMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
        vote: SlotVote?,
    ): ApiResult<MeetingPoll>

    /** AND-136 — confirm a winning slot (creator); POSTs then re-fetches the canonical poll. */
    suspend fun confirmMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
    ): ApiResult<MeetingPoll>

    // ---- AND-137: countdown ----

    /** AND-137 — enqueue an optimistic SENDING countdown outbox row (renders + ticks immediately). */
    suspend fun enqueueOptimisticCountdown(
        conversationId: String,
        clientId: String,
        title: String,
        targetEpochSeconds: Long,
        nowSeconds: Long,
    )

    /** AND-137 — send a countdown message (optimistic insert -> POST -> reconcile). */
    suspend fun sendCountdown(
        conversationId: String,
        clientId: String,
        draft: CountdownDraft,
    ): ApiResult<Message>


    // ---- AND-139: tips / paid-unlockable / lottery ----

    /**
     * AND-139 — unlock a fixed-price paid message: POST /unlock with [paymentMethodId] (receipt
     * only), then re-fetch the thread to obtain the revealed body and reconcile the row to unlocked.
     * The billing-authorize step happens in the ViewModel; this is the server unlock + reveal.
     */
    suspend fun unlockMessage(
        conversationId: String,
        messageId: String,
        paymentMethodId: String?,
    ): ApiResult<Message>

    /** AND-139 — single atomic lottery draw+reveal (empty body); writes the revealed outcome to Room. */
    suspend fun unlockLottery(
        conversationId: String,
        messageId: String,
    ): ApiResult<Message>

    /** AND-139 — tip a message (server captures); returns the tip receipt. */
    suspend fun tipMessage(
        conversationId: String,
        messageId: String,
        amountCents: Long,
        currency: String,
        note: String?,
        paymentMethodId: String?,
    ): ApiResult<TipReceipt>

    // ---- MSG: new in-app composers ----

    /** Lottery DM (conversation_id in BODY). Outcomes default-split weights to sum 10000. */
    suspend fun sendLottery(
        conversationId: String,
        outcomes: List<LotteryOutcomeDraft>,
        image: LotteryImageRef? = null,
        text: String? = null,
    ): ApiResult<Message>

    /**
     * C10 — upload a picked image for a lottery message (reuses the conversation image presign/PUT
     * transport; no confirm step). Returns the bucket/key/dimensions ref, or null on failure.
     */
    suspend fun uploadLotteryImage(
        conversationId: String,
        localUri: String,
    ): LotteryImageRef?

    /**
     * Number-13 — upload a per-OPTION image/video for a lottery outcome (reuses the conversation image
     * presign/PUT transport; the resulting key is scoped conversationId/owner/ as the B-LOT media
     * validator requires). Returns the media_asset_id ("bucket:key") to send, or null on failure.
     */
    suspend fun uploadLotteryOptionMedia(
        conversationId: String,
        localUri: String,
        isVideo: Boolean,
    ): String?

    /** Find-a-DateTime ("custom") poll. */
    suspend fun createFindDateTime(
        conversationId: String,
        draft: FindDateTimeDraft,
    ): ApiResult<Message>

    /** Share a calendar event. */
    suspend fun shareCalendarEvent(
        conversationId: String,
        calendarId: String,
        eventId: String,
        text: String?,
    ): ApiResult<Message>

    /** Share a calendar (read/write, optional booking link). */
    suspend fun shareCalendar(
        conversationId: String,
        calendarId: String,
        permission: String,
        includeBookingLink: Boolean,
        text: String?,
    ): ApiResult<Message>

    /** Send an encrypted text message (envelope populated; no plaintext on the wire). */
    suspend fun sendEncryptedText(
        conversationId: String,
        clientId: String,
        envelope: MessageEncryptionEnvelopeDto,
        replyToMessageId: String?,
    ): ApiResult<Message>

    /** Discovery: the user's calendars. */
    suspend fun listCalendars(): ApiResult<List<CalendarAccessUi>>

    /** Discovery: events in a calendar. */
    suspend fun listCalendarEvents(calendarId: String): ApiResult<List<CalendarEventUi>>

    /** Discovery: file-manager files at [path] (default root). */
    suspend fun listFiles(path: String = "/"): ApiResult<List<FileEntryUi>>
}

/**
 * A single lottery outcome draft from the composer. payloadType is "text"|"image"|"video". For media
 * outcomes mediaAssetId is the resolved S3 key ("bucket:key") of an image/video already uploaded via
 * the conversation image-presign transport; text is the revealed text for "text" outcomes.
 */
data class LotteryOutcomeDraft(
    val label: String?,
    val text: String,
    val weightBps: Int? = null,
    val payloadType: String = "text",
    val mediaAssetId: String? = null,
    // #24 — per-option media LIST. Before upload these are local content uris (with isVideo); the
    // ViewModel uploads each and replaces them with the resolved "bucket:key" media_asset_ids.
    val mediaItems: List<LotteryOutcomeMediaItem> = emptyList(),
    val mediaAssetIds: List<String>? = null,
)

/** #24 — one picked/resolved media asset on a lottery outcome. [ref] is a local content uri before
 *  upload, or a resolved "bucket:key" after. */
data class LotteryOutcomeMediaItem(
    val ref: String,
    val isVideo: Boolean,
)

/** C10 — resolved upload result for a lottery cover image (Backend B3 image object fields). */
data class LotteryImageRef(
    val bucket: String,
    val key: String,
    val contentType: String?,
    val width: Int?,
    val height: Int?,
)

/** A Find-a-DateTime poll creation draft. */
data class FindDateTimeDraft(
    val title: String,
    val fromDate: String,
    val toDate: String,
    val startHour: Int,
    val endHour: Int,
    val slotDurationMinutes: Int,
    val deadlineHours: Int = 48,
    val text: String? = null,
)

/** Discovery: a calendar the user can pick to share an event from or share wholesale. */
data class CalendarAccessUi(
    val calendarId: String,
    val name: String,
    val permission: String,
)

/** Discovery: a calendar event the user can share. */
data class CalendarEventUi(
    val eventId: String,
    val calendarId: String,
    val name: String,
    val startUtc: String?,
)

/** Discovery: a file the user can share (path is absolute, starts with /). */
data class FileEntryUi(
    val path: String,
    val name: String,
    val isFolder: Boolean,
    val sizeBytes: Long?,
)

/** AND-137 — a countdown creation draft (validated by the ViewModel before send). */
data class CountdownDraft(
    val title: String,
    val targetEpochSeconds: Long,
    val associatedEventType: AssociatedEventType = AssociatedEventType.CUSTOM,
    val associatedEventId: String? = null,
    /** #31 — optional text revealed when the countdown completes. */
    val revealText: String? = null,
    /** #31 — optional image revealed when the countdown completes (already uploaded). */
    val revealImage: LotteryImageRef? = null,
)

/** AND-139 — the receipt returned by a successful tip. */
data class TipReceipt(
    val tipPaymentId: String?,
    val amountCents: Long,
    val currency: String,
)

/** AND-135 — a GIF the user picked from search/trending, sent verbatim. */
data class GifSendPayload(
    val url: String,
    val altText: String?,
    val width: Int?,
    val height: Int?,
)

/** AND-135 — a sticker the user picked from a collection. */
data class StickerPick(
    val stickerId: String,
    val collectionId: String,
    val url: String,
    val altText: String?,
)

/** AND-135 — a GIF search/trending result for the picker grid. */
data class GifResult(
    val id: String,
    val url: String,
    val altText: String?,
    val width: Int?,
    val height: Int?,
)

/** AND-135 — a sticker (for the picker grid). */
data class StickerUi(
    val stickerId: String,
    val collectionId: String,
    val url: String,
    val altText: String?,
)

/** AND-135 — a sticker collection (for the picker). */
data class StickerCollectionUi(
    val collectionId: String,
    val name: String,
    val thumbnailUrl: String?,
    val stickers: List<StickerUi>,
)

/** AND-135 — a custom emoji (picker grid + inline render). [animated] is inferred from content_type. */
data class CustomEmojiUi(
    val shortcode: String,
    val name: String,
    val imageUrl: String,
    val animated: Boolean,
)

/** AND-136 — a candidate slot in the meeting-poll composer. */
data class MeetingPollSlotDraft(
    val startUtc: String,
    val endUtc: String,
)

/** AND-136 — a meeting-poll creation draft (validated by the ViewModel before send). */
data class MeetingPollDraft(
    val title: String,
    val durationMinutes: Int,
    val slots: List<MeetingPollSlotDraft>,
    val text: String? = null,
)

/** AND-131 — a video the current user can share, for the picker. */
data class ShareableVideo(
    val videoId: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSeconds: Int?,
)

@Singleton
class MessagingRepositoryImpl @Inject constructor(
    private val api: MessagingApi,
    private val conversationDao: ConversationDao,
    private val messageDao: MessageDao,
    private val outboxDao: OutboxDao,
    private val customEmojiDao: CustomEmojiDao,
    private val meetingPollDao: MeetingPollDao,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
    @dagger.hilt.android.qualifiers.ApplicationContext private val appContext: android.content.Context,
    private val uploader: AttachmentUploader,
    private val imageProcessor: MessageImageProcessor,
    private val uriMetadata: com.testlogon.android.data.upload.UriMetadata,
    private val storageClient: com.testlogon.android.data.upload.StorageUploadClient,
    private val attachmentDownloader: AttachmentDownloader,
    private val moshi: com.squareup.moshi.Moshi,
) : MessagingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun observeConversations(): Flow<List<Conversation>> =
        conversationDao.observeAll().map { rows -> rows.map(ConversationEntity::toDomain) }

    override suspend fun refreshConversations(): ApiResult<List<Conversation>> = withContext(io) {
        apiCall { api.listConversations() }.let { result ->
            when (result) {
                is ApiResult.Success -> {
                    val domain = result.data.map(ConversationDto::toDomain).sortedNewestFirst()
                    conversationDao.upsertAll(domain.map(Conversation::toEntity))
                    ApiResult.Success(domain)
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    override fun observeThread(conversationId: String): Flow<List<Message>> =
        combine(
            messageDao.observeForConversation(conversationId),
            outboxDao.observe(conversationId),
        ) { history, outbox ->
            mergeThread(history.map(MessageEntity::toDomain), outbox.map(OutboxMessageEntity::toDomain))
        }

    override suspend fun loadHistory(
        conversationId: String,
        before: String?,
        limit: Int,
    ): ApiResult<List<Message>> = withContext(io) {
        apiCall { api.listMessages(conversationId, limit = limit, before = before) }.let { result ->
            when (result) {
                is ApiResult.Success -> {
                    val domain = result.data.map { it.toDomain() }
                    messageDao.upsertAll(domain.map { it.toEntity(clientId = null) })
                    ApiResult.Success(domain)
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    override suspend fun enqueueOptimistic(
        conversationId: String,
        clientId: String,
        text: String,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = text,
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
            ),
        )
    }

    override suspend fun sendOutbox(
        conversationId: String,
        clientId: String,
        text: String,
        replyToMessageId: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        lockDescription: String?,
        sendAtEpochSeconds: Long?,
        expiresInSeconds: Long?,
        countdownTargetEpochSeconds: Long?,
        countdownTitle: String?,
        countdownRevealText: String?,
        countdownRevealImage: LotteryImageRef?,
    ): ApiResult<Message> = withContext(io) {
        val req = SendTextMessageReq(
            text = text,
            replyToMessageId = replyToMessageId,
            viewOnce = viewOnce.takeIf { it },
            lockPriceCents = lockPriceCents,
            lockDescription = lockDescription,
            sendAt = sendAtEpochSeconds,
            expiresInSeconds = expiresInSeconds,
            // #6 (B-COUNTDOWN3) — countdown attached to this message (any kind).
            countdownTargetDatetime = countdownTargetEpochSeconds,
            countdownTitle = countdownTitle?.takeIf { it.isNotBlank() },
            countdownRevealText = countdownRevealText?.takeIf { it.isNotBlank() },
            countdownRevealImage = countdownRevealImage?.let {
                CountdownRevealImageReq(
                    bucket = it.bucket,
                    key = it.key,
                    contentType = it.contentType,
                    width = it.width,
                    height = it.height,
                )
            },
        )
        when (val result = apiCall { api.sendMessage(conversationId, req) }) {
            is ApiResult.Success -> {
                // Reconcile: persist the server message (stamped with our clientId for cleanup),
                // then drop the optimistic outbox row.
                val message = result.data.toDomain(clientId = clientId)
                // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                outboxDao.delete(clientId)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> {
                markOutboxFailed(clientId)
                result
            }
            is ApiResult.NetworkError -> {
                markOutboxFailed(clientId)
                result
            }
        }
    }

    override suspend fun applyInboundMessage(event: MessagingEvent.NewMessage) = withContext(io) {
        // Ignore if we already have this message (e.g. our own send already reconciled).
        if (messageDao.findById(event.messageId) != null) return@withContext
        // Prefer the canonical message from the list (real created_at + full media), mirroring
        // applyMessageMutation. The realtime frame often omits created_at/url, which previously made
        // the bubble show "0 minutes ago" and drop its media until the next manual refresh.
        when (val r = apiCall { api.listMessages(event.conversationId, limit = PAGE_SIZE, before = null) }) {
            is ApiResult.Success -> {
                val fresh = r.data.firstOrNull { it.messageId == event.messageId }
                if (fresh != null) {
                    reconcilePreservingLocalFlags(fresh.toDomain())
                    return@withContext
                }
            }
            else -> Unit
        }
        // Fallback (offline / not yet in the list): insert a minimal row. Use the frame's created_at
        // when present, else NOW (the message just arrived) — never 0, which renders a blank time.
        val created = event.createdAtEpochSeconds.takeIf { it > 0L } ?: (System.currentTimeMillis() / 1000L)
        messageDao.upsert(
            MessageEntity(
                messageId = event.messageId,
                conversationId = event.conversationId,
                senderId = event.senderId,
                text = event.text.orEmpty(),
                createdAtEpochSeconds = created,
                clientId = null,
                kind = event.kind,
            ),
        )
    }

    override suspend fun applyMessageMutation(event: MessagingEvent.MessageMutated) = withContext(io) {
        // Re-fetch the affected message and reconcile the cache (mirrors the web refetch-on-event).
        when (val r = apiCall { api.listMessages(event.conversationId, limit = PAGE_SIZE, before = null) }) {
            is ApiResult.Success -> {
                val fresh = r.data.firstOrNull { it.messageId == event.messageId } ?: return@withContext
                reconcilePreservingLocalFlags(fresh.toDomain())
            }
            else -> Unit // best-effort; a later list refresh reconciles
        }
    }

    // ---- AND-140: reactions / pins / edits / delete / revoke / hide ----

    override suspend fun toggleReaction(
        conversationId: String,
        messageId: String,
        emoji: String,
        add: Boolean,
    ): ApiResult<Message> = withContext(io) {
        val prior = messageDao.findById(messageId)
            ?: return@withContext ApiResult.Failure(
                ApiError(status = ApiError.STATUS_PARSE, message = "Message not found"),
            )
        // Optimistic chip update so the thread Flow emits before the network returns.
        val optimistic = prior.toDomain().withReactionToggled(emoji, add)
        messageDao.upsert(optimistic.toEntity(clientId = prior.clientId))
        when (val r = apiCall { api.react(conversationId, messageId, ReactIn(emoji, if (add) "add" else "remove")) }) {
            is ApiResult.Success -> {
                // Empty 200 — re-fetch to reconcile authoritative counts (server is the source of truth).
                refetchAndReconcile(conversationId, messageId, fallback = optimistic)
            }
            is ApiResult.Failure -> { messageDao.upsert(prior); r }
            is ApiResult.NetworkError -> { messageDao.upsert(prior); r }
        }
    }

    override suspend fun reactionDetails(
        conversationId: String,
        messageId: String,
    ): ApiResult<List<Reactor>> = withContext(io) {
        when (val r = apiCall { api.reactionDetails(conversationId, messageId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toReactors())
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun setPinned(
        conversationId: String,
        messageId: String,
        pinned: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        val prior = messageDao.findById(messageId)
        // Optimistic local pin flag (targeted update so the rest of the row is untouched).
        if (prior != null) messageDao.setPinned(messageId, pinned)
        val call = if (pinned) {
            apiCall { api.pinMessage(conversationId, messageId) }
        } else {
            apiCall { api.unpinMessage(conversationId, messageId) }
        }
        when (call) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> { if (prior != null) messageDao.setPinned(messageId, prior.isPinned); call }
            is ApiResult.NetworkError -> { if (prior != null) messageDao.setPinned(messageId, prior.isPinned); call }
        }
    }

    override suspend fun pinnedMessages(
        conversationId: String,
        cursor: String?,
    ): ApiResult<List<Message>> = withContext(io) {
        when (val r = apiCall { api.listPins(conversationId, cursor = cursor) }) {
            is ApiResult.Success -> {
                // Pins endpoint returns REFS; resolve each against the cache, fetching any miss.
                val active = r.data.items.filter { it.isActive }.sortedByDescending { it.pinnedAt }
                val resolved = active.mapNotNull { ref ->
                    messageDao.findById(ref.messageId)?.toDomain() ?: fetchSingleMessage(conversationId, ref.messageId)
                }
                ApiResult.Success(resolved)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun editMessage(
        conversationId: String,
        messageId: String,
        text: String?,
        image: MessageImageDto?,
        filePath: String?,
        videoId: String?,
        freeImages: List<GalleryImageDto>?,
        lockedImages: List<GalleryImageDto>?,
        removeMedia: Boolean,
    ): ApiResult<Message> = withContext(io) {
        val body = EditMessageIn(
            text = text,
            image = image,
            filePath = filePath,
            videoId = videoId,
            freeImages = freeImages,
            lockedImages = lockedImages,
            removeMedia = removeMedia.takeIf { it },
        )
        when (val r = apiCall { api.editMessage(conversationId, messageId, body) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                reconcilePreservingLocalFlags(message)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun uploadEditImage(
        conversationId: String,
        localUri: String,
    ): ApiResult<MessageImageDto> =
        // Identical presign+PUT flow as the scheduled-edit photo attach; reuse it verbatim.
        uploadRescheduleImage(conversationId, localUri)

    override suspend fun uploadEditFile(
        conversationId: String,
        localUri: String,
        fileName: String,
        mimeType: String,
    ): ApiResult<String> = withContext(io) {
        val uri = Uri.parse(localUri)
        val info = uriMetadata.resolve(uri, fallbackMime = mimeType)
        val resolvedName = info.displayName ?: fileName
        // Same VFS destination the file-message outbox uses; complete-upload echoes back the path.
        val remotePath = "messages/$conversationId/$resolvedName"
        var ref: com.testlogon.android.data.upload.AttachmentRef? = null
        var uploadError: ApiError? = null
        uploader.upload(
            UploadRequest(
                uri = uri,
                mimeType = info.mimeType,
                category = "message",
                sizeBytes = info.sizeBytes,
                displayName = resolvedName,
                presignPath = "v1/fs/presign-upload",
                confirmPath = "v1/fs/complete-upload",
                remotePath = remotePath,
            ),
        ).collect { progress ->
            when (progress) {
                is UploadProgress.Succeeded -> ref = progress.attachment
                is UploadProgress.Failed -> uploadError = ApiError(
                    status = progress.error.httpStatus ?: ApiError.STATUS_NETWORK,
                    message = progress.error.message ?: "Upload failed",
                )
                UploadProgress.Cancelled ->
                    uploadError = ApiError(status = ApiError.STATUS_NETWORK, message = "Cancelled")
                else -> Unit
            }
        }
        val attachment = ref
            ?: return@withContext ApiResult.Failure(
                uploadError ?: ApiError(status = ApiError.STATUS_NETWORK, message = "Upload failed"),
            )
        ApiResult.Success(attachment.remotePath ?: remotePath)
    }

    override suspend fun editHistory(
        conversationId: String,
        messageId: String,
        limit: Int,
    ): ApiResult<List<MessageEdit>> = withContext(io) {
        when (val r = apiCall { api.editHistory(conversationId, messageId, limit) }) {
            is ApiResult.Success -> {
                val entries = parseEditHistory(r.data.string())
                ApiResult.Success(entries.toMessageEdits())
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun deleteMessage(
        conversationId: String,
        messageId: String,
    ): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.deleteMessage(conversationId, messageId) }) {
            is ApiResult.Success -> { markDeletedLocally(messageId); ApiResult.Success(Unit) }
            is ApiResult.Failure -> {
                // 404 (already deleted server-side) reconciles to a tombstone rather than rolling back.
                if (r.error.status == HTTP_NOT_FOUND) { markDeletedLocally(messageId); ApiResult.Success(Unit) } else r
            }
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun revokeMessage(
        conversationId: String,
        messageId: String,
    ): ApiResult<Message> = withContext(io) {
        when (val r = apiCall { api.revokeMessage(conversationId, messageId) }) {
            is ApiResult.Success -> {
                // Map the returned MessageOut; revoked_at -> REVOKED. Gated body never carried.
                val message = r.data.toDomain().copy(text = "", lifecycle = MessageLifecycle.REVOKED)
                reconcilePreservingLocalFlags(message)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun listScheduledMessages(
        conversationId: String,
    ): ApiResult<List<ScheduledMessage>> = withContext(io) {
        when (val r = apiCall { api.listScheduledMessages(conversationId) }) {
            is ApiResult.Success ->
                ApiResult.Success(r.data.map { it.toScheduledDomain() }.sortedBy { it.deliverAtEpochSeconds })
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun rescheduleMessage(
        conversationId: String,
        messageId: String,
        text: String?,
        sendAtEpochSeconds: Long?,
        image: MessageImageDto?,
        filePath: String?,
        videoId: String?,
    ): ApiResult<ScheduledMessage> = withContext(io) {
        val req = RescheduleMessageReq(
            text = text,
            sendAt = sendAtEpochSeconds,
            image = image,
            filePath = filePath,
            videoId = videoId,
        )
        when (val r = apiCall { api.rescheduleMessage(conversationId, messageId, req) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toScheduledDomain())
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun uploadRescheduleImage(
        conversationId: String,
        localUri: String,
    ): ApiResult<MessageImageDto> = withContext(io) {
        val processed = imageProcessor.process(Uri.parse(localUri))
            ?: return@withContext ApiResult.Failure(
                ApiError(status = ApiError.STATUS_PARSE, message = "Couldn't process this image."),
            )
        val fileName = processed.uri.lastPathSegment ?: "image.jpg"
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
        var uploadError: ApiError? = null
        uploader.upload(
            UploadRequest(
                uri = processed.uri,
                mimeType = processed.mimeType,
                category = "message",
                sizeBytes = processed.byteSize,
                displayName = fileName,
                presignPath = "messaging/conversations/$conversationId/images/presign",
                confirmPath = null,
            ),
        ).collect { progress ->
            when (progress) {
                is UploadProgress.Succeeded -> attachment = progress.attachment
                is UploadProgress.Failed -> uploadError = ApiError(
                    status = progress.error.httpStatus ?: ApiError.STATUS_NETWORK,
                    message = progress.error.message ?: "Upload failed",
                )
                UploadProgress.Cancelled ->
                    uploadError = ApiError(status = ApiError.STATUS_NETWORK, message = "Cancelled")
                else -> Unit
            }
        }
        val ref = attachment
            ?: return@withContext ApiResult.Failure(
                uploadError ?: ApiError(status = ApiError.STATUS_NETWORK, message = "Upload failed"),
            )
        ApiResult.Success(
            MessageImageDto(
                bucket = ref.bucket,
                key = ref.key,
                contentType = ref.contentType,
                width = processed.width,
                height = processed.height,
                filename = fileName,
                filesize = processed.byteSize,
            ),
        )
    }

    override suspend fun cancelScheduledMessage(
        conversationId: String,
        messageId: String,
    ): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.cancelScheduledMessage(conversationId, messageId) }) {
            // Body is {ok,message_id}; we only need the 200 (close the raw stream).
            is ApiResult.Success -> { runCatching { r.data.close() }; ApiResult.Success(Unit) }
            is ApiResult.Failure ->
                // 404 == already gone (delivered or cancelled elsewhere) -> treat as success.
                if (r.error.status == HTTP_NOT_FOUND) ApiResult.Success(Unit) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun setHidden(
        conversationId: String,
        messageId: String,
        hidden: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        val prior = messageDao.findById(messageId)
        if (prior != null) messageDao.setHidden(messageId, hidden) // optimistic, targeted update
        val call = if (hidden) {
            apiCall { api.hideMessage(conversationId, messageId) }
        } else {
            apiCall { api.unhideMessage(conversationId, messageId) }
        }
        when (call) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> { if (prior != null) messageDao.setHidden(messageId, prior.isHidden); call }
            is ApiResult.NetworkError -> { if (prior != null) messageDao.setHidden(messageId, prior.isHidden); call }
        }
    }

    override suspend fun hiddenMessages(
        conversationId: String,
        cursor: String?,
    ): ApiResult<List<Message>> = withContext(io) {
        when (val r = apiCall { api.listHiddenMessages(conversationId, cursor = cursor) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.items.map { it.toDomain().copy(isHiddenLocal = true) })
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    /** Re-fetch the message page and reconcile the named message; [fallback] kept if the fetch misses. */
    private suspend fun refetchAndReconcile(
        conversationId: String,
        messageId: String,
        fallback: Message,
    ): ApiResult<Message> {
        return when (val r = apiCall { api.listMessages(conversationId, limit = PAGE_SIZE, before = null) }) {
            is ApiResult.Success -> {
                val fresh = r.data.firstOrNull { it.messageId == messageId }?.toDomain()
                val reconciled = fresh ?: fallback
                reconcilePreservingLocalFlags(reconciled)
                ApiResult.Success(reconciled)
            }
            // Network/parse issue on the read-back: keep the optimistic state (already written).
            else -> ApiResult.Success(fallback)
        }
    }

    /** Upsert a server-authoritative message while preserving the local hide flag (R5 / merge rule). */
    private suspend fun reconcilePreservingLocalFlags(message: Message) {
        val priorHidden = messageDao.findById(message.id ?: return)?.isHidden ?: false
        messageDao.upsert(message.toEntity(clientId = null).copy(isHidden = priorHidden))
    }

    private suspend fun markDeletedLocally(messageId: String) {
        val prior = messageDao.findById(messageId) ?: return
        messageDao.upsert(prior.copy(text = "", lifecycle = MessageLifecycle.DELETED.name))
    }

    private suspend fun fetchSingleMessage(conversationId: String, messageId: String): Message? {
        val r = apiCall { api.listMessages(conversationId, limit = PAGE_SIZE, before = null) }
        if (r !is ApiResult.Success) return null
        val dto = r.data.firstOrNull { it.messageId == messageId } ?: return null
        val message = dto.toDomain()
        messageDao.upsert(message.toEntity(clientId = null))
        return message
    }

    /** Parse the unpinned GET …/edits body: a bare array or {items:[...]}. Tolerant of garbage. */
    private fun parseEditHistory(body: String): List<EditHistoryEntryDto> {
        if (body.isBlank()) return emptyList()
        val trimmed = body.trimStart()
        return runCatching {
            if (trimmed.startsWith("[")) {
                val type = com.squareup.moshi.Types.newParameterizedType(
                    List::class.java, EditHistoryEntryDto::class.java,
                )
                moshi.adapter<List<EditHistoryEntryDto>>(type).fromJson(body) ?: emptyList()
            } else {
                moshi.adapter(EditHistoryPageOut::class.java).fromJson(body)?.items ?: emptyList()
            }
        }.getOrDefault(emptyList())
    }

    override suspend fun markRead(
        conversationId: String,
        lastReadMessageId: String?,
        lastReadAtEpochSeconds: Long?,
    ): ApiResult<Unit> = withContext(io) {
        // FR-3: optimistic local clear so the unread badge / aggregate update without the network.
        conversationDao.clearUnread(conversationId)
        // FR-7 (corrected): no config gate exists; always attempt the POST after the optimistic clear.
        // Mirror the web client: send `last_read_at` (newest message created_at); include the
        // message id too when known (MarkReadIn accepts both nullable fields).
        apiCall {
            api.markRead(
                conversationId,
                MarkReadReq(
                    lastReadMessageId = lastReadMessageId,
                    lastReadAt = lastReadAtEpochSeconds,
                ),
            )
        }
        // FR-4: on success or failure we keep the optimistic clear (read intent is not lost). The
        // authoritative unread_count is reconciled by the next conversation-list refresh.
    }

    override fun observeTotalUnread(): Flow<Int> = conversationDao.observeUnreadConversationCount()

    // ---- AND-147: read receipts / views ----

    /** Once-per-process guard so a message is reported viewed at most once (FR-1 / AC-2). */
    private val reportedViews = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /** Bounded in-memory queue of (conversationId, messageId) reports to retry on reconnect (FR-8). */
    private val pendingViews = java.util.Collections.synchronizedSet(mutableSetOf<Pair<String, String>>())

    override suspend fun reportView(conversationId: String, messageId: String): ApiResult<Unit> =
        withContext(io) {
            // Idempotent once-guard: never re-POST a view we already reported this lifetime.
            if (!reportedViews.add(messageId)) return@withContext ApiResult.Success(Unit)
            when (apiCall { api.reportView(conversationId, messageId, ViewMessageIn()) }) {
                is ApiResult.Success -> { pendingViews.remove(conversationId to messageId); ApiResult.Success(Unit) }
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    // Silent to the user; allow a retry on the next reconnect (drop the once-guard so the
                    // retry can re-attempt, then re-arm it on success via the queue).
                    reportedViews.remove(messageId)
                    if (pendingViews.size < MAX_PENDING_VIEWS) pendingViews.add(conversationId to messageId)
                    ApiResult.Success(Unit) // never surface a receipt error to the UI (FR-8)
                }
            }
        }

    override suspend fun consumeOnceMedia(conversationId: String, messageId: String, trigger: String) =
        withContext(io) {
            runCatching {
                val grant = api.createAttachmentGrant(conversationId, messageId)
                api.consumeAttachment(
                    id = conversationId,
                    messageId = messageId,
                    grantToken = grant.grantToken,
                    body = ConsumeAttachmentReq(
                        consumptionAttemptId = java.util.UUID.randomUUID().toString(),
                        trigger = trigger,
                    ),
                )
            }
            Unit
        }

    override suspend fun fetchEncryptedImageBytes(url: String): ByteArray? =
        withContext(io) { storageClient.getBytesBlocking(url) }

    override suspend fun getViewers(
        conversationId: String,
        messageId: String,
        limit: Int,
    ): ApiResult<List<com.testlogon.android.data.messaging.realtime.MessageViewer>> = withContext(io) {
        when (val r = apiCall { api.getViews(conversationId, messageId, limit) }) {
            is ApiResult.Success -> {
                val self = authStateStore.userSub.value
                val viewers = r.data.map {
                    com.testlogon.android.data.messaging.realtime.MessageViewer(
                        userId = it.userId,
                        viewedAtEpochSeconds = it.lastViewedAt,
                        viewCount = it.viewCount,
                    )
                }
                ApiResult.Success(
                    com.testlogon.android.data.messaging.realtime.ReceiptReducer.fromRoster(viewers, self),
                )
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun retryPendingViews() = withContext(io) {
        val snapshot = synchronized(pendingViews) { pendingViews.toList() }
        snapshot.forEach { (cid, mid) ->
            // reportView re-arms the once-guard + clears the queue entry on success.
            reportView(cid, mid)
        }
    }

    // ---- AND-151 / AND-152: message search ----

    override suspend fun searchInConversation(
        conversationId: String,
        query: String,
    ): ApiResult<List<MessageSearchMatch>> = withContext(io) {
        val trimmed = query.trim().take(SEARCH_QUERY_MAX)
        when (val r = apiCall { api.searchInConversation(conversationId, trimmed) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.toSearchMatches(trimmed))
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun searchAllMessages(
        query: String,
        senderId: String?,
        afterTs: Long?,
    ): ApiResult<List<MessageSearchResultItem>> = withContext(io) {
        val trimmed = query.trim().take(SEARCH_QUERY_MAX)
        val call = apiCall {
            api.searchAllMessages(
                query = trimmed,
                senderId = senderId?.takeIf { it.isNotBlank() },
                afterTs = afterTs,
            )
        }
        when (call) {
            is ApiResult.Success -> ApiResult.Success(call.data.map { it.toSearchResultItem() })
            is ApiResult.Failure -> call
            is ApiResult.NetworkError -> call
        }
    }

    override suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation> = withContext(io) {
        // FR-5: self-DM guard — short-circuit locally with no network request.
        val me = authStateStore.userSub.value
        if (me != null && me == peerUserId) {
            return@withContext ApiResult.Failure(
                ApiError(status = STATUS_SELF_DM, message = "You can't message yourself."),
            )
        }
        when (val result = apiCall { api.findOrCreateDm(FindOrCreateDmReq(peerUserId)) }) {
            is ApiResult.Success -> {
                val conversation = result.data.toDomain()
                // Non-blocking side effect: surface a brand-new DM in the list immediately.
                conversationDao.upsertAll(listOf(conversation.toEntity()))
                ApiResult.Success(conversation)
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    // #18 — resolve peers from the conversation record (participants), used by the thread call menu.
    override suspend fun conversationPeers(conversationId: String): ApiResult<ConversationPeers> =
        withContext(io) {
            when (val r = apiCall { api.getConversation(conversationId) }) {
                is ApiResult.Success -> {
                    val me = authStateStore.userSub.value
                    val others = r.data.participants
                        .map { it.userId }
                        .filter { it.isNotBlank() && it != me }
                        .distinct()
                    ApiResult.Success(ConversationPeers(type = r.data.type, otherUserSubs = others))
                }
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    // ---- AND-153: contact search ----

    override suspend fun searchContacts(query: String): ApiResult<List<Contact>> = withContext(io) {
        // A blank/whitespace-only query is the idle state — never hit the network (blank `q` -> 422).
        val trimmed = query.trim().take(CONTACTS_QUERY_MAX)
        if (trimmed.isEmpty()) return@withContext ApiResult.Success(emptyList())
        when (val call = apiCall { api.searchContacts(query = trimmed) }) {
            is ApiResult.Success -> ApiResult.Success(call.data.map { it.toDomain() })
            is ApiResult.Failure -> call
            is ApiResult.NetworkError -> call
        }
    }

    override suspend fun enqueueOptimisticImage(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                kind = "image",
                imageLocalUri = localUri,
                uploadPercent = 0,
            ),
        )
    }

    override suspend fun sendImageOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        caption: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
        encryptionPassphrase: String?,
    ): ApiResult<Message> = withContext(io) {
        try {
            // 1. Process (compress, EXIF-strip) the picked uri.
            val processed = imageProcessor.process(Uri.parse(localUri))
                ?: return@withContext failImage(clientId, "Couldn't process this image.")
            val fileName = processed.uri.lastPathSegment ?: "image.jpg"

            // MSG (encrypted image) — if a passphrase is armed, encrypt the bytes and upload the
            // CIPHERTEXT; the message carries only the salt/iv envelope. The receiver downloads the
            // ciphertext and decrypts with the same passphrase.
            var uploadUri = processed.uri
            var uploadSize = processed.byteSize
            var encEnvelope: MessageEncryptionEnvelopeDto? = null
            if (!encryptionPassphrase.isNullOrBlank()) {
                val plain = appContext.contentResolver.openInputStream(processed.uri)?.use { it.readBytes() }
                    ?: return@withContext failImage(clientId, "Couldn't read image to encrypt.")
                val (env, cipher) = MessageCrypto.encryptBytes(plain, encryptionPassphrase)
                val encFile = java.io.File(appContext.cacheDir, "enc_$clientId.bin").apply { writeBytes(cipher) }
                uploadUri = Uri.fromFile(encFile)
                uploadSize = cipher.size.toLong()
                encEnvelope = env
            }

            // 2. Presign + PUT via the AND-129 uploader (image flow has NO confirm step). The
            //    uploader returns an AttachmentRef carrying the presign bucket/key we send next.
            var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
            var uploadError: ApiError? = null
            uploader.upload(
                UploadRequest(
                    uri = uploadUri,
                    mimeType = processed.mimeType,
                    category = "message",
                    sizeBytes = uploadSize,
                    displayName = fileName,
                    presignPath = "messaging/conversations/$conversationId/images/presign",
                    confirmPath = null,
                ),
            ).collect { progress ->
                when (progress) {
                    is UploadProgress.Uploading ->
                        outboxDao.updateUploadPercent(clientId, (progress.fraction * 100).toInt())
                    is UploadProgress.Succeeded -> {
                        outboxDao.updateUploadPercent(clientId, 100)
                        attachment = progress.attachment
                    }
                    is UploadProgress.Failed -> uploadError = ApiError(
                        status = progress.error.httpStatus ?: ApiError.STATUS_NETWORK,
                        message = progress.error.message ?: "Upload failed",
                    )
                    UploadProgress.Cancelled ->
                        uploadError = ApiError(status = ApiError.STATUS_NETWORK, message = "Cancelled")
                    else -> Unit
                }
            }
            val ref = attachment
            if (ref == null) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    uploadError ?: ApiError(status = ApiError.STATUS_NETWORK, message = "Upload failed"),
                )
            }

            // 3. Create the image message referencing bucket+key from the presign (in the ref).
            when (
                val created = apiCall {
                    api.createImageMessage(
                        conversationId,
                        CreateImageMessageReq(
                            bucket = ref.bucket,
                            key = ref.key,
                            contentType = ref.contentType,
                            filename = fileName,
                            filesize = processed.byteSize,
                            width = processed.width,
                            height = processed.height,
                            caption = caption?.takeIf { it.isNotBlank() },
                            consumptionPolicy = if (viewOnce) "view_once" else null,
                            viewOnce = viewOnce,
                            expiresInSeconds = expiresInSeconds,
                            lockPriceCents = lockPriceCents,
                            sendAt = sendAtEpochSeconds,
                            encryption = encEnvelope,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    private suspend fun failImage(clientId: String, message: String): ApiResult<Message> {
        markOutboxFailed(clientId)
        return ApiResult.Failure(ApiError(status = ApiError.STATUS_PARSE, message = message))
    }

    override suspend fun enqueueOptimisticGallery(
        conversationId: String,
        clientId: String,
        firstLocalUri: String,
        imageCount: Int,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                // Optimistic gallery rows reuse the "image" kind (single thumbnail) until the server
                // kind="gallery" message replaces the row with the full grid. `fileSizeBytes` stashes
                // the picked-image count for an optimistic "+N" badge (no schema migration needed).
                kind = "image",
                imageLocalUri = firstLocalUri,
                fileSizeBytes = imageCount.toLong(),
                uploadPercent = 0,
            ),
        )
    }

    /** C6 — process + presign + PUT a single image, returning its gallery item ref (or null). */
    private suspend fun uploadGalleryImage(
        conversationId: String,
        localUri: String,
    ): GalleryImageItemReq? {
        val processed = imageProcessor.process(Uri.parse(localUri)) ?: return null
        val fileName = processed.uri.lastPathSegment ?: "image.jpg"
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
        uploader.upload(
            UploadRequest(
                uri = processed.uri,
                mimeType = processed.mimeType,
                category = "message",
                sizeBytes = processed.byteSize,
                displayName = fileName,
                presignPath = "messaging/conversations/$conversationId/images/presign",
                confirmPath = null,
            ),
        ).collect { progress ->
            if (progress is UploadProgress.Succeeded) attachment = progress.attachment
        }
        return attachment?.let {
            GalleryImageItemReq(
                bucket = it.bucket,
                key = it.key,
                contentType = it.contentType,
                width = processed.width,
                height = processed.height,
                filename = fileName,
                filesize = processed.byteSize,
            )
        }
    }

    override suspend fun sendGalleryOutbox(
        conversationId: String,
        clientId: String,
        localUris: List<String>,
        caption: String?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> = withContext(io) {
        try {
            if (localUris.isEmpty()) return@withContext failImage(clientId, "No images selected.")
            val total = localUris.size
            // MV3 — upload all images CONCURRENTLY (each is an independent process+presign+PUT) instead
            // of strictly sequentially, so the 2nd/Nth image no longer waits on the 1st. Order is
            // preserved by awaitAll (results come back in the launched order); a completion counter
            // drives coarse progress as each finishes.
            val done = AtomicInteger(0)
            val refs = coroutineScope {
                localUris.map { uri ->
                    async {
                        val ref = uploadGalleryImage(conversationId, uri)
                        if (ref != null) {
                            outboxDao.updateUploadPercent(clientId, (done.incrementAndGet() * 100 / total))
                        }
                        ref
                    }
                }.awaitAll()
            }
            if (refs.any { it == null }) {
                return@withContext failImage(clientId, "Couldn't upload one of the images.")
            }
            @Suppress("UNCHECKED_CAST")
            val readyRefs = refs as List<GalleryImageItemReq>
            when (
                val created = apiCall {
                    api.createGalleryMessage(
                        conversationId,
                        CreateGalleryMessageReq(
                            freeImages = readyRefs,
                            text = caption?.takeIf { it.isNotBlank() },
                            expiresInSeconds = expiresInSeconds,
                            sendAt = sendAtEpochSeconds,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    /**
     * #25/#27 — presign + PUT a single SHORT video (raw bytes, NO processing) via the messaging media
     * presign, returning a gallery item ref carrying the video content_type (the server derives
     * media_kind="video" from it). Returns null on failure / oversize.
     */
    private suspend fun uploadGalleryVideo(
        conversationId: String,
        localUri: String,
    ): GalleryImageItemReq? {
        val uri = Uri.parse(localUri)
        val info = uriMetadata.resolve(uri, fallbackMime = "video/mp4")
        if (info.sizeBytes > 50L * 1024L * 1024L) return null
        val resolvedName = info.displayName ?: "video.mp4"
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
        uploader.upload(
            UploadRequest(
                uri = uri,
                mimeType = info.mimeType,
                category = "message",
                sizeBytes = info.sizeBytes,
                displayName = resolvedName,
                presignPath = "messaging/conversations/$conversationId/images/presign",
                confirmPath = null,
            ),
        ).collect { progress ->
            if (progress is UploadProgress.Succeeded) attachment = progress.attachment
        }
        return attachment?.let {
            GalleryImageItemReq(
                bucket = it.bucket,
                key = it.key,
                contentType = info.mimeType,
                filename = resolvedName,
                filesize = info.sizeBytes,
            )
        }
    }

    override suspend fun sendMixedGalleryOutbox(
        conversationId: String,
        clientId: String,
        media: List<MediaItem>,
        caption: String?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> = withContext(io) {
        try {
            if (media.isEmpty()) return@withContext failImage(clientId, "No media selected.")
            val total = media.size
            val done = AtomicInteger(0)
            // Upload every item concurrently (each is an independent presign + PUT); awaitAll preserves
            // order so the gallery free_images keep the staged order.
            val refs = coroutineScope {
                media.map { item ->
                    async {
                        val ref = if (item.isVideo) {
                            uploadGalleryVideo(conversationId, item.localUri)
                        } else {
                            uploadGalleryImage(conversationId, item.localUri)
                        }
                        if (ref != null) {
                            outboxDao.updateUploadPercent(clientId, (done.incrementAndGet() * 100 / total))
                        }
                        ref
                    }
                }.awaitAll()
            }
            if (refs.any { it == null }) {
                return@withContext failImage(clientId, "Couldn't upload one of the items.")
            }
            @Suppress("UNCHECKED_CAST")
            val readyRefs = refs as List<GalleryImageItemReq>
            when (
                val created = apiCall {
                    api.createGalleryMessage(
                        conversationId,
                        CreateGalleryMessageReq(
                            freeImages = readyRefs,
                            text = caption?.takeIf { it.isNotBlank() },
                            expiresInSeconds = expiresInSeconds,
                            sendAt = sendAtEpochSeconds,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    override suspend fun enqueueOptimisticVideoClip(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    ) = withContext(io) {
        val info = uriMetadata.resolve(Uri.parse(localUri), fallbackMime = "video/mp4")
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                // MV2 — optimistic short-video rows render as an inline VIDEO clip bubble (poster from
                // the local source uri), matching the reconciled server kind="video" render.
                kind = "video",
                attachmentLocalUri = localUri,
                fileName = info.displayName ?: "video.mp4",
                fileSizeBytes = info.sizeBytes,
                fileMimeType = info.mimeType,
                uploadPercent = 0,
            ),
        )
    }

    override suspend fun sendVideoClipOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        caption: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> = withContext(io) {
        try {
            val uri = Uri.parse(localUri)
            val info = uriMetadata.resolve(uri, fallbackMime = "video/mp4")
            val resolvedName = info.displayName ?: "video.mp4"
            // Guard: keep clips SHORT (size-bounded; the picker also requests short videos). Reject
            // anything over 50 MB rather than uploading a huge file.
            if (info.sizeBytes > 50L * 1024L * 1024L) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    ApiError(status = ApiError.STATUS_PARSE, message = "That video is too large (max 50 MB)."),
                )
            }

            // Presign + PUT via the messaging IMAGES transport (no VFS entitlement gates, no confirm),
            // streaming the raw video bytes (NO bitmap processing).
            var ref: com.testlogon.android.data.upload.AttachmentRef? = null
            var uploadError: ApiError? = null
            uploader.upload(
                UploadRequest(
                    uri = uri,
                    mimeType = info.mimeType,
                    category = "message",
                    sizeBytes = info.sizeBytes,
                    displayName = resolvedName,
                    presignPath = "messaging/conversations/$conversationId/images/presign",
                    confirmPath = null,
                ),
            ).collect { progress ->
                when (progress) {
                    is UploadProgress.Uploading ->
                        outboxDao.updateUploadPercent(clientId, (progress.fraction * 100).toInt())
                    is UploadProgress.Succeeded -> {
                        outboxDao.updateUploadPercent(clientId, 100)
                        ref = progress.attachment
                    }
                    is UploadProgress.Failed -> uploadError = ApiError(
                        status = progress.error.httpStatus ?: ApiError.STATUS_NETWORK,
                        message = progress.error.message ?: "Upload failed",
                    )
                    UploadProgress.Cancelled ->
                        uploadError = ApiError(status = ApiError.STATUS_NETWORK, message = "Cancelled")
                    else -> Unit
                }
            }
            val attachment = ref
            if (attachment == null) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    uploadError ?: ApiError(status = ApiError.STATUS_NETWORK, message = "Upload failed"),
                )
            }

            when (
                val created = apiCall {
                    api.createImageMessage(
                        conversationId,
                        CreateImageMessageReq(
                            bucket = attachment.bucket,
                            key = attachment.key,
                            contentType = info.mimeType,
                            kind = "video",
                            filename = resolvedName,
                            filesize = info.sizeBytes,
                            caption = caption?.takeIf { it.isNotBlank() },
                            consumptionPolicy = if (viewOnce) "view_once" else null,
                            viewOnce = viewOnce,
                            expiresInSeconds = expiresInSeconds,
                            lockPriceCents = lockPriceCents,
                            sendAt = sendAtEpochSeconds,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    override suspend fun listShareableVideos(): ApiResult<List<ShareableVideo>> = withContext(io) {
        when (val r = apiCall { api.listMyVideos(status = "published") }) {
            is ApiResult.Success -> ApiResult.Success(
                r.data.items.map {
                    ShareableVideo(
                        videoId = it.videoId,
                        title = it.title,
                        thumbnailUrl = it.thumbnailUrl,
                        durationSeconds = it.durationSeconds,
                    )
                },
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun sendVideoShare(
        conversationId: String,
        videoId: String,
        caption: String?,
    ): ApiResult<Message> = withContext(io) {
        when (
            val r = apiCall {
                api.createVideoShareMessage(
                    conversationId,
                    CreateVideoShareReq(videoId = videoId, text = caption?.takeIf { it.isNotBlank() }),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    // ---- AND-132: file messages + share + download ----

    override suspend fun enqueueOptimisticFile(
        conversationId: String,
        clientId: String,
        localUri: String,
        fileName: String,
        sizeBytes: Long,
        mimeType: String,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                kind = "file",
                attachmentLocalUri = localUri,
                fileName = fileName,
                fileSizeBytes = sizeBytes,
                fileMimeType = mimeType,
                uploadPercent = 0,
            ),
        )
    }

    override suspend fun sendFileOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
        fileName: String,
        mimeType: String,
        caption: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        lockDescription: String?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> = withContext(io) {
        try {
            val uri = Uri.parse(localUri)
            val info = uriMetadata.resolve(uri, fallbackMime = mimeType)
            val resolvedName = info.displayName ?: fileName
            // VFS destination path the fs presign/complete flow writes the object to (mirrors the web
            // files upload destination); the complete-upload echoes this `path` back for the message.
            val remotePath = "messages/$conversationId/$resolvedName"

            // Presign -> PUT -> complete-upload via the AND-129 uploader (fs flow HAS a confirm step).
            var ref: com.testlogon.android.data.upload.AttachmentRef? = null
            var uploadError: ApiError? = null
            uploader.upload(
                UploadRequest(
                    uri = uri,
                    mimeType = info.mimeType,
                    category = "message",
                    sizeBytes = info.sizeBytes,
                    displayName = resolvedName,
                    presignPath = "v1/fs/presign-upload",
                    confirmPath = "v1/fs/complete-upload",
                    remotePath = remotePath,
                ),
            ).collect { progress ->
                when (progress) {
                    is UploadProgress.Uploading ->
                        outboxDao.updateUploadPercent(clientId, (progress.fraction * 100).toInt())
                    is UploadProgress.Succeeded -> {
                        outboxDao.updateUploadPercent(clientId, 100)
                        ref = progress.attachment
                    }
                    is UploadProgress.Failed -> uploadError = ApiError(
                        status = progress.error.httpStatus ?: ApiError.STATUS_NETWORK,
                        message = progress.error.message ?: "Upload failed",
                    )
                    UploadProgress.Cancelled ->
                        uploadError = ApiError(status = ApiError.STATUS_NETWORK, message = "Cancelled")
                    else -> Unit
                }
            }
            val attachment = ref
            if (attachment == null) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    uploadError ?: ApiError(status = ApiError.STATUS_NETWORK, message = "Upload failed"),
                )
            }

            // The server-side VFS path returned by complete-upload is what messages/file requires.
            val serverPath = attachment.remotePath ?: remotePath
            when (
                val created = apiCall {
                    api.createFileMessage(
                        conversationId,
                        CreateFileMessageReq(
                            path = serverPath,
                            kind = "file",
                            text = caption?.takeIf { it.isNotBlank() },
                            consumptionPolicy = if (viewOnce) "view_once" else null,
                            viewOnce = viewOnce,
                            expiresInSeconds = expiresInSeconds,
                            lockPriceCents = lockPriceCents,
                            lockDescription = lockDescription,
                            sendAt = sendAtEpochSeconds,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    override suspend fun shareFile(
        conversationId: String,
        filePath: String,
        permission: String,
        text: String?,
    ): ApiResult<Message> = withContext(io) {
        when (
            val r = apiCall {
                api.createFileShareMessage(
                    conversationId,
                    CreateFileShareReq(
                        filePath = filePath,
                        permission = permission,
                        text = text?.takeIf { it.isNotBlank() },
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override fun downloadAttachment(
        conversationId: String,
        messageId: String,
        fileName: String,
        consumptionPolicy: String,
    ): Flow<DownloadProgress> =
        attachmentDownloader.download(conversationId, messageId, fileName, consumptionPolicy)

    // ---- AND-133: voice messages ----

    override suspend fun enqueueOptimisticVoice(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                kind = "voice_message",
                attachmentLocalUri = localFilePath,
                voiceDurationSeconds = durationSeconds,
                voiceWaveformJson = waveformToJson(waveform),
                uploadPercent = 0,
            ),
        )
    }

    override suspend fun sendVoiceOutbox(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        consumptionPolicy: String,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> = withContext(io) {
        try {
            val clip = java.io.File(localFilePath)
            if (!clip.exists() || clip.length() <= 0L) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    ApiError(status = ApiError.STATUS_PARSE, message = "Recording is missing."),
                )
            }
            val sizeBytes = clip.length()
            val contentType = VOICE_CONTENT_TYPE

            // 1. Presign (server allocates message_id + s3_key + upload_url).
            val presign = when (
                val p = apiCall {
                    api.presignVoice(
                        conversationId,
                        PresignVoiceReq(contentType, sizeBytes, durationSeconds),
                    )
                }
            ) {
                is ApiResult.Success -> p.data
                is ApiResult.Failure -> { markOutboxFailed(clientId); return@withContext p }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); return@withContext p }
            }

            // 2. PUT bytes to the presigned url via the COOKIELESS storage client (AND-129 transport).
            val putResult = try {
                val body = clip.asRequestBody(contentType.toMediaTypeOrNull())
                storageClient.put(presign.uploadUrl, contentType, body)
            } catch (e: CancellationException) {
                throw e
            } catch (e: IOException) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
            }
            if (!putResult.success) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    ApiError(status = putResult.httpStatus, message = "Voice upload failed"),
                )
            }
            outboxDao.updateUploadPercent(clientId, 100)

            // 3. Create the voice message (carries duration + waveform_data). A retry re-issues create
            //    with the SAME message_id/s3_key so the already-uploaded object is reused.
            when (
                val created = apiCall {
                    api.createVoiceMessage(
                        conversationId,
                        CreateVoiceReq(
                            messageId = presign.messageId,
                            s3Key = presign.s3Key,
                            contentType = contentType,
                            sizeBytes = sizeBytes,
                            durationSeconds = durationSeconds,
                            waveformData = waveform,
                            consumptionPolicy = consumptionPolicy,
                            sendAt = sendAtEpochSeconds,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    clip.delete()
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    // ---- AND-134: voicemail ----

    override suspend fun enqueueOptimisticVoicemail(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        isVideo: Boolean,
        nowSeconds: Long,
    ) = withContext(io) {
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = "",
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                kind = "voicemail",
                attachmentLocalUri = localFilePath,
                voiceDurationSeconds = durationSeconds,
                voiceWaveformJson = waveformToJson(waveform),
                uploadPercent = 0,
            ),
        )
    }

    override suspend fun sendVoicemailOutbox(
        conversationId: String,
        clientId: String,
        callId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        contentType: String,
        isVideo: Boolean,
    ): ApiResult<Message> = withContext(io) {
        try {
            val clip = java.io.File(localFilePath)
            if (!clip.exists() || clip.length() <= 0L) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    ApiError(status = ApiError.STATUS_PARSE, message = "Recording is missing."),
                )
            }
            val sizeBytes = clip.length()
            val mode = if (isVideo) "video" else "audio"

            // 1. Presign (server allocates message_id + s3_key + upload_url).
            val presign = when (
                val p = apiCall {
                    api.presignVoicemail(
                        conversationId,
                        PresignVoicemailReq(callId, contentType, sizeBytes, mode),
                    )
                }
            ) {
                is ApiResult.Success -> p.data
                is ApiResult.Failure -> { markOutboxFailed(clientId); return@withContext p }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); return@withContext p }
            }

            // 2. PUT bytes to the presigned url via the COOKIELESS storage client (AND-129 transport).
            val putResult = try {
                val body = clip.asRequestBody(contentType.toMediaTypeOrNull())
                storageClient.put(presign.uploadUrl, contentType, body)
            } catch (e: CancellationException) {
                throw e
            } catch (e: IOException) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
            }
            if (!putResult.success) {
                markOutboxFailed(clientId)
                return@withContext ApiResult.Failure(
                    ApiError(status = putResult.httpStatus, message = "Voicemail upload failed"),
                )
            }
            outboxDao.updateUploadPercent(clientId, 100)

            // 3. Create the voicemail (carries duration + waveform_data + call_id). A retry re-issues
            //    create with the SAME message_id/s3_key so the already-uploaded object is reused.
            when (
                val created = apiCall {
                    api.createVoicemail(
                        conversationId,
                        CreateVoicemailReq(
                            messageId = presign.messageId,
                            callId = callId,
                            s3Key = presign.s3Key,
                            contentType = contentType,
                            sizeBytes = sizeBytes,
                            durationSeconds = durationSeconds,
                            waveformData = waveform,
                            mode = mode,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                    outboxDao.delete(clientId)
                    clip.delete()
                    ApiResult.Success(message)
                }
                is ApiResult.Failure -> { markOutboxFailed(clientId); created }
                is ApiResult.NetworkError -> { markOutboxFailed(clientId); created }
            }
        } catch (e: CancellationException) {
            throw e
        }
    }

    // ---- AND-135: gifs / stickers / custom emoji ----

    override suspend fun sendGif(
        conversationId: String,
        clientId: String,
        payload: GifSendPayload,
    ): ApiResult<Message> = withContext(io) {
        when (
            val r = apiCall {
                api.sendGifMessage(
                    conversationId,
                    SendGifMessageReq(
                        gifUrl = payload.url,
                        gifAltText = payload.altText,
                        gifWidth = payload.width,
                        gifHeight = payload.height,
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain(clientId = clientId)
                // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                outboxDao.delete(clientId)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> { markOutboxFailed(clientId); r }
            is ApiResult.NetworkError -> { markOutboxFailed(clientId); r }
        }
    }

    override suspend fun sendSticker(
        conversationId: String,
        clientId: String,
        sticker: StickerPick,
    ): ApiResult<Message> = withContext(io) {
        when (
            val r = apiCall {
                api.sendStickerMessage(
                    conversationId,
                    SendStickerMessageReq(
                        stickerId = sticker.stickerId,
                        stickerCollectionId = sticker.collectionId,
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain(clientId = clientId)
                // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                outboxDao.delete(clientId)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> { markOutboxFailed(clientId); r }
            is ApiResult.NetworkError -> { markOutboxFailed(clientId); r }
        }
    }

    override suspend fun searchGifs(query: String, limit: Int): ApiResult<List<GifResult>> =
        withContext(io) {
            val clamped = limit.coerceIn(1, 50)
            val call = if (query.isBlank()) {
                apiCall { api.trendingGifs(clamped) }
            } else {
                apiCall { api.searchGifs(query, clamped) }
            }
            when (call) {
                is ApiResult.Success -> ApiResult.Success(
                    call.data.map { GifResult(it.id, it.url, it.altText, it.width, it.height) },
                )
                is ApiResult.Failure -> call
                is ApiResult.NetworkError -> call
            }
        }

    override suspend fun stickerCollections(): ApiResult<List<StickerCollectionUi>> = withContext(io) {
        when (val r = apiCall { api.stickerCollections() }) {
            is ApiResult.Success -> ApiResult.Success(
                r.data.collections.map { c ->
                    StickerCollectionUi(
                        collectionId = c.collectionId,
                        name = c.name,
                        thumbnailUrl = c.thumbnailUrl,
                        stickers = c.stickers.sortedBy { it.sortOrder }.map { s ->
                            StickerUi(s.stickerId, c.collectionId, s.imageUrl, s.altText)
                        },
                    )
                },
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override fun observeCustomEmoji(): Flow<List<CustomEmojiUi>> =
        customEmojiDao.observeAll().map { rows ->
            rows.map { CustomEmojiUi(it.shortcode, it.name, it.imageUrl, it.animated) }
        }

    override suspend fun refreshCustomEmoji(): ApiResult<Unit> = withContext(io) {
        when (val r = apiCall { api.customEmoji() }) {
            is ApiResult.Success -> {
                val now = System.currentTimeMillis() / 1000L
                val rows = r.data.emojis.map {
                    CustomEmojiEntity(
                        shortcode = it.shortcode,
                        name = it.name,
                        imageUrl = it.imageUrl,
                        animated = isAnimatedContentType(it.contentType),
                        fetchedAt = now,
                    )
                }
                customEmojiDao.upsertAll(rows)
                customEmojiDao.deleteStale(now)
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    // ---- AND-136: meeting poll ----

    override fun observeMeetingPoll(pollId: String): Flow<MeetingPoll?> =
        meetingPollDao.observePoll(pollId).map { it?.toDomain() }

    override suspend fun createMeetingPoll(
        conversationId: String,
        draft: MeetingPollDraft,
    ): ApiResult<MeetingPoll> = withContext(io) {
        val createResult = apiCall {
            api.createMeetingPoll(
                conversationId,
                CreateMeetingPollReq(
                    title = draft.title,
                    durationMinutes = draft.durationMinutes,
                    slots = draft.slots.map { MeetingPollSlotInDto(it.startUtc, it.endUtc) },
                    text = draft.text?.takeIf { it.isNotBlank() },
                ),
            )
        }
        when (createResult) {
            is ApiResult.Success -> {
                // Insert the poll message into the thread so it renders immediately.
                val message = createResult.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                val pollId = (message.media as? MessageMedia.MeetingPoll)?.pollId
                // Reconcile canonical slots/counts via the GET (the create body has no slots).
                if (pollId != null) {
                    refreshMeetingPoll(conversationId, pollId)
                } else {
                    ApiResult.Failure(
                        ApiError(status = ApiError.STATUS_PARSE, message = "Poll id missing in response."),
                    )
                }
            }
            is ApiResult.Failure -> createResult
            is ApiResult.NetworkError -> createResult
        }
    }

    override suspend fun sendArbitraryPoll(
        conversationId: String,
        question: String,
        options: List<String>,
        multiSelect: Boolean,
        maxSelections: Int?,
        closesAt: Long?,
        text: String?,
    ): ApiResult<Unit> = withContext(io) {
        val create = apiCall {
            api.createPollMessage(
                conversationId,
                CreatePollMessageReq(
                    question = question,
                    options = options,
                    choiceMode = if (multiSelect) "multi" else "single",
                    maxSelections = if (multiSelect) maxSelections else null,
                    closesAt = closesAt,
                    text = text?.takeIf { it.isNotBlank() },
                ),
            )
        }
        when (create) {
            is ApiResult.Success -> {
                messageDao.upsert(create.data.toDomain().toEntity(clientId = null))
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> ApiResult.Failure(create.error)
            is ApiResult.NetworkError -> ApiResult.NetworkError(create.cause, create.isTimeout)
        }
    }

    override suspend fun refreshMeetingPoll(
        conversationId: String,
        pollId: String,
    ): ApiResult<MeetingPoll> = withContext(io) {
        when (val r = apiCall { api.getMeetingPoll(conversationId, pollId) }) {
            is ApiResult.Success -> {
                val poll = r.data.toDomain()
                persistPoll(conversationId, poll)
                ApiResult.Success(poll)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun voteMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
        vote: SlotVote?,
    ): ApiResult<MeetingPoll> = withContext(io) {
        // Build the votes map: every slot the caller has responded to, with this slot updated.
        val current = meetingPollDao.observePollOnce(pollId)?.toDomain()
        val votesMap = buildVotesMap(current, slotId, vote)
        when (val r = apiCall { api.voteMeetingPoll(conversationId, pollId, PollVoteReq(votesMap)) }) {
            is ApiResult.Success ->
                // Vote returns only {ok}; re-fetch the canonical poll to reconcile tallies.
                refreshMeetingPoll(conversationId, pollId)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun confirmMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
    ): ApiResult<MeetingPoll> = withContext(io) {
        when (
            val r = apiCall { api.confirmMeetingPoll(conversationId, pollId, PollConfirmReq(slotId)) }
        ) {
            is ApiResult.Success -> refreshMeetingPoll(conversationId, pollId)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    // ---- AND-137: countdown ----

    override suspend fun enqueueOptimisticCountdown(
        conversationId: String,
        clientId: String,
        title: String,
        targetEpochSeconds: Long,
        nowSeconds: Long,
    ) = withContext(io) {
        // Reuse the outbox: `text` carries the title, `voiceDurationSeconds` carries the target epoch
        // (epoch seconds fit exactly in a Double). No new outbox column needed.
        outboxDao.upsert(
            OutboxMessageEntity(
                clientId = clientId,
                conversationId = conversationId,
                text = title,
                createdAtEpochSeconds = nowSeconds,
                status = SendStatus.SENDING.name,
                kind = "countdown",
                voiceDurationSeconds = targetEpochSeconds.toDouble(),
            ),
        )
    }

    override suspend fun sendCountdown(
        conversationId: String,
        clientId: String,
        draft: CountdownDraft,
    ): ApiResult<Message> = withContext(io) {
        when (
            val r = apiCall {
                api.sendCountdown(
                    conversationId,
                    SendCountdownMessageReq(
                        title = draft.title,
                        targetDatetime = draft.targetEpochSeconds,
                        associatedEventType = draft.associatedEventType.wire(),
                        associatedEventId = draft.associatedEventId,
                        revealText = draft.revealText?.takeIf { it.isNotBlank() },
                        revealImage = draft.revealImage?.let {
                            CountdownRevealImageReq(
                                bucket = it.bucket,
                                key = it.key,
                                contentType = it.contentType,
                                width = it.width,
                                height = it.height,
                            )
                        },
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain(clientId = clientId)
                // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                outboxDao.delete(clientId)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> { markOutboxFailed(clientId); r }
            is ApiResult.NetworkError -> { markOutboxFailed(clientId); r }
        }
    }

    // ---- AND-139: tips / paid-unlockable / lottery ----

    override suspend fun unlockMessage(
        conversationId: String,
        messageId: String,
        paymentMethodId: String?,
    ): ApiResult<Message> = withContext(io) {
        when (val r = apiCall { api.unlockMessage(conversationId, messageId, UnlockMessageReq(paymentMethodId)) }) {
            is ApiResult.Success -> {
                // UnlockOut is a receipt only; re-fetch the thread to obtain the revealed content.
                refreshAndReveal(conversationId, messageId)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun unlockLottery(
        conversationId: String,
        messageId: String,
    ): ApiResult<Message> = withContext(io) {
        when (val r = apiCall { api.unlockLottery(messageId) }) {
            is ApiResult.Success -> {
                val selected = r.data.selectedOutcome
                val payloadType = selected?.payloadType ?: "text"
                val revealed = selected?.takeIf { payloadType == "text" }?.textContent
                val revealedMediaList = selected
                    ?.takeIf { payloadType == "image" || payloadType == "video" }
                    ?.let { buildRevealedMedia(it.mediaAssetIds, it.mediaAssetId, payloadType == "video") }
                    ?: emptyList()
                val revealedMediaUrl = revealedMediaList.firstOrNull()?.url
                // Reconcile the cached row to unlocked + revealed text/media (server-authoritative).
                val existing = messageDao.findById(messageId)?.toDomain()
                if (existing != null) {
                    val paid = (existing.media as? MessageMedia.Paid)?.monetization
                    val updated = existing.copy(
                        media = MessageMedia.Paid(
                            (paid ?: MessageMonetization(UnlockType.LOTTERY, false, null, "USD", null)).copy(
                                unlocked = true,
                                revealedText = revealed,
                                revealedMediaUrl = revealedMediaUrl,
                                revealedMediaIsVideo = payloadType == "video",
                                revealedMedia = revealedMediaList,
                            ),
                        ),
                    )
                    messageDao.upsert(updated.toEntity(clientId = existing.clientId.takeIf { it != messageId }))
                    ApiResult.Success(updated)
                } else {
                    // No cached row (cold deep-link): hydrate via the lottery GET.
                    refreshLottery(conversationId, messageId)
                }
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun tipMessage(
        conversationId: String,
        messageId: String,
        amountCents: Long,
        currency: String,
        note: String?,
        paymentMethodId: String?,
    ): ApiResult<TipReceipt> = withContext(io) {
        when (
            val r = apiCall {
                api.tipMessage(
                    conversationId,
                    messageId,
                    SendTipReq(
                        amountCents = amountCents,
                        currency = currency,
                        note = note?.takeIf { it.isNotBlank() },
                        paymentMethodId = paymentMethodId,
                    ),
                )
            }
        ) {
            is ApiResult.Success -> ApiResult.Success(
                TipReceipt(r.data.tipPaymentId, r.data.amountCents, r.data.currency),
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    // ---- MSG: new in-app composers (implementations) ----

    override suspend fun uploadLotteryImage(
        conversationId: String,
        localUri: String,
    ): LotteryImageRef? = withContext(io) {
        // Reuse the conversation image presign/PUT transport (no confirm step), like sendImageOutbox.
        val processed = imageProcessor.process(Uri.parse(localUri)) ?: return@withContext null
        val fileName = processed.uri.lastPathSegment ?: "image.jpg"
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
        uploader.upload(
            UploadRequest(
                uri = processed.uri,
                mimeType = processed.mimeType,
                category = "message",
                sizeBytes = processed.byteSize,
                displayName = fileName,
                presignPath = "messaging/conversations/$conversationId/images/presign",
                confirmPath = null,
            ),
        ).collect { progress ->
            if (progress is UploadProgress.Succeeded) attachment = progress.attachment
        }
        attachment?.let {
            LotteryImageRef(
                bucket = it.bucket,
                key = it.key,
                contentType = it.contentType,
                width = processed.width,
                height = processed.height,
            )
        }
    }

    override suspend fun uploadLotteryOptionMedia(
        conversationId: String,
        localUri: String,
        isVideo: Boolean,
    ): String? = withContext(io) {
        // Reuse the conversation image presign/PUT transport (same endpoint images + video clips use).
        // Images are normalized through the processor; videos are uploaded as-is (no re-encode).
        val uploadUri: Uri
        val mime: String
        val sizeBytes: Long
        val name: String
        if (isVideo) {
            // FAIL-1 fix: a video option MUST upload with its REAL byte size. Previously sizeBytes
            // was hardcoded to 0L, so ProgressRequestBody.contentLength() declared Content-Length: 0
            // while writeTo() streamed the full clip -> OkHttp threw a Content-Length mismatch on the
            // PUT -> uploadLotteryOptionMedia returned null -> the ViewModel DEMOTED the option to
            // text ("Prize"), dropping every video. Resolve the size/mime from the content uri the
            // same way the working video-share path (sendVideoClipOutbox) does.
            uploadUri = Uri.parse(localUri)
            val info = uriMetadata.resolve(uploadUri, fallbackMime = "video/mp4")
            mime = info.mimeType
            sizeBytes = info.sizeBytes
            name = info.displayName ?: uploadUri.lastPathSegment ?: "clip.mp4"
        } else {
            val processed = imageProcessor.process(Uri.parse(localUri)) ?: return@withContext null
            uploadUri = processed.uri
            mime = processed.mimeType
            sizeBytes = processed.byteSize
            name = processed.uri.lastPathSegment ?: "image.jpg"
        }
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null
        uploader.upload(
            UploadRequest(
                uri = uploadUri,
                mimeType = mime,
                category = "message",
                sizeBytes = sizeBytes,
                displayName = name,
                presignPath = "messaging/conversations/$conversationId/images/presign",
                confirmPath = null,
            ),
        ).collect { progress ->
            if (progress is UploadProgress.Succeeded) attachment = progress.attachment
        }
        // Send media_asset_id as "bucket:key" (the B-LOT validator accepts this form and the key is
        // already under conversationId/owner/ from the presign).
        attachment?.let { "${it.bucket}:${it.key}" }
    }

    override suspend fun sendLottery(
        conversationId: String,
        outcomes: List<LotteryOutcomeDraft>,
        image: LotteryImageRef?,
        text: String?,
    ): ApiResult<Message> = withContext(io) {
        // Weights: use the sender-provided weight_bps when present (normalized to sum exactly 10000),
        // else split evenly. Any rounding remainder is added to the first outcome so the sum is 10000.
        val n = outcomes.size.coerceAtLeast(1)
        val hasWeights = outcomes.any { (it.weightBps ?: 0) > 0 }
        val rawWeights: List<Int> = if (hasWeights) {
            outcomes.map { (it.weightBps ?: 0).coerceAtLeast(0) }
        } else {
            val base = 10_000 / n
            List(n) { base }
        }
        val total = rawWeights.sum().coerceAtLeast(1)
        // Scale to 10000 bps.
        val scaled = rawWeights.map { (it.toLong() * 10_000L / total).toInt() }
        val remainder = 10_000 - scaled.sum()
        val finalWeights = scaled.mapIndexed { i, w -> (w + if (i == 0) remainder else 0).coerceAtLeast(1) }
        val outcomeReqs = outcomes.mapIndexed { i, o ->
            val isMedia = o.payloadType == "image" || o.payloadType == "video"
            // #24 — send the FULL list of resolved media assets (mediaAssetIds) for a media outcome;
            // media_asset_id stays as the first element for single-asset back-compat.
            val ids = o.mediaAssetIds?.filter { it.isNotBlank() }
                ?: listOfNotNull(o.mediaAssetId?.takeIf { it.isNotBlank() })
            LotteryOutcomeReq(
                displayLabel = o.label?.takeIf { it.isNotBlank() },
                weightBps = finalWeights.getOrElse(i) { 10_000 / n },
                payloadType = if (isMedia) o.payloadType else "text",
                // text_content only for text outcomes; media_asset_id(s) only for image/video outcomes.
                textContent = if (isMedia) null else o.text,
                mediaAssetId = if (isMedia) ids.firstOrNull() else null,
                mediaAssetIds = if (isMedia && ids.isNotEmpty()) ids else null,
            )
        }
        val req = CreateLotteryReq(
            conversationId = conversationId,
            lotteryConfig = LotteryConfigReq(version = "v1", outcomes = outcomeReqs),
            image = image?.let {
                LotteryMessageImageReq(
                    bucket = it.bucket,
                    key = it.key,
                    contentType = it.contentType,
                    width = it.width,
                    height = it.height,
                )
            },
            text = text?.takeIf { it.isNotBlank() },
        )
        when (val r = apiCall { api.createLottery(req) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun createFindDateTime(
        conversationId: String,
        draft: FindDateTimeDraft,
    ): ApiResult<Message> = withContext(io) {
        val req = CreateFindDateTimeReq(
            title = draft.title,
            fromDate = draft.fromDate,
            toDate = draft.toDate,
            startHour = draft.startHour,
            endHour = draft.endHour,
            slotDurationMinutes = draft.slotDurationMinutes,
            deadlineHours = draft.deadlineHours,
            text = draft.text?.takeIf { it.isNotBlank() },
        )
        when (val r = apiCall { api.createFindDateTime(conversationId, req) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun shareCalendarEvent(
        conversationId: String,
        calendarId: String,
        eventId: String,
        text: String?,
    ): ApiResult<Message> = withContext(io) {
        val req = CreateCalendarEventReq(
            calendarId = calendarId,
            eventId = eventId,
            text = text?.takeIf { it.isNotBlank() },
        )
        when (val r = apiCall { api.createCalendarEventMessage(conversationId, req) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun shareCalendar(
        conversationId: String,
        calendarId: String,
        permission: String,
        includeBookingLink: Boolean,
        text: String?,
    ): ApiResult<Message> = withContext(io) {
        val req = CreateCalendarShareReq(
            calendarId = calendarId,
            permission = permission,
            includeBookingLink = includeBookingLink,
            text = text?.takeIf { it.isNotBlank() },
        )
        when (val r = apiCall { api.createCalendarShareMessage(conversationId, req) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain()
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun sendEncryptedText(
        conversationId: String,
        clientId: String,
        envelope: MessageEncryptionEnvelopeDto,
        replyToMessageId: String?,
    ): ApiResult<Message> = withContext(io) {
        val req = SendTextMessageReq(
            text = null,
            replyToMessageId = replyToMessageId,
            encryption = envelope,
        )
        when (val r = apiCall { api.sendMessage(conversationId, req) }) {
            is ApiResult.Success -> {
                val message = r.data.toDomain(clientId = clientId)
                // #20 — scheduled sends stay out of the live thread (they live in the Scheduled manager
                // until delivered); only the outbox row is cleared. A delivered message persists as usual.
                if (!message.scheduled) messageDao.upsert(message.toEntity(clientId = clientId))
                outboxDao.delete(clientId)
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> { markOutboxFailed(clientId); r }
            is ApiResult.NetworkError -> { markOutboxFailed(clientId); r }
        }
    }

    override suspend fun listCalendars(): ApiResult<List<CalendarAccessUi>> = withContext(io) {
        when (val r = apiCall { api.listCalendars() }) {
            is ApiResult.Success -> ApiResult.Success(
                r.data.map { CalendarAccessUi(it.calendarId, it.name, it.permission) },
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun listCalendarEvents(calendarId: String): ApiResult<List<CalendarEventUi>> =
        withContext(io) {
            when (val r = apiCall { api.listCalendarEvents(calendarId) }) {
                is ApiResult.Success -> ApiResult.Success(
                    r.data.events.map { CalendarEventUi(it.eventId, it.calendarId.ifBlank { calendarId }, it.name, it.startUtc) },
                )
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun listFiles(path: String): ApiResult<List<FileEntryUi>> = withContext(io) {
        when (val r = apiCall { api.listFiles(path) }) {
            is ApiResult.Success -> ApiResult.Success(
                r.data.items.map { FileEntryUi(it.path, it.name, it.type == "folder", it.size) },
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    /** Re-fetch the newest thread page and reconcile the cache, then return the (now revealed) row. */
    private suspend fun refreshAndReveal(conversationId: String, messageId: String): ApiResult<Message> {
        return when (val r = apiCall { api.listMessages(conversationId, limit = 30, before = null) }) {
            is ApiResult.Success -> {
                val domain = r.data.map { it.toDomain() }
                messageDao.upsertAll(domain.map { it.toEntity(clientId = null) })
                val revealed = domain.firstOrNull { it.id == messageId }
                    ?: messageDao.findById(messageId)?.toDomain()
                if (revealed != null) ApiResult.Success(revealed)
                else ApiResult.Failure(ApiError(status = ApiError.STATUS_PARSE, message = "Message not found after unlock."))
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    private suspend fun refreshLottery(conversationId: String, messageId: String): ApiResult<Message> {
        return when (val r = apiCall { api.getLottery(messageId) }) {
            is ApiResult.Success -> {
                val unlocked = r.data.lockState == "unlocked"
                val message = Message(
                    id = messageId,
                    clientId = messageId,
                    conversationId = conversationId,
                    senderId = r.data.senderId,
                    text = "",
                    createdAtEpochSeconds = r.data.createdAt,
                    kind = "lottery_dm",
                    media = MessageMedia.Paid(
                        MessageMonetization(
                            type = UnlockType.LOTTERY,
                            unlocked = unlocked,
                            priceMinorUnits = null,
                            currency = "USD",
                            teaser = null,
                            revealedText = r.data.selectedOutcome?.takeIf { unlocked && (it.payloadType == "text") }?.textContent,
                            revealedMediaUrl = r.data.selectedOutcome
                                ?.takeIf { unlocked && (it.payloadType == "image" || it.payloadType == "video") }
                                ?.let { deriveMediaAssetUrl(it.mediaAssetIds?.firstOrNull() ?: it.mediaAssetId) },
                            revealedMediaIsVideo = unlocked && (r.data.selectedOutcome?.payloadType == "video"),
                            revealedMedia = r.data.selectedOutcome
                                ?.takeIf { unlocked && (it.payloadType == "image" || it.payloadType == "video") }
                                ?.let { buildRevealedMedia(it.mediaAssetIds, it.mediaAssetId, it.payloadType == "video") }
                                ?: emptyList(),
                        ),
                    ),
                )
                messageDao.upsert(message.toEntity(clientId = null))
                ApiResult.Success(message)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    private suspend fun persistPoll(conversationId: String, poll: MeetingPoll) {
        meetingPollDao.replacePoll(
            MeetingPollEntity(
                pollId = poll.pollId,
                conversationId = conversationId,
                title = poll.title,
                durationMinutes = poll.durationMinutes,
                creatorId = poll.creatorId,
                status = poll.status.name.lowercase(java.util.Locale.ROOT),
                confirmedSlotId = poll.confirmedSlotId,
            ),
            poll.slots.mapIndexed { i, s ->
                MeetingPollSlotEntity(
                    slotId = s.slotId,
                    pollId = poll.pollId,
                    position = i,
                    startUtc = s.startUtc,
                    endUtc = s.endUtc,
                    yesCount = s.yesCount,
                    maybeCount = s.maybeCount,
                    noCount = s.noCount,
                    myVote = s.myVote?.wire(),
                )
            },
        )
    }

    private suspend fun markOutboxFailed(clientId: String) {
        val current = outboxDao.findById(clientId) ?: return
        outboxDao.upsert(
            current.copy(status = SendStatus.FAILED.name, attemptCount = current.attemptCount + 1),
        )
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    } catch (e: com.squareup.moshi.JsonDataException) {
        // MSG — a single malformed/unexpected field must not crash the whole call (it previously took
        // out the entire message-list parse, dropping rich messages on the receiver). Degrade to a
        // recoverable failure so the cached thread keeps rendering.
        ApiResult.NetworkError(java.io.IOException(e), isTimeout = false)
    }

    companion object {
        /** Sentinel status for a locally-rejected self-DM attempt (no HTTP response involved). */
        const val STATUS_SELF_DM = -100

        /** AND-133 — AAC-LC / M4A container MIME (matches the recorder + the presign content-type pattern). */
        const val VOICE_CONTENT_TYPE = "audio/mp4"

        /** AND-140 — HTTP 404 (message already deleted server-side -> reconcile to a tombstone). */
        const val HTTP_NOT_FOUND = 404

        /** Default page size for thread history fetches (mirrors the thread VM PAGE_SIZE). */
        const val PAGE_SIZE = 30

        /** AND-147 — cap on the in-memory failed-view retry queue so a flaky host can't grow it unbounded. */
        const val MAX_PENDING_VIEWS = 256

        /** AND-151/152 — server `q` constraint is maxLength 200; cap client-side to avoid a 422. */
        const val SEARCH_QUERY_MAX = 200

        /** AND-153 — contacts `q` constraint is maxLength 64; cap client-side to avoid a 422. */
        const val CONTACTS_QUERY_MAX = 64
    }
}

/**
 * AND-140 — pure optimistic reaction toggle on a [Message]'s chip list: bumps/decrements the count
 * for [emoji] and flips reactedByMe, removing the chip when the count hits zero. JVM-testable.
 */
internal fun Message.withReactionToggled(emoji: String, add: Boolean): Message {
    val existing = reactions.firstOrNull { it.emoji == emoji }
    val next: List<Reaction> = when {
        add && existing == null -> reactions + Reaction(emoji, 1, reactedByMe = true)
        add && existing != null && !existing.reactedByMe ->
            reactions.map { if (it.emoji == emoji) it.copy(count = it.count + 1, reactedByMe = true) else it }
        !add && existing != null && existing.reactedByMe -> {
            val newCount = existing.count - 1
            if (newCount <= 0) {
                reactions.filterNot { it.emoji == emoji }
            } else {
                reactions.map { if (it.emoji == emoji) it.copy(count = newCount, reactedByMe = false) else it }
            }
        }
        // add when already reacted, or remove when not reacted: idempotent no-op.
        else -> reactions
    }
    return copy(reactions = next.sortedWith(compareByDescending<Reaction> { it.count }.thenBy { it.emoji }))
}

// ---- merge + entity mappers ----

/**
 * Merge cached history with the outbox: outbox rows whose clientId already has a confirmed history
 * row are dropped (reconciled); the rest append after history, sorted oldest-first by timestamp.
 */
internal fun mergeThread(history: List<Message>, outbox: List<Message>): List<Message> {
    val confirmedClientIds = history.mapNotNull { it.clientId }.toSet()
    val pending = outbox.filter { it.clientId !in confirmedClientIds }
    return (history + pending)
        .sortedWith(compareBy<Message> { it.createdAtEpochSeconds }.thenBy { it.clientId })
}

internal fun Conversation.toEntity(): ConversationEntity = ConversationEntity(
    conversationId = id,
    title = title,
    iconUrl = iconUrl,
    lastMessagePreview = lastMessagePreview,
    lastActivityEpochSeconds = lastActivityEpochSeconds,
    unreadCount = unreadCount,
)

internal fun ConversationEntity.toDomain(): Conversation = Conversation(
    id = conversationId,
    title = title,
    iconUrl = iconUrl,
    lastMessagePreview = lastMessagePreview,
    lastActivityEpochSeconds = lastActivityEpochSeconds,
    unreadCount = unreadCount,
)

internal fun Message.toEntity(clientId: String?): MessageEntity {
    val image = media as? MessageMedia.Image
    val gallery = media as? MessageMedia.Gallery
    val video = media as? MessageMedia.VideoShare
    val file = media as? MessageMedia.File
    val videoClip = media as? MessageMedia.VideoClip
    val voice = media as? MessageMedia.Voice
    val voicemail = media as? MessageMedia.Voicemail
    val gif = media as? MessageMedia.Gif
    val sticker = media as? MessageMedia.Sticker
    val poll = media as? MessageMedia.MeetingPoll
    val fadt = media as? MessageMedia.FindDateTime
    val calEvent = media as? MessageMedia.CalendarEvent
    val calShare = media as? MessageMedia.CalendarShare
    val paid = (media as? MessageMedia.Paid)?.monetization
    return MessageEntity(
        messageId = id ?: this.clientId,
        conversationId = conversationId,
        senderId = senderId,
        text = text,
        replyToMessageId = replyToMessageId,
        deliveredToCount = deliveredToCount,
        readByCount = readByCount,
        expiresAtEpochSeconds = expiresAtEpochSeconds,
        serverExpired = expired,
        createdAtEpochSeconds = createdAtEpochSeconds,
        clientId = clientId,
        kind = kind,
        imageUrl = image?.url,
        imageWidth = image?.width,
        imageHeight = image?.height,
        galleryImagesJson = gallery?.images?.let(::galleryToJson),
        pollJson = (media as? MessageMedia.Poll)?.poll?.let(::arbitraryPollToJson),
        videoId = video?.videoId,
        videoTitle = video?.title,
        videoThumbnailUrl = video?.thumbnailUrl,
        videoDurationSeconds = video?.durationSeconds ?: videoClip?.durationSeconds,
        videoHlsManifestUrl = video?.hlsManifestUrl,
        videoDrmEnabled = video?.drmEnabled ?: false,
        fileName = file?.fileName,
        fileSizeBytes = file?.sizeBytes,
        fileMimeType = file?.mimeType,
        fileIsShare = file?.isShare ?: false,
        // MV2 — persist the video clip's playable object url (new fileUrl column).
        fileUrl = videoClip?.playbackUrl,
        consumptionPolicy = consumptionPolicy,
        voiceAudioUrl = voice?.audioUrl,
        // Reuse the generic duration/waveform columns for voicemail too (both are audio peaks 0..1).
        voiceDurationSeconds = voice?.durationSeconds ?: voicemail?.durationSeconds,
        voiceWaveformJson = (voice?.waveform ?: voicemail?.waveform)?.let(::waveformToJson),
        voicemailMediaUrl = voicemail?.mediaUrl,
        voicemailIsVideo = voicemail?.isVideo ?: false,
        voicemailCallId = voicemail?.callId,
        voicemailCallState = voicemail?.callState,
        gifUrl = gif?.url,
        gifAltText = gif?.altText,
        gifWidth = gif?.width,
        gifHeight = gif?.height,
        stickerUrl = sticker?.url,
        stickerAltText = sticker?.altText,
        stickerId = sticker?.stickerId,
        stickerCollectionId = sticker?.collectionId,
        pollId = poll?.pollId ?: fadt?.pollId,
        pollTitle = poll?.title ?: fadt?.title,
        pollCreatorId = poll?.creatorId ?: fadt?.creatorId,
        pollStatus = poll?.status ?: fadt?.status,
        pollConfirmedSlotId = poll?.confirmedSlotId,
        // #6 (B-COUNTDOWN3) — persist from the transient countdown attribute (a countdown can now
        // ride any message kind; it is no longer a MessageMedia.Countdown). Reveal media is not cached.
        countdownTitle = this.countdown?.title,
        countdownTargetEpochSeconds = this.countdown?.targetEpochSeconds,
        countdownEventType = null,
        // #6 (B-COUNTDOWN3) — persist the reveal payload in the unused countdownEventId string column
        // (no schema bump) so the live thread (which observes Room) shows the reveal at target.
        countdownEventId = countdownRevealToBlob(this.countdown?.reveal),
        calEventId = calEvent?.eventId,
        calEventCalendarId = calEvent?.calendarId,
        calEventName = calEvent?.name,
        calEventStartUtc = calEvent?.startUtc,
        calEventEndUtc = calEvent?.endUtc,
        calEventAllDay = calEvent?.allDay ?: false,
        calEventAllDayDate = calEvent?.allDayDate,
        calEventTimezone = calEvent?.timezone,
        calEventDescription = calEvent?.description,
        calEventOwner = calEvent?.owner,
        calShareCalendarId = calShare?.calendarId,
        calShareName = calShare?.name,
        calShareOwner = calShare?.owner,
        calSharePermission = calShare?.permission?.name?.lowercase(java.util.Locale.ROOT),
        calShareBookingUrl = calShare?.bookingPublicUrl,
        monetizationType = paid?.type?.name,
        monetizationUnlocked = paid?.unlocked ?: false,
        // R2 — persist the lock price even when the message is NOT a Paid bubble (the sender's own
        // locked image is a plain Image with the gated media present), so the own "Locked $X" badge
        // survives the Room round-trip.
        lockPriceCents = paid?.priceMinorUnits ?: lockPriceCents,
        lockCurrency = paid?.currency ?: lockCurrency,
        lockTeaser = paid?.teaser,
        revealedText = paid?.revealedText,
        // Number-13 - persist the revealed lottery option media url across a Room round-trip.
        revealedMediaUrl = paid?.revealedMediaUrl,
        revealedMediaIsVideo = paid?.revealedMediaIsVideo ?: false,
        // #24 - persist the FULL revealed media list (image+video) so a multi-media reveal survives.
        revealedMediaJson = paid?.revealedMedia?.takeIf { it.isNotEmpty() }?.let(::revealedMediaToJson),
        // MSG — find_datetime detail (the card needs date range + hours).
        fadtFromDate = fadt?.fromDate,
        fadtToDate = fadt?.toDate,
        fadtStartHour = fadt?.startHour,
        fadtEndHour = fadt?.endHour,
        fadtSlotDurationMinutes = fadt?.slotDurationMinutes,
        // MSG — lottery lock_state + revealed outcome (Paid+LOTTERY already carries unlocked/revealedText;
        // these mirror it for clarity and a kind-based round-trip).
        lotteryLockState = paid?.takeIf { it.type == UnlockType.LOTTERY }?.let { if (it.unlocked) "unlocked" else "locked" },
        lotterySelectedText = paid?.takeIf { it.type == UnlockType.LOTTERY }?.revealedText,
        // #15 — persist the sender's lottery sender-view (config + per-recipient results) as JSON.
        lotterySenderViewJson = paid?.lotterySenderView?.let(::lotterySenderViewToJson),
        // MSG — client-side encryption flag + envelope.
        isEncrypted = isEncrypted,
        encVersion = encryption?.version,
        encAlg = encryption?.alg,
        encKdf = encryption?.kdf,
        encIterations = encryption?.iterations,
        encSaltB64 = encryption?.saltB64,
        encIvB64 = encryption?.ivB64,
        encCiphertextB64 = encryption?.ciphertextB64,
        viewOnce = viewOnce,
        consumed = consumed,
        // AND-140 — moderation / engagement columns.
        reactionsJson = reactionsToJson(reactions),
        isPinned = isPinned,
        lifecycle = lifecycle.name,
        editedAtEpochSeconds = editedAtEpochSeconds,
        isHidden = isHiddenLocal,
    )
}

/**
 * AND-140 — serialize the reaction chip list to a compact JSON array string for the Room TEXT
 * column. Pure / JVM-testable; null for an empty list so legacy rows stay null. Emoji are
 * JSON-string-escaped minimally (quote + backslash).
 */
internal fun reactionsToJson(reactions: List<Reaction>): String? {
    if (reactions.isEmpty()) return null
    return reactions.joinToString(prefix = "[", postfix = "]") { r ->
        val emoji = r.emoji.replace("\\", "\\\\").replace("\"", "\\\"")
        "{\"e\":\"$emoji\",\"c\":${r.count},\"m\":${r.reactedByMe}}"
    }
}

/** AND-140 — parse the reactions JSON column back into chips; tolerant of null/blank/garbage. */
internal fun reactionsFromJson(json: String?): List<Reaction> {
    if (json.isNullOrBlank() || json == "[]") return emptyList()
    return ReactionJsonRegex.findAll(json).mapNotNull { match ->
        val emoji = match.groupValues[1].replace("\\\"", "\"").replace("\\\\", "\\")
        val count = match.groupValues[2].toIntOrNull() ?: return@mapNotNull null
        val mine = match.groupValues[3].toBooleanStrictOrNull() ?: false
        Reaction(emoji, count, mine)
    }.toList()
}

private val ReactionJsonRegex =
    Regex("\\{\"e\":\"((?:[^\"\\\\]|\\\\.)*)\",\"c\":(\\d+),\"m\":(true|false)\\}")

/** Serializes a normalized waveform (0..1) to a compact JSON number[] string for the Room TEXT column. */
internal fun waveformToJson(values: List<Float>): String =
    values.joinToString(prefix = "[", postfix = "]") { String.format(java.util.Locale.ROOT, "%.3f", it) }

/**
 * C6 — serialize gallery images as one "url|width|height" record per line (URLs never contain a
 * newline). Kept JVM-test-safe (no org.json, which is unmocked in :app unit tests).
 */
private const val GALLERY_RECORD_SEP = "\n"

/** Codegen-adapter persistence shape for an arbitrary poll snapshot (Room cache round-trip). */
@com.squareup.moshi.JsonClass(generateAdapter = true)
data class PersistedPollDto(
    val pollId: String,
    val question: String,
    val owner: String?,
    val closed: Boolean,
    val closesAt: Long?,
    val totalVotes: Int,
    val questions: List<PersistedPollQuestionDto>,
)

@com.squareup.moshi.JsonClass(generateAdapter = true)
data class PersistedPollQuestionDto(
    val id: String,
    val text: String,
    val multiSelect: Boolean,
    val maxSelections: Int?,
    val options: List<PersistedPollOptionDto>,
    val myVoteOptionIds: List<String>,
)

@com.squareup.moshi.JsonClass(generateAdapter = true)
data class PersistedPollOptionDto(
    val id: String,
    val text: String,
    val count: Int,
)

private val arbitraryPollAdapter by lazy { lsvMoshi.adapter(PersistedPollDto::class.java) }

internal fun arbitraryPollToJson(p: com.testlogon.android.core.model.poll.ArbitraryPoll): String =
    arbitraryPollAdapter.toJson(
        PersistedPollDto(
            pollId = p.pollId,
            question = p.question,
            owner = p.owner,
            closed = p.closed,
            closesAt = p.closesAtEpochSeconds,
            totalVotes = p.totalVotes,
            questions = p.questions.map { q ->
                PersistedPollQuestionDto(
                    id = q.id,
                    text = q.text,
                    multiSelect = q.multiSelect,
                    maxSelections = q.maxSelections,
                    options = q.options.map { PersistedPollOptionDto(it.id, it.text, it.count) },
                    myVoteOptionIds = q.myVoteOptionIds,
                )
            },
        ),
    )

internal fun arbitraryPollFromJson(json: String?): com.testlogon.android.core.model.poll.ArbitraryPoll? {
    if (json.isNullOrBlank()) return null
    val dto = runCatching { arbitraryPollAdapter.fromJson(json) }.getOrNull() ?: return null
    return com.testlogon.android.core.model.poll.ArbitraryPoll(
        pollId = dto.pollId,
        question = dto.question,
        owner = dto.owner,
        closed = dto.closed,
        closesAtEpochSeconds = dto.closesAt,
        totalVotes = dto.totalVotes,
        questions = dto.questions.map { q ->
            com.testlogon.android.core.model.poll.ArbitraryPollQuestion(
                id = q.id,
                text = q.text,
                multiSelect = q.multiSelect,
                maxSelections = q.maxSelections,
                options = q.options.map {
                    com.testlogon.android.core.model.poll.ArbitraryPollOption(it.id, it.text, it.count)
                },
                myVoteOptionIds = q.myVoteOptionIds,
            )
        },
    )
}

internal fun galleryToJson(images: List<MessageMedia.GalleryImage>): String =
    // #8/#12 — persist isVideo + posterUrl so a mixed gallery keeps each item's media kind across the
    // Room cache round-trip (otherwise a cached video item reloads as an image). Format per record:
    // url|width|height|isVideo(0/1)|posterUrl
    images.joinToString(GALLERY_RECORD_SEP) {
        "${it.url.orEmpty()}|${it.width ?: ""}|${it.height ?: ""}|${if (it.isVideo) "1" else "0"}|${it.posterUrl.orEmpty()}"
    }

/** #24 - serialize the revealed lottery media list as "url|isVideo" records (one per line). */
internal fun revealedMediaToJson(items: List<RevealedMediaItem>): String =
    items.joinToString(GALLERY_RECORD_SEP) { "${it.url}|${if (it.isVideo) "1" else "0"}" }

/**
 * #6 (B-COUNTDOWN3) — serialize a countdown reveal payload into the (otherwise-unused) countdown
 * string column so it survives the Room cache round-trip WITHOUT a schema bump. Records (sep="\n"):
 *   T|<base64(text)>        — present only when reveal text is set
 *   M|<url>|<isVideo 0/1>   — one per reveal media item
 * Returns null for an empty/absent reveal so the column stays null for non-countdown rows.
 */
internal fun countdownRevealToBlob(reveal: com.testlogon.android.data.messaging.CountdownReveal?): String? {
    if (reveal == null || reveal.isEmpty) return null
    val recs = buildList {
        reveal.text?.takeIf { it.isNotBlank() }?.let {
            val b64 = android.util.Base64.encodeToString(it.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
            add("T|" + b64)
        }
        reveal.media.forEach { add("M|" + it.url + "|" + (if (it.isVideo) "1" else "0")) }
    }
    return recs.takeIf { it.isNotEmpty() }?.joinToString(GALLERY_RECORD_SEP)
}

/** #6 (B-COUNTDOWN3) — parse a persisted countdown reveal blob back into [CountdownReveal] (null if empty). */
internal fun countdownRevealFromBlob(blob: String?): com.testlogon.android.data.messaging.CountdownReveal? {
    if (blob.isNullOrBlank()) return null
    var text: String? = null
    val media = mutableListOf<com.testlogon.android.data.messaging.CountdownRevealMedia>()
    blob.split(GALLERY_RECORD_SEP).forEach { line ->
        if (line.isBlank()) return@forEach
        val parts = line.split("|")
        when (parts.getOrNull(0)) {
            "T" -> parts.getOrNull(1)?.let {
                text = runCatching { String(android.util.Base64.decode(it, android.util.Base64.NO_WRAP), Charsets.UTF_8) }.getOrNull()
            }
            "M" -> parts.getOrNull(1)?.takeIf { it.isNotBlank() }?.let { url ->
                media.add(com.testlogon.android.data.messaging.CountdownRevealMedia(url = url, isVideo = parts.getOrNull(2) == "1"))
            }
        }
    }
    val r = com.testlogon.android.data.messaging.CountdownReveal(text = text, media = media)
    return r.takeIf { !it.isEmpty }
}

/** #24 - parse the revealed lottery media records back into [RevealedMediaItem]s. */
internal fun revealedMediaFromJson(json: String?): List<RevealedMediaItem> {
    if (json.isNullOrBlank()) return emptyList()
    return json.split(GALLERY_RECORD_SEP).mapNotNull { line ->
        if (line.isBlank()) return@mapNotNull null
        val parts = line.split("|")
        val url = parts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
        RevealedMediaItem(url = url, isVideo = parts.getOrNull(1) == "1")
    }
}

// #15 — sender-view (config + per-recipient results) Room serialization. Serialized as a small JSON
// blob via a process-wide Moshi (these mappers are top-level extensions without the injected Moshi).
// Codegen adapters keep this JVM-unit-test-safe (no reflective KotlinJsonAdapterFactory needed).
@com.squareup.moshi.JsonClass(generateAdapter = true)
internal data class LsvBlob(
    val version: String,
    val totalWeightBps: Int,
    val outcomes: List<LsvOutcomeBlob>,
    val unlocks: List<LsvUnlockBlob>,
)

@com.squareup.moshi.JsonClass(generateAdapter = true)
internal data class LsvOutcomeBlob(
    val outcomeId: String,
    val displayLabel: String? = null,
    val weightBps: Int = 0,
    val payloadType: String = "text",
    val textContent: String? = null,
    val media: List<LsvMediaBlob> = emptyList(),
)

@com.squareup.moshi.JsonClass(generateAdapter = true)
internal data class LsvMediaBlob(val url: String, val isVideo: Boolean = false)

@com.squareup.moshi.JsonClass(generateAdapter = true)
internal data class LsvUnlockBlob(
    val recipientId: String,
    val unlockedAt: Long? = null,
    val selectedOutcome: LsvOutcomeBlob? = null,
)

private val lsvMoshi: com.squareup.moshi.Moshi by lazy { com.squareup.moshi.Moshi.Builder().build() }
private val lsvAdapter by lazy { lsvMoshi.adapter(LsvBlob::class.java) }

private fun LotterySenderOutcome.toBlob(): LsvOutcomeBlob = LsvOutcomeBlob(
    outcomeId = outcomeId,
    displayLabel = displayLabel,
    weightBps = weightBps,
    payloadType = payloadType,
    textContent = textContent,
    media = media.map { LsvMediaBlob(url = it.url, isVideo = it.isVideo) },
)

private fun LsvOutcomeBlob.toDomain(): LotterySenderOutcome = LotterySenderOutcome(
    outcomeId = outcomeId,
    displayLabel = displayLabel?.takeIf { it.isNotBlank() },
    weightBps = weightBps,
    payloadType = payloadType.takeIf { it.isNotBlank() } ?: "text",
    textContent = textContent?.takeIf { it.isNotBlank() },
    media = media.map { RevealedMediaItem(url = it.url, isVideo = it.isVideo) },
)

/** #15 — serialize the lottery sender-view into a JSON blob for Room. */
internal fun lotterySenderViewToJson(v: LotterySenderView): String = lsvAdapter.toJson(
    LsvBlob(
        version = v.version,
        totalWeightBps = v.totalWeightBps,
        outcomes = v.outcomes.map { it.toBlob() },
        unlocks = v.unlocks.map {
            LsvUnlockBlob(
                recipientId = it.recipientId,
                unlockedAt = it.unlockedAtEpochSeconds,
                selectedOutcome = it.selectedOutcome?.toBlob(),
            )
        },
    ),
)

/** #15 — parse the lottery sender-view back from its Room JSON blob; null on blank/unparseable. */
internal fun lotterySenderViewFromJson(json: String?): LotterySenderView? {
    if (json.isNullOrBlank()) return null
    val blob = runCatching { lsvAdapter.fromJson(json) }.getOrNull() ?: return null
    return LotterySenderView(
        version = blob.version.takeIf { it.isNotBlank() } ?: "v1",
        totalWeightBps = blob.totalWeightBps,
        outcomes = blob.outcomes.map { it.toDomain() },
        unlocks = blob.unlocks.map {
            LotterySenderUnlock(
                recipientId = it.recipientId,
                unlockedAtEpochSeconds = it.unlockedAt,
                selectedOutcome = it.selectedOutcome?.toDomain(),
            )
        },
    )
}

/** C6 — parse the gallery records back into [MessageMedia.GalleryImage]s; tolerates null/blank. */
internal fun galleryFromJson(json: String?): List<MessageMedia.GalleryImage> {
    if (json.isNullOrBlank()) return emptyList()
    return json.split(GALLERY_RECORD_SEP).mapNotNull { line ->
        if (line.isBlank()) return@mapNotNull null
        val parts = line.split("|")
        val url = parts.getOrNull(0)?.takeIf { it.isNotBlank() }
        MessageMedia.GalleryImage(
            url = url,
            width = parts.getOrNull(1)?.toIntOrNull(),
            height = parts.getOrNull(2)?.toIntOrNull(),
            // #8/#12 — restore the per-item media kind + poster (3-field legacy records -> image).
            isVideo = parts.getOrNull(3) == "1",
            posterUrl = parts.getOrNull(4)?.takeIf { it.isNotBlank() },
        )
    }
}

/** Parses a JSON number[] string back into a waveform; tolerates null/blank/garbage -> empty list. */
internal fun waveformFromJson(json: String?): List<Float> {
    if (json.isNullOrBlank()) return emptyList()
    return json.trim().removePrefix("[").removeSuffix("]")
        .split(',')
        .mapNotNull { it.trim().toFloatOrNull() }
}

internal fun MessageEntity.toDomain(): Message = Message(
    id = messageId,
    clientId = clientId ?: messageId,
    conversationId = conversationId,
    senderId = senderId,
    text = text,
    replyToMessageId = replyToMessageId,
    deliveredToCount = deliveredToCount,
    readByCount = readByCount,
    expiresAtEpochSeconds = expiresAtEpochSeconds,
    expired = serverExpired,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = SendStatus.SENT,
    kind = kind,
    reactions = reactionsFromJson(reactionsJson),
    isPinned = isPinned,
    lifecycle = runCatching { MessageLifecycle.valueOf(lifecycle) }.getOrDefault(MessageLifecycle.ACTIVE),
    editedAtEpochSeconds = editedAtEpochSeconds,
    isHiddenLocal = isHidden,
    // RG22 — keep the encrypted flag set when an envelope is present (post-unlock the server returns
    // the envelope; the flag must not regress to a plain/blank bubble).
    isEncrypted = isEncrypted || encSaltB64 != null,
    encryption = encSaltB64?.let { salt ->
        com.testlogon.android.data.messaging.MessageEncryption(
            version = encVersion ?: 1,
            alg = encAlg ?: "AES-256-GCM",
            kdf = encKdf ?: "PBKDF2-SHA256",
            iterations = encIterations ?: 100000,
            saltB64 = salt,
            ivB64 = encIvB64.orEmpty(),
            ciphertextB64 = encCiphertextB64,
        )
    },
    viewOnce = viewOnce,
    consumed = consumed,
    consumptionPolicy = consumptionPolicy,
    // R2 — restore the lock price/currency for the own "Locked $X" badge (set for any locked message,
    // including the sender's own locked image which renders as a plain Image, not a Paid bubble).
    lockPriceCents = lockPriceCents,
    lockCurrency = lockCurrency ?: "USD",
    media = when (kind) {
        "image" -> MessageMedia.Image(url = imageUrl, width = imageWidth, height = imageHeight)
        "gallery" -> MessageMedia.Gallery(images = galleryFromJson(galleryImagesJson))
        "video_share" -> MessageMedia.VideoShare(
            videoId = videoId.orEmpty(),
            title = videoTitle,
            thumbnailUrl = videoThumbnailUrl,
            durationSeconds = videoDurationSeconds,
            // playback_token is not persisted; a play attempt re-fetches the message for a fresh one.
            hlsManifestUrl = videoHlsManifestUrl,
            playbackToken = null,
            drmEnabled = videoDrmEnabled,
        )
        "voice_message" -> MessageMedia.Voice(
            audioUrl = voiceAudioUrl,
            durationSeconds = voiceDurationSeconds ?: 0.0,
            waveform = waveformFromJson(voiceWaveformJson),
            consumptionPolicy = consumptionPolicy,
        )
        "voicemail" -> MessageMedia.Voicemail(
            mediaUrl = voicemailMediaUrl,
            isVideo = voicemailIsVideo,
            durationSeconds = voiceDurationSeconds ?: 0.0,
            waveform = waveformFromJson(voiceWaveformJson),
            callId = voicemailCallId.orEmpty(),
            callState = voicemailCallState,
        )
        "gif" -> MessageMedia.Gif(
            url = gifUrl.orEmpty(),
            altText = gifAltText,
            width = gifWidth,
            height = gifHeight,
        )
        "sticker" -> MessageMedia.Sticker(
            url = stickerUrl.orEmpty(),
            altText = stickerAltText,
            stickerId = stickerId,
            collectionId = stickerCollectionId,
        )
        "poll" -> arbitraryPollFromJson(pollJson)?.let { MessageMedia.Poll(it) } ?: MessageMedia.None
        "meeting_poll" -> MessageMedia.MeetingPoll(
            pollId = pollId.orEmpty(),
            title = pollTitle.orEmpty(),
            creatorId = pollCreatorId.orEmpty(),
            status = pollStatus ?: "open",
            confirmedSlotId = pollConfirmedSlotId,
        )
        "find_datetime" -> MessageMedia.FindDateTime(
            pollId = pollId.orEmpty(),
            title = pollTitle.orEmpty(),
            creatorId = pollCreatorId.orEmpty(),
            status = pollStatus ?: "open",
            fromDate = fadtFromDate,
            toDate = fadtToDate,
            startHour = fadtStartHour,
            endHour = fadtEndHour,
            slotDurationMinutes = fadtSlotDurationMinutes,
        )
        // #6 (B-COUNTDOWN3) — a persisted countdown is restored as the transient Message.countdown
        // attribute (below), not as a media kind, so it renders via the shared overlay path.
        "calendar_event" -> MessageMedia.CalendarEvent(
            eventId = calEventId.orEmpty(),
            calendarId = calEventCalendarId.orEmpty(),
            name = calEventName.orEmpty(),
            startUtc = calEventStartUtc,
            endUtc = calEventEndUtc,
            allDay = calEventAllDay,
            allDayDate = calEventAllDayDate,
            timezone = calEventTimezone,
            description = calEventDescription,
            owner = calEventOwner.orEmpty(),
        )
        "calendar_share" -> MessageMedia.CalendarShare(
            calendarId = calShareCalendarId.orEmpty(),
            name = calShareName.orEmpty(),
            owner = calShareOwner.orEmpty(),
            permission = calSharePermission.toSharePermission(),
            bookingPublicUrl = calShareBookingUrl,
        )
        // MV2 — an uploaded video clip persists its playable url in fileUrl; render as a video bubble.
        "video" -> MessageMedia.VideoClip(
            playbackUrl = fileUrl,
            durationSeconds = videoDurationSeconds,
        )
        "file", "file_share", "audio" -> MessageMedia.File(
            fileName = fileName ?: "file",
            sizeBytes = fileSizeBytes,
            mimeType = fileMimeType,
            consumptionPolicy = consumptionPolicy,
            isShare = fileIsShare,
        )
        else -> if (monetizationType != null) {
            // AND-139 — a paid message (any kind) persisted with monetization columns. Lottery and
            // fixed-price share the Paid variant; gated body was never persisted while locked.
            MessageMedia.Paid(
                MessageMonetization(
                    type = runCatching { UnlockType.valueOf(monetizationType!!) }.getOrDefault(UnlockType.FIXED),
                    unlocked = monetizationUnlocked,
                    priceMinorUnits = lockPriceCents,
                    currency = lockCurrency ?: "USD",
                    teaser = lockTeaser,
                    revealedText = revealedText,
                    revealedMediaUrl = revealedMediaUrl,
                    revealedMediaIsVideo = revealedMediaIsVideo,
                    // #24 - restore the full revealed media list; fall back to the singular url.
                    revealedMedia = revealedMediaFromJson(revealedMediaJson).ifEmpty {
                        listOfNotNull(
                            revealedMediaUrl?.takeIf { it.isNotBlank() }
                                ?.let { RevealedMediaItem(url = it, isVideo = revealedMediaIsVideo) },
                        )
                    },
                    // #15 - restore the sender's lottery sender-view (config + per-recipient results).
                    lotterySenderView = lotterySenderViewFromJson(lotterySenderViewJson),
                ),
            )
        } else {
            MessageMedia.None
        }
    },
    // #6 (B-COUNTDOWN3) — restore a persisted countdown as the transient attribute. The reveal media
    // is not persisted; once the row refetches from the wire the full reveal repopulates.
    countdown = countdownTargetEpochSeconds?.let { tgt ->
        com.testlogon.android.data.messaging.MessageCountdown(
            targetEpochSeconds = tgt,
            title = countdownTitle?.takeIf { it.isNotBlank() },
            // #6 (B-COUNTDOWN3) — restore the reveal blob persisted in the countdownEventId column.
            reveal = countdownRevealFromBlob(countdownEventId),
        )
    },
)

internal fun OutboxMessageEntity.toDomain(): Message = Message(
    id = null,
    clientId = clientId,
    conversationId = conversationId,
    senderId = "", // self; the ViewModel knows the current user_sub for alignment
    text = text,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = runCatching { SendStatus.valueOf(status) }.getOrDefault(SendStatus.SENDING),
    kind = kind,
    media = when (kind) {
        "image" -> MessageMedia.Image(
            url = null,
            localUri = imageLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
        "file" -> MessageMedia.File(
            fileName = fileName ?: "file",
            sizeBytes = fileSizeBytes,
            mimeType = fileMimeType,
            localUri = attachmentLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
        // MV2 — optimistic short-video row: poster from the local source uri while the clip uploads.
        "video" -> MessageMedia.VideoClip(
            playbackUrl = null,
            localUri = attachmentLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
        "voice_message" -> MessageMedia.Voice(
            audioUrl = null,
            durationSeconds = voiceDurationSeconds ?: 0.0,
            waveform = waveformFromJson(voiceWaveformJson),
            localUri = attachmentLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
        "voicemail" -> MessageMedia.Voicemail(
            mediaUrl = null,
            isVideo = false,
            durationSeconds = voiceDurationSeconds ?: 0.0,
            waveform = waveformFromJson(voiceWaveformJson),
            callId = "",
            callState = null,
            localUri = attachmentLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
        // #6 (B-COUNTDOWN3) — an optimistic countdown is carried by the transient attribute (below);
        // the base text holds the message body (may be blank for a title-only countdown).
        else -> MessageMedia.None
    },
    // #6 — optimistic countdown attribute: title persisted in `text`, target epoch in the reused
    // voiceDurationSeconds column. Title-only (no body) renders the headline in the overlay.
    countdown = if (kind == "countdown") {
        com.testlogon.android.data.messaging.MessageCountdown(
            targetEpochSeconds = (voiceDurationSeconds ?: 0.0).toLong(),
            title = text.takeIf { it.isNotBlank() },
        )
    } else {
        null
    },
)
