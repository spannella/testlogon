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
    suspend fun sendOutbox(conversationId: String, clientId: String, text: String): ApiResult<Message>

    /** Apply an inbound realtime new-message event to the caches. */
    suspend fun applyInboundMessage(event: MessagingEvent.NewMessage)

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

    /**
     * AND-127 — find-or-create a 1:1 DM with [peerUserId], resolving to a [Conversation]. Guards
     * against self-DM locally (no network). The returned conversation is upserted into the cache so
     * the list reflects a brand-new DM immediately.
     */
    suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation>

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
    ): ApiResult<Message>

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
}

/** AND-137 — a countdown creation draft (validated by the ViewModel before send). */
data class CountdownDraft(
    val title: String,
    val targetEpochSeconds: Long,
    val associatedEventType: AssociatedEventType = AssociatedEventType.CUSTOM,
    val associatedEventId: String? = null,
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
    private val uploader: AttachmentUploader,
    private val imageProcessor: MessageImageProcessor,
    private val uriMetadata: com.testlogon.android.data.upload.UriMetadata,
    private val storageClient: com.testlogon.android.data.upload.StorageUploadClient,
    private val attachmentDownloader: AttachmentDownloader,
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
    ): ApiResult<Message> = withContext(io) {
        when (val result = apiCall { api.sendMessage(conversationId, SendTextMessageReq(text)) }) {
            is ApiResult.Success -> {
                // Reconcile: persist the server message (stamped with our clientId for cleanup),
                // then drop the optimistic outbox row.
                val message = result.data.toDomain(clientId = clientId)
                messageDao.upsert(message.toEntity(clientId = clientId))
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
        messageDao.upsert(
            MessageEntity(
                messageId = event.messageId,
                conversationId = event.conversationId,
                senderId = event.senderId,
                text = event.text.orEmpty(),
                createdAtEpochSeconds = event.createdAtEpochSeconds,
                clientId = null,
                kind = event.kind,
                // Media fields (urls) arrive on the next list refresh; the SSE frame carries no url.
            ),
        )
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
    ): ApiResult<Message> = withContext(io) {
        try {
            // 1. Process (compress, EXIF-strip) the picked uri.
            val processed = imageProcessor.process(Uri.parse(localUri))
                ?: return@withContext failImage(clientId, "Couldn't process this image.")
            val fileName = processed.uri.lastPathSegment ?: "image.jpg"

            // 2. Presign + PUT via the AND-129 uploader (image flow has NO confirm step). The
            //    uploader returns an AttachmentRef carrying the presign bucket/key we send next.
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
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    messageDao.upsert(message.toEntity(clientId = clientId))
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
                        CreateFileMessageReq(path = serverPath, kind = "file"),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    messageDao.upsert(message.toEntity(clientId = clientId))
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
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> {
                    val message = created.data.toDomain(clientId = clientId)
                    messageDao.upsert(message.toEntity(clientId = clientId))
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
                    messageDao.upsert(message.toEntity(clientId = clientId))
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
                messageDao.upsert(message.toEntity(clientId = clientId))
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
                messageDao.upsert(message.toEntity(clientId = clientId))
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
                    ),
                )
            }
        ) {
            is ApiResult.Success -> {
                val message = r.data.toDomain(clientId = clientId)
                messageDao.upsert(message.toEntity(clientId = clientId))
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
                val revealed = r.data.selectedOutcome?.textContent
                // Reconcile the cached row to unlocked + revealed text (server-authoritative).
                val existing = messageDao.findById(messageId)?.toDomain()
                if (existing != null) {
                    val paid = (existing.media as? MessageMedia.Paid)?.monetization
                    val updated = existing.copy(
                        media = MessageMedia.Paid(
                            (paid ?: MessageMonetization(UnlockType.LOTTERY, false, null, "USD", null)).copy(
                                unlocked = true,
                                revealedText = revealed,
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
                            revealedText = r.data.selectedOutcome?.takeIf { unlocked }?.textContent,
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
    }

    companion object {
        /** Sentinel status for a locally-rejected self-DM attempt (no HTTP response involved). */
        const val STATUS_SELF_DM = -100

        /** AND-133 — AAC-LC / M4A container MIME (matches the recorder + the presign content-type pattern). */
        const val VOICE_CONTENT_TYPE = "audio/mp4"
    }
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
    val video = media as? MessageMedia.VideoShare
    val file = media as? MessageMedia.File
    val voice = media as? MessageMedia.Voice
    val voicemail = media as? MessageMedia.Voicemail
    val gif = media as? MessageMedia.Gif
    val sticker = media as? MessageMedia.Sticker
    val poll = media as? MessageMedia.MeetingPoll
    val countdown = media as? MessageMedia.Countdown
    val calEvent = media as? MessageMedia.CalendarEvent
    val calShare = media as? MessageMedia.CalendarShare
    val paid = (media as? MessageMedia.Paid)?.monetization
    return MessageEntity(
        messageId = id ?: this.clientId,
        conversationId = conversationId,
        senderId = senderId,
        text = text,
        createdAtEpochSeconds = createdAtEpochSeconds,
        clientId = clientId,
        kind = kind,
        imageUrl = image?.url,
        imageWidth = image?.width,
        imageHeight = image?.height,
        videoId = video?.videoId,
        videoTitle = video?.title,
        videoThumbnailUrl = video?.thumbnailUrl,
        videoDurationSeconds = video?.durationSeconds,
        videoHlsManifestUrl = video?.hlsManifestUrl,
        videoDrmEnabled = video?.drmEnabled ?: false,
        fileName = file?.fileName,
        fileSizeBytes = file?.sizeBytes,
        fileMimeType = file?.mimeType,
        fileIsShare = file?.isShare ?: false,
        consumptionPolicy = file?.consumptionPolicy ?: "none",
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
        pollId = poll?.pollId,
        pollTitle = poll?.title,
        pollCreatorId = poll?.creatorId,
        pollStatus = poll?.status,
        pollConfirmedSlotId = poll?.confirmedSlotId,
        countdownTitle = countdown?.title,
        countdownTargetEpochSeconds = countdown?.targetEpochSeconds,
        countdownEventType = countdown?.associatedEventType?.wire(),
        countdownEventId = countdown?.associatedEventId,
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
        lockPriceCents = paid?.priceMinorUnits,
        lockCurrency = paid?.currency,
        lockTeaser = paid?.teaser,
        revealedText = paid?.revealedText,
    )
}

/** Serializes a normalized waveform (0..1) to a compact JSON number[] string for the Room TEXT column. */
internal fun waveformToJson(values: List<Float>): String =
    values.joinToString(prefix = "[", postfix = "]") { String.format(java.util.Locale.ROOT, "%.3f", it) }

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
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = SendStatus.SENT,
    kind = kind,
    media = when (kind) {
        "image" -> MessageMedia.Image(url = imageUrl, width = imageWidth, height = imageHeight)
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
        "meeting_poll" -> MessageMedia.MeetingPoll(
            pollId = pollId.orEmpty(),
            title = pollTitle.orEmpty(),
            creatorId = pollCreatorId.orEmpty(),
            status = pollStatus ?: "open",
            confirmedSlotId = pollConfirmedSlotId,
        )
        "countdown" -> MessageMedia.Countdown(
            title = countdownTitle.orEmpty(),
            targetEpochSeconds = countdownTargetEpochSeconds ?: 0L,
            associatedEventType = countdownEventType.toAssociatedEventType(),
            associatedEventId = countdownEventId,
        )
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
        "file", "file_share", "audio", "video" -> MessageMedia.File(
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
                ),
            )
        } else {
            MessageMedia.None
        }
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
        "countdown" -> MessageMedia.Countdown(
            // Optimistic countdown: title in `text`, target epoch in voiceDurationSeconds (Double).
            title = text,
            targetEpochSeconds = (voiceDurationSeconds ?: 0.0).toLong(),
            associatedEventType = AssociatedEventType.CUSTOM,
        )
        else -> MessageMedia.None
    },
)
