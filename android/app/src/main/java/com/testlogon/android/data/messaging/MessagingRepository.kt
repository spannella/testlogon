package com.testlogon.android.data.messaging

import android.net.Uri
import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
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
}

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
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
    private val uploader: AttachmentUploader,
    private val imageProcessor: MessageImageProcessor,
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
    )
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
        else -> MessageMedia.None
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
    media = if (kind == "image") {
        MessageMedia.Image(
            url = null,
            localUri = imageLocalUri,
            uploadProgress = uploadPercent?.let { it / 100f },
        )
    } else {
        MessageMedia.None
    },
)
