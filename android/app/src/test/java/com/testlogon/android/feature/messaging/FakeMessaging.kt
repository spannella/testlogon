package com.testlogon.android.feature.messaging

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.ShareableVideo
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import java.io.IOException

/** In-memory [MessagingRepository] fake for ViewModel unit tests. */
class FakeMessagingRepository : MessagingRepository {

    private val conversations = MutableStateFlow<List<Conversation>>(emptyList())
    private val thread = MutableStateFlow<List<Message>>(emptyList())

    /** Result the next refreshConversations() returns; defaults to echoing the current cache. */
    var refreshResult: ApiResult<List<Conversation>>? = null

    /** Result the next loadHistory() returns. */
    var historyResult: ApiResult<List<Message>> = ApiResult.Success(emptyList())

    /** Result the next sendOutbox() returns. Drives reconcile vs FAILED. */
    var sendResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded markRead calls: (conversationId, lastReadMessageId, lastReadAtEpochSeconds). */
    var markReadCalls = mutableListOf<Triple<String, String?, Long?>>()
    var inboundApplied = mutableListOf<MessagingEvent.NewMessage>()

    /** Result the next markRead() returns; defaults to success. */
    var markReadResult: ApiResult<Unit> = ApiResult.Success(Unit)

    private val totalUnread = MutableStateFlow(0)
    fun emitTotalUnread(value: Int) { totalUnread.value = value }

    /** Recorded findOrCreateDm calls (peerUserId). */
    var findOrCreateDmCalls = mutableListOf<String>()

    /** Result the next findOrCreateDm() returns. */
    var findOrCreateDmResult: ApiResult<Conversation> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    fun emitConversations(list: List<Conversation>) { conversations.value = list }
    fun emitThread(list: List<Message>) { thread.value = list }

    override fun observeConversations(): Flow<List<Conversation>> = conversations.asStateFlow()

    override suspend fun refreshConversations(): ApiResult<List<Conversation>> =
        refreshResult ?: ApiResult.Success(conversations.value)

    override fun observeThread(conversationId: String): Flow<List<Message>> = thread.asStateFlow()

    override suspend fun loadHistory(
        conversationId: String,
        before: String?,
        limit: Int,
    ): ApiResult<List<Message>> = historyResult

    override suspend fun enqueueOptimistic(
        conversationId: String,
        clientId: String,
        text: String,
        nowSeconds: Long,
    ) {
        // Upsert by clientId (mirrors the Room PK upsert): a retry with the same clientId
        // replaces the existing row (resets it to SENDING) rather than appending a duplicate.
        val row = Message(
            id = null,
            clientId = clientId,
            conversationId = conversationId,
            senderId = "",
            text = text,
            createdAtEpochSeconds = nowSeconds,
            sendStatus = SendStatus.SENDING,
        )
        thread.value =
            if (thread.value.any { it.clientId == clientId }) {
                thread.value.map { if (it.clientId == clientId) row else it }
            } else {
                thread.value + row
            }
    }

    override suspend fun sendOutbox(
        conversationId: String,
        clientId: String,
        text: String,
    ): ApiResult<Message> {
        return when (val result = sendResult) {
            is ApiResult.Success -> {
                // Reconcile: replace the optimistic row with a SENT server row.
                thread.value = thread.value.map {
                    if (it.clientId == clientId) result.data.copy(clientId = clientId) else it
                }
                result
            }
            else -> {
                thread.value = thread.value.map {
                    if (it.clientId == clientId) it.copy(sendStatus = SendStatus.FAILED) else it
                }
                result
            }
        }
    }

    override suspend fun applyInboundMessage(event: MessagingEvent.NewMessage) {
        inboundApplied += event
        thread.value = thread.value + Message(
            id = event.messageId,
            clientId = event.messageId,
            conversationId = event.conversationId,
            senderId = event.senderId,
            text = event.text.orEmpty(),
            createdAtEpochSeconds = event.createdAtEpochSeconds,
            sendStatus = SendStatus.SENT,
        )
    }

    override suspend fun markRead(
        conversationId: String,
        lastReadMessageId: String?,
        lastReadAtEpochSeconds: Long?,
    ): ApiResult<Unit> {
        markReadCalls += Triple(conversationId, lastReadMessageId, lastReadAtEpochSeconds)
        return markReadResult
    }

    override fun observeTotalUnread(): Flow<Int> = totalUnread.asStateFlow()

    override suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation> {
        findOrCreateDmCalls += peerUserId
        return findOrCreateDmResult
    }

    // ---- AND-130 / AND-131 ----

    /** Recorded image sends: (conversationId, clientId, localUri). */
    var imageSendCalls = mutableListOf<Triple<String, String, String>>()

    /** Result the next sendImageOutbox() returns. */
    var imageSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded video-share sends: (conversationId, videoId, caption). */
    var videoShareCalls = mutableListOf<Triple<String, String, String?>>()
    var videoShareResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    var shareableVideosResult: ApiResult<List<ShareableVideo>> = ApiResult.Success(emptyList())

    override suspend fun enqueueOptimisticImage(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    ) {
        val row = Message(
            id = null,
            clientId = clientId,
            conversationId = conversationId,
            senderId = "",
            text = "",
            createdAtEpochSeconds = nowSeconds,
            sendStatus = SendStatus.SENDING,
            kind = "image",
            media = MessageMedia.Image(url = null, localUri = localUri, uploadProgress = 0f),
        )
        thread.value =
            if (thread.value.any { it.clientId == clientId }) {
                thread.value.map { if (it.clientId == clientId) row else it }
            } else {
                thread.value + row
            }
    }

    override suspend fun sendImageOutbox(
        conversationId: String,
        clientId: String,
        localUri: String,
    ): ApiResult<Message> {
        imageSendCalls += Triple(conversationId, clientId, localUri)
        return when (val result = imageSendResult) {
            is ApiResult.Success -> {
                thread.value = thread.value.map {
                    if (it.clientId == clientId) result.data.copy(clientId = clientId) else it
                }
                result
            }
            else -> {
                thread.value = thread.value.map {
                    if (it.clientId == clientId) it.copy(sendStatus = SendStatus.FAILED) else it
                }
                result
            }
        }
    }

    override suspend fun listShareableVideos(): ApiResult<List<ShareableVideo>> = shareableVideosResult

    override suspend fun sendVideoShare(
        conversationId: String,
        videoId: String,
        caption: String?,
    ): ApiResult<Message> {
        videoShareCalls += Triple(conversationId, videoId, caption)
        return videoShareResult
    }

    companion object {
        fun failure(status: Int = 500, message: String = "boom"): ApiResult<Nothing> =
            ApiResult.Failure(ApiError(status = status, message = message))
    }
}

/**
 * Manually-driven [MessagingEventStream] fake. By default the stream is silent (the realtime
 * collector just suspends). Tests push events via [send]; the flow stays open for further events.
 */
class FakeMessagingEventStream : MessagingEventStream {
    private val channel = kotlinx.coroutines.channels.Channel<MessagingStreamEvent>(
        capacity = kotlinx.coroutines.channels.Channel.UNLIMITED,
    )

    override fun events(): Flow<MessagingStreamEvent> = channel.receiveAsFlow()

    suspend fun send(event: MessagingStreamEvent) = channel.send(event)
}
