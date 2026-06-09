package com.testlogon.android.data.messaging

import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.MessageDao
import com.testlogon.android.core.data.messaging.MessageEntity
import com.testlogon.android.core.data.messaging.OutboxDao
import com.testlogon.android.core.data.messaging.OutboxMessageEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.realtime.MessagingEvent
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

    /** Best-effort mark-read (POST); failures are swallowed (non-critical). */
    suspend fun markRead(conversationId: String, lastReadMessageId: String?)
}

@Singleton
class MessagingRepositoryImpl @Inject constructor(
    private val api: MessagingApi,
    private val conversationDao: ConversationDao,
    private val messageDao: MessageDao,
    private val outboxDao: OutboxDao,
    private val errorParser: ApiErrorParser,
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
            ),
        )
    }

    override suspend fun markRead(conversationId: String, lastReadMessageId: String?) {
        withContext(io) {
            runCatching { api.markRead(conversationId, MarkReadReq(lastReadMessageId = lastReadMessageId)) }
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

internal fun Message.toEntity(clientId: String?): MessageEntity = MessageEntity(
    messageId = id ?: this.clientId,
    conversationId = conversationId,
    senderId = senderId,
    text = text,
    createdAtEpochSeconds = createdAtEpochSeconds,
    clientId = clientId,
)

internal fun MessageEntity.toDomain(): Message = Message(
    id = messageId,
    clientId = clientId ?: messageId,
    conversationId = conversationId,
    senderId = senderId,
    text = text,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = SendStatus.SENT,
)

internal fun OutboxMessageEntity.toDomain(): Message = Message(
    id = null,
    clientId = clientId,
    conversationId = conversationId,
    senderId = "", // self; the ViewModel knows the current user_sub for alignment
    text = text,
    createdAtEpochSeconds = createdAtEpochSeconds,
    sendStatus = runCatching { SendStatus.valueOf(status) }.getOrDefault(SendStatus.SENDING),
)
