package com.testlogon.android.data.messaging

import com.testlogon.android.core.data.messaging.ConversationDao
import com.testlogon.android.core.data.messaging.ConversationEntity
import com.testlogon.android.core.data.messaging.MessageDao
import com.testlogon.android.core.data.messaging.MessageEntity
import com.testlogon.android.core.data.messaging.OutboxDao
import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.messaging.OutboxMessageEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-125 / AND-127 / AND-128 — repository tests for read-state (mark-read, aggregate unread) and
 * DM find-or-create, using in-memory DAO + API fakes. Pure JVM (no Room runtime).
 */
class MessagingRepositoryTest {

    // ---- in-memory DAO fakes (honour the real query contracts) ----

    private class FakeConversationDao : ConversationDao {
        val rows = MutableStateFlow<List<ConversationEntity>>(emptyList())
        override fun observeAll(): Flow<List<ConversationEntity>> = rows
        override suspend fun upsertAll(items: List<ConversationEntity>) {
            val byId = rows.value.associateBy { it.conversationId }.toMutableMap()
            items.forEach { byId[it.conversationId] = it }
            rows.value = byId.values.toList()
        }
        override suspend fun findById(id: String): ConversationEntity? =
            rows.value.firstOrNull { it.conversationId == id }
        override suspend fun clearUnread(id: String) {
            rows.value = rows.value.map { if (it.conversationId == id) it.copy(unreadCount = 0) else it }
        }
        override fun observeUnreadConversationCount(): Flow<Int> =
            rows.map { list -> list.count { it.unreadCount > 0 } }
        override suspend fun clear() { rows.value = emptyList() }
    }

    private class FakeMessageDao : MessageDao {
        val rows = MutableStateFlow<List<MessageEntity>>(emptyList())
        override fun observeForConversation(conversationId: String): Flow<List<MessageEntity>> =
            rows.map { it.filter { m -> m.conversationId == conversationId }.sortedBy { m -> m.createdAtEpochSeconds } }
        override suspend fun upsert(message: MessageEntity) {
            rows.value = rows.value.filterNot { it.messageId == message.messageId } + message
        }
        override suspend fun upsertAll(messages: List<MessageEntity>) { messages.forEach { upsert(it) } }
        override suspend fun findById(messageId: String): MessageEntity? =
            rows.value.firstOrNull { it.messageId == messageId }
    }

    private class FakeOutboxDao : OutboxDao {
        val rows = MutableStateFlow<List<OutboxMessageEntity>>(emptyList())
        override fun observe(conversationId: String): Flow<List<OutboxMessageEntity>> =
            rows.map { it.filter { o -> o.conversationId == conversationId } }
        override suspend fun upsert(entry: OutboxMessageEntity) {
            rows.value = rows.value.filterNot { it.clientId == entry.clientId } + entry
        }
        override suspend fun delete(clientId: String) {
            rows.value = rows.value.filterNot { it.clientId == clientId }
        }
        override suspend fun findById(clientId: String): OutboxMessageEntity? =
            rows.value.firstOrNull { it.clientId == clientId }
    }

    // ---- API fake ----

    private class FakeApi : MessagingApi {
        var markReadCalls = mutableListOf<Triple<String, MarkReadReq, Unit>>()
        var markReadThrows: Throwable? = null
        var findOrCreateResult: ConversationDto? = null
        var findOrCreateThrows: Throwable? = null
        var findOrCreateCalls = mutableListOf<FindOrCreateDmReq>()

        override suspend fun config() = error("unused")
        override suspend fun listConversations(): List<ConversationDto> = error("unused")
        override suspend fun getConversation(id: String): ConversationDto = error("unused")
        override suspend fun listMessages(id: String, limit: Int?, before: String?): List<MessageDto> = error("unused")
        override suspend fun sendMessage(id: String, body: SendTextMessageReq): MessageDto = error("unused")
        override suspend fun markRead(id: String, body: MarkReadReq) {
            markReadThrows?.let { throw it }
            markReadCalls += Triple(id, body, Unit)
        }
        override suspend fun findOrCreateDm(body: FindOrCreateDmReq): ConversationDto {
            findOrCreateCalls += body
            findOrCreateThrows?.let { throw it }
            return requireNotNull(findOrCreateResult)
        }
    }

    private val conversationDao = FakeConversationDao()
    private val messageDao = FakeMessageDao()
    private val outboxDao = FakeOutboxDao()
    private val api = FakeApi()
    private val auth = FakeAuthStateStore()

    private fun repo() = MessagingRepositoryImpl(
        api = api,
        conversationDao = conversationDao,
        messageDao = messageDao,
        outboxDao = outboxDao,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
        authStateStore = auth,
    )

    private fun convEntity(id: String, unread: Int) = ConversationEntity(
        conversationId = id, title = id, iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = 1, unreadCount = unread,
    )

    // ---- AND-125: mark-read ----

    @Test
    fun markRead_clearsUnreadOptimistically_andPostsLastReadAt() = runTest {
        conversationDao.rows.value = listOf(convEntity("c1", unread = 3))
        val result = repo().markRead("c1", lastReadMessageId = "m9", lastReadAtEpochSeconds = 1749126660L)

        assertTrue(result is ApiResult.Success)
        assertEquals(0, conversationDao.findById("c1")?.unreadCount) // optimistic clear (FR-3)
        assertEquals(1, api.markReadCalls.size)
        val (cid, body, _) = api.markReadCalls.single()
        assertEquals("c1", cid)
        assertEquals(1749126660L, body.lastReadAt)
        assertEquals("m9", body.lastReadMessageId)
    }

    @Test
    fun markRead_retainsOptimisticClear_onNetworkFailure() = runTest {
        conversationDao.rows.value = listOf(convEntity("c1", unread = 2))
        api.markReadThrows = IOException("offline")
        val result = repo().markRead("c1", lastReadAtEpochSeconds = 1L)

        assertTrue(result is ApiResult.NetworkError)
        // FR-4: optimistic clear is retained even though the POST failed.
        assertEquals(0, conversationDao.findById("c1")?.unreadCount)
    }

    @Test
    fun observeTotalUnread_recomputesAfterClear() = runTest {
        conversationDao.rows.value = listOf(convEntity("c1", 1), convEntity("c2", 1), convEntity("c3", 0))
        val r = repo()
        assertEquals(2, r.observeTotalUnread().first())
        r.markRead("c1", lastReadAtEpochSeconds = 1L)
        assertEquals(1, r.observeTotalUnread().first()) // FR-5 reactive recompute
    }

    // ---- AND-127: find-or-create DM ----

    @Test
    fun findOrCreateDm_selfDm_shortCircuits_noNetwork() = runTest {
        auth.setAuthenticated("usr_self")
        val result = repo().findOrCreateDm("usr_self")

        assertTrue(result is ApiResult.Failure)
        assertEquals(MessagingRepositoryImpl.STATUS_SELF_DM, (result as ApiResult.Failure).error.status)
        assertTrue(api.findOrCreateCalls.isEmpty()) // FR-5 no request issued
    }

    @Test
    fun findOrCreateDm_success_mapsConversation_andUpsertsCache() = runTest {
        auth.setAuthenticated("usr_self")
        api.findOrCreateResult = ConversationDto(
            conversationId = "conv_new",
            type = "dm",
            createdAt = 100,
            participants = listOf(
                ParticipantDto(userId = "usr_self", displayName = "You"),
                ParticipantDto(userId = "usr_peer", displayName = "Ada"),
            ),
        )
        val result = repo().findOrCreateDm("usr_peer")

        assertTrue(result is ApiResult.Success)
        assertEquals("conv_new", (result as ApiResult.Success).data.id)
        assertEquals(FindOrCreateDmReq("usr_peer"), api.findOrCreateCalls.single())
        // Side effect: new DM upserted into the cache for the list.
        assertEquals("conv_new", conversationDao.findById("conv_new")?.conversationId)
    }

    @Test
    fun findOrCreateDm_networkError_propagates_noUpsert() = runTest {
        auth.setAuthenticated("usr_self")
        api.findOrCreateThrows = IOException("timeout")
        val result = repo().findOrCreateDm("usr_peer")

        assertTrue(result is ApiResult.NetworkError)
        assertNull(conversationDao.findById("conv_new"))
    }
}
