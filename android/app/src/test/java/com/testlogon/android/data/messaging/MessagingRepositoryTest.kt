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
        override suspend fun updateUploadPercent(clientId: String, percent: Int) {
            rows.value = rows.value.map {
                if (it.clientId == clientId) it.copy(uploadPercent = percent) else it
            }
        }
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

        // AND-130 / AND-131 — image + video-share endpoints.
        var presignImageResult: ImagePresignResp? = null
        var createImageCalls = mutableListOf<Pair<String, CreateImageMessageReq>>()
        var createImageResult: MessageDto? = null
        var createVideoShareCalls = mutableListOf<Pair<String, CreateVideoShareReq>>()
        var createVideoShareResult: MessageDto? = null
        var createVideoShareThrows: Throwable? = null
        var listVideosResult: VideoListRespDto? = null

        override suspend fun presignImage(id: String, body: ImagePresignReq): ImagePresignResp =
            requireNotNull(presignImageResult)
        override suspend fun createImageMessage(id: String, body: CreateImageMessageReq): MessageDto {
            createImageCalls += id to body
            return requireNotNull(createImageResult)
        }
        override suspend fun createVideoShareMessage(id: String, body: CreateVideoShareReq): MessageDto {
            createVideoShareCalls += id to body
            createVideoShareThrows?.let { throw it }
            return requireNotNull(createVideoShareResult)
        }
        override suspend fun listMyVideos(status: String?, limit: Int?, cursor: String?): VideoListRespDto =
            requireNotNull(listVideosResult)

        // AND-132 / AND-133 — file/file-share/grant/consume/download + voice presign/create.
        var createFileCalls = mutableListOf<Pair<String, CreateFileMessageReq>>()
        var createFileResult: MessageDto? = null
        var createFileShareCalls = mutableListOf<Pair<String, CreateFileShareReq>>()
        var createFileShareResult: MessageDto? = null
        var presignVoiceResult: PresignVoiceResp? = null
        var createVoiceCalls = mutableListOf<Pair<String, CreateVoiceReq>>()
        var createVoiceResult: MessageDto? = null

        override suspend fun createFileMessage(id: String, body: CreateFileMessageReq): MessageDto {
            createFileCalls += id to body
            return requireNotNull(createFileResult)
        }
        override suspend fun createFileShareMessage(id: String, body: CreateFileShareReq): MessageDto {
            createFileShareCalls += id to body
            return requireNotNull(createFileShareResult)
        }
        override suspend fun createAttachmentGrant(
            id: String,
            messageId: String,
            body: Map<String, String>,
        ): AttachmentGrantResp = error("unused")
        override suspend fun consumeAttachment(
            id: String,
            messageId: String,
            grantToken: String,
            body: ConsumeAttachmentReq,
        ): ConsumeAttachmentResp = error("unused")
        override suspend fun downloadAttachment(
            id: String,
            messageId: String,
            grantToken: String,
        ): okhttp3.ResponseBody = error("unused")
        override suspend fun presignVoice(id: String, body: PresignVoiceReq): PresignVoiceResp {
            return requireNotNull(presignVoiceResult)
        }
        override suspend fun createVoiceMessage(id: String, body: CreateVoiceReq): MessageDto {
            createVoiceCalls += id to body
            return requireNotNull(createVoiceResult)
        }
    }

    // ---- AND-130 fakes: uploader + image processor ----

    private class FakeUploader(
        var attachment: com.testlogon.android.data.upload.AttachmentRef? = null,
        var failure: com.testlogon.android.data.upload.UploadError? = null,
    ) : com.testlogon.android.data.upload.AttachmentUploader {
        var lastRequest: com.testlogon.android.data.upload.UploadRequest? = null
        override fun upload(
            request: com.testlogon.android.data.upload.UploadRequest,
        ): Flow<com.testlogon.android.data.upload.UploadProgress> {
            lastRequest = request
            return kotlinx.coroutines.flow.flow {
                emit(com.testlogon.android.data.upload.UploadProgress.Preparing)
                emit(com.testlogon.android.data.upload.UploadProgress.Uploading(50, 100))
                val fail = failure
                if (fail != null) {
                    emit(
                        com.testlogon.android.data.upload.UploadProgress.Failed(
                            fail, com.testlogon.android.data.upload.UploadPhase.PUT,
                        ),
                    )
                } else {
                    emit(
                        com.testlogon.android.data.upload.UploadProgress.Succeeded(
                            requireNotNull(attachment),
                        ),
                    )
                }
            }
        }
    }

    private class FakeImageProcessor(var result: ProcessedImage?) : MessageImageProcessor {
        override suspend fun process(source: android.net.Uri): ProcessedImage? = result
    }

    private val conversationDao = FakeConversationDao()
    private val messageDao = FakeMessageDao()
    private val outboxDao = FakeOutboxDao()
    private val api = FakeApi()
    private val auth = FakeAuthStateStore()

    private val uploader = FakeUploader()
    private val imageProcessor = FakeImageProcessor(result = null)

    // AND-132/133 — runtime collaborators not exercised by these (text/dm/file-share) tests; mocked
    // so the repo is constructible. shareFile/createVoice use only `api`, so no real impl is needed.
    private val uriMetadata =
        org.mockito.Mockito.mock(com.testlogon.android.data.upload.UriMetadata::class.java)
    private val storageClient =
        org.mockito.Mockito.mock(com.testlogon.android.data.upload.StorageUploadClient::class.java)
    private val attachmentDownloader =
        org.mockito.Mockito.mock(AttachmentDownloader::class.java)

    private fun repo() = MessagingRepositoryImpl(
        api = api,
        conversationDao = conversationDao,
        messageDao = messageDao,
        outboxDao = outboxDao,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
        authStateStore = auth,
        uploader = uploader,
        imageProcessor = imageProcessor,
        uriMetadata = uriMetadata,
        storageClient = storageClient,
        attachmentDownloader = attachmentDownloader,
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

    // ---- AND-131: video-share ----

    @Test
    fun listShareableVideos_mapsPublishedItems() = runTest {
        api.listVideosResult = VideoListRespDto(
            items = listOf(
                VideoListItemDto("vid_1", title = "Clip A", durationSeconds = 42, thumbnailUrl = "t1"),
                VideoListItemDto("vid_2", title = "Clip B"),
            ),
        )
        val result = repo().listShareableVideos()
        assertTrue(result is ApiResult.Success)
        val videos = (result as ApiResult.Success).data
        assertEquals(2, videos.size)
        assertEquals("vid_1", videos[0].videoId)
        assertEquals(42, videos[0].durationSeconds)
    }

    @Test
    fun sendVideoShare_postsVideoId_andCachesMessage() = runTest {
        api.createVideoShareResult = MessageDto(
            messageId = "msg_v1",
            conversationId = "c1",
            senderId = "usr_self",
            createdAt = 100,
            kind = "video_share",
            videoShare = VideoShareDto(
                videoId = "vid_1",
                title = "Clip A",
                thumbnailUrl = "thumb",
                durationSeconds = 42,
                hlsManifestUrl = "https://h/manifest.m3u8",
                playbackToken = "tok",
            ),
        )
        val result = repo().sendVideoShare("c1", videoId = "vid_1", caption = "look")

        assertTrue(result is ApiResult.Success)
        val (cid, body) = api.createVideoShareCalls.single()
        assertEquals("c1", cid)
        assertEquals("vid_1", body.videoId)
        assertEquals("look", body.text)
        val message = (result as ApiResult.Success).data
        assertEquals("video_share", message.kind)
        assertTrue(message.media is MessageMedia.VideoShare)
        assertEquals("msg_v1", messageDao.findById("msg_v1")?.messageId)
    }

    @Test
    fun sendVideoShare_networkError_propagates_noCache() = runTest {
        api.createVideoShareThrows = IOException("offline")
        val result = repo().sendVideoShare("c1", "vid_x", null)
        assertTrue(result is ApiResult.NetworkError)
        assertNull(messageDao.findById("msg_v1"))
    }

    // ---- AND-132: file share ----

    @Test
    fun shareFile_postsFilePathAndPermission_cachesFileShareMessage() = runTest {
        api.createFileShareResult = MessageDto(
            messageId = "msg_fs", conversationId = "c1", senderId = "u1", createdAt = 100,
            kind = "file_share",
            fileShare = MessageFileDto(name = "shared.pdf", permission = "read", path = "u/shared.pdf"),
        )
        val result = repo().shareFile("c1", filePath = "u/shared.pdf", permission = "read")

        assertTrue(result is ApiResult.Success)
        val (cid, body) = api.createFileShareCalls.single()
        assertEquals("c1", cid)
        assertEquals("u/shared.pdf", body.filePath)
        assertEquals("read", body.permission)
        val message = (result as ApiResult.Success).data
        assertEquals("file_share", message.kind)
        assertTrue(message.media is MessageMedia.File)
        assertTrue((message.media as MessageMedia.File).isShare)
        assertEquals("msg_fs", messageDao.findById("msg_fs")?.messageId)
    }
}
