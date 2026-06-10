package com.testlogon.android.data.messaging

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

    private class FakeCustomEmojiDao : CustomEmojiDao {
        val rows = MutableStateFlow<List<CustomEmojiEntity>>(emptyList())
        override fun observeAll(): Flow<List<CustomEmojiEntity>> = rows
        override suspend fun upsertAll(items: List<CustomEmojiEntity>) {
            val byCode = rows.value.associateBy { it.shortcode }.toMutableMap()
            items.forEach { byCode[it.shortcode] = it }
            rows.value = byCode.values.toList()
        }
        override suspend fun deleteStale(before: Long) {
            rows.value = rows.value.filterNot { it.fetchedAt < before }
        }
        override suspend fun clear() { rows.value = emptyList() }
    }

    private class FakeMeetingPollDao : MeetingPollDao {
        val polls = MutableStateFlow<List<MeetingPollEntity>>(emptyList())
        val slots = MutableStateFlow<List<MeetingPollSlotEntity>>(emptyList())
        private fun build(pollId: String): MeetingPollWithSlots? =
            polls.value.firstOrNull { it.pollId == pollId }
                ?.let { MeetingPollWithSlots(it, slots.value.filter { s -> s.pollId == pollId }) }
        override fun observePoll(pollId: String): Flow<MeetingPollWithSlots?> =
            polls.map { build(pollId) }
        override suspend fun observePollOnce(pollId: String): MeetingPollWithSlots? = build(pollId)
        override suspend fun upsertPoll(poll: MeetingPollEntity) {
            polls.value = polls.value.filterNot { it.pollId == poll.pollId } + poll
        }
        override suspend fun upsertSlots(s: List<MeetingPollSlotEntity>) {
            val byId = slots.value.associateBy { it.slotId }.toMutableMap()
            s.forEach { byId[it.slotId] = it }
            slots.value = byId.values.toList()
        }
        override suspend fun deleteSlots(pollId: String) {
            slots.value = slots.value.filterNot { it.pollId == pollId }
        }
        override suspend fun clearPolls() { polls.value = emptyList() }
        override suspend fun clearSlots() { slots.value = emptyList() }
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
        override suspend fun listMessages(id: String, limit: Int?, before: String?): List<MessageDto> = listMessagesResult
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

        // AND-134 / AND-135 / AND-136 — rich message endpoints.
        var presignVoicemailResult: PresignVoicemailResp? = null
        var createVoicemailCalls = mutableListOf<Pair<String, CreateVoicemailReq>>()
        var createVoicemailResult: MessageDto? = null
        var sendGifCalls = mutableListOf<Pair<String, SendGifMessageReq>>()
        var sendGifResult: MessageDto? = null
        var sendGifThrows: Throwable? = null
        var sendStickerCalls = mutableListOf<Pair<String, SendStickerMessageReq>>()
        var sendStickerResult: MessageDto? = null
        var searchGifsResult: List<GifSearchResultDto> = emptyList()
        var trendingGifsResult: List<GifSearchResultDto> = emptyList()
        var searchGifsCalls = mutableListOf<Pair<String, Int>>()
        var trendingGifsCalls = mutableListOf<Int>()
        var collectionsResult: StickerCollectionListRespDto? = null
        var customEmojiResult: CustomEmojiListRespDto? = null
        var createPollCalls = mutableListOf<Pair<String, CreateMeetingPollReq>>()
        var createPollResult: MessageDto? = null
        var getPollResults = ArrayDeque<MeetingPollStateDto>()
        var voteCalls = mutableListOf<Triple<String, String, PollVoteReq>>()
        var voteResult: OkResp = OkResp(ok = true)
        var voteThrows: Throwable? = null
        var confirmCalls = mutableListOf<Triple<String, String, PollConfirmReq>>()
        var confirmResult: OkResp = OkResp(ok = true)

        override suspend fun presignVoicemail(id: String, body: PresignVoicemailReq): PresignVoicemailResp =
            requireNotNull(presignVoicemailResult)
        override suspend fun createVoicemail(id: String, body: CreateVoicemailReq): MessageDto {
            createVoicemailCalls += id to body
            return requireNotNull(createVoicemailResult)
        }
        override suspend fun sendGifMessage(id: String, body: SendGifMessageReq): MessageDto {
            sendGifCalls += id to body
            sendGifThrows?.let { throw it }
            return requireNotNull(sendGifResult)
        }
        override suspend fun sendStickerMessage(id: String, body: SendStickerMessageReq): MessageDto {
            sendStickerCalls += id to body
            return requireNotNull(sendStickerResult)
        }
        override suspend fun searchGifs(q: String, limit: Int): List<GifSearchResultDto> {
            searchGifsCalls += q to limit
            return searchGifsResult
        }
        override suspend fun trendingGifs(limit: Int): List<GifSearchResultDto> {
            trendingGifsCalls += limit
            return trendingGifsResult
        }
        override suspend fun stickerCollections(): StickerCollectionListRespDto =
            requireNotNull(collectionsResult)
        override suspend fun collectionStickers(collectionId: String): StickerListRespDto = error("unused")
        override suspend fun customEmoji(): CustomEmojiListRespDto = requireNotNull(customEmojiResult)
        override suspend fun resolveShortcodes(codes: String): ResolveShortcodesRespDto = error("unused")
        override suspend fun createMeetingPoll(id: String, body: CreateMeetingPollReq): MessageDto {
            createPollCalls += id to body
            return requireNotNull(createPollResult)
        }
        override suspend fun getMeetingPoll(id: String, pollId: String): MeetingPollStateDto =
            getPollResults.removeFirstOrNull() ?: error("no scripted poll state")
        override suspend fun voteMeetingPoll(id: String, pollId: String, body: PollVoteReq): OkResp {
            voteCalls += Triple(id, pollId, body)
            voteThrows?.let { throw it }
            return voteResult
        }
        override suspend fun confirmMeetingPoll(id: String, pollId: String, body: PollConfirmReq): OkResp {
            confirmCalls += Triple(id, pollId, body)
            return confirmResult
        }

        // AND-137 / AND-139 — countdown / tip / unlock / lottery.
        var sendCountdownCalls = mutableListOf<Pair<String, SendCountdownMessageReq>>()
        var sendCountdownResult: MessageDto? = null
        var sendCountdownThrows: Throwable? = null
        var unlockCalls = mutableListOf<Triple<String, String, UnlockMessageReq>>()
        var unlockResult: UnlockOutDto? = null
        var unlockThrows: Throwable? = null
        var tipCalls = mutableListOf<Triple<String, String, SendTipReq>>()
        var tipResult: TipOutDto? = null
        var tipThrows: Throwable? = null
        var lotteryUnlockCalls = mutableListOf<String>()
        var lotteryUnlockResult: LotteryUnlockOutDto? = null
        var lotteryUnlockThrows: Throwable? = null
        var getLotteryResult: LotteryMessageOutDto? = null
        var listMessagesResult: List<MessageDto> = emptyList()

        override suspend fun sendCountdown(id: String, body: SendCountdownMessageReq): MessageDto {
            sendCountdownCalls += id to body
            sendCountdownThrows?.let { throw it }
            return requireNotNull(sendCountdownResult)
        }
        override suspend fun unlockMessage(id: String, messageId: String, body: UnlockMessageReq): UnlockOutDto {
            unlockCalls += Triple(id, messageId, body)
            unlockThrows?.let { throw it }
            return requireNotNull(unlockResult)
        }
        override suspend fun tipMessage(id: String, messageId: String, body: SendTipReq): TipOutDto {
            tipCalls += Triple(id, messageId, body)
            tipThrows?.let { throw it }
            return requireNotNull(tipResult)
        }
        override suspend fun unlockLottery(messageId: String, body: Map<String, String>): LotteryUnlockOutDto {
            lotteryUnlockCalls += messageId
            lotteryUnlockThrows?.let { throw it }
            return requireNotNull(lotteryUnlockResult)
        }
        override suspend fun getLottery(messageId: String): LotteryMessageOutDto =
            requireNotNull(getLotteryResult)
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
    private val customEmojiDao = FakeCustomEmojiDao()
    private val meetingPollDao = FakeMeetingPollDao()
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
        customEmojiDao = customEmojiDao,
        meetingPollDao = meetingPollDao,
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

    // ---- AND-135: gif / sticker ----

    @Test
    fun sendGif_postsFlatBody_cachesGifMessage() = runTest {
        api.sendGifResult = MessageDto(
            messageId = "msg_g", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "gif",
            gifUrl = "https://media/x.gif", gifAltText = "cat", gifWidth = 480, gifHeight = 270,
        )
        val result = repo().sendGif("c1", "client-1", GifSendPayload("https://media/x.gif", "cat", 480, 270))

        assertTrue(result is ApiResult.Success)
        val (cid, body) = api.sendGifCalls.single()
        assertEquals("c1", cid)
        assertEquals("https://media/x.gif", body.gifUrl)
        val message = (result as ApiResult.Success).data
        assertTrue(message.media is MessageMedia.Gif)
        assertEquals("msg_g", messageDao.findById("msg_g")?.messageId)
    }

    @Test
    fun sendGif_failure_returnsError_doesNotCache() = runTest {
        api.sendGifThrows = IOException("offline")
        val result = repo().sendGif("c1", "client-1", GifSendPayload("https://media/x.gif", null, null, null))
        assertTrue(result is ApiResult.NetworkError)
        assertNull(messageDao.findById("msg_g"))
    }

    @Test
    fun sendSticker_postsCollectionId_cachesStickerMessage() = runTest {
        api.sendStickerResult = MessageDto(
            messageId = "msg_s", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "sticker",
            stickerUrl = "https://s/st.png", stickerId = "st_42", stickerCollectionId = "col_1",
        )
        val result = repo().sendSticker(
            "c1", "client-2", StickerPick("st_42", "col_1", "https://s/st.png", "wave"),
        )
        assertTrue(result is ApiResult.Success)
        val (_, body) = api.sendStickerCalls.single()
        assertEquals("st_42", body.stickerId)
        assertEquals("col_1", body.stickerCollectionId)
        assertTrue((result as ApiResult.Success).data.media is MessageMedia.Sticker)
    }

    @Test
    fun searchGifs_blankQuery_usesTrending() = runTest {
        api.trendingGifsResult = listOf(GifSearchResultDto("a", "https://g/1.gif", "cat", 1, 1))
        val result = repo().searchGifs("", 20)
        assertTrue(result is ApiResult.Success)
        assertEquals(1, api.trendingGifsCalls.size)
        assertTrue(api.searchGifsCalls.isEmpty())
        assertEquals("a", (result as ApiResult.Success).data.single().id)
    }

    @Test
    fun refreshCustomEmoji_inferAnimated_fromContentType_writesRoom() = runTest {
        api.customEmojiResult = CustomEmojiListRespDto(
            emojis = listOf(
                CustomEmojiDto("e1", "partyparrot", "Party", "https://e/p.gif", "image/gif", "global"),
                CustomEmojiDto("e2", "static", "Static", "https://e/s.png", "image/png", "global"),
            ),
        )
        val result = repo().refreshCustomEmoji()
        assertTrue(result is ApiResult.Success)
        val rows = customEmojiDao.rows.value.associateBy { it.shortcode }
        assertTrue(rows["partyparrot"]!!.animated)
        assertTrue(!rows["static"]!!.animated)
    }

    // ---- AND-136: meeting poll ----

    @Test
    fun createMeetingPoll_postsSlots_reconcilesViaGet_writesRoom() = runTest {
        api.createPollResult = MessageDto(
            messageId = "msg_p", conversationId = "c1", senderId = "u1", createdAt = 100, kind = "meeting_poll",
            meetingPoll = MeetingPollAttachmentDto(pollId = "poll_9", creatorId = "u1", title = "T", status = "open"),
        )
        api.getPollResults.add(
            MeetingPollStateDto(
                pollId = "poll_9", title = "T", creatorId = "u1", status = "open",
                slots = listOf(MeetingPollSlotStateDto("slot_1", "2026-06-08T15:00:00Z", "2026-06-08T15:30:00Z", 0, 0, 0, null)),
            ),
        )
        val result = repo().createMeetingPoll(
            "c1",
            MeetingPollDraft("T", 30, listOf(MeetingPollSlotDraft("2026-06-08T15:00:00Z", "2026-06-08T15:30:00Z"), MeetingPollSlotDraft("2026-06-09T15:00:00Z", "2026-06-09T15:30:00Z"))),
        )
        assertTrue(result is ApiResult.Success)
        assertEquals(2, api.createPollCalls.single().second.slots.size)
        // Poll cached with its slots via the reconcile GET.
        assertEquals("poll_9", meetingPollDao.polls.value.single().pollId)
        assertEquals(1, meetingPollDao.slots.value.size)
    }

    @Test
    fun voteMeetingPoll_postsVotesMap_thenReconcilesViaGet() = runTest {
        // Seed a cached poll so buildVotesMap has prior state.
        api.getPollResults.add(
            MeetingPollStateDto(
                pollId = "poll_9", title = "T", creatorId = "u1", status = "open",
                slots = listOf(MeetingPollSlotStateDto("slot_1", "s", "e", 1, 0, 0, "yes")),
            ),
        )
        val result = repo().voteMeetingPoll("c1", "poll_9", "slot_1", SlotVote.NO)
        assertTrue(result is ApiResult.Success)
        val (_, pollId, body) = api.voteCalls.single()
        assertEquals("poll_9", pollId)
        assertEquals("no", body.votes["slot_1"])
        // Reconciled state written to Room.
        assertEquals(SlotVote.YES, (result as ApiResult.Success).data.slots.single().myVote)
    }

    @Test
    fun voteMeetingPoll_postFails_returnsError_noReconcile() = runTest {
        api.voteThrows = IOException("offline")
        val result = repo().voteMeetingPoll("c1", "poll_9", "slot_1", SlotVote.YES)
        assertTrue(result is ApiResult.NetworkError)
        assertTrue(meetingPollDao.polls.value.isEmpty())
    }

    @Test
    fun confirmMeetingPoll_postsSlotId_reconciles() = runTest {
        api.confirmResult = OkResp(ok = true, eventId = "evt_1")
        api.getPollResults.add(
            MeetingPollStateDto(
                pollId = "poll_9", title = "T", creatorId = "u1", status = "confirmed", confirmedSlotId = "slot_2",
                slots = listOf(MeetingPollSlotStateDto("slot_2", "s", "e", 3, 0, 0, "yes")),
            ),
        )
        val result = repo().confirmMeetingPoll("c1", "poll_9", "slot_2")
        assertTrue(result is ApiResult.Success)
        assertEquals("slot_2", api.confirmCalls.single().third.slotId)
        assertEquals(MeetingPollStatus.CONFIRMED, (result as ApiResult.Success).data.status)
    }

    // ---- AND-137: countdown ----

    @Test
    fun sendCountdown_postsDraft_reconcilesAndDropsOutbox() = runTest {
        outboxDao.rows.value = listOf(
            OutboxMessageEntity(
                clientId = "cid1", conversationId = "c1", text = "Launch",
                createdAtEpochSeconds = 1, status = "SENDING", kind = "countdown",
                voiceDurationSeconds = 1780000000.0,
            ),
        )
        api.sendCountdownResult = MessageDto(
            messageId = "msg_cd", conversationId = "c1", senderId = "u1", createdAt = 1780000000,
            kind = "countdown", countdownTitle = "Launch", targetDatetime = 1780000000,
        )
        val r = repo().sendCountdown("c1", "cid1", CountdownDraft(title = "Launch", targetEpochSeconds = 1780000000))

        assertTrue(r is ApiResult.Success)
        val media = (r as ApiResult.Success).data.media as MessageMedia.Countdown
        assertEquals(1780000000L, media.targetEpochSeconds)
        assertEquals("Launch", api.sendCountdownCalls.single().second.title)
        assertNull(outboxDao.findById("cid1")) // reconciled
        assertEquals("msg_cd", messageDao.findById("msg_cd")?.messageId)
    }

    @Test
    fun sendCountdown_failure_marksOutboxFailed() = runTest {
        outboxDao.rows.value = listOf(
            OutboxMessageEntity(clientId = "cid1", conversationId = "c1", text = "Launch", createdAtEpochSeconds = 1, status = "SENDING", kind = "countdown"),
        )
        api.sendCountdownThrows = IOException("offline")
        val r = repo().sendCountdown("c1", "cid1", CountdownDraft("Launch", 1780000000))
        assertTrue(r is ApiResult.NetworkError)
        assertEquals("FAILED", outboxDao.findById("cid1")?.status)
    }

    // ---- AND-139: unlock / tip / lottery ----

    @Test
    fun unlockMessage_postsPaymentMethodId_thenRefetchesAndRevealsBody() = runTest {
        api.unlockResult = UnlockOutDto(ok = true, conversationId = "c1", messageId = "m1", unlockPaymentId = "upay_1", amountCents = 500)
        // The re-fetch returns the now-revealed (unlocked) message.
        api.listMessagesResult = listOf(
            MessageDto(messageId = "m1", conversationId = "c1", senderId = "u2", createdAt = 100, kind = "text", text = "revealed", locked = true, isUnlocked = true),
        )
        val r = repo().unlockMessage("c1", "m1", "pm_1")

        assertTrue(r is ApiResult.Success)
        assertEquals("pm_1", api.unlockCalls.single().third.paymentMethodId)
        assertEquals("revealed", (r as ApiResult.Success).data.text)
        // Cached row is reconciled (and is no longer a locked teaser).
        assertEquals("revealed", messageDao.findById("m1")?.text)
    }

    @Test
    fun unlockMessage_serverError_isFailure_noReveal() = runTest {
        api.unlockThrows = retrofit2.HttpException(
            retrofit2.Response.error<Any>(500, okhttp3.ResponseBody.create(null, """{"detail":"boom"}""")),
        )
        val r = repo().unlockMessage("c1", "m1", "pm_1")
        assertTrue(r is ApiResult.Failure)
    }

    @Test
    fun unlockLottery_revealsSelectedOutcome_onCachedRow() = runTest {
        // Seed a cached locked lottery row.
        messageDao.upsert(
            MessageEntity(
                messageId = "lot1", conversationId = "c1", senderId = "u2", text = "",
                createdAtEpochSeconds = 100, clientId = null, kind = "lottery_dm",
                monetizationType = "LOTTERY", monetizationUnlocked = false,
            ),
        )
        api.lotteryUnlockResult = LotteryUnlockOutDto(
            messageId = "lot1", lockState = "unlocked",
            selectedOutcome = LotterySelectedOutcomeDto(outcomeId = "o1", payloadType = "text", textContent = "You win"),
            unlockedAt = 1717600000,
        )
        val r = repo().unlockLottery("c1", "lot1")

        assertTrue(r is ApiResult.Success)
        assertEquals(listOf("lot1"), api.lotteryUnlockCalls)
        val media = (r as ApiResult.Success).data.media as MessageMedia.Paid
        assertTrue(media.monetization.unlocked)
        assertEquals("You win", media.monetization.revealedText)
    }

    @Test
    fun tipMessage_postsAmountCents_returnsReceipt() = runTest {
        api.tipResult = TipOutDto(ok = true, conversationId = "c1", messageId = "m1", tipPaymentId = "tpay_1", amountCents = 500, currency = "USD")
        val r = repo().tipMessage("c1", "m1", amountCents = 500, currency = "USD", note = "ty", paymentMethodId = "pm_1")

        assertTrue(r is ApiResult.Success)
        assertEquals("tpay_1", (r as ApiResult.Success).data.tipPaymentId)
        val call = api.tipCalls.single().third
        assertEquals(500L, call.amountCents)
        assertEquals("ty", call.note)
        assertEquals("pm_1", call.paymentMethodId)
    }
}
