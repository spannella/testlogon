package com.testlogon.android.feature.messaging

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.CountdownDraft
import com.testlogon.android.data.messaging.CustomEmojiUi
import com.testlogon.android.data.messaging.GifResult
import com.testlogon.android.data.messaging.GifSendPayload
import com.testlogon.android.data.messaging.MeetingPoll
import com.testlogon.android.data.messaging.MeetingPollDraft
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.ShareableVideo
import com.testlogon.android.data.messaging.SlotVote
import com.testlogon.android.data.messaging.StickerCollectionUi
import com.testlogon.android.data.messaging.StickerPick
import com.testlogon.android.data.messaging.TipReceipt
import com.testlogon.android.data.messaging.withReactionToggled
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
        replyToMessageId: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        lockDescription: String?,
        sendAtEpochSeconds: Long?,
        expiresInSeconds: Long?,
        countdownTargetEpochSeconds: Long?,
        countdownTitle: String?,
        countdownRevealText: String?,
        countdownRevealImage: com.testlogon.android.data.messaging.LotteryImageRef?,
        tipAmountCents: Long?,
        tipPaymentMethodId: String?,
        tipRecipientId: String?,
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

    // ---- AND-140: reactions / pins / edits / delete / revoke / hide ----

    var mutationsApplied = mutableListOf<MessagingEvent.MessageMutated>()
    var toggleReactionCalls = mutableListOf<ReactionCall>()
    var toggleReactionResult: ApiResult<Message>? = null
    var reactionDetailsResult: ApiResult<List<com.testlogon.android.data.messaging.Reactor>> =
        ApiResult.Success(emptyList())
    var setPinnedCalls = mutableListOf<Pair<String, Boolean>>()
    var setPinnedResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var pinnedMessagesResult: ApiResult<List<Message>> = ApiResult.Success(emptyList())
    var editCalls = mutableListOf<Pair<String, String>>()
    var editResult: ApiResult<Message>? = null
    var editHistoryResult: ApiResult<List<com.testlogon.android.data.messaging.MessageEdit>> =
        ApiResult.Success(emptyList())
    var deleteCalls = mutableListOf<String>()
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var revokeCalls = mutableListOf<String>()
    var revokeResult: ApiResult<Message>? = null
    var setHiddenCalls = mutableListOf<Pair<String, Boolean>>()
    var setHiddenResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var hiddenMessagesResult: ApiResult<List<Message>> = ApiResult.Success(emptyList())

    data class ReactionCall(val messageId: String, val emoji: String, val add: Boolean)

    private fun threadMessage(messageId: String): Message? =
        thread.value.firstOrNull { it.id == messageId || it.clientId == messageId }

    private fun updateThread(messageId: String, transform: (Message) -> Message) {
        thread.value = thread.value.map {
            if (it.id == messageId || it.clientId == messageId) transform(it) else it
        }
    }

    override suspend fun applyMessageMutation(event: MessagingEvent.MessageMutated) {
        mutationsApplied += event
    }

    override suspend fun toggleReaction(
        conversationId: String,
        messageId: String,
        emoji: String,
        add: Boolean,
    ): ApiResult<Message> {
        toggleReactionCalls += ReactionCall(messageId, emoji, add)
        val current = threadMessage(messageId)
        if (current != null) {
            updateThread(messageId) { it.withReactionToggled(emoji, add) }
        }
        return toggleReactionResult ?: (threadMessage(messageId)?.let { ApiResult.Success(it) }
            ?: failure())
    }

    override suspend fun reactionDetails(
        conversationId: String,
        messageId: String,
    ): ApiResult<List<com.testlogon.android.data.messaging.Reactor>> = reactionDetailsResult

    override suspend fun setPinned(
        conversationId: String,
        messageId: String,
        pinned: Boolean,
    ): ApiResult<Unit> {
        setPinnedCalls += messageId to pinned
        if (setPinnedResult is ApiResult.Success) updateThread(messageId) { it.copy(isPinned = pinned) }
        return setPinnedResult
    }

    override suspend fun pinnedMessages(conversationId: String, cursor: String?): ApiResult<List<Message>> =
        pinnedMessagesResult

    override suspend fun editMessage(
        conversationId: String,
        messageId: String,
        text: String?,
        image: com.testlogon.android.data.messaging.MessageImageDto?,
        filePath: String?,
        videoId: String?,
        freeImages: List<com.testlogon.android.data.messaging.GalleryImageDto>?,
        lockedImages: List<com.testlogon.android.data.messaging.GalleryImageDto>?,
        removeMedia: Boolean,
    ): ApiResult<Message> {
        editCalls += messageId to (text ?: "")
        val r = editResult
        if (r is ApiResult.Success) updateThread(messageId) { r.data }
        return r ?: failure()
    }

    override suspend fun uploadEditImage(
        conversationId: String,
        localUri: String,
    ): ApiResult<com.testlogon.android.data.messaging.MessageImageDto> =
        ApiResult.Failure(ApiError(status = 400, message = "fake"))

    override suspend fun uploadEditFile(
        conversationId: String,
        localUri: String,
        fileName: String,
        mimeType: String,
    ): ApiResult<String> =
        ApiResult.Failure(ApiError(status = 400, message = "fake"))

    override suspend fun editHistory(
        conversationId: String,
        messageId: String,
        limit: Int,
    ): ApiResult<List<com.testlogon.android.data.messaging.MessageEdit>> = editHistoryResult

    override suspend fun deleteMessage(conversationId: String, messageId: String): ApiResult<Unit> {
        deleteCalls += messageId
        if (deleteResult is ApiResult.Success) {
            updateThread(messageId) {
                it.copy(text = "", lifecycle = com.testlogon.android.data.messaging.MessageLifecycle.DELETED)
            }
        }
        return deleteResult
    }

    override suspend fun revokeMessage(conversationId: String, messageId: String): ApiResult<Message> {
        revokeCalls += messageId
        val r = revokeResult
        if (r is ApiResult.Success) updateThread(messageId) { r.data }
        return r ?: failure()
    }

    override suspend fun setHidden(
        conversationId: String,
        messageId: String,
        hidden: Boolean,
    ): ApiResult<Unit> {
        setHiddenCalls += messageId to hidden
        if (setHiddenResult is ApiResult.Success) updateThread(messageId) { it.copy(isHiddenLocal = hidden) }
        return setHiddenResult
    }

    override suspend fun hiddenMessages(conversationId: String, cursor: String?): ApiResult<List<Message>> =
        hiddenMessagesResult

    override suspend fun markRead(
        conversationId: String,
        lastReadMessageId: String?,
        lastReadAtEpochSeconds: Long?,
    ): ApiResult<Unit> {
        markReadCalls += Triple(conversationId, lastReadMessageId, lastReadAtEpochSeconds)
        return markReadResult
    }

    override fun observeTotalUnread(): Flow<Int> = totalUnread.asStateFlow()

    // ---- AND-147: read receipts / views ----

    /** Recorded reportView calls: (conversationId, messageId). */
    var reportViewCalls = mutableListOf<Pair<String, String>>()
    var reportViewResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var getViewersResult: ApiResult<List<com.testlogon.android.data.messaging.realtime.MessageViewer>> =
        ApiResult.Success(emptyList())
    var retryPendingViewsCalls = 0

    override suspend fun reportView(conversationId: String, messageId: String): ApiResult<Unit> {
        reportViewCalls += conversationId to messageId
        return reportViewResult
    }

    override suspend fun getViewers(
        conversationId: String,
        messageId: String,
        limit: Int,
    ): ApiResult<List<com.testlogon.android.data.messaging.realtime.MessageViewer>> = getViewersResult

    override suspend fun retryPendingViews() { retryPendingViewsCalls++ }

    // ---- AND-151 / AND-152: message search ----

    /** Recorded in-conversation search calls: (conversationId, query). */
    var searchInConversationCalls = mutableListOf<Pair<String, String>>()
    var searchInConversationResult: ApiResult<List<com.testlogon.android.data.messaging.MessageSearchMatch>> =
        ApiResult.Success(emptyList())

    /** Recorded global search calls: (query, senderId, afterTs). */
    var searchAllCalls = mutableListOf<Triple<String, String?, Long?>>()
    var searchAllResult: ApiResult<List<com.testlogon.android.data.messaging.MessageSearchResultItem>> =
        ApiResult.Success(emptyList())

    override suspend fun searchInConversation(
        conversationId: String,
        query: String,
    ): ApiResult<List<com.testlogon.android.data.messaging.MessageSearchMatch>> {
        searchInConversationCalls += conversationId to query
        return searchInConversationResult
    }

    override suspend fun searchAllMessages(
        query: String,
        senderId: String?,
        afterTs: Long?,
    ): ApiResult<List<com.testlogon.android.data.messaging.MessageSearchResultItem>> {
        searchAllCalls += Triple(query, senderId, afterTs)
        return searchAllResult
    }

    override suspend fun findOrCreateDm(peerUserId: String): ApiResult<Conversation> {
        findOrCreateDmCalls += peerUserId
        return findOrCreateDmResult
    }

    // ---- AND-153: contact search ----

    /** Recorded searchContacts queries (raw, as passed by the caller). */
    var searchContactsCalls = mutableListOf<String>()
    var searchContactsResult: ApiResult<List<com.testlogon.android.data.messaging.Contact>> =
        ApiResult.Success(emptyList())

    override suspend fun searchContacts(
        query: String,
    ): ApiResult<List<com.testlogon.android.data.messaging.Contact>> {
        // Mirror the real repo: a blank/whitespace query never reaches the network (returns Idle/empty).
        if (query.trim().isEmpty()) return ApiResult.Success(emptyList())
        searchContactsCalls += query
        return searchContactsResult
    }

    // ---- AND-130 / AND-131 ----

    /** Recorded image sends: (conversationId, clientId, localUri). */
    var imageSendCalls = mutableListOf<Triple<String, String, String>>()

    /** Result the next sendImageOutbox() returns. */
    var imageSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** C5 — caption passed to the most recent sendImageOutbox(). */
    var lastImageCaption: String? = null

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
        caption: String?,
        viewOnce: Boolean,
        lockPriceCents: Long?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
        encryptionPassphrase: String?,
    ): ApiResult<Message> {
        imageSendCalls += Triple(conversationId, clientId, localUri)
        lastImageCaption = caption
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

    // C6 - gallery (multi-image) recorders.
    var galleryEnqueueCalls = mutableListOf<Triple<String, String, Int>>()
    var gallerySendCalls = mutableListOf<Pair<String, List<String>>>()
    var lastGalleryCaption: String? = null
    var gallerySendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    override suspend fun enqueueOptimisticGallery(
        conversationId: String,
        clientId: String,
        firstLocalUri: String,
        imageCount: Int,
        nowSeconds: Long,
    ) {
        galleryEnqueueCalls += Triple(conversationId, clientId, imageCount)
    }

    override suspend fun sendGalleryOutbox(
        conversationId: String,
        clientId: String,
        localUris: List<String>,
        caption: String?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> {
        gallerySendCalls += conversationId to localUris
        lastGalleryCaption = caption
        return gallerySendResult
    }

    // C7 - short-video recorders.
    var videoClipEnqueueCalls = mutableListOf<Pair<String, String>>()
    var videoClipSendCalls = mutableListOf<Triple<String, String, String>>()
    var lastVideoClipCaption: String? = null
    var videoClipSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    override suspend fun enqueueOptimisticVideoClip(
        conversationId: String,
        clientId: String,
        localUri: String,
        nowSeconds: Long,
    ) {
        videoClipEnqueueCalls += conversationId to clientId
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
    ): ApiResult<Message> {
        videoClipSendCalls += Triple(conversationId, clientId, localUri)
        lastVideoClipCaption = caption
        return videoClipSendResult
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

    // ---- AND-132 / AND-133 ----

    /** Recorded file sends: (conversationId, clientId, localUri). */
    var fileSendCalls = mutableListOf<Triple<String, String, String>>()
    var fileSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded shareFile calls: (conversationId, filePath, permission). */
    var shareFileCalls = mutableListOf<Triple<String, String, String>>()
    var shareFileResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded voice sends: (conversationId, clientId, localFilePath). */
    var voiceSendCalls = mutableListOf<Triple<String, String, String>>()
    var voiceSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Scripted download emissions (per call). */
    var downloadProgress: List<com.testlogon.android.data.messaging.DownloadProgress> = emptyList()

    override suspend fun enqueueOptimisticFile(
        conversationId: String,
        clientId: String,
        localUri: String,
        fileName: String,
        sizeBytes: Long,
        mimeType: String,
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
            kind = "file",
            media = MessageMedia.File(
                fileName = fileName,
                sizeBytes = sizeBytes,
                mimeType = mimeType,
                localUri = localUri,
                uploadProgress = 0f,
            ),
        )
        thread.value =
            if (thread.value.any { it.clientId == clientId }) {
                thread.value.map { if (it.clientId == clientId) row else it }
            } else {
                thread.value + row
            }
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
    ): ApiResult<Message> {
        fileSendCalls += Triple(conversationId, clientId, localUri)
        lastFileViewOnce = viewOnce
        return when (val result = fileSendResult) {
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

    override suspend fun shareFile(
        conversationId: String,
        filePath: String,
        permission: String,
        text: String?,
    ): ApiResult<Message> {
        shareFileCalls += Triple(conversationId, filePath, permission)
        return shareFileResult
    }

    override fun downloadAttachment(
        conversationId: String,
        messageId: String,
        fileName: String,
        consumptionPolicy: String,
    ): Flow<com.testlogon.android.data.messaging.DownloadProgress> =
        kotlinx.coroutines.flow.flow { downloadProgress.forEach { emit(it) } }

    override suspend fun enqueueOptimisticVoice(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
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
            kind = "voice_message",
            media = MessageMedia.Voice(
                audioUrl = null,
                durationSeconds = durationSeconds,
                waveform = waveform,
                localUri = localFilePath,
                uploadProgress = 0f,
            ),
        )
        thread.value =
            if (thread.value.any { it.clientId == clientId }) {
                thread.value.map { if (it.clientId == clientId) row else it }
            } else {
                thread.value + row
            }
    }

    override suspend fun sendVoiceOutbox(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        consumptionPolicy: String,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> {
        voiceSendCalls += Triple(conversationId, clientId, localFilePath)
        return when (val result = voiceSendResult) {
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

    // ---- AND-134 / AND-135 / AND-136 ----

    var voicemailSendCalls = mutableListOf<Triple<String, String, String>>() // conversationId, clientId, callId
    var voicemailSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    var gifSendCalls = mutableListOf<Pair<String, GifSendPayload>>()
    var gifSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    var stickerSendCalls = mutableListOf<Pair<String, StickerPick>>()
    var stickerSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    var gifSearchResult: ApiResult<List<GifResult>> = ApiResult.Success(emptyList())
    var gifSearchCalls = mutableListOf<String>()
    var stickerCollectionsResult: ApiResult<List<StickerCollectionUi>> = ApiResult.Success(emptyList())
    private val customEmoji = MutableStateFlow<List<CustomEmojiUi>>(emptyList())
    fun emitCustomEmoji(list: List<CustomEmojiUi>) { customEmoji.value = list }
    var refreshCustomEmojiResult: ApiResult<Unit> = ApiResult.Success(Unit)

    private val polls = mutableMapOf<String, MutableStateFlow<MeetingPoll?>>()
    fun emitPoll(poll: MeetingPoll) { pollFlow(poll.pollId).value = poll }
    private fun pollFlow(pollId: String) = polls.getOrPut(pollId) { MutableStateFlow(null) }

    var createPollResult: ApiResult<MeetingPoll> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var voteCalls = mutableListOf<Triple<String, String, SlotVote?>>() // pollId, slotId, vote
    var voteResult: ApiResult<MeetingPoll> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var confirmCalls = mutableListOf<Pair<String, String>>() // pollId, slotId
    var confirmResult: ApiResult<MeetingPoll> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    override suspend fun enqueueOptimisticVoicemail(
        conversationId: String,
        clientId: String,
        localFilePath: String,
        durationSeconds: Double,
        waveform: List<Float>,
        isVideo: Boolean,
        nowSeconds: Long,
    ) {
        thread.value = thread.value + Message(
            id = null,
            clientId = clientId,
            conversationId = conversationId,
            senderId = "",
            text = "",
            createdAtEpochSeconds = nowSeconds,
            sendStatus = SendStatus.SENDING,
            kind = "voicemail",
            media = MessageMedia.Voicemail(
                mediaUrl = null,
                isVideo = isVideo,
                durationSeconds = durationSeconds,
                waveform = waveform,
                callId = "",
                callState = null,
                localUri = localFilePath,
                uploadProgress = 0f,
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
    ): ApiResult<Message> {
        voicemailSendCalls += Triple(conversationId, clientId, callId)
        return reconcile(clientId, voicemailSendResult)
    }

    override suspend fun sendGif(
        conversationId: String,
        clientId: String,
        payload: GifSendPayload,
    ): ApiResult<Message> {
        gifSendCalls += conversationId to payload
        return when (val r = gifSendResult) {
            is ApiResult.Success -> { thread.value = thread.value + r.data; r }
            else -> r
        }
    }

    override suspend fun sendSticker(
        conversationId: String,
        clientId: String,
        sticker: StickerPick,
    ): ApiResult<Message> {
        stickerSendCalls += conversationId to sticker
        return when (val r = stickerSendResult) {
            is ApiResult.Success -> { thread.value = thread.value + r.data; r }
            else -> r
        }
    }

    override suspend fun searchGifs(query: String, limit: Int): ApiResult<List<GifResult>> {
        gifSearchCalls += query
        return gifSearchResult
    }

    override suspend fun stickerCollections(): ApiResult<List<StickerCollectionUi>> =
        stickerCollectionsResult

    override fun observeCustomEmoji(): Flow<List<CustomEmojiUi>> = customEmoji.asStateFlow()

    override suspend fun refreshCustomEmoji(): ApiResult<Unit> = refreshCustomEmojiResult

    override fun observeMeetingPoll(pollId: String): Flow<MeetingPoll?> = pollFlow(pollId).asStateFlow()

    override suspend fun createMeetingPoll(
        conversationId: String,
        draft: MeetingPollDraft,
    ): ApiResult<MeetingPoll> {
        val r = createPollResult
        if (r is ApiResult.Success) emitPoll(r.data)
        return r
    }

    override suspend fun sendArbitraryPoll(
        conversationId: String,
        question: String,
        options: List<String>,
        multiSelect: Boolean,
        maxSelections: Int?,
        closesAt: Long?,
        text: String?,
        allowWriteIn: Boolean,
    ): ApiResult<Unit> = ApiResult.Success(Unit)

    // MSG program additions (view-once media consumption, mixed gallery, encrypted image fetch,
    // tip-reactions, lottery-option media upload). Programmable; sensible defaults.
    val consumeOnceMediaCalls = mutableListOf<Triple<String, String, String>>()
    val mixedGalleryCalls = mutableListOf<String>()
    val tipReactCalls = mutableListOf<Pair<String, String>>()
    var tipReactResult: ApiResult<com.testlogon.android.data.messaging.TipReactReceipt> =
        ApiResult.Success(
            com.testlogon.android.data.messaging.TipReactReceipt(
                tipPaymentId = "tp_1",
                chargedCents = 0L,
                netCents = 0L,
                recipientId = null,
                emoji = null,
            ),
        )

    override suspend fun consumeOnceMedia(conversationId: String, messageId: String, trigger: String) {
        consumeOnceMediaCalls += Triple(conversationId, messageId, trigger)
    }

    override suspend fun sendMixedGalleryOutbox(
        conversationId: String,
        clientId: String,
        media: List<com.testlogon.android.data.messaging.MediaItem>,
        caption: String?,
        expiresInSeconds: Long?,
        sendAtEpochSeconds: Long?,
    ): ApiResult<Message> {
        mixedGalleryCalls += clientId
        return sendResult
    }

    override suspend fun fetchEncryptedImageBytes(url: String): ByteArray? = null

    override suspend fun tipReactMessage(
        conversationId: String,
        messageId: String,
        amountCents: Long,
        emoji: String?,
        paymentMethodId: String?,
    ): ApiResult<com.testlogon.android.data.messaging.TipReactReceipt> {
        tipReactCalls += conversationId to messageId
        return tipReactResult
    }

    override suspend fun uploadLotteryOptionMedia(
        conversationId: String,
        localUri: String,
        isVideo: Boolean,
    ): String? = null

    override suspend fun refreshMeetingPoll(
        conversationId: String,
        pollId: String,
    ): ApiResult<MeetingPoll> {
        val r = voteResult
        if (r is ApiResult.Success) emitPoll(r.data)
        return r
    }

    override suspend fun voteMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
        vote: SlotVote?,
    ): ApiResult<MeetingPoll> {
        voteCalls += Triple(pollId, slotId, vote)
        val r = voteResult
        if (r is ApiResult.Success) emitPoll(r.data)
        return r
    }

    override suspend fun confirmMeetingPoll(
        conversationId: String,
        pollId: String,
        slotId: String,
    ): ApiResult<MeetingPoll> {
        confirmCalls += pollId to slotId
        val r = confirmResult
        if (r is ApiResult.Success) emitPoll(r.data)
        return r
    }

    // ---- AND-137 / AND-139 ----

    /** Recorded countdown sends: (conversationId, clientId, draft). */
    var countdownSendCalls = mutableListOf<Triple<String, String, CountdownDraft>>()
    var countdownSendResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)
    var enqueuedCountdowns = mutableListOf<Triple<String, String, Long>>() // clientId, title, target

    /** Recorded unlock calls: (conversationId, messageId, paymentMethodId). */
    var unlockCalls = mutableListOf<Triple<String, String, String?>>()
    var unlockResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded lottery unlock calls: (conversationId, messageId). */
    var lotteryUnlockCalls = mutableListOf<Pair<String, String>>()
    var lotteryUnlockResult: ApiResult<Message> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    /** Recorded tip calls. */
    var tipCalls = mutableListOf<TipCall>()
    var tipResult: ApiResult<TipReceipt> =
        ApiResult.NetworkError(IOException("default"), isTimeout = false)

    data class TipCall(
        val conversationId: String,
        val messageId: String,
        val amountCents: Long,
        val currency: String,
        val note: String?,
        val paymentMethodId: String?,
    )

    override suspend fun enqueueOptimisticCountdown(
        conversationId: String,
        clientId: String,
        title: String,
        targetEpochSeconds: Long,
        nowSeconds: Long,
    ) {
        enqueuedCountdowns += Triple(clientId, title, targetEpochSeconds)
        thread.value = thread.value + Message(
            id = null,
            clientId = clientId,
            conversationId = conversationId,
            senderId = "",
            text = "",
            createdAtEpochSeconds = nowSeconds,
            sendStatus = SendStatus.SENDING,
            kind = "countdown",
            media = MessageMedia.Countdown(title = title, targetEpochSeconds = targetEpochSeconds),
        )
    }

    override suspend fun sendCountdown(
        conversationId: String,
        clientId: String,
        draft: CountdownDraft,
    ): ApiResult<Message> {
        countdownSendCalls += Triple(conversationId, clientId, draft)
        return reconcile(clientId, countdownSendResult)
    }

    override suspend fun listScheduledMessages(
        conversationId: String,
    ): ApiResult<List<com.testlogon.android.data.messaging.ScheduledMessage>> = ApiResult.Success(emptyList())

    override suspend fun rescheduleMessage(
        conversationId: String,
        messageId: String,
        text: String?,
        sendAtEpochSeconds: Long?,
        image: com.testlogon.android.data.messaging.MessageImageDto?,
        filePath: String?,
        videoId: String?,
    ): ApiResult<com.testlogon.android.data.messaging.ScheduledMessage> =
        ApiResult.Failure(ApiError(status = 400, message = "fake"))

    override suspend fun uploadRescheduleImage(
        conversationId: String,
        localUri: String,
    ): ApiResult<com.testlogon.android.data.messaging.MessageImageDto> =
        ApiResult.Failure(ApiError(status = 400, message = "fake"))

    override suspend fun cancelScheduledMessage(
        conversationId: String,
        messageId: String,
    ): ApiResult<Unit> = ApiResult.Success(Unit)

    override suspend fun unlockMessage(
        conversationId: String,
        messageId: String,
        paymentMethodId: String?,
    ): ApiResult<Message> {
        unlockCalls += Triple(conversationId, messageId, paymentMethodId)
        val r = unlockResult
        if (r is ApiResult.Success) {
            thread.value = thread.value.map { if (it.id == messageId || it.clientId == messageId) r.data else it }
        }
        return r
    }

    override suspend fun unlockLottery(
        conversationId: String,
        messageId: String,
    ): ApiResult<Message> {
        lotteryUnlockCalls += conversationId to messageId
        val r = lotteryUnlockResult
        if (r is ApiResult.Success) {
            thread.value = thread.value.map { if (it.id == messageId || it.clientId == messageId) r.data else it }
        }
        return r
    }

    override suspend fun tipMessage(
        conversationId: String,
        messageId: String,
        amountCents: Long,
        currency: String,
        note: String?,
        paymentMethodId: String?,
    ): ApiResult<TipReceipt> {
        tipCalls += TipCall(conversationId, messageId, amountCents, currency, note, paymentMethodId)
        return tipResult
    }

    // ---- MSG: new in-app composers (fakes) ----
    /** C9 — view-once flag passed to the most recent sendFileOutbox(). */
    var lastFileViewOnce: Boolean = false
    var lotteryCalls = mutableListOf<Pair<String, List<com.testlogon.android.data.messaging.LotteryOutcomeDraft>>>()
    var lotteryResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)
    /** C10 — image ref passed to the most recent sendLottery(). */
    var lastLotteryImage: com.testlogon.android.data.messaging.LotteryImageRef? = null
    /** C10 — result the next uploadLotteryImage() returns. */
    var uploadLotteryImageResult: com.testlogon.android.data.messaging.LotteryImageRef? = null
    var uploadLotteryImageCalls = mutableListOf<Pair<String, String>>()
    override suspend fun uploadLotteryImage(
        conversationId: String,
        localUri: String,
    ): com.testlogon.android.data.messaging.LotteryImageRef? {
        uploadLotteryImageCalls += conversationId to localUri
        return uploadLotteryImageResult
    }
    /** #23 — cover text passed to the most recent sendLottery(). */
    var lastLotteryText: String? = null
    override suspend fun sendLottery(
        conversationId: String,
        outcomes: List<com.testlogon.android.data.messaging.LotteryOutcomeDraft>,
        image: com.testlogon.android.data.messaging.LotteryImageRef?,
        text: String?,
    ): ApiResult<Message> {
        lotteryCalls += conversationId to outcomes
        lastLotteryImage = image
        lastLotteryText = text
        return lotteryResult
    }

    var findDateTimeCalls = mutableListOf<Pair<String, com.testlogon.android.data.messaging.FindDateTimeDraft>>()
    var findDateTimeResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)
    override suspend fun createFindDateTime(
        conversationId: String,
        draft: com.testlogon.android.data.messaging.FindDateTimeDraft,
    ): ApiResult<Message> {
        findDateTimeCalls += conversationId to draft
        return findDateTimeResult
    }

    var calendarEventCalls = mutableListOf<Triple<String, String, String>>()
    var calendarEventResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)
    override suspend fun shareCalendarEvent(
        conversationId: String,
        calendarId: String,
        eventId: String,
        text: String?,
    ): ApiResult<Message> {
        calendarEventCalls += Triple(conversationId, calendarId, eventId)
        return calendarEventResult
    }

    var calendarShareCalls = mutableListOf<Triple<String, String, String>>()
    var calendarShareResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)
    override suspend fun shareCalendar(
        conversationId: String,
        calendarId: String,
        permission: String,
        includeBookingLink: Boolean,
        text: String?,
    ): ApiResult<Message> {
        calendarShareCalls += Triple(conversationId, calendarId, permission)
        return calendarShareResult
    }

    var encryptedCalls = mutableListOf<String>()
    var encryptedResult: ApiResult<Message> = ApiResult.NetworkError(IOException("default"), isTimeout = false)
    override suspend fun sendEncryptedText(
        conversationId: String,
        clientId: String,
        envelope: com.testlogon.android.data.messaging.MessageEncryptionEnvelopeDto,
        replyToMessageId: String?,
    ): ApiResult<Message> {
        encryptedCalls += clientId
        return reconcile(clientId, encryptedResult)
    }

    var calendarsResult: ApiResult<List<com.testlogon.android.data.messaging.CalendarAccessUi>> =
        ApiResult.Success(emptyList())
    override suspend fun listCalendars(): ApiResult<List<com.testlogon.android.data.messaging.CalendarAccessUi>> =
        calendarsResult

    var calendarEventsResult: ApiResult<List<com.testlogon.android.data.messaging.CalendarEventUi>> =
        ApiResult.Success(emptyList())
    override suspend fun listCalendarEvents(calendarId: String): ApiResult<List<com.testlogon.android.data.messaging.CalendarEventUi>> =
        calendarEventsResult

    var filesResult: ApiResult<List<com.testlogon.android.data.messaging.FileEntryUi>> =
        ApiResult.Success(emptyList())
    override suspend fun listFiles(path: String): ApiResult<List<com.testlogon.android.data.messaging.FileEntryUi>> =
        filesResult

    private fun reconcile(clientId: String, result: ApiResult<Message>): ApiResult<Message> =
        when (result) {
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

    companion object {
        fun failure(status: Int = 500, message: String = "boom"): ApiResult<Nothing> =
            ApiResult.Failure(ApiError(status = status, message = message))
    }
}

/** AND-141 — in-memory [com.testlogon.android.data.messaging.DraftRepository] fake. */
class FakeDraftRepository : com.testlogon.android.data.messaging.DraftRepository {
    private val drafts =
        MutableStateFlow<Map<String, com.testlogon.android.data.messaging.Draft>>(emptyMap())

    var saveCalls = mutableListOf<Pair<String, String>>()
    var clearCalls = mutableListOf<String>()
    var flushCalls = 0
    var loadResult: ApiResult<com.testlogon.android.data.messaging.Draft?>? = null

    fun seed(draft: com.testlogon.android.data.messaging.Draft) {
        drafts.value = drafts.value + (draft.conversationId to draft)
    }

    override fun observeDraft(conversationId: String): Flow<com.testlogon.android.data.messaging.Draft?> =
        kotlinx.coroutines.flow.MutableStateFlow(drafts.value[conversationId])

    override suspend fun loadAndReconcile(
        conversationId: String,
    ): ApiResult<com.testlogon.android.data.messaging.Draft?> =
        loadResult ?: ApiResult.Success(drafts.value[conversationId])

    override suspend fun saveDraft(
        conversationId: String,
        text: String,
    ): ApiResult<com.testlogon.android.data.messaging.Draft> {
        saveCalls += conversationId to text
        val draft = com.testlogon.android.data.messaging.Draft(
            conversationId = conversationId,
            text = text,
            updatedAtEpochMs = 0L,
            pendingSync = false,
        )
        drafts.value = drafts.value + (conversationId to draft)
        return ApiResult.Success(draft)
    }

    override suspend fun clearDraft(conversationId: String): ApiResult<Unit> {
        clearCalls += conversationId
        drafts.value = drafts.value - conversationId
        return ApiResult.Success(Unit)
    }

    override suspend fun flushPending() { flushCalls++ }
}

/** AND-146 — in-memory [com.testlogon.android.data.messaging.typing.TypingRepository] fake. */
class FakeTypingRepository : com.testlogon.android.data.messaging.typing.TypingRepository {
    var startCalls = mutableListOf<String>()
    var stopCalls = mutableListOf<String>()
    var pollResult: List<com.testlogon.android.data.messaging.typing.TypingUserDto> = emptyList()

    override suspend fun start(conversationId: String) { startCalls += conversationId }
    override suspend fun stop(conversationId: String) { stopCalls += conversationId }
    override suspend fun poll(conversationId: String) = pollResult
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
