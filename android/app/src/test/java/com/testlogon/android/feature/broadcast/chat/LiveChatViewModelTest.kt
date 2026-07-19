package com.testlogon.android.feature.broadcast.chat

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.chat.BroadcastChatRepository
import com.testlogon.android.data.broadcast.chat.ChatConnectionState
import com.testlogon.android.data.broadcast.chat.ChatMessage
import com.testlogon.android.data.broadcast.chat.ChatStreamEvent
import com.testlogon.android.data.broadcast.chat.ChatStreamSignal
import com.testlogon.android.data.broadcast.chat.DeliveryState
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class LiveChatViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val streamChannel = Channel<ChatStreamSignal>(Channel.UNLIMITED)

    private class FakeRepo(
        private val stream: Flow<ChatStreamSignal>,
        var sendResult: ApiResult<ChatMessage>? = null,
        val self: String = "u_self",
    ) : BroadcastChatRepository {
        var sendCalls = 0
        override fun chatEvents(sessionId: String): Flow<ChatStreamSignal> = stream
        override suspend fun loadHistory(sessionId: String, limit: Int): ApiResult<List<ChatMessage>> =
            ApiResult.Success(emptyList())
        override suspend fun send(
            sessionId: String,
            text: String?,
            options: com.testlogon.android.data.broadcast.chat.ChatComposeOptions,
            imageUrl: String?,
            videoUrl: String?,
            thumbnailUrl: String?,
        ): ApiResult<ChatMessage> {
            sendCalls++
            return sendResult ?: ApiResult.Success(serverMessage(text.orEmpty()))
        }
        override suspend fun reactToMessage(
            sessionId: String,
            messageId: String,
            emoji: String,
            action: String,
        ): ApiResult<Map<String, Int>> = ApiResult.Success(mapOf(emoji to 1))
        // Rich-media + paid-message chat surface; not exercised by the live-append/send tests.
        override suspend fun unlock(sessionId: String, messageId: String, paymentMethodId: String): ApiResult<ChatMessage?> =
            ApiResult.Success(null)
        override suspend fun consumeView(sessionId: String, messageId: String): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun uploadImage(localUri: String): ApiResult<String> = ApiResult.Success("")
        override suspend fun uploadVideo(localUri: String): ApiResult<com.testlogon.android.data.broadcast.chat.BroadcastVideoUpload> =
            ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 0, message = "not exercised"))
        override fun selfId(): String = self

        fun serverMessage(text: String) = ChatMessage(
            id = "srv_$text",
            clientNonce = null,
            sessionId = "s1",
            senderId = self,
            senderDisplayName = "Me",
            isSelf = true,
            text = text,
            createdAtEpochSeconds = 100L,
            deliveryState = DeliveryState.SENT,
        )
    }

    private fun incoming(id: String, sender: String, text: String) = ChatMessage(
        id = id,
        clientNonce = null,
        sessionId = "s1",
        senderId = sender,
        senderDisplayName = sender,
        isSelf = false,
        text = text,
        createdAtEpochSeconds = 100L,
        deliveryState = DeliveryState.SENT,
    )

    private fun vm(repo: BroadcastChatRepository) = LiveChatViewModel(sessionId = "s1", repo = repo)

    @Test
    fun chatUpdatesLive_appendsAndSetsLive() = runTest {
        val repo = FakeRepo(streamChannel.receiveAsFlow())
        val viewModel = vm(repo)
        advanceUntilIdle()

        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
        streamChannel.send(ChatStreamSignal.Decoded(ChatStreamEvent.MessageReceived(incoming("m1", "u2", "hi"))))
        advanceUntilIdle()

        val state = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(ConnectionStatus.LIVE, state.connection)
        assertEquals(1, state.messages.size)
        assertEquals("hi", state.messages.single().text)
    }

    @Test
    fun sendWorks_optimisticThenReconciledOnce() = runTest {
        val repo = FakeRepo(streamChannel.receiveAsFlow())
        val viewModel = vm(repo)
        advanceUntilIdle()
        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
        advanceUntilIdle()

        viewModel.onComposerTextChange("gg")
        viewModel.send()
        // Optimistic bubble inserted (SENDING) before the POST resolves.
        var content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(1, content.messages.size)

        advanceUntilIdle() // POST resolves -> reconcile
        content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(1, content.messages.size) // no duplicate
        assertEquals(DeliveryState.SENT, content.messages.single().deliveryState)
        assertEquals(1, repo.sendCalls)

        // The SSE echo of the same message must NOT add a duplicate.
        streamChannel.send(
            ChatStreamSignal.Decoded(
                ChatStreamEvent.MessageReceived(
                    incoming("srv_gg", "u_self", "gg").copy(isSelf = true),
                ),
            ),
        )
        advanceUntilIdle()
        content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(1, content.messages.size)
    }

    @Test
    fun sendFailure_marksFailed_retryReissues() = runTest {
        val repo = FakeRepo(streamChannel.receiveAsFlow(), sendResult = ApiResult.Failure(ApiError(500, "x")))
        val viewModel = vm(repo)
        advanceUntilIdle()
        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
        advanceUntilIdle()

        viewModel.onComposerTextChange("boom")
        viewModel.send()
        advanceUntilIdle()

        var content = viewModel.uiState.value as LiveChatUiState.Content
        val failed = content.messages.single()
        assertEquals(DeliveryState.FAILED, failed.deliveryState)

        repo.sendResult = null // now succeeds
        viewModel.retrySend(failed.clientNonce!!)
        advanceUntilIdle()
        content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(DeliveryState.SENT, content.messages.single().deliveryState)
        assertEquals(2, repo.sendCalls)
    }

    @Test
    fun reconnect_keepsMessages_disablesSend() = runTest {
        val repo = FakeRepo(streamChannel.receiveAsFlow())
        val viewModel = vm(repo)
        advanceUntilIdle()
        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
        streamChannel.send(ChatStreamSignal.Decoded(ChatStreamEvent.MessageReceived(incoming("m1", "u2", "hi"))))
        advanceUntilIdle()

        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.OFFLINE))
        advanceUntilIdle()

        val content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(ConnectionStatus.OFFLINE, content.connection)
        assertEquals(1, content.messages.size) // stale-readable
        viewModel.onComposerTextChange("nope")
        assertTrue(!(viewModel.uiState.value as LiveChatUiState.Content).canSend)
    }

    @Test
    fun maxRetained_evictsOldest() = runTest {
        val repo = FakeRepo(streamChannel.receiveAsFlow())
        val viewModel = vm(repo)
        advanceUntilIdle()
        streamChannel.send(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
        repeat(LiveChatViewModel.MAX_RETAINED + 10) { i ->
            streamChannel.send(ChatStreamSignal.Decoded(ChatStreamEvent.MessageReceived(incoming("m$i", "u2", "t$i"))))
        }
        advanceUntilIdle()

        val content = viewModel.uiState.value as LiveChatUiState.Content
        assertEquals(LiveChatViewModel.MAX_RETAINED, content.messages.size)
    }
}
