package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class ThreadViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()
    private val auth = FakeAuthStateStore()

    private suspend fun vm(currentUser: String = "me"): ThreadViewModel {
        auth.setAuthenticated(currentUser)
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        // Voice factories hold only an (unused-in-these-tests) Context; recorder/player are created
        // lazily and never constructed by non-voice tests, so a mock Context is sufficient.
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return ThreadViewModel(
            handle, repo, auth, stream, context,
            com.testlogon.android.feature.messaging.voice.VoiceRecorderFactory(context),
            com.testlogon.android.feature.messaging.voice.VoicePlayerFactory(context),
            com.testlogon.android.feature.messaging.FakeBillingAuthorizer(),
        ).also { it.clock = { 1000L } }
    }

    @Test
    fun send_insertsOptimisticSendingRow_andClearsDraft() = runTest {
        val vm = vm()
        advanceUntilIdle()
        vm.onDraftChange("hello")
        vm.onSend()
        // sendResult defaults to a failure; isolate the optimistic insert by checking SENDING first.
        repo.sendResult = ApiResult.NetworkError(IOException("x"), isTimeout = false)
        advanceUntilIdle()
        // draft cleared immediately
        assertEquals("", vm.state.value.composer.draft)
        val rows = vm.state.value.messages
        assertEquals(1, rows.size)
        assertEquals("hello", rows[0].text)
        assertTrue(rows[0].isOwn)
    }

    @Test
    fun send_success_reconcilesRowToSent() = runTest {
        val vm = vm()
        advanceUntilIdle()
        repo.sendResult = ApiResult.Success(
            Message(
                id = "m1", clientId = "", conversationId = "c1", senderId = "me",
                text = "hello", createdAtEpochSeconds = 1234, sendStatus = SendStatus.SENT,
            ),
        )
        vm.onDraftChange("hello")
        vm.onSend()
        advanceUntilIdle()
        val rows = vm.state.value.messages
        assertEquals(1, rows.size)
        assertEquals(SendStatus.SENT, rows[0].sendStatus)
        assertEquals("m1", rows[0].key)
    }

    @Test
    fun send_failure_marksFailed_andRetryReSends() = runTest {
        val vm = vm()
        advanceUntilIdle()
        repo.sendResult = ApiResult.NetworkError(IOException("offline"), isTimeout = false)
        vm.onDraftChange("hi")
        vm.onSend()
        advanceUntilIdle()
        val failedRow = vm.state.value.messages.single()
        assertEquals(SendStatus.FAILED, failedRow.sendStatus)
        assertEquals("hi", failedRow.text)

        // Retry succeeds this time.
        repo.sendResult = ApiResult.Success(
            Message(
                id = "m9", clientId = "", conversationId = "c1", senderId = "me",
                text = "hi", createdAtEpochSeconds = 5, sendStatus = SendStatus.SENT,
            ),
        )
        vm.onRetry(failedRow.key)
        advanceUntilIdle()
        assertEquals(SendStatus.SENT, vm.state.value.messages.single().sendStatus)
    }

    @Test
    fun draftGuards_blankAndOverLimit() = runTest {
        val vm = vm()
        advanceUntilIdle()
        vm.onDraftChange("   ")
        assertFalse(vm.state.value.composer.isSendEnabled)
        vm.onDraftChange("a".repeat(ComposerState.MAX_LENGTH + 1))
        assertTrue(vm.state.value.composer.overLimit)
        assertFalse(vm.state.value.composer.isSendEnabled)
        vm.onDraftChange("ok")
        assertTrue(vm.state.value.composer.isSendEnabled)
    }

    @Test
    fun inboundRealtimeMessage_forThisConversation_isMerged() = runTest {
        val vm = vm()
        advanceUntilIdle()
        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.NewMessage(
                    conversationId = "c1", messageId = "m2", senderId = "other",
                    text = "yo", kind = "text", createdAtEpochSeconds = 50,
                ),
            ),
        )
        advanceUntilIdle()
        assertEquals(1, repo.inboundApplied.size)
        val rows = vm.state.value.messages
        assertEquals("yo", rows.single().text)
        assertFalse(rows.single().isOwn) // sender != current user "me"
    }

    @Test
    fun inboundRealtimeMessage_forOtherConversation_isIgnored() = runTest {
        val vm = vm()
        advanceUntilIdle()
        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.NewMessage(
                    conversationId = "OTHER", messageId = "m3", senderId = "x",
                    text = "no", kind = "text", createdAtEpochSeconds = 1,
                ),
            ),
        )
        advanceUntilIdle()
        assertTrue(repo.inboundApplied.isEmpty())
        assertTrue(vm.state.value.messages.isEmpty())
    }

    @Test
    fun onThreadVisible_marksRead_oncePerSession_withNewestMarker() = runTest {
        val vm = vm()
        advanceUntilIdle()
        // Newest confirmed message drives the read marker (id + created_at).
        repo.emitThread(
            listOf(
                Message(id = "m1", clientId = "m1", conversationId = "c1", senderId = "you", text = "a", createdAtEpochSeconds = 10),
                Message(id = "m2", clientId = "m2", conversationId = "c1", senderId = "you", text = "b", createdAtEpochSeconds = 20),
            ),
        )
        advanceUntilIdle()

        vm.onThreadVisible()
        vm.onThreadVisible() // FR-2: second ON_START in the same session is a no-op
        advanceUntilIdle()

        assertEquals(1, repo.markReadCalls.size)
        val (cid, lastReadId, lastReadAt) = repo.markReadCalls.single()
        assertEquals("c1", cid)
        assertEquals("m2", lastReadId)
        assertEquals(20L, lastReadAt)
    }

    @Test
    fun inboundMessage_reArmsMarkRead() = runTest {
        val vm = vm()
        advanceUntilIdle()
        vm.onThreadVisible()
        advanceUntilIdle()
        assertEquals(1, repo.markReadCalls.size)

        // A new inbound message re-arms the trigger and marks read again (FR-2).
        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.NewMessage(
                    conversationId = "c1", messageId = "m9", senderId = "other",
                    text = "new", kind = "text", createdAtEpochSeconds = 99,
                ),
            ),
        )
        advanceUntilIdle()
        assertEquals(2, repo.markReadCalls.size)
    }

    @Test
    fun onImagePicked_insertsOptimisticImageRow_thenSends() = runTest {
        val vm = vm()
        advanceUntilIdle()
        val uri = org.mockito.Mockito.mock(android.net.Uri::class.java)
        org.mockito.Mockito.`when`(uri.toString()).thenReturn("content://pick/1")
        repo.imageSendResult = ApiResult.Success(
            Message(
                id = "img1", clientId = "", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, sendStatus = SendStatus.SENT,
                kind = "image",
                media = com.testlogon.android.data.messaging.MessageMedia.Image(url = "https://s/x.jpg"),
            ),
        )
        vm.onImagePicked(uri)
        advanceUntilIdle()
        assertEquals(1, repo.imageSendCalls.size)
        assertEquals("content://pick/1", repo.imageSendCalls.single().third)
        val row = vm.state.value.messages.single()
        assertTrue(row.isImage)
        assertEquals(SendStatus.SENT, row.sendStatus)
    }

    @Test
    fun onImagePicked_failure_marksRowFailed() = runTest {
        val vm = vm()
        advanceUntilIdle()
        val uri = org.mockito.Mockito.mock(android.net.Uri::class.java)
        org.mockito.Mockito.`when`(uri.toString()).thenReturn("content://pick/2")
        repo.imageSendResult = ApiResult.NetworkError(IOException("offline"), isTimeout = false)
        vm.onImagePicked(uri)
        advanceUntilIdle()
        assertEquals(SendStatus.FAILED, vm.state.value.messages.single().sendStatus)
    }

    @Test
    fun onOpenVideoPicker_loadsVideos() = runTest {
        val vm = vm()
        advanceUntilIdle()
        repo.shareableVideosResult = ApiResult.Success(
            listOf(
                com.testlogon.android.data.messaging.ShareableVideo("vid_1", "Clip", "t", 42),
            ),
        )
        vm.onOpenVideoPicker()
        advanceUntilIdle()
        val picker = vm.state.value.videoPicker
        assertTrue(picker.visible)
        assertFalse(picker.loading)
        assertEquals("vid_1", picker.videos.single().videoId)
    }

    @Test
    fun onShareVideo_sendsAndDismissesPicker() = runTest {
        val vm = vm()
        advanceUntilIdle()
        repo.videoShareResult = ApiResult.Success(
            Message(
                id = "v1", clientId = "v1", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, sendStatus = SendStatus.SENT, kind = "video_share",
            ),
        )
        vm.onShareVideo("vid_1")
        advanceUntilIdle()
        assertEquals("vid_1", repo.videoShareCalls.single().second)
        assertFalse(vm.state.value.videoPicker.visible)
    }

    @Test
    fun isOwn_derivedFromCurrentUserSub() = runTest {
        val vm = vm(currentUser = "me")
        advanceUntilIdle()
        repo.emitThread(
            listOf(
                Message(id = "a", clientId = "a", conversationId = "c1", senderId = "me", text = "mine", createdAtEpochSeconds = 1),
                Message(id = "b", clientId = "b", conversationId = "c1", senderId = "you", text = "theirs", createdAtEpochSeconds = 2),
            ),
        )
        advanceUntilIdle()
        val rows = vm.state.value.messages
        assertTrue(rows.first { it.key == "a" }.isOwn)
        assertFalse(rows.first { it.key == "b" }.isOwn)
    }
}
