package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.realtime.MessageViewer
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.data.messaging.realtime.ReceiptStatus
import com.testlogon.android.data.messaging.realtime.StreamConnectionState
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import com.testlogon.android.feature.messaging.FakeTypingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-147 / AND-150 — ThreadViewModel receipt behavior: report-once on visibility, no self-report,
 * live SEEN via message:viewed, roster fetch + live fold, and pending-view retry on reconnect.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ThreadReceiptsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()
    private val auth = FakeAuthStateStore()
    private val typingRepo = FakeTypingRepository()

    private suspend fun vm(currentUser: String = "me"): ThreadViewModel {
        auth.setAuthenticated(currentUser)
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return com.testlogon.android.feature.messaging.newThreadViewModel(
            handle, repo, auth, stream, context,
            com.testlogon.android.feature.messaging.FakeBillingAuthorizer(),
            com.testlogon.android.feature.messaging.FakeDraftRepository(),
            typingRepo,
        ).also { it.clock = { 1000L } }
    }

    private fun ownMessage(id: String) = Message(
        id = id, clientId = id, conversationId = "c1", senderId = "me",
        text = "hi", createdAtEpochSeconds = 100, sendStatus = SendStatus.SENT,
    )

    @Test
    fun onMessageVisible_reportsOnce_acrossRepeatedCalls() = runTest {
        // AC-2 — exactly one report despite repeated visibility for the same inbound message.
        val vm = vm()
        advanceUntilIdle()
        repeat(5) { vm.onMessageVisible("m_in", authoredByMe = false) }
        advanceUntilIdle()
        assertEquals(1, repo.reportViewCalls.count { it.second == "m_in" })
    }

    @Test
    fun onMessageVisible_ownMessage_isNeverReported() = runTest {
        // AC-5 — own messages are never reported viewed.
        val vm = vm()
        advanceUntilIdle()
        vm.onMessageVisible("m_self", authoredByMe = true)
        advanceUntilIdle()
        assertTrue(repo.reportViewCalls.none { it.second == "m_self" })
    }

    @Test
    fun messageViewedEvent_setsSeenLive_onOwnMessage() = runTest {
        // AC-1 — injecting message:viewed transitions an own message to SEEN with no refetch.
        val vm = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(ownMessage("m1")))
        advanceUntilIdle()
        assertEquals(ReceiptStatus.SENT, vm.state.value.receipts["m1"]?.status)

        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.MessageViewed("c1", "m1", viewerId = "u9", viewedAtEpochSeconds = 200),
            ),
        )
        advanceUntilIdle()
        val r = vm.state.value.receipts["m1"]
        assertEquals(ReceiptStatus.SEEN, r?.status)
        assertEquals(1, r?.seenCount)
    }

    @Test
    fun duplicateViewedEvent_doesNotDoubleCount() = runTest {
        // AC-3 — a replayed identical event is idempotent.
        val vm = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(ownMessage("m1")))
        advanceUntilIdle()
        val e = MessagingStreamEvent.Event(
            MessagingEvent.MessageViewed("c1", "m1", viewerId = "u9", viewedAtEpochSeconds = 200),
        )
        stream.send(e)
        stream.send(e)
        advanceUntilIdle()
        assertEquals(1, vm.state.value.receipts["m1"]?.seenCount)
    }

    @Test
    fun selfViewedEvent_isIgnored() = runTest {
        // AC-5 — the local user never appears as a viewer of their own message.
        val vm = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(ownMessage("m1")))
        advanceUntilIdle()
        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.MessageViewed("c1", "m1", viewerId = "me", viewedAtEpochSeconds = 200),
            ),
        )
        advanceUntilIdle()
        assertEquals(ReceiptStatus.SENT, vm.state.value.receipts["m1"]?.status)
    }

    @Test
    fun openViewers_loadsRoster_andFoldsLiveEvent() = runTest {
        // AC-4 — roster sheet opens from the views endpoint and updates live on a new event.
        val vm = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(ownMessage("m1")))
        repo.getViewersResult = ApiResult.Success(listOf(MessageViewer("u1", 100, 1), MessageViewer("u2", 200, 1)))
        advanceUntilIdle()

        vm.openViewers("m1")
        advanceUntilIdle()
        assertEquals("m1", vm.state.value.viewerRoster.messageId)
        assertEquals(listOf("u2", "u1"), vm.state.value.viewerRoster.viewers.map { it.userId })

        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.MessageViewed("c1", "m1", viewerId = "u3", viewedAtEpochSeconds = 300),
            ),
        )
        advanceUntilIdle()
        assertEquals("u3", vm.state.value.viewerRoster.viewers.first().userId)
    }

    @Test
    fun reconnect_retriesPendingViews() = runTest {
        // AC-6 — a CONNECTED transition drains the failed-view retry queue.
        val vm = vm()
        advanceUntilIdle()
        stream.send(MessagingStreamEvent.State(StreamConnectionState.CONNECTED))
        advanceUntilIdle()
        assertTrue(repo.retryPendingViewsCalls >= 1)
    }
}
