package com.testlogon.android.feature.messaging.list

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ConversationListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()

    private fun vm() = ConversationListViewModel(repo, stream)

    private fun conv(id: String, unread: Int = 0, activity: Long = 100) = Conversation(
        id = id, title = id, iconUrl = null, lastMessagePreview = "p",
        lastActivityEpochSeconds = activity, unreadCount = unread,
    )

    @Test
    fun successWithRows_emitsContent() = runTest {
        repo.emitConversations(listOf(conv("c1", unread = 2)))
        repo.refreshResult = ApiResult.Success(listOf(conv("c1", unread = 2)))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ConversationListUiState.Content)
        val content = state as ConversationListUiState.Content
        assertEquals(1, content.rows.size)
        assertEquals(2, content.rows[0].unreadCount)
        assertTrue(content.rows[0].isUnread)
    }

    @Test
    fun successEmpty_emitsEmpty() = runTest {
        repo.refreshResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        assertEquals(ConversationListUiState.Empty, vm.state.value)
    }

    @Test
    fun firstLoadServerFailure_noCache_emitsError() = runTest {
        repo.refreshResult = FakeMessagingRepository.failure(500)
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ConversationListUiState.Error)
        assertEquals(false, (state as ConversationListUiState.Error).offline)
    }

    @Test
    fun firstLoadNetworkError_noCache_emitsOfflineError() = runTest {
        repo.refreshResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = true)
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ConversationListUiState.Error)
        assertTrue((state as ConversationListUiState.Error).offline)
    }

    @Test
    fun refreshFailureWithCache_keepsContent_withStaleBanner() = runTest {
        repo.emitConversations(listOf(conv("c1")))
        repo.refreshResult = ApiResult.Success(listOf(conv("c1")))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is ConversationListUiState.Content)

        repo.refreshResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = false)
        vm.refresh()
        advanceUntilIdle()
        val state = vm.state.value as ConversationListUiState.Content
        assertEquals(1, state.rows.size)
        assertEquals(StaleReason.OFFLINE, state.staleReason)
    }

    @Test
    fun inboundRealtimeEvent_triggersRefresh() = runTest {
        repo.refreshResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()

        // New conversation appears server-side; the realtime event drives a re-refresh.
        repo.emitConversations(listOf(conv("c2", unread = 1)))
        repo.refreshResult = ApiResult.Success(listOf(conv("c2", unread = 1)))
        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.NewMessage(
                    conversationId = "c2", messageId = "m1", senderId = "u2",
                    text = "hi", kind = "text", createdAtEpochSeconds = 1,
                ),
            ),
        )
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ConversationListUiState.Content)
        assertEquals("c2", (state as ConversationListUiState.Content).rows[0].id)
    }
}
