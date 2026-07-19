package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessageEdit
import com.testlogon.android.data.messaging.MessageLifecycle
import com.testlogon.android.data.messaging.Reaction
import com.testlogon.android.data.messaging.Reactor
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.feature.messaging.FakeBillingAuthorizer
import com.testlogon.android.feature.messaging.FakeDraftRepository
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-140 / AND-142 — ViewModel transition tests for the action surface. Uses the in-memory
 * FakeMessagingRepository; asserts UiState + Async sheet states + transientError on failure.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MessageActionsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()
    private val auth = FakeAuthStateStore()
    private val drafts = FakeDraftRepository()

    private suspend fun vm(currentUser: String = "me"): ThreadViewModel {
        auth.setAuthenticated(currentUser)
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return com.testlogon.android.feature.messaging.newThreadViewModel(
            handle, repo, auth, stream, context,
            FakeBillingAuthorizer(),
            drafts,
            com.testlogon.android.feature.messaging.FakeTypingRepository(),
        ).also { it.clock = { 1000L } }
    }

    private fun ownMessage(id: String, text: String = "hi") = Message(
        id = id, clientId = id, conversationId = "c1", senderId = "me",
        text = text, createdAtEpochSeconds = 100, sendStatus = SendStatus.SENT,
    )

    @Test
    fun toggleReaction_dispatchesAdd_whenNotReacted() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.ToggleReaction("m1", "👍"))
        advanceUntilIdle()
        val call = repo.toggleReactionCalls.single()
        assertEquals("👍", call.emoji)
        assertTrue(call.add)
    }

    @Test
    fun toggleReaction_failure_setsTransientError() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        repo.toggleReactionResult = ApiResult.Failure(ApiError(status = 422, message = "nope"))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.ToggleReaction("m1", "👍"))
        advanceUntilIdle()
        assertEquals("nope", v.state.value.actions.transientError)
    }

    @Test
    fun openReactionDetails_movesAsyncLoadingToSuccess() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        repo.reactionDetailsResult = ApiResult.Success(listOf(Reactor("u2", "Ann", null, "👍")))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.OpenReactionDetails("m1"))
        advanceUntilIdle()
        val state = v.state.value.actions
        assertTrue(state.reactionDetailsVisible)
        assertTrue(state.reactionDetails is Async.Success)
        assertEquals("Ann", (state.reactionDetails as Async.Success).data.single().displayName)
    }

    @Test
    fun openPinsList_loadsPinnedMessages() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        repo.pinnedMessagesResult = ApiResult.Success(listOf(ownMessage("m1", "pinned one").copy(isPinned = true)))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.OpenPinsList)
        advanceUntilIdle()
        val state = v.state.value.actions
        assertTrue(state.pinsSheetVisible)
        assertTrue(state.pinned is Async.Success)
        assertEquals("pinned one", (state.pinned as Async.Success).data.single().text)
    }

    @Test
    fun startEdit_setsEditTarget_forOwnMessage() = runTest {
        repo.emitThread(listOf(ownMessage("m1", "original")))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.StartEdit("m1"))
        advanceUntilIdle()
        assertEquals("original", v.state.value.actions.editing?.originalText)
    }

    @Test
    fun submitEdit_callsRepo_clearsEditTarget() = runTest {
        repo.emitThread(listOf(ownMessage("m1", "original")))
        repo.editResult = ApiResult.Success(ownMessage("m1", "updated").copy(lifecycle = MessageLifecycle.EDITED))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.StartEdit("m1"))
        v.onAction(ThreadAction.SubmitEdit("m1", "updated"))
        advanceUntilIdle()
        assertNull(v.state.value.actions.editing)
        assertEquals("updated", repo.editCalls.single().second)
    }

    @Test
    fun openEditHistory_loadsHistory() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        repo.editHistoryResult = ApiResult.Success(listOf(MessageEdit(1, "v1", 100)))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.OpenEditHistory("m1"))
        advanceUntilIdle()
        assertTrue(v.state.value.actions.editHistory is Async.Success)
    }

    @Test
    fun delete_callsRepo() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.Delete("m1"))
        advanceUntilIdle()
        assertEquals(listOf("m1"), repo.deleteCalls)
    }

    @Test
    fun revoke_windowExpired403_showsPreciseMessage() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        repo.revokeResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.Revoke("m1"))
        advanceUntilIdle()
        assertEquals("Revoke window expired", v.state.value.actions.transientError)
    }

    @Test
    fun setHidden_callsRepo_andHiddenMessageDropsFromList() = runTest {
        repo.emitThread(listOf(ownMessage("m1")))
        val v = vm()
        advanceUntilIdle()
        v.onAction(ThreadAction.SetHidden("m1", true))
        advanceUntilIdle()
        assertEquals(listOf("m1" to true), repo.setHiddenCalls)
        // The repository fake flags the row hidden; the VM filters hidden rows out of the rendered list.
        assertTrue(v.state.value.messages.none { it.key == "m1" })
    }

    @Test
    fun tombstoneMessage_rendersAsTombstone() = runTest {
        repo.emitThread(listOf(ownMessage("m1").copy(lifecycle = MessageLifecycle.REVOKED, text = "")))
        val v = vm()
        advanceUntilIdle()
        val ui = v.state.value.messages.single()
        assertTrue(ui.isRevoked)
        assertTrue(ui.isTombstone)
    }

    @Test
    fun reactionsCarryThroughToUi() = runTest {
        repo.emitThread(listOf(ownMessage("m1").copy(reactions = listOf(Reaction("👍", 2, true)))))
        val v = vm()
        advanceUntilIdle()
        val ui = v.state.value.messages.single()
        assertEquals(1, ui.reactions.size)
        assertEquals(2, ui.reactions.single().count)
    }
}
