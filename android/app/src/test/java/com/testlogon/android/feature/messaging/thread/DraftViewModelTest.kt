package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Draft
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.feature.messaging.FakeBillingAuthorizer
import com.testlogon.android.feature.messaging.FakeDraftRepository
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-141 / AND-142 — ViewModel draft behaviour: restore on open, debounced save, clear on send,
 * discard, ON_STOP flush.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DraftViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()
    private val auth = FakeAuthStateStore()
    private val drafts = FakeDraftRepository()

    private suspend fun vm(): ThreadViewModel {
        auth.setAuthenticated("me")
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return ThreadViewModel(
            handle, repo, auth, stream, context,
            com.testlogon.android.feature.messaging.voice.VoiceRecorderFactory(context),
            com.testlogon.android.feature.messaging.voice.VoicePlayerFactory(context),
            FakeBillingAuthorizer(),
            drafts,
            com.testlogon.android.feature.messaging.FakeTypingRepository(),
        ).also { it.clock = { 1000L } }
    }

    @Test
    fun restoreOnOpen_populatesComposer_andHasDraft() = runTest {
        drafts.seed(Draft("c1", "see you at 6", updatedAtEpochMs = 1, pendingSync = false))
        val v = vm()
        advanceUntilIdle()
        assertEquals("see you at 6", v.state.value.composer.draft)
        assertTrue(v.state.value.hasDraft)
    }

    @Test
    fun typing_debouncesToOneSave() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onDraftChange("h")
        v.onDraftChange("he")
        v.onDraftChange("hel")
        v.onDraftChange("hello")
        // Before the debounce window elapses, no save yet.
        advanceTimeBy(700)
        assertTrue(drafts.saveCalls.isEmpty())
        advanceUntilIdle()
        assertEquals(listOf("c1" to "hello"), drafts.saveCalls)
    }

    @Test
    fun emptyComposer_clearsDraft() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onDraftChange("   ")
        advanceUntilIdle()
        assertTrue(drafts.clearCalls.contains("c1"))
        assertFalse(v.state.value.hasDraft)
    }

    @Test
    fun successfulSend_clearsDraft() = runTest {
        repo.sendResult = ApiResult.Success(
            Message(id = "m1", clientId = "", conversationId = "c1", senderId = "me",
                text = "hi", createdAtEpochSeconds = 1, sendStatus = SendStatus.SENT),
        )
        val v = vm()
        advanceUntilIdle()
        v.onDraftChange("hi")
        v.onSend()
        advanceUntilIdle()
        assertTrue(drafts.clearCalls.contains("c1"))
        assertEquals("", v.state.value.composer.draft)
        assertFalse(v.state.value.hasDraft)
    }

    @Test
    fun discardDraft_clearsComposerAndCallsRepo() = runTest {
        drafts.seed(Draft("c1", "keep me", updatedAtEpochMs = 1, pendingSync = false))
        val v = vm()
        advanceUntilIdle()
        v.onDiscardDraft()
        advanceUntilIdle()
        assertEquals("", v.state.value.composer.draft)
        assertFalse(v.state.value.hasDraft)
        assertTrue(drafts.clearCalls.contains("c1"))
    }

    @Test
    fun flushDraft_persistsImmediately_bypassingDebounce() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onDraftChange("buffered")
        // Do not advance past the debounce window; flush should still save now.
        v.flushDraft()
        advanceUntilIdle()
        assertTrue(drafts.saveCalls.any { it == "c1" to "buffered" })
    }
}
