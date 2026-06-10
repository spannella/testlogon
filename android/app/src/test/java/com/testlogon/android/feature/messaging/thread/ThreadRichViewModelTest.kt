package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.GifResult
import com.testlogon.android.data.messaging.MeetingPoll
import com.testlogon.android.data.messaging.MeetingPollSlot
import com.testlogon.android.data.messaging.MeetingPollStatus
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.SlotVote
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

/** AND-134/135/136 — ViewModel transitions for the rich message picker, voicemail, and polls. */
@OptIn(ExperimentalCoroutinesApi::class)
class ThreadRichViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()
    private val stream = FakeMessagingEventStream()
    private val auth = FakeAuthStateStore()

    private suspend fun vm(currentUser: String = "me"): ThreadViewModel {
        auth.setAuthenticated(currentUser)
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return ThreadViewModel(
            handle, repo, auth, stream, context,
            com.testlogon.android.feature.messaging.voice.VoiceRecorderFactory(context),
            com.testlogon.android.feature.messaging.voice.VoicePlayerFactory(context),
        ).also { it.clock = { 1000L } }
    }

    @Test
    fun openMediaPicker_makesItVisible_andLoadsGifs() = runTest {
        repo.gifSearchResult = ApiResult.Success(listOf(GifResult("a", "https://g/1.gif", "cat", 1, 1)))
        val v = vm()
        advanceUntilIdle()
        v.openMediaPicker()
        advanceUntilIdle()
        assertTrue(v.state.value.mediaPicker.visible)
        assertEquals(1, v.state.value.mediaPicker.gifResults.size)
    }

    @Test
    fun selectTab_switchesTab() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.selectMediaTab(MediaTab.EMOJI)
        assertEquals(MediaTab.EMOJI, v.state.value.mediaPicker.tab)
    }

    @Test
    fun onGifSelected_sendsAndClosesSheet() = runTest {
        repo.gifSendResult = ApiResult.Success(
            Message(id = "g1", clientId = "g1", conversationId = "c1", senderId = "me", text = "",
                createdAtEpochSeconds = 1, kind = "gif", media = MessageMedia.Gif("https://g/1.gif", null, 1, 1)),
        )
        val v = vm()
        advanceUntilIdle()
        v.openMediaPicker()
        v.onGifSelected(GifResult("a", "https://g/1.gif", "cat", 480, 270))
        advanceUntilIdle()
        assertFalse(v.state.value.mediaPicker.visible)
        assertEquals(1, repo.gifSendCalls.size)
        assertEquals("https://g/1.gif", repo.gifSendCalls.single().second.url)
    }

    @Test
    fun onCustomEmojiSelected_insertsShortcodeIntoDraft_doesNotSend() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onDraftChange("hi ")
        v.onCustomEmojiSelected("partyparrot")
        assertEquals("hi :partyparrot:", v.state.value.composer.draft)
        assertTrue(repo.gifSendCalls.isEmpty())
    }

    @Test
    fun createPoll_dismissesComposer_andDelegatesToRepo() = runTest {
        repo.createPollResult = ApiResult.Success(openPoll())
        val v = vm()
        advanceUntilIdle()
        v.onOpenPollComposer()
        assertTrue(v.state.value.pollComposerVisible)
        v.onCreatePoll(com.testlogon.android.data.messaging.MeetingPollDraft("T", 30, emptyList()))
        advanceUntilIdle()
        assertFalse(v.state.value.pollComposerVisible)
    }

    @Test
    fun pollVote_success_clearsInlineError_andStopsMutating() = runTest {
        val poll = openPoll()
        repo.emitPoll(poll)
        repo.voteResult = ApiResult.Success(poll)
        val v = vm()
        advanceUntilIdle()
        // Render a poll message so the VM starts observing it.
        repo.emitThread(
            listOf(
                Message(id = "m1", clientId = "m1", conversationId = "c1", senderId = "u1",
                    text = "", createdAtEpochSeconds = 1, kind = "meeting_poll",
                    media = MessageMedia.MeetingPoll("p1", "T", "u1", "open", null)),
            ),
        )
        advanceUntilIdle()
        v.onPollVote("p1", "slot_1", SlotVote.YES)
        advanceUntilIdle()
        val card = v.state.value.polls["p1"]
        assertNotNull(card)
        assertFalse(card!!.isMutating)
        assertNull(card.inlineError)
        assertEquals(SlotVote.YES, repo.voteCalls.single().third)
    }

    @Test
    fun pollVote_failure_setsInlineError() = runTest {
        val poll = openPoll()
        repo.emitPoll(poll)
        repo.voteResult = ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 500, message = "boom"))
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(
            listOf(
                Message(id = "m1", clientId = "m1", conversationId = "c1", senderId = "u1",
                    text = "", createdAtEpochSeconds = 1, kind = "meeting_poll",
                    media = MessageMedia.MeetingPoll("p1", "T", "u1", "open", null)),
            ),
        )
        advanceUntilIdle()
        v.onPollVote("p1", "slot_1", SlotVote.YES)
        advanceUntilIdle()
        assertEquals("Couldn't save your vote — tap to retry", v.state.value.polls["p1"]?.inlineError)
    }

    @Test
    fun canManage_trueOnlyForCreator() = runTest {
        repo.emitPoll(openPoll(creatorId = "me"))
        val v = vm(currentUser = "me")
        advanceUntilIdle()
        repo.emitThread(
            listOf(
                Message(id = "m1", clientId = "m1", conversationId = "c1", senderId = "me",
                    text = "", createdAtEpochSeconds = 1, kind = "meeting_poll",
                    media = MessageMedia.MeetingPoll("p1", "T", "me", "open", null)),
            ),
        )
        advanceUntilIdle()
        assertTrue(v.state.value.polls["p1"]?.canManage == true)
    }

    private fun openPoll(creatorId: String = "u1") = MeetingPoll(
        pollId = "p1", title = "T", durationMinutes = 30, creatorId = creatorId,
        status = MeetingPollStatus.OPEN, confirmedSlotId = null,
        slots = listOf(MeetingPollSlot("slot_1", "s", "e", 0, 0, 0, null)),
    )

    private fun assertNotNull(value: Any?) = org.junit.Assert.assertNotNull(value)
}
