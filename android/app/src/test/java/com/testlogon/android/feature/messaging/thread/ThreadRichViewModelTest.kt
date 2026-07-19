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

    private val billing = com.testlogon.android.feature.messaging.FakeBillingAuthorizer()

    private suspend fun vm(currentUser: String = "me"): ThreadViewModel {
        auth.setAuthenticated(currentUser)
        repo.historyResult = ApiResult.Success(emptyList())
        val handle = SavedStateHandle(mapOf(ThreadViewModel.ARG_CONVERSATION_ID to "c1"))
        val context = org.mockito.Mockito.mock(android.content.Context::class.java)
        return com.testlogon.android.feature.messaging.newThreadViewModel(
            handle, repo, auth, stream, context,
            billing,
            com.testlogon.android.feature.messaging.FakeDraftRepository(),
            com.testlogon.android.feature.messaging.FakeTypingRepository(),
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

    // ---- AND-137: countdown VM ----

    @Test
    fun sendCountdown_validFutureTarget_enqueuesOptimistic_andSends() = runTest {
        repo.countdownSendResult = ApiResult.Success(
            Message(id = "cd1", clientId = "cid", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, kind = "countdown",
                media = MessageMedia.Countdown("Launch", 9999L)),
        )
        val v = vm()
        advanceUntilIdle()
        v.onOpenCountdownPicker()
        v.onCountdownTitleChange("Launch")
        v.onCountdownTargetChange(9999L) // > clock()==1000
        v.onSendCountdown()
        advanceUntilIdle()
        assertFalse(v.state.value.countdownPicker.visible)
        assertEquals(1, repo.countdownSendCalls.size)
        assertEquals("Launch", repo.countdownSendCalls.single().third.title)
        assertEquals(1, repo.enqueuedCountdowns.size)
    }

    @Test
    fun sendCountdown_pastTarget_blockedWithInlineError() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onOpenCountdownPicker()
        v.onCountdownTitleChange("Launch")
        v.onCountdownTargetChange(500L) // < clock()==1000
        v.onSendCountdown()
        advanceUntilIdle()
        assertTrue(v.state.value.countdownPicker.visible)
        assertEquals("Pick a future time", v.state.value.countdownPicker.error)
        assertTrue(repo.countdownSendCalls.isEmpty())
    }

    @Test
    fun sendCountdown_blankTitle_blocked() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onOpenCountdownPicker()
        v.onCountdownTargetChange(9999L)
        v.onSendCountdown()
        advanceUntilIdle()
        assertTrue(repo.countdownSendCalls.isEmpty())
        assertNotNull(v.state.value.countdownPicker.error)
    }

    // ---- MSG: new in-app composers VM ----

    @Test
    fun sendLottery_twoOutcomes_dismissesAndCallsRepo() = runTest {
        repo.lotteryResult = ApiResult.Success(
            Message(id = "lot1", clientId = "lot1", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, kind = "lottery_dm"),
        )
        val v = vm()
        advanceUntilIdle()
        v.onAttachLottery()
        assertTrue(v.state.value.lotteryComposerVisible)
        v.onSendLottery(
            listOf(
                com.testlogon.android.data.messaging.LotteryOutcomeDraft("A", "win"),
                com.testlogon.android.data.messaging.LotteryOutcomeDraft("B", "lose"),
            ),
        )
        advanceUntilIdle()
        assertFalse(v.state.value.lotteryComposerVisible)
        assertEquals(1, repo.lotteryCalls.size)
        assertEquals(2, repo.lotteryCalls.single().second.size)
    }

    @Test
    fun sendLottery_singleOutcome_blocked() = runTest {
        val v = vm()
        advanceUntilIdle()
        v.onAttachLottery()
        v.onSendLottery(listOf(com.testlogon.android.data.messaging.LotteryOutcomeDraft(null, "only")))
        advanceUntilIdle()
        assertTrue(repo.lotteryCalls.isEmpty())
    }

    @Test
    fun sendFindDateTime_callsRepo_andDismisses() = runTest {
        repo.findDateTimeResult = ApiResult.Success(
            Message(id = "f1", clientId = "f1", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, kind = "find_datetime"),
        )
        val v = vm()
        advanceUntilIdle()
        v.onAttachFindDateTime()
        assertTrue(v.state.value.findDateTimeComposerVisible)
        v.onSendFindDateTime(
            com.testlogon.android.data.messaging.FindDateTimeDraft(
                title = "Sync", fromDate = "2026-07-01", toDate = "2026-07-03",
                startHour = 9, endHour = 17, slotDurationMinutes = 30,
            ),
        )
        advanceUntilIdle()
        assertFalse(v.state.value.findDateTimeComposerVisible)
        assertEquals(1, repo.findDateTimeCalls.size)
        assertEquals("Sync", repo.findDateTimeCalls.single().second.title)
    }

    @Test
    fun sendFileShare_callsShareFile_withReadPermission() = runTest {
        repo.shareFileResult = ApiResult.Success(
            Message(id = "fs1", clientId = "fs1", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, kind = "file_share"),
        )
        val v = vm()
        advanceUntilIdle()
        v.onSendFileShare("/docs/report.pdf")
        advanceUntilIdle()
        assertFalse(v.state.value.fileShareComposer.visible)
        assertEquals(1, repo.shareFileCalls.size)
        assertEquals("/docs/report.pdf", repo.shareFileCalls.single().second)
        assertEquals("read", repo.shareFileCalls.single().third)
    }

    @Test
    fun encryptedToggle_routesSendThroughEncryptedPath() = runTest {
        repo.encryptedResult = ApiResult.Success(
            Message(id = "e1", clientId = "e1", conversationId = "c1", senderId = "me",
                text = "", createdAtEpochSeconds = 1, kind = "text", isEncrypted = true),
        )
        val v = vm()
        advanceUntilIdle()
        v.setEncrypted(true)
        v.onDraftChange("secret")
        v.onSend()
        advanceUntilIdle()
        assertEquals(1, repo.encryptedCalls.size)
    }

    // ---- AND-139: unlock / tip / lottery VM ----

    private fun lockedFixed(key: String = "m1", sender: String = "u2") = Message(
        id = key, clientId = key, conversationId = "c1", senderId = sender,
        text = "", createdAtEpochSeconds = 1, kind = "text",
        media = MessageMedia.Paid(
            com.testlogon.android.data.messaging.MessageMonetization(
                type = com.testlogon.android.data.messaging.UnlockType.FIXED,
                unlocked = false, priceMinorUnits = 500, currency = "USD", teaser = "preview",
            ),
        ),
    )

    @Test
    fun unlockFixed_authorized_callsServerUnlock() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.Authorized("pm_1", 0L)
        repo.unlockResult = ApiResult.Success(lockedFixed().copy(
            media = MessageMedia.Paid(
                com.testlogon.android.data.messaging.MessageMonetization(
                    com.testlogon.android.data.messaging.UnlockType.FIXED, true, 500, "USD", null, "revealed"),
            ),
        ))
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onUnlockClick("m1")
        advanceUntilIdle()
        assertEquals(1, repo.unlockCalls.size)
        assertEquals("pm_1", repo.unlockCalls.single().third)
        // phase cleared on success.
        assertEquals(UnlockPhase.IDLE, (v.state.value.unlocks["m1"]?.phase ?: UnlockPhase.IDLE))
    }

    @Test
    fun unlockFixed_billingCancelled_doesNotCallServer() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.Cancelled
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onUnlockClick("m1")
        advanceUntilIdle()
        assertTrue(repo.unlockCalls.isEmpty())
    }

    @Test
    fun unlockFixed_billingDeclined_failsWithDistinctMessage_noServerCall() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.Declined("card_declined")
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onUnlockClick("m1")
        advanceUntilIdle()
        assertTrue(repo.unlockCalls.isEmpty())
        assertEquals(UnlockPhase.FAILED, v.state.value.unlocks["m1"]?.phase)
        assertTrue(v.state.value.unlocks["m1"]?.error?.contains("declined") == true)
    }

    @Test
    fun unlockFixed_notConfigured_flagsPaymentsUnavailable_noServerCall() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.NotConfigured
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onUnlockClick("m1")
        advanceUntilIdle()
        assertTrue(repo.unlockCalls.isEmpty())
        assertEquals(UnlockPhase.FAILED, v.state.value.unlocks["m1"]?.phase)
    }

    @Test
    fun unlockLottery_singleServerCall_noBillingAuthorize() = runTest {
        repo.lotteryUnlockResult = ApiResult.Success(
            Message(id = "lot1", clientId = "lot1", conversationId = "c1", senderId = "u2",
                text = "", createdAtEpochSeconds = 1, kind = "lottery_dm",
                media = MessageMedia.Paid(
                    com.testlogon.android.data.messaging.MessageMonetization(
                        com.testlogon.android.data.messaging.UnlockType.LOTTERY, true, null, "USD", null, "win"),
                )),
        )
        val lottery = Message(id = "lot1", clientId = "lot1", conversationId = "c1", senderId = "u2",
            text = "", createdAtEpochSeconds = 1, kind = "lottery_dm",
            media = MessageMedia.Paid(
                com.testlogon.android.data.messaging.MessageMonetization(
                    com.testlogon.android.data.messaging.UnlockType.LOTTERY, false, null, "USD", null),
            ))
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lottery))
        advanceUntilIdle()
        v.onUnlockClick("lot1")
        advanceUntilIdle()
        assertEquals(1, repo.lotteryUnlockCalls.size)
        assertTrue(billing.authorizeCalls.isEmpty()) // no client-side billing for lottery
    }

    @Test
    fun ownMessage_unlockIsSuppressed() = runTest {
        val v = vm(currentUser = "me")
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed(sender = "me")))
        advanceUntilIdle()
        v.onUnlockClick("m1")
        advanceUntilIdle()
        assertTrue(repo.unlockCalls.isEmpty())
    }

    @Test
    fun tip_validAmount_authorizesAndSends_thenConfirms() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.Authorized("pm_1", 0L)
        repo.tipResult = ApiResult.Success(
            com.testlogon.android.data.messaging.TipReceipt("tpay_1", 500, "USD"),
        )
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onTipOpen("m1")
        v.onTipPresetSelect(500)
        v.onTipConfirm()
        advanceUntilIdle()
        assertEquals(1, repo.tipCalls.size)
        assertEquals(500L, repo.tipCalls.single().amountCents)
        assertNull(v.state.value.tipSheet.messageId) // sheet closed
        assertTrue(v.state.value.transientMessage?.startsWith("Tip sent") == true) // now "Tip sent · $5.00"
    }

    @Test
    fun tip_outOfRangeCustomAmount_blocked() = runTest {
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onTipOpen("m1")
        v.onTipCustomChange("0") // below min
        v.onTipConfirm()
        advanceUntilIdle()
        assertTrue(repo.tipCalls.isEmpty())
        assertNotNull(v.state.value.tipSheet.amountError)
        assertNotNull(v.state.value.tipSheet.messageId) // sheet stays open
    }

    @Test
    fun tip_failure_keepsSheetOpenWithError() = runTest {
        billing.result = com.testlogon.android.data.messaging.BillingResult.Authorized("pm_1", 0L)
        repo.tipResult = FakeMessagingRepository.failure(422, "bad")
        val v = vm()
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed()))
        advanceUntilIdle()
        v.onTipOpen("m1")
        v.onTipPresetSelect(500)
        v.onTipConfirm()
        advanceUntilIdle()
        assertNotNull(v.state.value.tipSheet.messageId)
        assertEquals(500L, v.state.value.tipSheet.selectedCents)
        assertNotNull(v.state.value.tipSheet.amountError)
    }

    @Test
    fun tip_ownMessage_doesNotOpenSheet() = runTest {
        val v = vm(currentUser = "me")
        advanceUntilIdle()
        repo.emitThread(listOf(lockedFixed(sender = "me")))
        advanceUntilIdle()
        v.onTipOpen("m1")
        assertNull(v.state.value.tipSheet.messageId)
    }
}
