package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import com.testlogon.android.data.messaging.helpdesk.ClaimState as RoutingClaimState
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class HelpdeskDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeHelpdeskRepository()
    private val messaging = FakeMessagingRepository()
    private val auth = FakeAuthStateStore().apply { runBlocking { setAuthenticated("usr_me") } }

    private fun vm(initialAssignment: HelpdeskAssignment = HelpdeskAssignment.UNCLAIMED): HelpdeskDetailViewModel {
        val saved = SavedStateHandle(
            mapOf(
                HelpdeskDetailViewModel.ARG_CONVERSATION_ID to "conv_1",
                HelpdeskDetailViewModel.ARG_CLAIM_STATE to HelpdeskDetailViewModel.encodeAssignment(initialAssignment),
            ),
        )
        // Repo refresh on entry: keep the row-provided state by returning a miss.
        repo.refreshResult = ApiResult.Success(null)
        return HelpdeskDetailViewModel(saved, repo, messaging, auth)
    }

    @Test
    fun claimSuccess_enablesReply() = runTest {
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("conv_1", HelpdeskAssignment.ASSIGNED_TO_ME, "usr_me", 3, idempotent = false),
        )
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        val s = viewModel.uiState.value
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, s.assignment)
        assertTrue(s.replyEnabled)
        assertEquals(ClaimState.Idle, s.claim)
    }

    @Test
    fun idempotentReclaim_isSuccess() = runTest {
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("conv_1", HelpdeskAssignment.ASSIGNED_TO_ME, "usr_me", 3, idempotent = true),
        )
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, viewModel.uiState.value.assignment)
    }

    @Test
    fun concurrentLoser_200OtherAgent_isAssignedToOther_notError() = runTest {
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("conv_1", HelpdeskAssignment.ASSIGNED_TO_OTHER, "usr_other", 4, idempotent = false),
        )
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        val s = viewModel.uiState.value
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_OTHER, s.assignment)
        assertFalse(s.replyEnabled)
        assertEquals(ClaimState.Idle, s.claim) // 200 path -> not an error
    }

    @Test
    fun conflict409_mapsToAlreadyClaimed_andRefreshes() = runTest {
        repo.claimResult = ApiResult.Failure(ApiError(status = 409, message = "conflict"))
        repo.refreshResult = ApiResult.Success(
            HelpdeskQueueItem(
                conversationId = "conv_1", title = "T", preview = null,
                routingState = HelpdeskRoutingState.ASSIGNED, claimState = RoutingClaimState.CLAIMED_BY_OTHER,
                activeAgentUserId = "usr_other", unreadCount = 0, lastMessageAtEpochSeconds = 1,
            ),
        )
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        val s = viewModel.uiState.value
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_OTHER, s.assignment)
        val claim = s.claim
        assertTrue(claim is ClaimState.Failed)
        assertEquals(ClaimError.ALREADY_CLAIMED, (claim as ClaimState.Failed).error)
        assertFalse(claim.retryable)
    }

    @Test
    fun forbidden403_isForbiddenNonRetryable() = runTest {
        repo.claimResult = ApiResult.Failure(ApiError(status = 403, message = "no", code = "role_required"))
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        val claim = viewModel.uiState.value.claim
        assertTrue(claim is ClaimState.Failed)
        assertEquals(ClaimError.FORBIDDEN, (claim as ClaimState.Failed).error)
        assertFalse(claim.retryable)
    }

    @Test
    fun network_isRetryable_andRetryRefires() = runTest {
        repo.claimResult = ApiResult.NetworkError(java.io.IOException("down"))
        val viewModel = vm()
        advanceUntilIdle()
        viewModel.onClaimClick()
        advanceUntilIdle()
        val claim = viewModel.uiState.value.claim
        assertTrue(claim is ClaimState.Failed)
        assertEquals(ClaimError.NETWORK, (claim as ClaimState.Failed).error)
        assertTrue(claim.retryable)

        // Retry now succeeds.
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("conv_1", HelpdeskAssignment.ASSIGNED_TO_ME, "usr_me", 3, idempotent = false),
        )
        viewModel.onRetryClaim()
        advanceUntilIdle()
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, viewModel.uiState.value.assignment)
        assertEquals(2, repo.claimedIds.size) // claim issued exactly once per user action
    }

    @Test
    fun replyBlocked_untilAssignedToMe() = runTest {
        val viewModel = vm(initialAssignment = HelpdeskAssignment.UNCLAIMED)
        advanceUntilIdle()
        viewModel.onDraftChange("hello")
        viewModel.onSendReply() // no-op while unclaimed
        advanceUntilIdle()
        assertEquals("hello", viewModel.uiState.value.draft) // draft preserved, not sent

        // Claim, then send.
        messaging.sendResult = ApiResult.Success(
            Message(
                id = "m1", clientId = "c", conversationId = "conv_1", senderId = "usr_me",
                text = "hello", createdAtEpochSeconds = 1, sendStatus = SendStatus.SENT,
            ),
        )
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("conv_1", HelpdeskAssignment.ASSIGNED_TO_ME, "usr_me", 3, idempotent = false),
        )
        viewModel.onClaimClick()
        advanceUntilIdle()
        viewModel.onSendReply()
        advanceUntilIdle()
        assertEquals("", viewModel.uiState.value.draft) // sent -> draft cleared
    }

    @Test
    fun replyEnabled_derivationMatrix() {
        assertTrue(
            HelpdeskDetailUiState("c", assignment = HelpdeskAssignment.ASSIGNED_TO_ME).replyEnabled,
        )
        assertFalse(HelpdeskDetailUiState("c", assignment = HelpdeskAssignment.UNCLAIMED).replyEnabled)
        assertFalse(HelpdeskDetailUiState("c", assignment = HelpdeskAssignment.ASSIGNED_TO_OTHER).replyEnabled)
        assertFalse(HelpdeskDetailUiState("c", assignment = HelpdeskAssignment.CLOSED).replyEnabled)
    }
}
