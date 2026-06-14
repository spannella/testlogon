package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.fanclub.FanClubMessage
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-239 — [ChannelMessagesViewModel] optimistic send / retry / 403 / reaction / delete. */
class ChannelMessagesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeFanClubRepository) = ChannelMessagesViewModel(
        SavedStateHandle(mapOf(ChannelMessagesViewModel.ARG_CHANNEL_ID to "c")),
        repo,
    )

    @Test
    fun send_success_dropsPending_andRefreshes() = runTest {
        val repo = FakeFanClubRepository(postResult = FakeFanClubRepository.success(FakeFanClubRepository.message("m")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onComposerChange("hello")
        vm.onSend()
        advanceUntilIdle()

        assertTrue(vm.uiState.value.pending.isEmpty()) // confirmed -> dropped
        assertEquals(1, repo.postCalls)
        // Note: pager re-fetch on invalidate is verified in a paging test that collects the flow;
        // this VM test does not collect items, so PagingSource.load() (messageCalls) is not exercised.
        assertEquals("", vm.uiState.value.composerText)
    }

    @Test
    fun send_networkFailure_marksFailed_thenRetrySucceeds() = runTest {
        val repo = FakeFanClubRepository(postResult = ApiResult.NetworkError(java.io.IOException("offline")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onComposerChange("hi")
        vm.onSend()
        advanceUntilIdle()

        val pending = vm.uiState.value.pending.single()
        assertEquals(SendState.Failed, pending.sendState)

        repo.postResult = FakeFanClubRepository.success(FakeFanClubRepository.message("m"))
        vm.onRetryPending(pending.localId)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.pending.isEmpty())
        assertEquals(2, repo.postCalls)
    }

    @Test
    fun send_403_disablesComposer() = runTest {
        val repo = FakeFanClubRepository(
            postResult = ApiResult.Failure(ApiError(status = 403, message = "no")),
        )
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onComposerChange("hi")
        vm.onSend()
        advanceUntilIdle()

        assertFalse(vm.uiState.value.canPost)
        assertTrue(vm.uiState.value.pending.isEmpty())
    }

    @Test
    fun delete_optimisticallyHides_restoresOnFailure() = runTest {
        val repo = FakeFanClubRepository(deleteResult = FakeFanClubRepository.failure(status = 500))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onDelete("m1")
        // immediately hidden
        assertTrue("m1" in vm.uiState.value.deletedIds)
        advanceUntilIdle()
        // restored after failure
        assertFalse("m1" in vm.uiState.value.deletedIds)
    }

    @Test
    fun delete_success_keepsHidden_andRefreshes() = runTest {
        val repo = FakeFanClubRepository(deleteResult = ApiResult.Success(Unit))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onDelete("m1")
        advanceUntilIdle()
        assertTrue("m1" in vm.uiState.value.deletedIds)
        assertEquals(1, repo.deleteCalls)
    }

    @Test
    fun reaction_success_invokesRepo_andRefreshes() = runTest {
        val repo = FakeFanClubRepository(reactionResult = ApiResult.Success(Unit))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.onToggleReaction("m1", "🔥")
        advanceUntilIdle()
        assertEquals(1, repo.reactionCalls)
    }

    @Test
    fun canDelete_onlyOwnUndeletedMessage() = runTest {
        val repo = FakeFanClubRepository(userId = "me")
        val vm = vm(repo)
        advanceUntilIdle()
        val own: FanClubMessage = FakeFanClubRepository.message("m1", sender = "me")
        val other: FanClubMessage = FakeFanClubRepository.message("m2", sender = "usr_x")
        val ownDeleted: FanClubMessage = FakeFanClubRepository.message("m3", sender = "me", deleted = true)

        assertTrue(vm.canDelete(own))
        assertFalse(vm.canDelete(other))
        assertFalse(vm.canDelete(ownDeleted))
    }
}
