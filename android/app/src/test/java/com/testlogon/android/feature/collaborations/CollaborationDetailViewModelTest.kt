package com.testlogon.android.feature.collaborations

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.collaborations.testing.FakeCollabAuthStore
import com.testlogon.android.feature.collaborations.testing.FakeCollaborationsRepo
import com.testlogon.android.feature.collaborations.ui.CollaborationDetailUiState
import com.testlogon.android.feature.collaborations.ui.CollaborationDetailViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-358 - tests for [CollaborationDetailViewModel]: load -> Content (+ split distributions, tolerating a
 * splits failure); a 401-after-refresh -> SessionExpired; a non-401 refresh failure KEEPS the last-good
 * Content with isStale=true (in-memory); the split-total warning flag is surfaced via splitTotalsOk. Uses
 * runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CollaborationDetailViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private fun vm(
        repo: FakeCollaborationsRepo,
        collabId: String = "c1",
        viewerId: String? = "usr_a",
    ) = CollaborationDetailViewModel(
        repository = repo,
        savedState = SavedStateHandle(mapOf(CollaborationDetailViewModel.ARG_COLLAB_ID to collabId)),
        authStateStore = FakeCollabAuthStore(viewerId),
    )

    private fun content(vm: CollaborationDetailViewModel): CollaborationDetailUiState.Content =
        vm.uiState.value as CollaborationDetailUiState.Content

    @Test
    fun load_success_isContent_withDistributions() = runTest {
        val repo = FakeCollaborationsRepo(
            splitsResult = ApiResult.Success(
                listOf(SplitDistribution(userId = "usr_a", percent = 60, amountCents = 6000)),
            ),
        )
        val vm = vm(repo)
        runCurrent()

        val state = content(vm)
        assertEquals("Track", state.collab.title)
        assertFalse(state.isStale)
        assertEquals(1, state.distributions.size)
        assertEquals(6000, state.distributions.single().amountCents)
        // viewer id is exposed for the split-row highlight
        assertEquals("usr_a", vm.viewerId)
    }

    @Test
    fun load_splitsFailure_isTolerated_emptyDistributions() = runTest {
        val repo = FakeCollaborationsRepo(splitsResult = FakeCollaborationsRepo.failure(status = 500))
        val vm = vm(repo)
        runCurrent()

        val state = content(vm)
        assertTrue(state.distributions.isEmpty())
        assertEquals("Track", state.collab.title)
    }

    @Test
    fun load_splitTotalsOk_surfacedOnContent() = runTest {
        // off-by-one split -> splitTotalsOk false (drives the non-blocking warning at the UI)
        val repo = FakeCollaborationsRepo(
            collaborationResult = ApiResult.Success(
                Collaboration(
                    id = "c1", title = "Track", status = "active", statusEnum = CollabStatus.ACTIVE,
                    initiatorId = "usr_a", recipientId = "usr_b",
                    split = mapOf("usr_a" to 60, "usr_b" to 39),
                ),
            ),
        )
        val vm = vm(repo)
        runCurrent()

        assertFalse(content(vm).collab.splitTotalsOk)
        assertEquals(99, content(vm).collab.splitTotalPercent)
    }

    @Test
    fun load_401_isSessionExpired() = runTest {
        val repo = FakeCollaborationsRepo(collaborationResult = FakeCollaborationsRepo.failure(status = 401))
        val vm = vm(repo)
        runCurrent()
        assertEquals(CollaborationDetailUiState.SessionExpired, vm.uiState.value)
    }

    @Test
    fun load_nonAuthFailure_isError() = runTest {
        val repo = FakeCollaborationsRepo(collaborationResult = FakeCollaborationsRepo.failure(status = 500))
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is CollaborationDetailUiState.Error)
    }

    @Test
    fun refreshFailure_keepsLastGoodContent_andSetsStale() = runTest {
        val repo = FakeCollaborationsRepo()
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is CollaborationDetailUiState.Content)

        repo.collaborationResult = FakeCollaborationsRepo.failure(status = 500)
        vm.refresh()
        runCurrent()

        val state = content(vm)
        assertTrue(state.isStale)
        assertEquals("Track", state.collab.title)
    }

    @Test
    fun refresh401_isSessionExpired_evenWithPriorContent() = runTest {
        val repo = FakeCollaborationsRepo()
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is CollaborationDetailUiState.Content)

        repo.collaborationResult = FakeCollaborationsRepo.failure(status = 401)
        vm.refresh()
        runCurrent()

        assertEquals(CollaborationDetailUiState.SessionExpired, vm.uiState.value)
    }
}
