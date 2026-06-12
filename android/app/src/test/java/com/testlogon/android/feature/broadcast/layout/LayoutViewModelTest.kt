package com.testlogon.android.feature.broadcast.layout

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastLayout
import com.testlogon.android.data.broadcast.InputsRepository
import com.testlogon.android.data.broadcast.LayoutMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-311 — unit tests for [LayoutViewModel]. Uses MainDispatcherRule + runCurrent (NEVER advanceUntilIdle,
 * which would spin the Eagerly-shared flow + the poll loop). Fake [LayoutRepository] + fake
 * [InputsRepository] expose mutable Flows so the test drives Room-cache emissions. The poll loop is exercised
 * only by an explicit startPolling()/runCurrent()/stopPolling() so runTest's end-of-test drain doesn't spin
 * the parked delay loop.
 */
class LayoutViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Fake layout repository: a mutable cache Flow + canned refresh / setLayout outcomes. */
    private class FakeLayoutRepo : LayoutRepository {
        val layout = MutableStateFlow<BroadcastLayout?>(null)

        var refreshResult: ApiResult<BroadcastLayout> =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList()))
        var setLayoutResult: ApiResult<BroadcastLayout> =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList()))

        var setLayoutCalls = 0
        var lastSetMode: String? = null

        override fun observeLayout(sessionId: String): Flow<BroadcastLayout?> = layout

        override suspend fun refresh(sessionId: String): ApiResult<BroadcastLayout> {
            if (refreshResult is ApiResult.Success) {
                layout.value = (refreshResult as ApiResult.Success).data
            }
            return refreshResult
        }

        override suspend fun setLayout(
            sessionId: String,
            mode: String,
            inputIds: List<String>?,
            primaryInputId: String?,
        ): ApiResult<BroadcastLayout> {
            setLayoutCalls++
            lastSetMode = mode
            if (setLayoutResult is ApiResult.Success) {
                layout.value = (setLayoutResult as ApiResult.Success).data
            }
            return setLayoutResult
        }
    }

    /** Minimal fake inputs repository (only observeInputs is exercised here). */
    private class FakeInputsRepo : InputsRepository {
        val inputs = MutableStateFlow<List<BroadcastInput>>(emptyList())

        override fun observeInputs(sessionId: String): Flow<List<BroadcastInput>> = inputs
        override fun observeLayout(sessionId: String): Flow<BroadcastLayout?> = MutableStateFlow(null)
        override suspend fun refresh(sessionId: String): ApiResult<List<BroadcastInput>> =
            ApiResult.Success(emptyList())
        override suspend fun refreshLayout(sessionId: String): ApiResult<BroadcastLayout> =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList()))
        override suspend fun setActive(
            sessionId: String,
            inputId: String,
            active: Boolean,
        ): ApiResult<List<BroadcastInput>> = ApiResult.Success(emptyList())
        override suspend fun setProgram(
            sessionId: String,
            inputId: String,
            mode: String,
        ): ApiResult<BroadcastLayout> =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList()))
    }

    private fun input(id: String, isLive: Boolean = true) = BroadcastInput(
        inputId = id,
        sessionId = SESSION,
        inputType = "guest",
        label = "Input $id",
        ingestUrl = null,
        streamKey = null,
        position = 0,
        isLive = isLive,
    )

    private fun vm(
        layoutRepo: LayoutRepository,
        inputsRepo: InputsRepository,
        sessionId: String? = SESSION,
    ): LayoutViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(LayoutViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return LayoutViewModel(saved, layoutRepo, inputsRepo)
    }

    @Test
    fun loading_thenContent_withFourCards_cachedModeIsLive() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        val vm = vm(layoutRepo, inputsRepo)
        assertEquals(LayoutUiState.Loading, vm.uiState.value)

        layoutRepo.layout.value = BroadcastLayout(LayoutMode.PIP, null, emptyList(), emptyList())
        runCurrent()

        val state = vm.uiState.value as LayoutUiState.Content
        assertEquals(4, state.cards.size)
        assertEquals(LayoutModeUi.PIP, state.currentMode)
        assertEquals(1, state.cards.count { it.isLive })
        assertTrue(state.cards.first { it.mode == LayoutModeUi.PIP }.isLive)
    }

    @Test
    fun selectCurrentMode_isNoOp() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        layoutRepo.layout.value = BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList())
        val vm = vm(layoutRepo, inputsRepo)
        runCurrent()

        vm.onSelectMode(LayoutModeUi.SINGLE)
        runCurrent()

        // Selecting the live mode must NOT POST (FR-5).
        assertEquals(0, layoutRepo.setLayoutCalls)
        assertNull((vm.uiState.value as LayoutUiState.Content).pendingMode)
    }

    @Test
    fun selectOther_optimisticPending_thenSuccessMovesBadge_andClearsPending() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        layoutRepo.layout.value = BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList())
        layoutRepo.setLayoutResult =
            ApiResult.Success(BroadcastLayout(LayoutMode.GRID, null, emptyList(), emptyList()))
        val vm = vm(layoutRepo, inputsRepo)
        runCurrent()

        vm.onSelectMode(LayoutModeUi.GRID)
        runCurrent()

        val state = vm.uiState.value as LayoutUiState.Content
        assertEquals("grid", layoutRepo.lastSetMode)
        assertNull(state.pendingMode)
        assertEquals(LayoutModeUi.GRID, state.currentMode)
        assertEquals(1, state.cards.count { it.isLive })
        assertTrue(state.cards.first { it.mode == LayoutModeUi.GRID }.isLive)
    }

    @Test
    fun selectOther_failure_rollsBack_andBanners() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        layoutRepo.layout.value = BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList())
        layoutRepo.setLayoutResult = ApiResult.Failure(ApiError(422, "nope"))
        val vm = vm(layoutRepo, inputsRepo)
        runCurrent()

        vm.onSelectMode(LayoutModeUi.PIP)
        runCurrent()

        val state = vm.uiState.value as LayoutUiState.Content
        assertNull(state.pendingMode)
        // Rolled back to the cached single mode.
        assertEquals(LayoutModeUi.SINGLE, state.currentMode)
        assertEquals("nope", state.banner)
    }

    @Test
    fun needsSource_trueWhenNoActiveInputs() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        layoutRepo.layout.value = BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList())
        val vm = vm(layoutRepo, inputsRepo)
        runCurrent()

        var state = vm.uiState.value as LayoutUiState.Content
        assertEquals(0, state.activeInputCount)
        assertTrue(state.cards.all { it.needsSource })

        inputsRepo.inputs.value = listOf(input("a", isLive = true))
        runCurrent()

        state = vm.uiState.value as LayoutUiState.Content
        assertEquals(1, state.activeInputCount)
        assertFalse(state.cards.any { it.needsSource })
    }

    @Test
    fun warmCache_setsStaleWhenRefreshFails() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        layoutRepo.layout.value = BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList())
        layoutRepo.refreshResult = ApiResult.NetworkError(java.io.IOException("offline"), isTimeout = false)
        val vm = vm(layoutRepo, inputsRepo)
        // Drive ONE poll iteration (refresh fails) without advanceUntilIdle, then stop the loop so runTest's
        // end-of-test drain doesn't spin the parked delay loop forever.
        vm.startPolling()
        runCurrent()
        vm.stopPolling()

        val state = vm.uiState.value as LayoutUiState.Content
        assertTrue(state.isStale)
    }

    @Test
    fun refreshSuccess_surfacesInMemoryPositions() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        val positions = listOf(
            com.testlogon.android.data.broadcast.LayoutPosition("a", 0.0, 0.0, 1280.0, 720.0, 0),
        )
        layoutRepo.refreshResult =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, listOf("a"), positions))
        val vm = vm(layoutRepo, inputsRepo)

        vm.startPolling()
        runCurrent()
        vm.stopPolling()

        val state = vm.uiState.value as LayoutUiState.Content
        // FR-4: positions come from the in-memory refresh, not Room.
        assertEquals(1, state.positions.size)
        assertEquals("a", state.positions.single().inputId)
    }

    @Test
    fun noSession_isColdError_notRetryable() = runTest {
        val layoutRepo = FakeLayoutRepo()
        val inputsRepo = FakeInputsRepo()
        val vm = vm(layoutRepo, inputsRepo, sessionId = null)
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is LayoutUiState.Error)
        assertFalse((state as LayoutUiState.Error).retryable)
        assertEquals(0, layoutRepo.setLayoutCalls)
    }

    private companion object {
        const val SESSION = "bcs_1"
    }
}
