package com.testlogon.android.feature.broadcast.inputs

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
 * AND-310 — unit tests for [InputsViewModel]. Uses MainDispatcherRule + runCurrent (never advanceUntilIdle,
 * which would spin the WhileSubscribed flow + the poll loop). A fake [InputsRepository] exposes mutable
 * Flows so the test drives Room-cache emissions, and the poll interval is left at default while a SINGLE
 * iteration is driven by runCurrent.
 */
class InputsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun input(
        id: String,
        isLive: Boolean = false,
    ) = BroadcastInput(
        inputId = id,
        sessionId = SESSION,
        inputType = "guest",
        label = "Input $id",
        ingestUrl = null,
        streamKey = null,
        position = 0,
        isLive = isLive,
    )

    private class FakeRepo : InputsRepository {
        val inputs = MutableStateFlow<List<BroadcastInput>>(emptyList())
        val layout = MutableStateFlow<BroadcastLayout?>(null)

        var refreshResult: ApiResult<List<BroadcastInput>> = ApiResult.Success(emptyList())
        var setActiveResult: ApiResult<List<BroadcastInput>> = ApiResult.Success(emptyList())
        var setProgramResult: ApiResult<BroadcastLayout> =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, null, emptyList(), emptyList()))

        var setActiveCalls = 0
        var lastSetActiveTarget: Boolean? = null
        var lastProgramMode: String? = null

        override fun observeInputs(sessionId: String): Flow<List<BroadcastInput>> = inputs
        override fun observeLayout(sessionId: String): Flow<BroadcastLayout?> = layout

        override suspend fun refresh(sessionId: String): ApiResult<List<BroadcastInput>> = refreshResult
        override suspend fun refreshLayout(sessionId: String): ApiResult<BroadcastLayout> = setProgramResult

        override suspend fun setActive(
            sessionId: String,
            inputId: String,
            active: Boolean,
        ): ApiResult<List<BroadcastInput>> {
            setActiveCalls++
            lastSetActiveTarget = active
            // Simulate the authoritative refetch updating the cache on success.
            if (setActiveResult is ApiResult.Success) {
                inputs.value = (setActiveResult as ApiResult.Success).data
            }
            return setActiveResult
        }

        override suspend fun setProgram(
            sessionId: String,
            inputId: String,
            mode: String,
        ): ApiResult<BroadcastLayout> {
            lastProgramMode = mode
            if (setProgramResult is ApiResult.Success) {
                layout.value = (setProgramResult as ApiResult.Success).data
            }
            return setProgramResult
        }
    }

    private fun vm(repo: InputsRepository, sessionId: String? = SESSION): InputsViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(InputsViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return InputsViewModel(saved, repo)
    }

    @Test
    fun loading_thenContent_whenCacheEmits() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        assertEquals(InputsUiState.Loading, vm.uiState.value)

        repo.inputs.value = listOf(input("a", isLive = false))
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is InputsUiState.Content)
        assertEquals("a", (state as InputsUiState.Content).inputs.single().input.inputId)
    }

    @Test
    fun activate_optimisticSuccess_keepsIsLiveAfterRefetch_andClearsPending() = runTest {
        val repo = FakeRepo()
        repo.inputs.value = listOf(input("a", isLive = false))
        // The authoritative refetch will report the input as live.
        repo.setActiveResult = ApiResult.Success(listOf(input("a", isLive = true)))
        val vm = vm(repo)
        runCurrent()

        vm.onToggleActive("a", target = true)
        runCurrent()

        val state = vm.uiState.value as InputsUiState.Content
        assertTrue(state.inputs.single().input.isLive)
        assertTrue(state.pendingIds.isEmpty())
        assertEquals(true, repo.lastSetActiveTarget)
    }

    @Test
    fun activate_failure_rollsBack_andBanners() = runTest {
        val repo = FakeRepo()
        repo.inputs.value = listOf(input("a", isLive = false))
        repo.setActiveResult = ApiResult.Failure(ApiError(422, "nope"))
        val vm = vm(repo)
        runCurrent()

        vm.onToggleActive("a", target = true)
        runCurrent()

        val state = vm.uiState.value as InputsUiState.Content
        // Optimistic overlay rolled back to the cached (false) value.
        assertFalse(state.inputs.single().input.isLive)
        assertTrue(state.pendingIds.isEmpty())
        assertEquals("nope", state.banner)
    }

    @Test
    fun makeLive_setsPrimary_exactlyOneProgram_priorDemoted() = runTest {
        val repo = FakeRepo()
        repo.inputs.value = listOf(input("a", isLive = true), input("b", isLive = true))
        repo.layout.value = BroadcastLayout(LayoutMode.SINGLE, primaryInputId = "a", emptyList(), emptyList())
        repo.setProgramResult =
            ApiResult.Success(BroadcastLayout(LayoutMode.SINGLE, primaryInputId = "b", emptyList(), emptyList()))
        val vm = vm(repo)
        runCurrent()

        // Initially "a" is the program.
        var rows = (vm.uiState.value as InputsUiState.Content).inputs
        assertTrue(rows.first { it.input.inputId == "a" }.input.isProgram)
        assertFalse(rows.first { it.input.inputId == "b" }.input.isProgram)

        vm.onMakeLive("b")
        runCurrent()

        rows = (vm.uiState.value as InputsUiState.Content).inputs
        assertEquals(LayoutMode.SINGLE, repo.lastProgramMode)
        assertEquals(1, rows.count { it.input.isProgram })
        assertTrue(rows.first { it.input.inputId == "b" }.input.isProgram)
        assertFalse(rows.first { it.input.inputId == "a" }.input.isProgram)
    }

    @Test
    fun canMakeLive_falseWhenNotLive_programCannotDeactivate() = runTest {
        val repo = FakeRepo()
        repo.inputs.value = listOf(input("a", isLive = false), input("b", isLive = true))
        repo.layout.value = BroadcastLayout(LayoutMode.SINGLE, primaryInputId = "b", emptyList(), emptyList())
        val vm = vm(repo)
        runCurrent()

        val rows = (vm.uiState.value as InputsUiState.Content).inputs
        val a = rows.first { it.input.inputId == "a" }
        val b = rows.first { it.input.inputId == "b" }
        // a is not live -> cannot make live.
        assertFalse(a.canMakeLive)
        // b is the program -> cannot make live (already program) and cannot deactivate.
        assertFalse(b.canMakeLive)
        assertFalse(b.canDeactivate)
        assertTrue(a.canDeactivate)
    }

    @Test
    fun warmCache_setsStaleWhenRefreshFails() = runTest {
        val repo = FakeRepo()
        repo.inputs.value = listOf(input("a"))
        repo.refreshResult = ApiResult.NetworkError(java.io.IOException("offline"), isTimeout = false)
        val vm = vm(repo)
        // Drive a single poll iteration (refresh fails) without advanceUntilIdle, then stop the loop so
        // runTest's end-of-test drain doesn't spin the (parked) delay loop forever.
        vm.startPolling()
        runCurrent()
        vm.stopPolling()

        val state = vm.uiState.value as InputsUiState.Content
        assertTrue(state.isStale)
    }

    @Test
    fun noSession_isColdError_notRetryable() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo, sessionId = null)
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is InputsUiState.Error)
        assertFalse((state as InputsUiState.Error).retryable)
        assertEquals(0, repo.setActiveCalls)
        assertNull(repo.lastProgramMode)
    }

    private companion object {
        const val SESSION = "bcs_1"
    }
}
