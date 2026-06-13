package com.testlogon.android.feature.kyc.liveness

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.kyc.liveness.data.LivenessCallRepository
import com.testlogon.android.feature.kyc.liveness.model.LivenessCall
import com.testlogon.android.feature.kyc.liveness.model.LivenessCallStatus
import com.testlogon.android.feature.kyc.liveness.model.LivenessResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-324 - unit tests for [LivenessCallViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop, so tests use only runCurrent() — NEVER advanceUntilIdle.
 * Helper funcs that call runCurrent are [TestScope] extensions; no nested runTest. A fake repo records
 * the schedule / cancel call counts + serves queued results (and can gate one schedule to exercise the
 * in-flight debounce).
 */
class LivenessCallViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : LivenessCallRepository {
        var scheduleCalls = 0
        var cancelCalls = 0
        var listResult: ApiResult<List<LivenessCall>> = ApiResult.Success(emptyList())
        val scheduleResults: ArrayDeque<ApiResult<LivenessCall>> = ArrayDeque()
        var cancelResult: ApiResult<LivenessCall> = ApiResult.Success(call("call_x", LivenessCallStatus.CANCELLED))

        // Optional gate to hold a schedule in flight (exercises the debounce).
        var scheduleGate: CompletableDeferred<Unit>? = null

        override suspend fun schedule(
            caseId: String,
            scheduledAtEpochSec: Long,
            durationMinutes: Int,
            note: String?,
        ): ApiResult<LivenessCall> {
            scheduleCalls++
            scheduleGate?.await()
            return if (scheduleResults.isEmpty()) {
                ApiResult.Success(call("call_new", LivenessCallStatus.SCHEDULED))
            } else {
                scheduleResults.removeFirst()
            }
        }

        override suspend fun list(): ApiResult<List<LivenessCall>> = listResult

        override suspend fun getCall(callId: String): ApiResult<LivenessCall> =
            ApiResult.Success(call(callId, LivenessCallStatus.SCHEDULED))

        override suspend fun cancel(callId: String): ApiResult<LivenessCall> {
            cancelCalls++
            return cancelResult
        }
    }

    private fun vm(
        repo: FakeRepo = FakeRepo(),
        caseId: String? = "kyc_1",
    ): LivenessCallViewModel {
        val saved = SavedStateHandle().apply {
            if (caseId != null) set(LivenessCallViewModel.ARG_CASE_ID, caseId)
        }
        return LivenessCallViewModel(repo, saved)
    }

    @Test
    fun init_loadsList_intoReady() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(listOf(call("call_1", LivenessCallStatus.SCHEDULED)))
        }
        val viewModel = vm(repo)
        // Before the launched list fetch runs, the state is Loading.
        assertTrue(viewModel.uiState.value is LivenessUiState.Loading)

        runCurrent()
        val state = viewModel.uiState.value as LivenessUiState.Ready
        assertEquals(1, state.calls.size)
        assertEquals("call_1", state.calls[0].callId)
        assertFalse(state.scheduling)
    }

    @Test
    fun schedule_setsScheduling_thenRefreshes_andClears() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(emptyList())
            scheduleResults.addLast(ApiResult.Success(call("call_new", LivenessCallStatus.SCHEDULED)))
            scheduleGate = CompletableDeferred()
        }
        val viewModel = vm(repo)
        runCurrent()
        // After the schedule completes, the list shows the new call.
        repo.listResult = ApiResult.Success(listOf(call("call_new", LivenessCallStatus.SCHEDULED)))

        viewModel.schedule(scheduledAtEpochSec = 1_780_000_000L, durationMinutes = 15)
        runCurrent()
        // Held in flight by the gate -> scheduling == true.
        assertTrue((viewModel.uiState.value as LivenessUiState.Ready).scheduling)

        repo.scheduleGate?.complete(Unit)
        runCurrent()
        val state = viewModel.uiState.value as LivenessUiState.Ready
        assertFalse(state.scheduling)
        assertNull(state.formError)
        assertEquals(1, state.calls.size)
        assertEquals(1, repo.scheduleCalls)
    }

    @Test
    fun schedule_422_setsFormError() = runTest {
        val repo = FakeRepo().apply {
            scheduleResults.addLast(ApiResult.Failure(ApiError(422, "scheduled_at required")))
        }
        val viewModel = vm(repo)
        runCurrent()

        viewModel.schedule(scheduledAtEpochSec = 1_780_000_000L, durationMinutes = 15)
        runCurrent()
        val state = viewModel.uiState.value as LivenessUiState.Ready
        assertFalse(state.scheduling)
        assertEquals("scheduled_at required", state.formError)
    }

    @Test
    fun schedule_debounce_ignoresSecondWhileInFlight() = runTest {
        val repo = FakeRepo().apply { scheduleGate = CompletableDeferred() }
        val viewModel = vm(repo)
        runCurrent()

        viewModel.schedule(scheduledAtEpochSec = 1_780_000_000L, durationMinutes = 15)
        runCurrent()
        // Second schedule while the first is still in flight is ignored.
        viewModel.schedule(scheduledAtEpochSec = 1_780_000_500L, durationMinutes = 30)
        runCurrent()
        assertEquals(1, repo.scheduleCalls)

        repo.scheduleGate?.complete(Unit)
        runCurrent()
    }

    @Test
    fun cancel_refreshesList() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(listOf(call("call_1", LivenessCallStatus.SCHEDULED)))
        }
        val viewModel = vm(repo)
        runCurrent()
        // After cancel the list reflects the cancelled status.
        repo.listResult = ApiResult.Success(listOf(call("call_1", LivenessCallStatus.CANCELLED)))

        viewModel.cancel("call_1")
        runCurrent()
        assertEquals(1, repo.cancelCalls)
        val state = viewModel.uiState.value as LivenessUiState.Ready
        assertEquals(LivenessCallStatus.CANCELLED, state.calls[0].status)
    }

    @Test
    fun onJoinClicked_returnsJoinUrl() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(
                listOf(call("call_1", LivenessCallStatus.IN_PROGRESS, joinUrl = "https://verify.example/join/abc")),
            )
        }
        val viewModel = vm(repo)
        runCurrent()

        assertEquals("https://verify.example/join/abc", viewModel.onJoinClicked("call_1"))
        assertNull(viewModel.onJoinClicked("missing"))
    }

    @Test
    fun blankCaseId_isNonRecoverableError_andScheduleIsNoOp() = runTest {
        val repo = FakeRepo()
        val viewModel = vm(repo, caseId = null)
        val state = viewModel.uiState.value as LivenessUiState.Error
        assertFalse(state.recoverable)

        // schedule is a no-op (no Ready state, blank case).
        viewModel.schedule(scheduledAtEpochSec = 1_780_000_000L, durationMinutes = 15)
        runCurrent()
        assertEquals(0, repo.scheduleCalls)
    }

    @Test
    fun listFailure_onInit_isRecoverableError() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Failure(ApiError(500, "boom")) }
        val viewModel = vm(repo)
        runCurrent()
        val state = viewModel.uiState.value as LivenessUiState.Error
        assertTrue(state.recoverable)
        assertEquals("boom", state.message)
    }

    private companion object {
        fun call(
            callId: String,
            status: LivenessCallStatus,
            joinUrl: String? = null,
            result: LivenessResult? = null,
        ) = LivenessCall(
            callId = callId,
            caseId = "kyc_1",
            status = status,
            scheduledAt = Instant.ofEpochSecond(1_780_000_000L),
            durationMinutes = 15,
            result = result,
            joinUrl = joinUrl,
        )
    }
}
