package com.testlogon.android.feature.broadcast.privateshow

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastMonetizationRepository
import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSession
import com.testlogon.android.data.broadcast.PrivateShowSummary
import com.testlogon.android.data.broadcast.PrivateStatus
import com.testlogon.android.data.broadcast.TipConfig
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-315 — unit tests for [PrivateShowViewModel].
 *
 * ANTI-HANG DISCIPLINE (CRITICAL): the request poll loop and the cost ticker are NEVER auto-started; every
 * test that starts them ALWAYS reaches Ended or calls stopPolling() BEFORE finishing, and uses bounded
 * advanceTimeBy(n) — NEVER advanceUntilIdle (which would spin the parked delay loops forever).
 */
class PrivateShowViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Configurable fake monetization repo (only the private-show methods matter here). */
    private class FakeRepo : BroadcastMonetizationRepository {
        var statusResult: ApiResult<PrivateStatus> = ApiResult.Success(idle())
        var requestsResult: ApiResult<List<PrivateShowRequest>> = ApiResult.Success(emptyList())
        var acceptResult: ApiResult<PrivateShowSession> =
            ApiResult.Success(session(startedAt = Instant.ofEpochSecond(1_000)))
        var endResult: ApiResult<PrivateShowSummary> =
            ApiResult.Success(PrivateShowSummary("ps_1", "bcs_1", "ended", 180, 1_500, "host"))
        var declineResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var acceptCalls = 0
        var endCalls = 0

        override suspend fun getSessionTipConfig(sessionId: String): ApiResult<TipConfig> =
            ApiResult.Success(TipConfig(false, null, null))
        override suspend fun saveTipConfig(
            sessionId: String,
            enabled: Boolean?,
            minCents: Long?,
            maxCents: Long?,
        ): ApiResult<TipConfig> = ApiResult.Success(TipConfig(false, null, null))

        override suspend fun listPrivateRequests(sessionId: String): ApiResult<List<PrivateShowRequest>> =
            requestsResult
        override suspend fun getPrivateStatus(sessionId: String): ApiResult<PrivateStatus> = statusResult
        override suspend fun acceptPrivateRequest(
            sessionId: String,
            requestId: String,
            behavior: String,
        ): ApiResult<PrivateShowSession> {
            acceptCalls++
            return acceptResult
        }
        override suspend fun declinePrivateRequest(sessionId: String, requestId: String): ApiResult<Unit> =
            declineResult
        override suspend fun endPrivateSession(
            sessionId: String,
            privateSessionId: String,
        ): ApiResult<PrivateShowSummary> {
            endCalls++
            return endResult
        }
    }

    private fun vm(repo: FakeRepo, now: Instant = Instant.ofEpochSecond(1_000)): PrivateShowViewModel {
        val saved = SavedStateHandle(mapOf(PrivateShowViewModel.ARG_SESSION_ID to SESSION))
        return PrivateShowViewModel(saved, repo).also { it.now = { now } }
    }

    @Test
    fun refreshStatus_idle_rehydratesIdle() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(idle())
        val vm = vm(repo)

        vm.refreshStatus()
        runCurrent()

        assertTrue(vm.uiState.value.state is PrivateShowState.Idle)
    }

    @Test
    fun refreshStatus_pending_rehydratesPending() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(
            PrivateStatus("pending", "req_1", null, SESSION, "v_1", "Jordan", 500, null, null, null),
        )
        val vm = vm(repo)

        vm.refreshStatus()
        runCurrent()

        val state = vm.uiState.value.state as PrivateShowState.Pending
        assertEquals("req_1", state.request.requestId)
        assertEquals(500L, state.request.ratePerMinuteCents)
    }

    @Test
    fun refreshStatus_active_rehydratesActive_thenStopPolling() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(
            PrivateStatus(
                "active", "req_1", "ps_1", SESSION, "v_1", "Jordan", 600, "pause", "call_1",
                Instant.ofEpochSecond(940),
            ),
        )
        val vm = vm(repo, now = Instant.ofEpochSecond(1_000))

        vm.refreshStatus()
        runCurrent()

        val state = vm.uiState.value.state as PrivateShowState.Active
        assertEquals("ps_1", state.session.privateSessionId)
        // 60s elapsed at 600 cents/min -> 600 cents accrued (client estimate).
        assertEquals(60L, state.elapsedSeconds)
        assertEquals(600L, state.accruedCents)

        // The active rehydrate armed the cost ticker -> stop it before the test ends.
        vm.stopPolling()
    }

    @Test
    fun poll_foldsIdleToPending_onNewRequest_thenStopPolling() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(idle())
        repo.requestsResult = ApiResult.Success(
            listOf(request("req_1", rate = 500)),
        )
        val vm = vm(repo)
        vm.pollIntervalMillis = 5_000L

        vm.startPolling()
        runCurrent() // ONE iteration: status idle -> fold requests -> Pending.
        vm.stopPolling()

        val state = vm.uiState.value.state as PrivateShowState.Pending
        assertEquals("req_1", state.request.requestId)
    }

    @Test
    fun accept_pendingToActive_viaRest() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(
            PrivateStatus("pending", "req_1", null, SESSION, "v_1", "Jordan", 500, null, null, null),
        )
        repo.acceptResult = ApiResult.Success(session(rate = 500, startedAt = Instant.ofEpochSecond(1_000)))
        val vm = vm(repo, now = Instant.ofEpochSecond(1_000))
        vm.refreshStatus()
        runCurrent()
        assertTrue(vm.uiState.value.state is PrivateShowState.Pending)

        vm.accept("req_1")
        runCurrent()

        assertEquals(1, repo.acceptCalls)
        assertTrue(vm.uiState.value.state is PrivateShowState.Active)
        // Active armed the ticker -> stop it before finishing.
        vm.stopPolling()
    }

    @Test
    fun ticker_increasesAccruedCents_thenEnd() = runTest {
        val repo = FakeRepo()
        // Active with a movable clock so each tick recomputes a larger elapsed.
        var nowSecond = 1_000L
        val saved = SavedStateHandle(mapOf(PrivateShowViewModel.ARG_SESSION_ID to SESSION))
        val vm = PrivateShowViewModel(saved, repo).also { it.now = { Instant.ofEpochSecond(nowSecond) } }
        vm.tickIntervalMillis = 1_000L
        repo.statusResult = ApiResult.Success(
            PrivateStatus(
                "active", "req_1", "ps_1", SESSION, "v_1", "Jordan", 600, "pause", "call_1",
                Instant.ofEpochSecond(1_000),
            ),
        )
        vm.refreshStatus()
        runCurrent()
        val initial = vm.uiState.value.state as PrivateShowState.Active
        assertEquals(0L, initial.elapsedSeconds)

        // Advance the clock + the test scheduler by a BOUNDED 3s and let the ticker recompute.
        nowSecond = 1_003L
        advanceTimeBy(3_000L)
        runCurrent()
        val ticked = vm.uiState.value.state as PrivateShowState.Active
        assertTrue(ticked.elapsedSeconds >= 3L)
        assertTrue(ticked.accruedCents >= 30L) // 3s * 600/60 = 30 cents.

        // ALWAYS reach a terminal state (cancels the ticker) before the test ends.
        repo.endResult = ApiResult.Success(PrivateShowSummary("ps_1", SESSION, "ended", 180, 1_500, "host"))
        vm.endShow()
        runCurrent()
        assertTrue(vm.uiState.value.state is PrivateShowState.Ended)
    }

    @Test
    fun end_activeToEnded_withServerSummary() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(
            PrivateStatus(
                "active", "req_1", "ps_1", SESSION, "v_1", "Jordan", 600, "pause", "call_1",
                Instant.ofEpochSecond(1_000),
            ),
        )
        repo.endResult = ApiResult.Success(PrivateShowSummary("ps_1", SESSION, "ended", 180, 1_500, "host"))
        val vm = vm(repo, now = Instant.ofEpochSecond(1_000))
        vm.refreshStatus()
        runCurrent()

        vm.endShow()
        runCurrent()

        assertEquals(1, repo.endCalls)
        val ended = vm.uiState.value.state as PrivateShowState.Ended
        assertEquals(1_500L, ended.summary.totalBilledCents)
        assertEquals(180, ended.summary.durationSeconds)
    }

    @Test
    fun accept_409_convergesViaRefreshStatus() = runTest {
        val repo = FakeRepo()
        repo.statusResult = ApiResult.Success(
            PrivateStatus("pending", "req_1", null, SESSION, "v_1", "Jordan", 500, null, null, null),
        )
        val vm = vm(repo, now = Instant.ofEpochSecond(1_000))
        vm.refreshStatus()
        runCurrent()

        // Accept conflicts (409). The convergence refreshStatus then reports the show is already active.
        repo.acceptResult = ApiResult.Failure(ApiError(409, "stale"))
        repo.statusResult = ApiResult.Success(
            PrivateStatus(
                "active", "req_1", "ps_1", SESSION, "v_1", "Jordan", 500, "pause", "call_1",
                Instant.ofEpochSecond(1_000),
            ),
        )
        vm.accept("req_1")
        runCurrent()

        assertTrue(vm.uiState.value.state is PrivateShowState.Active)
        // Converged into Active -> ticker armed -> stop before finishing.
        vm.stopPolling()
    }

    private companion object {
        const val SESSION = "bcs_1"

        fun idle() = PrivateStatus("idle", null, null, null, null, null, null, null, null, null)

        fun request(id: String, rate: Long) = PrivateShowRequest(
            requestId = id,
            privateSessionId = null,
            sessionId = SESSION,
            viewerId = "v_1",
            viewerDisplayName = "Jordan",
            ratePerMinuteCents = rate,
            status = "pending",
            maxDurationMinutes = 30,
            requestedAt = Instant.ofEpochSecond(900),
            startedAt = null,
        )

        fun session(rate: Long = 600, startedAt: Instant) = PrivateShowSession(
            privateSessionId = "ps_1",
            sessionId = SESSION,
            status = "active",
            behavior = "pause",
            callId = "call_1",
            ratePerMinuteCents = rate,
            startedAt = startedAt,
        )
    }
}
