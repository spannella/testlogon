package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.HealthLevel
import com.testlogon.android.data.broadcast.HostControlRepository
import com.testlogon.android.data.broadcast.HostHealthReport
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.PublishState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-309 — unit tests for [HostControlViewModel]. Uses MainDispatcherRule + runCurrent and a SHRUNK
 * injected poll interval; the health loop is driven a SINGLE iteration with runCurrent (NEVER
 * advanceUntilIdle, so it cannot spin). Verifies: no optimistic flip on start; two-step stop confirm +
 * publisher.stop() teardown; reschedule 422 -> transientError with no scheduledAt change; resume reject ->
 * error + re-sync; health one good sample then a failure -> healthStale with the last report kept; and the
 * double-dispatch guard.
 */
class HostControlViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun session(
        id: String = "bcs_1",
        status: BroadcastSessionStatus = BroadcastSessionStatus.SCHEDULED,
        scheduledAt: Instant? = null,
        startedAt: Instant? = null,
    ) = BroadcastSession(
        id = id,
        profileId = "prof_9",
        name = "Show",
        description = null,
        status = status,
        createdBy = "host",
        scheduledAt = scheduledAt,
        scheduleStatus = null,
        startedAt = startedAt,
        stoppedAt = null,
        cancelledAt = null,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    private fun health(level: HealthLevel = HealthLevel.HEALTHY) = HostHealthReport(
        sessionId = "bcs_1",
        connectionQuality = "healthy",
        level = level,
        ingestBitrateKbps = 4200,
        ingestFramerate = 30.0,
        droppedFrames = 0,
        droppedFramesPct = 0.0,
        outputErrors = 0,
        inputLossSeconds = 0.0,
        viewerCount = 100,
        updatedAt = Instant.ofEpochSecond(1749322800L),
    )

    /** A configurable host control repository (results are settable per-action). */
    private class FakeRepo(
        var sessionResult: ApiResult<BroadcastSession>,
        var startResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x")),
        var stopResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x")),
        var resumeResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x")),
        var rescheduleResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x")),
        var healthResults: ArrayDeque<ApiResult<HostHealthReport>> = ArrayDeque(),
    ) : HostControlRepository {
        var startCalls = 0
        var stopCalls = 0
        var resumeCalls = 0
        var rescheduleCalls = 0
        var sessionCalls = 0
        var healthCalls = 0
        var lastRescheduleAt: Long? = null

        override suspend fun start(sessionId: String): ApiResult<BroadcastSession> {
            startCalls++; return startResult
        }
        override suspend fun stop(sessionId: String): ApiResult<BroadcastSession> {
            stopCalls++; return stopResult
        }
        override suspend fun resume(sessionId: String): ApiResult<BroadcastSession> {
            resumeCalls++; return resumeResult
        }
        override suspend fun reschedule(
            sessionId: String,
            scheduledAtEpochSeconds: Long,
        ): ApiResult<BroadcastSession> {
            rescheduleCalls++; lastRescheduleAt = scheduledAtEpochSeconds; return rescheduleResult
        }
        override suspend fun health(sessionId: String): ApiResult<HostHealthReport> {
            healthCalls++
            return if (healthResults.isEmpty()) {
                ApiResult.Failure(ApiError(500, "no more health samples"))
            } else {
                healthResults.removeFirst()
            }
        }
        override suspend fun session(sessionId: String): ApiResult<BroadcastSession> {
            sessionCalls++; return sessionResult
        }
    }

    /** A publisher that records stop() calls; goLive is unused by the control surface. */
    private class FakePublisher : BroadcastPublisher {
        var stopCalls = 0
        private val _state = MutableStateFlow<PublishState>(PublishState.Idle)
        override val state: StateFlow<PublishState> = _state.asStateFlow()
        override suspend fun startPreview() {}
        override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult =
            GoLiveResult.NotConfigured
        override fun stop() { stopCalls++ }
    }

    private fun vm(
        repo: HostControlRepository,
        publisher: BroadcastPublisher = FakePublisher(),
        sessionId: String? = "bcs_1",
        pollIntervalMillis: Long = 50L,
    ): HostControlViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(HostControlViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return HostControlViewModel(
            repo,
            publisher,
            saved,
            com.testlogon.android.core.webrtc.ui.PlaceholderVideoRenderer,
        ).also { it.pollIntervalMillis = pollIntervalMillis }
    }

    @Test
    fun start_scheduled_inFlightThenLive_noOptimisticFlip() = runTest {
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED)),
            startResult = ApiResult.Success(
                session(status = BroadcastSessionStatus.LIVE, startedAt = Instant.ofEpochSecond(1749322800L)),
            ),
        )
        val vm = vm(repo)
        runCurrent()
        // Loaded SCHEDULED.
        assertEquals(BroadcastSessionStatus.SCHEDULED, vm.uiState.value.session?.status)

        vm.onStart()
        // Before the suspend resolves: in-flight set, but session still SCHEDULED (no optimistic LIVE).
        assertEquals(HostAction.START, vm.uiState.value.inFlight)
        assertEquals(BroadcastSessionStatus.SCHEDULED, vm.uiState.value.session?.status)

        runCurrent()
        assertEquals(1, repo.startCalls)
        assertNull(vm.uiState.value.inFlight)
        assertEquals(BroadcastSessionStatus.LIVE, vm.uiState.value.session?.status)
    }

    @Test
    fun onStop_showsConfirmDialog_noNetwork_thenConfirmStopsAndTearsDownPublisher() = runTest {
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE)),
            stopResult = ApiResult.Success(session(status = BroadcastSessionStatus.STOPPED)),
        )
        val publisher = FakePublisher()
        val vm = vm(repo, publisher)
        runCurrent()

        vm.onStop()
        assertTrue(vm.uiState.value.showStopConfirm)
        assertEquals(0, repo.stopCalls)

        vm.onConfirmStopDialog(true)
        runCurrent()
        assertEquals(1, repo.stopCalls)
        assertEquals(1, publisher.stopCalls)
        assertEquals(BroadcastSessionStatus.STOPPED, vm.uiState.value.session?.status)
        assertTrue(!vm.uiState.value.showStopConfirm)
    }

    @Test
    fun onStop_dialogDismissed_doesNotStop() = runTest {
        val repo = FakeRepo(sessionResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE)))
        val publisher = FakePublisher()
        val vm = vm(repo, publisher)
        runCurrent()

        vm.onStop()
        vm.onConfirmStopDialog(false)
        runCurrent()
        assertEquals(0, repo.stopCalls)
        assertEquals(0, publisher.stopCalls)
        assertTrue(!vm.uiState.value.showStopConfirm)
    }

    @Test
    fun reschedule_422_setsTransientError_noScheduledAtChange() = runTest {
        val original = session(
            status = BroadcastSessionStatus.SCHEDULED,
            scheduledAt = Instant.ofEpochSecond(1749319200L),
        )
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(original),
            rescheduleResult = ApiResult.Failure(ApiError(422, "in the past")),
        )
        val vm = vm(repo)
        runCurrent()

        vm.onReschedule(1L)
        runCurrent()

        assertEquals(1, repo.rescheduleCalls)
        assertEquals("in the past", vm.uiState.value.transientError)
        // Session re-synced from server; scheduledAt unchanged.
        assertEquals(Instant.ofEpochSecond(1749319200L), vm.uiState.value.session?.scheduledAt)
        assertNull(vm.uiState.value.inFlight)
    }

    @Test
    fun resume_rejected_setsError_andResyncs() = runTest {
        val live = session(status = BroadcastSessionStatus.LIVE)
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(live),
            resumeResult = ApiResult.Failure(ApiError(422, "cannot resume")),
        )
        val vm = vm(repo)
        runCurrent()
        val sessionCallsAfterInit = repo.sessionCalls

        vm.onResume()
        runCurrent()

        assertEquals(1, repo.resumeCalls)
        assertEquals("cannot resume", vm.uiState.value.transientError)
        // A re-sync session fetch happened after the failure.
        assertTrue(repo.sessionCalls > sessionCallsAfterInit)
        assertNull(vm.uiState.value.inFlight)
    }

    @Test
    fun health_oneGoodSampleThenFailure_marksStale_keepsLastReport() = runTest {
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE)),
            healthResults = ArrayDeque(
                listOf(
                    ApiResult.Success(health(level = HealthLevel.HEALTHY)),
                    ApiResult.Failure(ApiError(503, "unavailable")),
                ),
            ),
        )
        val vm = vm(repo)
        runCurrent()
        // Screen requests polling; session is LIVE -> first iteration (good sample) runs, then delays.
        vm.startHealthPolling()
        runCurrent()
        val first = vm.uiState.value.health
        assertEquals(HealthLevel.HEALTHY, first?.level)
        assertTrue(!vm.uiState.value.healthStale)

        // Advance virtual time past the single poll interval to run exactly the next iteration (the
        // failure). advanceTimeBy + runCurrent runs one more loop body without spinning (NOT
        // advanceUntilIdle, which would loop forever on the LIVE poll).
        advanceTimeBy(60L)
        runCurrent()
        assertTrue(vm.uiState.value.healthStale)
        // The last good report is retained.
        assertEquals(HealthLevel.HEALTHY, vm.uiState.value.health?.level)

        // Stop the parked loop so runTest's cleanup does not spin the LIVE poll.
        vm.stopHealthPolling()
    }

    @Test
    fun doubleDispatch_secondActionIgnoredWhileInFlight() = runTest {
        val repo = FakeRepo(
            sessionResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED)),
            startResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE)),
            rescheduleResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED)),
        )
        val vm = vm(repo)
        runCurrent()

        vm.onStart()
        // While START is in flight, a second action is ignored.
        vm.onReschedule(1749319200L)
        assertEquals(HostAction.START, vm.uiState.value.inFlight)
        assertEquals(0, repo.rescheduleCalls)

        runCurrent()
        assertEquals(1, repo.startCalls)
        assertEquals(0, repo.rescheduleCalls)
    }
}
