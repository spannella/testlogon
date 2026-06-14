package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-317 — [BroadcastHostViewModel] over a REAL host (pure FSM + serialized channel) with FAKE seams. Uses
 * [MainDispatcherRule] + StandardTestDispatcher; the VM runs everything on the injected dispatcher (the
 * rule's dispatcher), so [runCurrent] / bounded [advanceTimeBy] drive it deterministically.
 *
 * ANTI-HANG: the health ticker is cancellable, started ONLY by StartHealthTicker, and every test reaches a
 * StopHealthTicker (Stop / terminal) before it ends. We NEVER advanceUntilIdle while the ticker runs.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BroadcastHostViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val now: Instant = Instant.parse("2026-06-12T10:00:00Z")

    private fun session(
        id: String = "bcs_1",
        status: BroadcastSessionStatus,
        scheduledAt: Instant? = null,
        startedAt: Instant? = null,
        stoppedAt: Instant? = null,
    ) = BroadcastSession(
        id = id, profileId = "prof_9", name = "Show", description = null, status = status,
        createdBy = "host", scheduledAt = scheduledAt, scheduleStatus = null, startedAt = startedAt,
        stoppedAt = stoppedAt, cancelledAt = null, playbackUrl = null, thumbnailUrl = null,
        tipTotalCents = null, tipCount = null, createdAt = Instant.EPOCH, updatedAt = Instant.EPOCH,
    )

    private fun vm(
        repo: FakeBroadcastHostRepository = FakeBroadcastHostRepository(),
        ingest: FakeWebRtcIngestController = FakeWebRtcIngestController(),
        prefs: InMemoryHostSessionPrefs = InMemoryHostSessionPrefs(),
        analytics: RecordingHostAnalytics = RecordingHostAnalytics(),
    ): BroadcastHostViewModel {
        val v = BroadcastHostViewModel(
            repo = repo,
            ingest = ingest,
            prefs = prefs,
            dispatcher = mainDispatcher.dispatcher,
            analytics = analytics,
            savedStateHandle = SavedStateHandle(),
        )
        v.clock = { now }
        v.healthCadenceMillis = 1_000L
        return v
    }

    @Test
    fun goLive_fromScheduled_reachesLive_opensIngestAndStartsTickerOnce() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val analytics = RecordingHostAnalytics()
        val v = vm(repo = repo, ingest = ingest, analytics = analytics)
        // Seed Scheduled directly (cold start without persistence).
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Scheduled)

        v.onEvent(HostSessionEvent.GoLive(now))
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Connecting)
        assertEquals(1, ingest.openCalls)

        // Ingest connects -> Live + ticker started.
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        // Drive a couple bounded ticks (ticker is running), then Stop to cancel it before the test ends.
        advanceTimeBy(2_500L)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        // Stop -> Ending + CallControl(Stop); the fake control resolves immediately in the same runCurrent,
        // so the folded ControlResult(ok) advances Ending -> Ended. Accept either terminal-progress state.
        val stopped = v.uiState.value
        assertTrue(stopped is HostSessionState.Ending || stopped is HostSessionState.Ended)
        assertEquals(1, ingest.openCalls)
        assertTrue(ingest.closed)
    }

    @Test
    fun reconnect_recovers_backToLive() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE, startedAt = now))
        runCurrent()
        // Server-loaded LIVE seeds Live with ingest=Connecting; push Connected to settle.
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        ingest.emit(IngestStatus.Disconnected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Reconnecting)

        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
    }

    @Test
    fun reconnect_fails_goesError() = runTest {
        val ingest = FakeWebRtcIngestController()
        val repo = FakeBroadcastHostRepository().apply {
            loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE, startedAt = now))
        }
        val v = vm(repo = repo, ingest = ingest)
        // Drive into Live via the server-loaded LIVE phase + an ingest connect.
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        ingest.emit(IngestStatus.Failed)
        runCurrent()
        val s = v.uiState.value
        assertTrue(s is HostSessionState.Error && s.cause == HostError.IngestFailed)
    }

    @Test
    fun stop_reachesEnded_andPersists() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.STOPPED, stoppedAt = now))
        }
        val prefs = InMemoryHostSessionPrefs()
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest, prefs = prefs)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE, startedAt = now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Ended)
        assertEquals(HostSessionStatus.ENDED, prefs.lastStatus())
    }

    @Test
    fun duplicateGoLive_doesNotOpenIngestTwice() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        runCurrent()

        v.onEvent(HostSessionEvent.GoLive(now))
        // Second GoLive issued immediately, while still Connecting + go-live in flight -> dropped.
        v.onEvent(HostSessionEvent.GoLive(now))
        runCurrent()
        assertEquals(1, ingest.openCalls)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
    }

    @Test
    fun illegalEvent_isNoOp_andLogged() = runTest {
        val analytics = RecordingHostAnalytics()
        val v = vm(analytics = analytics)
        runCurrent()
        val before = v.uiState.value
        v.onEvent(HostSessionEvent.Pause(now)) // Pause @ Idle is illegal.
        runCurrent()
        assertEquals(before, v.uiState.value)
        assertTrue(analytics.illegal.isNotEmpty())
    }

    // ─── AND-318: health ticker drives HealthTick / uptime ───────────────────────────────────────────────

    @Test
    fun and318_healthTicker_producesHealthTicks_updatingUptime() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest)
        // clock advances with virtual time so HealthTick uptime is observable (read the scheduler's virtual
        // time at clock-invocation; `currentTime` is a TestScope member not visible inside this lambda).
        v.clock = { now.plusMillis(mainDispatcher.dispatcher.scheduler.currentTime) }

        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        runCurrent()
        v.onEvent(HostSessionEvent.GoLive(now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        val live = v.uiState.value as HostSessionState.Live
        assertEquals(kotlin.time.Duration.ZERO, live.health.uptime)

        // Cadence is 1_000ms; drive two bounded ticks (NOT advanceUntilIdle — the ticker is live).
        advanceTimeBy(1_000L)
        runCurrent()
        advanceTimeBy(1_000L)
        runCurrent()
        val ticked = v.uiState.value as HostSessionState.Live
        assertTrue("uptime should advance via HealthTick", ticked.health.uptime > kotlin.time.Duration.ZERO)

        // Terminal: Stop cancels the ticker before the test ends (anti-hang).
        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        assertTrue(ingest.closed)
    }

    // ─── AND-318: pause / resume (client-only) ───────────────────────────────────────────────────────────

    @Test
    fun and318_pauseThenResume_closesAndReopensIngest() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        runCurrent()
        v.onEvent(HostSessionEvent.GoLive(now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)
        assertEquals(1, ingest.openCalls)

        // Drive the ingest flow to a non-Connected value while Live so the post-resume Connected is a real
        // StateFlow change (StateFlow drops duplicate values). Idle @ Live is an absorbed no-op.
        ingest.emit(IngestStatus.Idle)
        runCurrent()

        v.onEvent(HostSessionEvent.Pause(now))
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Paused)
        assertTrue(ingest.closed)

        // Resume re-enters Connecting and re-opens ingest; a fresh Connected promotes back to Live.
        ingest.reset()
        v.onEvent(HostSessionEvent.Resume(now))
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Connecting)
        assertEquals(1, ingest.openCalls)
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
    }

    // ─── AND-318: Stop persists + clears + double-stop is a no-op ─────────────────────────────────────────

    @Test
    fun and318_stop_persistsEnded_andSecondStopIsNoOp() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.STOPPED, stoppedAt = now))
        }
        val prefs = InMemoryHostSessionPrefs()
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest, prefs = prefs)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE, startedAt = now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Ended)
        assertEquals(HostSessionStatus.ENDED, prefs.lastStatus())
        val controlsAfterStop = repo.controlCalls

        // Stop after Ended is illegal -> no-op; no extra control call.
        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Ended)
        assertEquals(controlsAfterStop, repo.controlCalls)
    }

    // ─── AND-318: events while Ended are no-ops ───────────────────────────────────────────────────────────

    @Test
    fun and318_eventsWhileEnded_areNoOps() = runTest {
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.STOPPED, stoppedAt = now))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE, startedAt = now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Ended)

        v.onEvent(HostSessionEvent.Pause(now))
        v.onEvent(HostSessionEvent.GoLive(now))
        v.onEvent(HostSessionEvent.Resume(now))
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Ended)
    }

    // ─── AND-318: cold-start restore from prefs ──────────────────────────────────────────────────────────

    @Test
    fun and318_coldStart_restoresFromPrefs_rehydratesToMappedPhase() = runTest {
        val prefs = InMemoryHostSessionPrefs()
        prefs.write("bcs_77", HostSessionStatus.SCHEDULED)
        val repo = FakeBroadcastHostRepository().apply {
            loadResult = ApiResult.Success(session(id = "bcs_77", status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest, prefs = prefs)
        // init's cold-start coroutine dispatches Load(persistedId); drive it.
        runCurrent()
        val s = v.uiState.value
        assertTrue("expected Scheduled, was $s", s is HostSessionState.Scheduled)
        assertEquals("bcs_77", s.sessionId)

        // Reach terminal so nothing is left pending.
        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
    }

    // ─── AND-318: error mapping per status band; VM never throws ──────────────────────────────────────────

    @Test
    fun and318_controlFailure_mapsToHostError_perStatusBand_andNeverThrows() = runTest {
        val cases = listOf(
            ApiResult.Failure(ApiError(401, "unauth")) to HostError.Auth,
            ApiResult.Failure(ApiError(409, "conflict")) to HostError.Conflict,
            ApiResult.Failure(ApiError(422, "invalid")) to HostError.Validation(field = null),
            ApiResult.NetworkError(RuntimeException("offline"), isTimeout = false) to HostError.Network,
            ApiResult.Failure(ApiError(500, "boom")) to HostError.Unknown,
        )
        for ((failure, expected) in cases) {
            val repo = FakeBroadcastHostRepository().apply {
                loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
                controlResult = failure
            }
            val ingest = FakeWebRtcIngestController()
            val v = vm(repo = repo, ingest = ingest)
            v.onEvent(HostSessionEvent.Load("bcs_1"))
            runCurrent()
            assertTrue(v.uiState.value is HostSessionState.Scheduled)

            // GoLive issues CallControl(Start); the fake fails -> ControlResult(err) -> Error.
            v.onEvent(HostSessionEvent.GoLive(now))
            runCurrent()
            val s = v.uiState.value
            assertTrue("case=$failure expected Error, was $s", s is HostSessionState.Error)
            assertEquals("case=$failure", expected, (s as HostSessionState.Error).cause)
        }
    }

    // ─── AND-318: analytics capture (only where the VM emits) ─────────────────────────────────────────────

    @Test
    fun and318_analytics_capturesPhaseChanges_andIllegalTransitions() = runTest {
        val analytics = RecordingHostAnalytics()
        val repo = FakeBroadcastHostRepository().apply {
            controlResult = ApiResult.Success(session(status = BroadcastSessionStatus.LIVE))
        }
        val ingest = FakeWebRtcIngestController()
        val v = vm(repo = repo, ingest = ingest, analytics = analytics)
        v.onEvent(HostSessionEvent.Load("bcs_1"))
        repo.loadResult = ApiResult.Success(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = now))
        runCurrent()
        v.onEvent(HostSessionEvent.GoLive(now))
        runCurrent()
        ingest.emit(IngestStatus.Connected)
        runCurrent()
        assertTrue(v.uiState.value is HostSessionState.Live)
        // At least one phase change was recorded (e.g. -> Scheduled, -> Connecting, -> Live).
        assertTrue(analytics.phases.isNotEmpty())
        assertTrue(analytics.phases.any { it.second == "Live" })

        // An illegal event in Live records an illegalTransition.
        v.onEvent(HostSessionEvent.Resume(now)) // Resume @ Live is illegal.
        runCurrent()
        assertTrue(analytics.illegal.any { it.second == "Resume" })

        v.onEvent(HostSessionEvent.Stop)
        runCurrent()
    }

    // ─── Fakes ───────────────────────────────────────────────────────────────────────────────────────────

    private class FakeBroadcastHostRepository : BroadcastHostRepository {
        var loadResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(404, "none"))
        var controlResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x"))
        var createResult: ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(500, "x"))
        var controlCalls = 0

        override suspend fun loadSession(id: String): ApiResult<BroadcastSession> = loadResult

        override suspend fun control(
            action: ControlAction,
            sessionId: String,
            draft: SessionDraft?,
            startsAt: Instant?,
        ): ApiResult<BroadcastSession> {
            controlCalls++
            return controlResult
        }

        override suspend fun create(profileId: String): ApiResult<BroadcastSession> = createResult
    }

    private class FakeWebRtcIngestController : WebRtcIngestController {
        private val _status = MutableStateFlow(IngestStatus.Unavailable)
        override val status: StateFlow<IngestStatus> = _status.asStateFlow()
        var openCalls = 0
        var closed = false

        fun emit(value: IngestStatus) {
            _status.value = value
        }

        /** AND-318 helper: zero the call counters between phases (e.g. across a pause/resume). */
        fun reset() {
            openCalls = 0
            closed = false
        }

        override suspend fun open(sessionId: String) {
            openCalls++
        }

        override fun close() {
            closed = true
        }
    }

    private class InMemoryHostSessionPrefs : HostSessionPrefs {
        private var id: String? = null
        private var status: HostSessionStatus? = null
        override suspend fun activeSessionId(): String? = id
        override suspend fun lastStatus(): HostSessionStatus? = status
        override suspend fun write(sessionId: String?, status: HostSessionStatus) {
            id = sessionId; this.status = status
        }
        override suspend fun clear() {
            id = null; status = null
        }
    }

    private class RecordingHostAnalytics : HostAnalytics {
        val phases = mutableListOf<Pair<String, String>>()
        val illegal = mutableListOf<Pair<String, String>>()
        override fun phaseChanged(from: String, to: String) {
            phases += from to to
        }
        override fun illegalTransition(from: String, event: String) {
            illegal += from to event
        }
    }
}
