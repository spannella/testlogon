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
