package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import kotlin.time.Duration

/**
 * AND-317 — PURE table tests for [HostSessionStateMachine.reduce]. No coroutines, no Android. Asserts the
 * legal transition matrix (next state + effects), a sample of ILLEGAL pairs (state unchanged + exactly one
 * [HostEffect.LogIllegalTransition]), and a totality property (reduce never throws / returns non-null).
 *
 * The full exhaustive suite is AND-318; this ships the reducer's own table coverage with AND-317.
 */
class HostSessionStateMachineTest {

    private val now: Instant = Instant.parse("2026-06-12T10:00:00Z")
    private val later: Instant = now.plusSeconds(30)

    private fun session(
        id: String = "bcs_1",
        status: BroadcastSessionStatus,
        scheduledAt: Instant? = null,
        startedAt: Instant? = null,
        stoppedAt: Instant? = null,
        cancelledAt: Instant? = null,
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
        stoppedAt = stoppedAt,
        cancelledAt = cancelledAt,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    private fun ok(s: BroadcastSession): ApiResult<BroadcastSession> = ApiResult.Success(s)

    private val health = HostHealth(uptime = Duration.ZERO, ingest = IngestStatus.Connected)
    private fun live(id: String = "bcs_1") =
        HostSessionState.Live(id, startedAt = now, ingest = IngestStatus.Connected, health = health)

    // ─── Legal edges ─────────────────────────────────────────────────────────────────────────────────────

    @Test
    fun idle_schedule_goesScheduling_andCallsControl() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Idle,
            HostSessionEvent.Schedule(SessionDraft(name = "S", scheduledAt = later), now),
        )
        assertTrue(r.state is HostSessionState.Scheduling)
        assertEquals(listOf(HostEffect.CallControl(ControlAction.Schedule)), r.effects)
    }

    @Test
    fun scheduling_controlOk_goesScheduled_andPersists() {
        val state = HostSessionState.Scheduling("bcs_1", SessionDraft(scheduledAt = later))
        val r = HostSessionStateMachine.reduce(
            state,
            HostSessionEvent.ControlResult(
                ControlAction.Schedule,
                ok(session(status = BroadcastSessionStatus.SCHEDULED, scheduledAt = later)),
                now,
            ),
        )
        assertEquals(HostSessionState.Scheduled("bcs_1", later), r.state)
        assertEquals(listOf(HostEffect.Persist("bcs_1", HostSessionStatus.SCHEDULED)), r.effects)
    }

    @Test
    fun scheduled_goLive_goesConnecting_withStartAndOpenIngest() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Scheduled("bcs_1", later),
            HostSessionEvent.GoLive(now),
        )
        assertEquals(HostSessionState.Connecting("bcs_1", 1), r.state)
        assertEquals(
            listOf(HostEffect.CallControl(ControlAction.Start), HostEffect.OpenIngest),
            r.effects,
        )
    }

    @Test
    fun preFlight_goLive_goesConnecting() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.PreFlight("bcs_1", DeviceSelection()),
            HostSessionEvent.GoLive(now),
        )
        assertEquals(HostSessionState.Connecting("bcs_1", 1), r.state)
    }

    @Test
    fun connecting_ingestConnected_goesLive_startsTicker_andPersists() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Connecting("bcs_1", 1),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Connected, now),
        )
        val s = r.state
        assertTrue(s is HostSessionState.Live)
        assertEquals(now, (s as HostSessionState.Live).startedAt)
        assertEquals(
            listOf(HostEffect.StartHealthTicker, HostEffect.Persist("bcs_1", HostSessionStatus.LIVE)),
            r.effects,
        )
    }

    @Test
    fun connecting_ingestFailed_goesRecoverableError_closesIngest_stopsTicker() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Connecting("bcs_1", 1),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Failed, now),
        )
        val s = r.state as HostSessionState.Error
        assertEquals(HostError.IngestFailed, s.cause)
        assertTrue(s.recoverable)
        assertEquals(listOf(HostEffect.CloseIngest, HostEffect.StopHealthTicker), r.effects)
    }

    @Test
    fun live_pause_goesPaused_closesIngest_noControl() {
        val r = HostSessionStateMachine.reduce(live(), HostSessionEvent.Pause(later))
        assertTrue(r.state is HostSessionState.Paused)
        assertEquals(listOf(HostEffect.CloseIngest), r.effects)
        // Pause is CLIENT-ONLY: never a CallControl.
        assertTrue(r.effects.none { it is HostEffect.CallControl })
    }

    @Test
    fun paused_resume_goesConnecting_withResumeAndOpenIngest() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Paused("bcs_1", since = now, health = health),
            HostSessionEvent.Resume(later),
        )
        assertEquals(HostSessionState.Connecting("bcs_1", 1), r.state)
        assertEquals(
            listOf(HostEffect.CallControl(ControlAction.Resume), HostEffect.OpenIngest),
            r.effects,
        )
    }

    @Test
    fun live_ingestDisconnected_goesReconnecting() {
        val r = HostSessionStateMachine.reduce(
            live(),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Disconnected, later),
        )
        assertTrue(r.state is HostSessionState.Reconnecting)
    }

    @Test
    fun reconnecting_ingestConnected_goesLive_startsTicker() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Reconnecting("bcs_1", 1, since = now),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Connected, later),
        )
        assertTrue(r.state is HostSessionState.Live)
        assertTrue(r.effects.contains(HostEffect.StartHealthTicker))
    }

    @Test
    fun reconnecting_ingestFailed_goesRecoverableError() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Reconnecting("bcs_1", 1, since = now),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Failed, later),
        )
        val s = r.state as HostSessionState.Error
        assertEquals(HostError.IngestFailed, s.cause)
        assertEquals(listOf(HostEffect.CloseIngest, HostEffect.StopHealthTicker), r.effects)
    }

    @Test
    fun live_stop_goesEnding_callsStop_closesIngest_stopsTicker() {
        val r = HostSessionStateMachine.reduce(live(), HostSessionEvent.Stop)
        assertEquals(HostSessionState.Ending("bcs_1"), r.state)
        assertEquals(
            listOf(
                HostEffect.CallControl(ControlAction.Stop),
                HostEffect.CloseIngest,
                HostEffect.StopHealthTicker,
            ),
            r.effects,
        )
    }

    @Test
    fun ending_controlOk_goesEnded_andPersists() {
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Ending("bcs_1"),
            HostSessionEvent.ControlResult(
                ControlAction.Stop,
                ok(session(status = BroadcastSessionStatus.STOPPED, stoppedAt = later)),
                now,
            ),
        )
        assertEquals(HostSessionState.Ended("bcs_1", later), r.state)
        assertEquals(listOf(HostEffect.Persist("bcs_1", HostSessionStatus.ENDED)), r.effects)
    }

    @Test
    fun controlError_tipsToError_preservingPrevious() {
        val state = live()
        val r = HostSessionStateMachine.reduce(
            state,
            HostSessionEvent.ControlResult(
                ControlAction.Stop,
                ApiResult.Failure(ApiError(409, "conflict")),
                now,
            ),
        )
        val s = r.state as HostSessionState.Error
        assertEquals(HostError.Conflict, s.cause)
        assertEquals(state, s.previous)
    }

    @Test
    fun recoverableError_refresh_restoresPrevious_andReloads() {
        val prev = HostSessionState.Scheduled("bcs_1", later)
        val r = HostSessionStateMachine.reduce(
            HostSessionState.Error("bcs_1", HostError.Network, recoverable = true, previous = prev),
            HostSessionEvent.Refresh,
        )
        assertEquals(prev, r.state)
        assertEquals(listOf(HostEffect.LoadSession("bcs_1")), r.effects)
    }

    @Test
    fun load_withId_seedsRestore_andLoadsSession() {
        val r = HostSessionStateMachine.reduce(HostSessionState.Idle, HostSessionEvent.Load("bcs_7"))
        assertEquals("bcs_7", r.state.sessionId)
        assertEquals(listOf(HostEffect.LoadSession("bcs_7")), r.effects)
    }

    @Test
    fun sessionLoaded_mapsServerStatusToPhase() {
        val pairs = listOf(
            BroadcastSessionStatus.READY to HostSessionState.PreFlight::class,
            BroadcastSessionStatus.PROVISIONING to HostSessionState.Connecting::class,
            BroadcastSessionStatus.LIVE to HostSessionState.Live::class,
            BroadcastSessionStatus.STOPPING to HostSessionState.Ending::class,
            BroadcastSessionStatus.STOPPED to HostSessionState.Ended::class,
            BroadcastSessionStatus.CANCELLED to HostSessionState.Ended::class,
            BroadcastSessionStatus.SCHEDULED to HostSessionState.Scheduled::class,
            BroadcastSessionStatus.DRAFT to HostSessionState.Idle::class,
            BroadcastSessionStatus.ERROR to HostSessionState.Error::class,
            BroadcastSessionStatus.UNKNOWN to HostSessionState.Error::class,
        )
        for ((serverStatus, phaseClass) in pairs) {
            val r = HostSessionStateMachine.reduce(
                HostSessionState.PreFlight("bcs_1", DeviceSelection()),
                HostSessionEvent.SessionLoaded(
                    ok(session(status = serverStatus, scheduledAt = later, startedAt = now)),
                    now,
                ),
            )
            assertEquals("status=$serverStatus", phaseClass, r.state::class)
        }
    }

    // ─── Illegal pairs (no-op + exactly one LogIllegalTransition) ────────────────────────────────────────

    @Test
    fun illegal_pauseAtIdle_isNoOp_withSingleLog() {
        assertIllegal(HostSessionState.Idle, HostSessionEvent.Pause(now))
    }

    @Test
    fun illegal_goLiveWhileLive_isNoOp_withSingleLog() {
        assertIllegal(live(), HostSessionEvent.GoLive(now))
    }

    @Test
    fun illegal_resumeAtScheduled_isNoOp_withSingleLog() {
        assertIllegal(HostSessionState.Scheduled("bcs_1", later), HostSessionEvent.Resume(now))
    }

    @Test
    fun illegal_stopAtEnded_isNoOp_withSingleLog() {
        assertIllegal(HostSessionState.Ended("bcs_1", later), HostSessionEvent.Stop)
    }

    private fun assertIllegal(state: HostSessionState, event: HostSessionEvent) {
        val r = HostSessionStateMachine.reduce(state, event)
        assertEquals("state must be unchanged", state, r.state)
        assertEquals(1, r.effects.size)
        assertTrue(r.effects.single() is HostEffect.LogIllegalTransition)
    }

    // ─── Totality property: reduce never throws / always non-null ────────────────────────────────────────

    @Test
    fun reduce_isTotal_overRepresentativeMatrix() {
        val states: List<HostSessionState> = listOf(
            HostSessionState.Idle,
            HostSessionState.Scheduling("bcs_1", SessionDraft()),
            HostSessionState.Scheduled("bcs_1", later),
            HostSessionState.PreFlight("bcs_1", DeviceSelection()),
            HostSessionState.Connecting("bcs_1", 1),
            live(),
            HostSessionState.Paused("bcs_1", now, health),
            HostSessionState.Reconnecting("bcs_1", 1, now),
            HostSessionState.Ending("bcs_1"),
            HostSessionState.Ended("bcs_1", later),
            HostSessionState.Error("bcs_1", HostError.Network, recoverable = true, previous = HostSessionState.Idle),
            HostSessionState.Error("bcs_1", HostError.Unknown, recoverable = false),
        )
        val events: List<HostSessionEvent> = listOf(
            HostSessionEvent.Load("bcs_1"),
            HostSessionEvent.Load(null),
            HostSessionEvent.Schedule(SessionDraft(), now),
            HostSessionEvent.CancelSchedule,
            HostSessionEvent.GoLive(now),
            HostSessionEvent.Pause(now),
            HostSessionEvent.Resume(now),
            HostSessionEvent.Reschedule(later),
            HostSessionEvent.Stop,
            HostSessionEvent.IngestStatusChanged(IngestStatus.Connected, now),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Failed, now),
            HostSessionEvent.IngestStatusChanged(IngestStatus.Disconnected, now),
            HostSessionEvent.HealthTick(now),
            HostSessionEvent.Refresh,
            HostSessionEvent.DismissError,
            HostSessionEvent.SessionLoaded(ok(session(status = BroadcastSessionStatus.LIVE)), now),
            HostSessionEvent.ControlResult(ControlAction.Start, ApiResult.Failure(ApiError(500, "x")), now),
        )
        for (s in states) {
            for (e in events) {
                val r = HostSessionStateMachine.reduce(s, e)
                assertNotNull("null result for ($s, $e)", r)
                assertNotNull(r.state)
            }
        }
    }
}
