package com.testlogon.android.data.analytics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * AND-171 / AND-172 — sink resilience + routing: bounded retry on 5xx/IO then drop, immediate 4xx
 * drop, offline short-circuit of HEARTBEATs, and the broadcast join->heartbeat->leave viewer_id reuse.
 * The sink's consumer scope is created per-test and cancelled so no coroutine leaks into [runTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CoroutineHeartbeatSinkTest {

    private val emptyJson = "{}".toResponseBody("application/json".toMediaType())

    private fun TestScope.sinkScope(): CoroutineScope =
        CoroutineScope(UnconfinedTestDispatcher(testScheduler))

    private fun snapshot(target: PlaybackTarget, phase: HeartbeatPhase) = PlaybackSnapshot(
        sessionId = "s",
        target = target,
        phase = phase,
        positionMs = 0L,
        durationMs = null,
        watchedMsDelta = 0L,
        isLive = target is PlaybackTarget.Broadcast,
        playbackSpeed = 1f,
        clientEventId = UUID.randomUUID().toString(),
        occurredAtEpochMs = 0L,
    )

    private class FakeApi(
        val viewResponse: () -> Response<ViewRecordDto>,
        val joinResponse: () -> Response<ViewerJoinDto> = {
            Response.success(ViewerJoinDto("vwr_1", "sess", 1))
        },
        val heartbeatResponse: () -> Response<ViewerHeartbeatDto> = {
            Response.success(ViewerHeartbeatDto(true, 1))
        },
        val leaveResponse: () -> Response<ViewerLeaveDto> = {
            Response.success(ViewerLeaveDto(true, 0))
        },
    ) : PlaybackAnalyticsApi {
        val viewCalls = AtomicInteger(0)
        val joinCalls = AtomicInteger(0)
        val heartbeatCalls = AtomicInteger(0)
        val leaveCalls = AtomicInteger(0)
        var lastHeartbeatViewerId: String? = null

        override suspend fun recordVideoView(videoId: String): Response<ViewRecordDto> {
            viewCalls.incrementAndGet(); return viewResponse()
        }
        override suspend fun viewerJoin(sessionId: String): Response<ViewerJoinDto> {
            joinCalls.incrementAndGet(); return joinResponse()
        }
        override suspend fun viewerHeartbeat(sessionId: String, viewerId: String): Response<ViewerHeartbeatDto> {
            heartbeatCalls.incrementAndGet(); lastHeartbeatViewerId = viewerId; return heartbeatResponse()
        }
        override suspend fun viewerLeave(sessionId: String, viewerId: String): Response<ViewerLeaveDto> {
            leaveCalls.incrementAndGet(); return leaveResponse()
        }
    }

    @Test
    fun content_start_recordsViewOnce() = runTest {
        val api = FakeApi(viewResponse = { Response.success(ViewRecordDto(1, true)) })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { false }, scope)
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.START))
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.HEARTBEAT))
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.STOP))
        advanceUntilIdle()
        assertEquals(1, api.viewCalls.get()) // only START records a VOD view
        scope.cancel()
    }

    @Test
    fun broadcast_joinHeartbeatLeave_reusesViewerId() = runTest {
        val api = FakeApi(viewResponse = { Response.success(ViewRecordDto(0, false)) })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { false }, scope)
        val target = PlaybackTarget.Broadcast("sess")
        sink.enqueue(snapshot(target, HeartbeatPhase.START))
        advanceUntilIdle()
        sink.enqueue(snapshot(target, HeartbeatPhase.HEARTBEAT))
        advanceUntilIdle()
        sink.enqueue(snapshot(target, HeartbeatPhase.STOP))
        advanceUntilIdle()
        assertEquals(1, api.joinCalls.get())
        assertEquals(1, api.heartbeatCalls.get())
        assertEquals(1, api.leaveCalls.get())
        assertEquals("vwr_1", api.lastHeartbeatViewerId)
        scope.cancel()
    }

    @Test
    fun offline_dropsHeartbeat_butNotStart() = runTest {
        val api = FakeApi(viewResponse = { Response.success(ViewRecordDto(1, true)) })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { true }, scope)
        sink.enqueue(snapshot(PlaybackTarget.Broadcast("sess"), HeartbeatPhase.HEARTBEAT))
        advanceUntilIdle()
        assertEquals(0, api.heartbeatCalls.get())
        assertTrue(sink.counters.droppedOffline.get() >= 1)
        scope.cancel()
    }

    @Test
    fun fourxx_droppedImmediately_noRetry() = runTest {
        val attempts = AtomicInteger(0)
        val api = FakeApi(viewResponse = {
            attempts.incrementAndGet()
            Response.error(422, emptyJson)
        })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { false }, scope)
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.START))
        advanceUntilIdle()
        assertEquals(1, attempts.get()) // no retry on 4xx
        assertTrue(sink.counters.dropped4xx.get() >= 1)
        scope.cancel()
    }

    @Test
    fun fivexx_retriesThenDrops() = runTest {
        val attempts = AtomicInteger(0)
        val api = FakeApi(viewResponse = {
            attempts.incrementAndGet()
            Response.error(500, emptyJson)
        })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { false }, scope)
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.START))
        advanceUntilIdle()
        // initial + MAX_RETRIES retries = 3 attempts.
        assertEquals(1 + CoroutineHeartbeatSink.MAX_RETRIES, attempts.get())
        assertTrue(sink.counters.droppedRetryExhausted.get() >= 1)
        scope.cancel()
    }

    @Test
    fun ioError_retriesThenDrops() = runTest {
        val attempts = AtomicInteger(0)
        val api = FakeApi(viewResponse = {
            attempts.incrementAndGet()
            throw IOException("boom")
        })
        val scope = sinkScope()
        val sink = CoroutineHeartbeatSink(api, OfflineGate { false }, scope)
        sink.enqueue(snapshot(PlaybackTarget.Content("vid"), HeartbeatPhase.START))
        advanceUntilIdle()
        assertEquals(1 + CoroutineHeartbeatSink.MAX_RETRIES, attempts.get())
        assertTrue(sink.counters.droppedRetryExhausted.get() >= 1)
        scope.cancel()
    }
}
