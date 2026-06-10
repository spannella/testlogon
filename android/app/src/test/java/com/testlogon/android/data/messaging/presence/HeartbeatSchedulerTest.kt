package com.testlogon.android.data.messaging.presence

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class HeartbeatSchedulerTest {

    private class FakePresenceApi : PresenceApi {
        var beats = 0
        var failNext = false
        override suspend fun heartbeat(body: HeartbeatReq): HeartbeatResp {
            beats++
            if (failNext) {
                failNext = false
                throw IOException("boom")
            }
            return HeartbeatResp()
        }
        override suspend fun getPresence(userIds: String): List<PresenceDto> = emptyList()
    }

    private val owner = object : androidx.lifecycle.LifecycleOwner {
        // The scheduler only uses the owner as a parameter (it never reads the lifecycle), so an
        // unsafe registry (no main-thread assertion) is sufficient for these JVM tests.
        private val registry = androidx.lifecycle.LifecycleRegistry.createUnsafe(this)
        override val lifecycle: androidx.lifecycle.Lifecycle get() = registry
    }

    @Test
    fun firesImmediatelyOnAuthAndRepeatsOnCadence() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(api, CoroutineScope(dispatcher))

        scheduler.onAuthenticated()
        runCurrent()
        assertEquals(1, api.beats) // immediate beat

        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS + 1)
        runCurrent()
        assertEquals(2, api.beats)

        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS + 1)
        runCurrent()
        assertEquals(3, api.beats)
        scheduler.onLoggedOut()
    }

    @Test
    fun backgroundStopsLoop_foregroundRestarts() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(api, CoroutineScope(dispatcher))

        scheduler.onAuthenticated()
        runCurrent()
        assertEquals(1, api.beats)

        scheduler.onStop(owner) // background
        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS * 3)
        runCurrent()
        assertEquals(1, api.beats) // no further beats while backgrounded

        scheduler.onStart(owner) // foreground again (still authenticated)
        runCurrent()
        assertEquals(2, api.beats) // immediate beat on return
        scheduler.onLoggedOut()
    }

    @Test
    fun failedBeatDoesNotStopLoop() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi().apply { failNext = true }
        val scheduler = HeartbeatScheduler(api, CoroutineScope(dispatcher))

        scheduler.onAuthenticated()
        runCurrent()
        assertEquals(1, api.beats) // failed beat still counted; loop survives

        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS + 1)
        runCurrent()
        assertEquals(2, api.beats) // next tick fires
        scheduler.onLoggedOut()
    }

    @Test
    fun doesNotStartWhenUnauthenticated() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(api, CoroutineScope(dispatcher))

        scheduler.onStart(owner) // foregrounded but never authenticated
        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS * 2)
        runCurrent()
        assertEquals(0, api.beats)
    }
}
