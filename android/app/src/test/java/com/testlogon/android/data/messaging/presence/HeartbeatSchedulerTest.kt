package com.testlogon.android.data.messaging.presence

import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.data.messaging.helpdesk.availability.AvailabilityRepository
import dagger.Lazy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
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
        val statuses = mutableListOf<String?>()
        override suspend fun heartbeat(body: HeartbeatReq): HeartbeatResp {
            beats++
            statuses += body.status
            if (failNext) {
                failNext = false
                throw IOException("boom")
            }
            return HeartbeatResp()
        }
        override suspend fun getPresence(userIds: String): List<PresenceDto> = emptyList()
    }

    /** AND-379 — fixed-availability fake; the scheduler reads it through a [Lazy]. */
    private class FakeAvailabilityRepository(
        private val value: Availability = Availability.AWAY,
    ) : AvailabilityRepository {
        override val availability: StateFlow<Availability> = MutableStateFlow(value)
        override suspend fun set(value: Availability) = Unit
        override suspend fun current(): Availability = value
    }

    private fun availabilityLazy(
        repo: AvailabilityRepository = FakeAvailabilityRepository(),
    ): Lazy<AvailabilityRepository> = Lazy { repo }

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
        val scheduler = HeartbeatScheduler(api, availabilityLazy(), CoroutineScope(dispatcher))

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
        val scheduler = HeartbeatScheduler(api, availabilityLazy(), CoroutineScope(dispatcher))

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
        val scheduler = HeartbeatScheduler(api, availabilityLazy(), CoroutineScope(dispatcher))

        scheduler.onAuthenticated()
        runCurrent()
        assertEquals(1, api.beats) // failed beat still counted; loop survives

        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS + 1)
        runCurrent()
        assertEquals(2, api.beats) // next tick fires
        scheduler.onLoggedOut()
    }

    @Test
    fun periodicBeatCarriesAvailabilityStatus() = runTest {
        // AND-379 — periodic heartbeat reads the single-source availability and sends its `status`.
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(
            api,
            availabilityLazy(FakeAvailabilityRepository(Availability.ONLINE)),
            CoroutineScope(dispatcher),
        )

        scheduler.onAuthenticated()
        runCurrent()
        assertEquals(listOf("available"), api.statuses)
        scheduler.onLoggedOut()
    }

    @Test
    fun sendHeartbeatNowPostsGivenStatus() = runTest {
        // AND-379 — the immediate out-of-band push carries exactly the requested status string.
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(api, availabilityLazy(), CoroutineScope(dispatcher))

        scheduler.sendHeartbeatNow("away")
        runCurrent()
        assertEquals(1, api.beats)
        assertEquals(listOf("away"), api.statuses)
    }

    @Test
    fun doesNotStartWhenUnauthenticated() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val api = FakePresenceApi()
        val scheduler = HeartbeatScheduler(api, availabilityLazy(), CoroutineScope(dispatcher))

        scheduler.onStart(owner) // foregrounded but never authenticated
        advanceTimeBy(HeartbeatScheduler.INTERVAL_MS * 2)
        runCurrent()
        assertEquals(0, api.beats)
    }
}
