package com.testlogon.android.data.messaging.presence

import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingEventStream
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.data.messaging.realtime.StreamConnectionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PresenceRepositoryTest {

    private class FakePresenceApi : PresenceApi {
        var getCalls = mutableListOf<String>()
        var response: List<PresenceDto> = emptyList()
        override suspend fun heartbeat(body: HeartbeatReq): HeartbeatResp = HeartbeatResp()
        override suspend fun getPresence(userIds: String): List<PresenceDto> {
            getCalls += userIds
            return response
        }
    }

    private class FakeStream : MessagingEventStream {
        private val ch = Channel<MessagingStreamEvent>(Channel.UNLIMITED)
        override fun events(): Flow<MessagingStreamEvent> = ch.receiveAsFlow()
        suspend fun send(e: MessagingStreamEvent) = ch.send(e)
    }

    private fun repo(scope: CoroutineScope, api: FakePresenceApi, stream: FakeStream, self: String? = null):
        DefaultPresenceRepository {
        val auth = FakeAuthStateStore()
        if (self != null) {
            // setAuthenticated is suspend; FakeAuthStateStore sets the flow synchronously.
            kotlinx.coroutines.runBlocking { auth.setAuthenticated(self) }
        }
        return DefaultPresenceRepository(api, stream, auth, scope)
    }

    @Test
    fun sseUpdateMergesIntoCache() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val api = FakePresenceApi()
        val stream = FakeStream()
        val r = repo(scope, api, stream)
        r.start()
        advanceUntilIdle()

        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.PresenceUpdate(userId = "u2", online = true, lastSeenAtEpochSeconds = 1749126670),
            ),
        )
        advanceUntilIdle()

        val p = r.presence.value["u2"]
        assertEquals(PresenceStatus.ONLINE, p?.status)
        assertEquals(1749126670L, p?.lastSeenAtEpochSeconds)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun trackSeedsAndPresenceOfEmits() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val api = FakePresenceApi().apply {
            response = listOf(PresenceDto("u1", online = true, lastSeenAt = 5))
        }
        val stream = FakeStream()
        val r = repo(scope, api, stream)
        val sub = r.track(setOf("u1"))
        advanceUntilIdle()

        assertEquals(1, api.getCalls.size)
        assertEquals("u1", api.getCalls.first())
        assertEquals(PresenceStatus.ONLINE, r.presenceOf("u1").first().status)
        sub.close()
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun selfIsNeverTrackedOrSeeded() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val api = FakePresenceApi()
        val stream = FakeStream()
        val r = repo(scope, api, stream, self = "me")
        r.track(setOf("me", "u2"))
        advanceUntilIdle()
        // Only the peer u2 is seeded; "me" is excluded from the comma-joined query.
        assertEquals(1, api.getCalls.size)
        assertEquals("u2", api.getCalls.first())
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun reconnectMarksStaleThenReseeds() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val api = FakePresenceApi().apply {
            response = listOf(PresenceDto("u1", online = true, lastSeenAt = 5))
        }
        val stream = FakeStream()
        val r = repo(scope, api, stream)
        r.start()
        r.track(setOf("u1"))
        advanceUntilIdle()
        val seedCount = api.getCalls.size

        stream.send(MessagingStreamEvent.State(StreamConnectionState.DISCONNECTED))
        advanceUntilIdle()
        assertTrue(r.presence.value["u1"]?.stale == true)

        stream.send(MessagingStreamEvent.State(StreamConnectionState.CONNECTED))
        advanceUntilIdle()
        // A reconnect re-seeds the tracked id and clears stale.
        assertTrue(api.getCalls.size > seedCount)
        assertEquals(false, r.presence.value["u1"]?.stale)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun untrackEvictsWhenLastReferenceCloses() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val api = FakePresenceApi().apply {
            response = listOf(PresenceDto("u1", online = true, lastSeenAt = 5))
        }
        val stream = FakeStream()
        val r = repo(scope, api, stream)
        val a = r.track(setOf("u1"))
        val b = r.track(setOf("u1"))
        advanceUntilIdle()
        // Single seed for two trackers of the same id.
        assertEquals(1, api.getCalls.size)

        a.close()
        assertTrue(r.presence.value.containsKey("u1")) // still referenced by b
        b.close()
        assertTrue(!r.presence.value.containsKey("u1")) // evicted after last close
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
