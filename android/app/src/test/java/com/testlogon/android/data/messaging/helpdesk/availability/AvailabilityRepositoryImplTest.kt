package com.testlogon.android.data.messaging.helpdesk.availability

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import com.testlogon.android.core.model.helpdesk.Availability
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * AND-379 — TC-AND-379-02/03/05: default AWAY, set() persists + pushes the immediate heartbeat, and the
 * value survives a repository recreate (process-death analogue) against the same DataStore file.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AvailabilityRepositoryImplTest {

    private lateinit var tempDir: File

    /** Recording heartbeat-push seam (records BEFORE returning). */
    private class RecordingPush : PresenceHeartbeatPush {
        val statuses = mutableListOf<String>()
        override suspend fun sendHeartbeatNow(status: String) {
            statuses += status
        }
    }

    @Before
    fun setUp() {
        tempDir = File.createTempFile("avail", "ds").let { f ->
            f.delete()
            f.mkdirs()
            f
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private fun dataStore(): DataStore<Preferences> =
        PreferenceDataStoreFactory.create { File(tempDir, "agent_availability.preferences_pb") }

    @Test
    fun default_whenKeyAbsent_isAway() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val repo = AvailabilityRepositoryImpl(dataStore(), RecordingPush(), scope)
        advanceUntilIdle()
        assertEquals(Availability.AWAY, repo.current())
        assertEquals(Availability.AWAY, repo.availability.value)
        scope.cancel()
    }

    @Test
    fun set_persistsValue_andPushesImmediateHeartbeat() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val push = RecordingPush()
        val repo = AvailabilityRepositoryImpl(dataStore(), push, scope)
        advanceUntilIdle()

        repo.set(Availability.ONLINE)
        advanceUntilIdle()

        assertEquals(Availability.ONLINE, repo.current())
        assertEquals(Availability.ONLINE, repo.availability.value)
        assertEquals(listOf("available"), push.statuses)

        repo.set(Availability.AWAY)
        advanceUntilIdle()
        assertEquals(listOf("available", "away"), push.statuses)
        scope.cancel()
    }

    @Test
    fun value_survivesRepositoryRecreate() = runTest {
        // Use one DataStore instance across both repositories (a single file may have only one active
        // DataStore per process); recreating the repository simulates process death of the holder.
        val store = dataStore()
        val scope1 = CoroutineScope(StandardTestDispatcher(testScheduler))
        val repo1 = AvailabilityRepositoryImpl(store, RecordingPush(), scope1)
        advanceUntilIdle()
        repo1.set(Availability.ONLINE)
        advanceUntilIdle()
        scope1.cancel()

        val scope2 = CoroutineScope(StandardTestDispatcher(testScheduler))
        val repo2 = AvailabilityRepositoryImpl(store, RecordingPush(), scope2)
        advanceUntilIdle()
        assertEquals(Availability.ONLINE, repo2.current())
        scope2.cancel()
    }
}
