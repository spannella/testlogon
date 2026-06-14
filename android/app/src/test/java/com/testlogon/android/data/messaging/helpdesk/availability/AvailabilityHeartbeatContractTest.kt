package com.testlogon.android.data.messaging.helpdesk.availability

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.messaging.presence.HeartbeatScheduler
import com.testlogon.android.data.messaging.presence.PresenceApi
import dagger.Lazy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * AND-379 — TC-AND-379-09: contract test that [AvailabilityRepository.set] fires an immediate
 * out-of-band heartbeat whose request body `status` equals the toggled availability ("available" /
 * "away"). Drives the real [AvailabilityRepositoryImpl] -> real [HeartbeatScheduler] (its
 * [PresenceHeartbeatPush]) -> real [PresenceApi] over MockWebServer. Confirms the single-source
 * contract: the UI value equals the sent status.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AvailabilityHeartbeatContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private lateinit var tempDir: File

    @Before
    fun setUp() {
        tempDir = File.createTempFile("availc", "ds").let { f -> f.delete(); f.mkdirs(); f }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private fun api(): PresenceApi = backend.retrofit(moshi).create(PresenceApi::class.java)

    private fun dataStore(): DataStore<Preferences> =
        PreferenceDataStoreFactory.create { File(tempDir, "agent_availability.preferences_pb") }

    @Test
    fun set_firesImmediateHeartbeatCarryingStatus() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler))
        val scheduler = HeartbeatScheduler(api(), Lazy { error("unused in set() path") }, scope)
        val repo = AvailabilityRepositoryImpl(dataStore(), scheduler, scope)
        advanceUntilIdle()

        backend.enqueue(Fixtures.okBody("""{"ok":true,"user_id":"usr_self","online":true}"""))
        repo.set(Availability.ONLINE)
        advanceUntilIdle()

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/presence/heartbeat", req.requestUrl?.encodedPath)
        assertEquals("available", req.bodyJson()["status"])

        backend.enqueue(Fixtures.okBody("""{"ok":true,"user_id":"usr_self","online":false}"""))
        repo.set(Availability.AWAY)
        advanceUntilIdle()
        assertEquals("away", backend.takeRequest().bodyJson()["status"])
        scope.cancel()
    }
}
