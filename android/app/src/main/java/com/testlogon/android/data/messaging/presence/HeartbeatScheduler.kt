package com.testlogon.android.data.messaging.presence

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.testlogon.android.core.model.helpdesk.heartbeatStatus
import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.messaging.helpdesk.availability.AvailabilityRepository
import com.testlogon.android.data.messaging.helpdesk.availability.PresenceHeartbeatPush
import dagger.Lazy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-145 — foreground-bound presence heartbeat. AND-379 — carries the agent availability `status`.
 *
 * Exactly one loop runs while the app process is foregrounded (it is a [DefaultLifecycleObserver]
 * registered against the process lifecycle). It POSTs to messaging/presence/heartbeat on a fixed 30s
 * cadence (the backend advertises no TTL — cadence is a client constant, matching the web
 * HEARTBEAT_INTERVAL_MS). On foreground it fires immediately (loop body runs before the first delay);
 * on background it cancels. A failed beat is swallowed — the next tick is the retry — so one failure
 * never stops presence reporting. It never runs while unauthenticated: the app starts/stops it on
 * the login/logout edge.
 *
 * AND-379 — each periodic beat reads the current availability and sends `status` =
 * "available"/"away"; [sendHeartbeatNow] is the immediate out-of-band push the availability toggle
 * fires on change. Availability is read through a [Lazy] reference to avoid a construction cycle
 * (AvailabilityRepository depends on this scheduler as its [PresenceHeartbeatPush]).
 */
@Singleton
class HeartbeatScheduler @Inject constructor(
    private val api: PresenceApi,
    private val availabilityRepository: Lazy<AvailabilityRepository>,
    @AppScope private val scope: CoroutineScope,
) : DefaultLifecycleObserver, PresenceHeartbeatPush {

    private var job: Job? = null

    /** Whether the local user is authenticated; gates the loop (set on login/logout). */
    @Volatile
    private var enabled: Boolean = false

    override fun onStart(owner: LifecycleOwner) {
        if (enabled) startLoop()
    }

    override fun onStop(owner: LifecycleOwner) {
        stopLoop()
    }

    /** Called once auth is established; if already foregrounded, begins beating immediately. */
    fun onAuthenticated() {
        enabled = true
        startLoop()
    }

    /** Called on logout; stops the loop and prevents restart until re-auth. */
    fun onLoggedOut() {
        enabled = false
        stopLoop()
    }

    /**
     * AND-379 — fire one immediate heartbeat carrying [status] (out-of-band push on a toggle change).
     * Non-fatal: a failure is swallowed (the next periodic beat carries the persisted status), per §7.
     */
    override suspend fun sendHeartbeatNow(status: String) {
        runCatching { api.heartbeat(HeartbeatReq(device = DEVICE, status = status)) }
    }

    private fun startLoop() {
        if (job?.isActive == true) return
        job = scope.launch {
            while (isActive) {
                // FR-1/FR-8 — fire immediately, swallow failures, retry on the next tick.
                // AND-379 — each beat carries the current availability status (single source of truth).
                val status = runCatching { availabilityRepository.get().current().heartbeatStatus() }
                    .getOrNull()
                runCatching { api.heartbeat(HeartbeatReq(device = DEVICE, status = status)) }
                delay(INTERVAL_MS)
            }
        }
    }

    private fun stopLoop() {
        job?.cancel()
        job = null
    }

    companion object {
        const val INTERVAL_MS = 30_000L
        const val DEVICE = "android"
    }
}
