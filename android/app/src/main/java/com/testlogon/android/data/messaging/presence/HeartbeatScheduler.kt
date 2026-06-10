package com.testlogon.android.data.messaging.presence

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.testlogon.android.data.auth.AppScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-145 — foreground-bound presence heartbeat.
 *
 * Exactly one loop runs while the app process is foregrounded (it is a [DefaultLifecycleObserver]
 * registered against the process lifecycle). It POSTs to messaging/presence/heartbeat on a fixed 30s
 * cadence (the backend advertises no TTL — cadence is a client constant, matching the web
 * HEARTBEAT_INTERVAL_MS). On foreground it fires immediately (loop body runs before the first delay);
 * on background it cancels. A failed beat is swallowed — the next tick is the retry — so one failure
 * never stops presence reporting. It never runs while unauthenticated: the app starts/stops it on
 * the login/logout edge.
 */
@Singleton
class HeartbeatScheduler @Inject constructor(
    private val api: PresenceApi,
    @AppScope private val scope: CoroutineScope,
) : DefaultLifecycleObserver {

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

    private fun startLoop() {
        if (job?.isActive == true) return
        job = scope.launch {
            while (isActive) {
                // FR-1/FR-8 — fire immediately, swallow failures, retry on the next tick.
                runCatching { api.heartbeat(HeartbeatReq(device = DEVICE)) }
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
