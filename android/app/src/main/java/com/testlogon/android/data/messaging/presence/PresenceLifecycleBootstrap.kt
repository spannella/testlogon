package com.testlogon.android.data.messaging.presence

import androidx.lifecycle.ProcessLifecycleOwner
import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-145 — process-start wiring for presence: registers the [HeartbeatScheduler] against the
 * process lifecycle (so the heartbeat runs only while foregrounded), starts the [PresenceRepository]
 * SSE collector, and toggles the heartbeat on the auth edge (started after login, stopped on logout).
 *
 * Called once from [com.testlogon.android.TestLogonApp.onCreate] via [start]. All side effects are
 * idempotent and non-blocking.
 */
@Singleton
class PresenceLifecycleBootstrap @Inject constructor(
    private val scheduler: HeartbeatScheduler,
    private val presenceRepository: PresenceRepository,
    private val authStateStore: AuthStateStore,
    private val foregroundState: com.testlogon.android.data.messaging.realtime.ForegroundState,
    @AppScope private val scope: CoroutineScope,
) {
    @Volatile
    private var started = false

    fun start() {
        if (started) return
        started = true

        presenceRepository.start()

        scope.launch {
            // ProcessLifecycleOwner must be observed on the main thread.
            withContext(Dispatchers.Main.immediate) {
                ProcessLifecycleOwner.get().lifecycle.addObserver(scheduler)
                // AND-149 — drive the SSE foreground gate from the same process lifecycle so the
                // messaging stream connects only while foregrounded and tears down on background.
                ProcessLifecycleOwner.get().lifecycle.addObserver(foregroundState)
            }
            // Toggle the heartbeat on auth transitions. The StateFlow is already conflated/distinct.
            authStateStore.isAuthenticated.collect { authed ->
                if (authed) scheduler.onAuthenticated() else scheduler.onLoggedOut()
            }
        }
    }
}
