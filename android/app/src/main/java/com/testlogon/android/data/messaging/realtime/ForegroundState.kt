package com.testlogon.android.data.messaging.realtime

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-149 — process foreground/background gate for lifecycle-aware SSE.
 *
 * A single app-scoped [StateFlow]<Boolean> that the SSE stream observes so the connection is opened
 * only while the app is foregrounded and is torn down (no leaked socket/thread) when backgrounded
 * (FR-6). It is registered against [androidx.lifecycle.ProcessLifecycleOwner] once at process start;
 * it defaults to foregrounded so a stream collected before the observer is attached (and every unit
 * test) is not starved.
 *
 * This formalises the lifecycle binding that AND-145's HeartbeatScheduler already does for presence,
 * reusing the same ProcessLifecycleOwner mechanism rather than adding a second one.
 */
@Singleton
class ForegroundState @Inject constructor() : DefaultLifecycleObserver {

    private val _isForeground = MutableStateFlow(true)

    /** True while the process is at/above STARTED. Hot, conflated; read-only outward. */
    val isForeground: StateFlow<Boolean> = _isForeground.asStateFlow()

    override fun onStart(owner: LifecycleOwner) {
        _isForeground.value = true
    }

    override fun onStop(owner: LifecycleOwner) {
        _isForeground.value = false
    }
}
