package com.testlogon.android.feature.call.fsm

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-305 — schedules the bounded call timers ([TimerKey]) the FSM arms via [CallEffect.StartTimer] /
 * [CallEffect.CancelTimer]. Pulled behind an interface so the host test injects a manual/virtual-time fake
 * (the time-driven firing is tested with a fake, NEVER with advanceUntilIdle on the host's infinite flows).
 *
 * Each timer is a SINGLE bounded `delay` (no while(true)) — it fires [onFire] once unless cancelled.
 * Re-arming the same [TimerKey] replaces the prior job; [cancel]/[cancelAll] stop pending timers.
 */
interface CallTimerScheduler {
    fun start(key: TimerKey, delayMs: Long, onFire: () -> Unit)
    fun cancel(key: TimerKey)
    fun cancelAll()
}

/**
 * Default coroutine-backed scheduler. Each timer is a child [Job] of the injected app scope, so the host's
 * teardown (cancelAll) reliably stops them. The single `delay` makes it advanceTimeBy-friendly in tests
 * (the host test instead uses a fake to fire deterministically).
 */
@Singleton
class CoroutineCallTimerScheduler @Inject constructor(
    private val scope: CoroutineScope,
) : CallTimerScheduler {

    private val jobs = mutableMapOf<TimerKey, Job>()

    @Synchronized
    override fun start(key: TimerKey, delayMs: Long, onFire: () -> Unit) {
        jobs.remove(key)?.cancel()
        jobs[key] = scope.launch {
            delay(delayMs)
            if (isActive) onFire()
        }
    }

    @Synchronized
    override fun cancel(key: TimerKey) {
        jobs.remove(key)?.cancel()
    }

    @Synchronized
    override fun cancelAll() {
        jobs.values.forEach { it.cancel() }
        jobs.clear()
    }
}
