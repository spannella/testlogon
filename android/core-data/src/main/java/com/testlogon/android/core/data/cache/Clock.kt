package com.testlogon.android.core.data.cache

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-116/AND-118 — thin time abstraction so TTL/freshness behavior is deterministic in JVM unit
 * tests (no `Thread.sleep`, no real wall clock). Production uses [SystemClock]; tests inject a fake.
 *
 * Uses epoch millis via `System.currentTimeMillis()` (NOT `java.time` — keeps the freshness/TTL
 * logic JVM-unit-testable on minSdk 24 without API-26 desugaring).
 */
fun interface Clock {
    fun now(): Long
}

/** Real, wall-clock-backed [Clock]. Bound in `CacheModule`. */
@Singleton
class SystemClock @Inject constructor() : Clock {
    override fun now(): Long = System.currentTimeMillis()
}
