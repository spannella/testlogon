package com.testlogon.android.feature.discover

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.transformLatest

/**
 * AND-185 — debounce a Flow without the FlowPreview `debounce` operator: emit the latest value only
 * after [millis] of quiescence. Built on [transformLatest], which cancels the pending delay on a new
 * upstream value (the coalescing we want for search keystrokes). Mirrors the AND-141 `debounceCompat`
 * but lives in the discover feature package so it is imported WITH a receiver (gotcha) and never
 * reaches into the messaging package's internal helper. JVM-testable.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun <T> Flow<T>.debounceCompat(millis: Long): Flow<T> =
    transformLatest { value ->
        delay(millis)
        emit(value)
    }
