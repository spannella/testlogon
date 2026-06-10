package com.testlogon.android.feature.purchases

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.transformLatest

/**
 * AND-219 — debounce a Flow without the FlowPreview `debounce` operator: emit the latest value only
 * after [millis] of quiescence. Built on [transformLatest], which cancels the pending delay on a new
 * upstream value (the coalescing we want for search keystrokes). A purchases-package twin of the
 * catalog/discover helpers so it is imported WITH a receiver and never reaches into another feature's
 * internal helper. JVM-testable.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun <T> Flow<T>.debounceCompat(millis: Long): Flow<T> =
    transformLatest { value ->
        delay(millis)
        emit(value)
    }
