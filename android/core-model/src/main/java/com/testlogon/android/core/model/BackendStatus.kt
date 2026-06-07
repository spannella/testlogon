package com.testlogon.android.core.model

/**
 * Combined reachability signal for the backend, published by the network module's health monitor.
 * Lives in `core-model` so feature modules can read the type without depending on `core-network`.
 */
sealed interface BackendStatus {
    /** Initial state, before any signal has been observed. */
    data object Unknown : BackendStatus

    /** Transport is up and the backend is answering health checks. */
    data object Up : BackendStatus

    /** Either no network transport, or the backend is not answering. */
    data object Down : BackendStatus
}
