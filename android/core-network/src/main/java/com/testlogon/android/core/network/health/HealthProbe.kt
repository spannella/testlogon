package com.testlogon.android.core.network.health

import com.testlogon.android.core.model.BackendStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.delay
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Combines [ConnectivityMonitor] transport state with a periodic backend liveness ping into a
 * single observable [Flow] of [BackendStatus].
 *
 * - No transport, sustained -> [BackendStatus.Down]. A *momentary* transport drop is swallowed (see
 *   [OFFLINE_DEBOUNCE_MS]) so a Wi-Fi/cell blip doesn't blank the app to offline.
 * - Transport up -> probes [HealthApi] on an interval (faster while down, slower while up). A single
 *   failed probe does NOT latch Down: it takes [FAILURE_THRESHOLD] consecutive failures, so a
 *   transient 5xx/timeout is ignored. The first success immediately clears back to Up.
 *
 * Recovery is automatic: the moment the transport flips back to online we re-enter the ping loop and
 * probe right away, and any single 2xx flips the status to Up.
 */
@Singleton
class HealthProbe @Inject constructor(
    private val connectivityMonitor: ConnectivityMonitor,
    private val healthApi: HealthApi,
) {
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val status: Flow<BackendStatus> =
        connectivityMonitor.isOnline
            .debounceOffline()
            .distinctUntilChanged()
            .flatMapLatest { online ->
                if (!online) flowOf(BackendStatus.Down) else pingLoop()
            }
            .distinctUntilChanged()

    /** Forces a single immediate probe and returns the resulting status. */
    suspend fun probeNow(): BackendStatus = if (ping()) BackendStatus.Up else BackendStatus.Down

    /**
     * Holds an offline (`false`) transport edge for a short window before propagating it, while
     * letting an online (`true`) edge through immediately. A `true` arriving inside the window
     * cancels the pending offline, so transient transport blips never reach the status flow. This is
     * the transport-side anti-flap that complements the consecutive-failure ping logic.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private fun Flow<Boolean>.debounceOffline(): Flow<Boolean> =
        distinctUntilChanged().flatMapLatest { online ->
            if (online) {
                flowOf(true)
            } else flow {
                delay(OFFLINE_DEBOUNCE_MS)
                emit(false)
            }
        }

    private fun pingLoop(): Flow<BackendStatus> = flow {
        var consecutiveFailures = 0
        var lastEmitted: BackendStatus? = null
        while (true) {
            val up = ping()
            if (up) {
                consecutiveFailures = 0
            } else {
                consecutiveFailures++
            }
            // Stay Up until we've seen enough consecutive failures to be confident the backend is
            // really down; recover to Up on the first success. Until the threshold is crossed we
            // hold the previously emitted status (initially nothing, so the first state is Up only
            // once a probe succeeds, or Down once the threshold of failures is reached).
            val status = when {
                up -> BackendStatus.Up
                consecutiveFailures >= FAILURE_THRESHOLD -> BackendStatus.Down
                else -> lastEmitted ?: BackendStatus.Up
            }
            lastEmitted = status
            emit(status)
            delay(if (status == BackendStatus.Up) UP_INTERVAL_MS else DOWN_INTERVAL_MS)
        }
    }

    private suspend fun ping(): Boolean = try {
        val healthResp = healthApi.health()
        if (healthResp.isSuccessful) {
            true
        } else if (healthResp.code() == 404) {
            healthApi.ping().isSuccessful
        } else {
            false
        }
    } catch (_: Exception) {
        false
    }

    private companion object {
        const val UP_INTERVAL_MS = 15_000L
        const val DOWN_INTERVAL_MS = 5_000L
        /** Hold a transport-offline edge this long before believing it (anti-flap). */
        const val OFFLINE_DEBOUNCE_MS = 2_000L
        /** Consecutive failed probes required before declaring the backend Down. */
        const val FAILURE_THRESHOLD = 2
    }
}
