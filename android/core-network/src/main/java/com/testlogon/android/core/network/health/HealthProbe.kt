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
 * - No transport -> [BackendStatus.Down] immediately, with no ping issued.
 * - Transport up -> probes [HealthApi] on an interval (faster while down, slower while up); a 2xx
 *   is [BackendStatus.Up], anything else [BackendStatus.Down].
 *
 * Intentionally simple; richer hysteresis/jitter can be layered on later.
 */
@Singleton
class HealthProbe @Inject constructor(
    private val connectivityMonitor: ConnectivityMonitor,
    private val healthApi: HealthApi,
) {
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val status: Flow<BackendStatus> =
        connectivityMonitor.isOnline
            .flatMapLatest { online ->
                if (!online) flowOf(BackendStatus.Down) else pingLoop()
            }
            .distinctUntilChanged()

    /** Forces a single immediate probe and returns the resulting status. */
    suspend fun probeNow(): BackendStatus = if (ping()) BackendStatus.Up else BackendStatus.Down

    private fun pingLoop(): Flow<BackendStatus> = flow {
        while (true) {
            val up = ping()
            val status = if (up) BackendStatus.Up else BackendStatus.Down
            emit(status)
            delay(if (up) UP_INTERVAL_MS else DOWN_INTERVAL_MS)
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
    }
}
