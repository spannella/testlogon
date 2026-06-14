package com.testlogon.android.feature.player

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.distinctUntilChanged
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-169 §4.2 — observes the metered / OS-Data-Saver status that drives the quality cap.
 *
 * Distinct from core-network's online/offline [com.testlogon.android.core.network.health.ConnectivityMonitor]
 * (which only tracks reachability): this observer reports whether the active transport is metered and
 * whether the OS Data Saver background restriction is enabled. All the policy DECISIONS are pure
 * ([QualityPolicyResolver] over [NetworkStatus]); this class only maps Android capabilities to the
 * framework-free [NetworkStatus] and fails open (both false) when connectivity can't be observed (§7).
 */
interface MeteredNetworkObserver {
    /** Emits the current status immediately, then on every change. Conflated + distinct. */
    fun observe(): Flow<NetworkStatus>
    fun current(): NetworkStatus
}

@Singleton
class MeteredNetworkObserverImpl @Inject constructor(
    @ApplicationContext private val context: Context,
) : MeteredNetworkObserver {

    private val cm: ConnectivityManager?
        get() = context.getSystemService(ConnectivityManager::class.java)

    override fun current(): NetworkStatus {
        val manager = cm ?: return NetworkStatus()
        val caps = manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
        return statusOf(caps, manager.restrictBackgroundStatus)
    }

    override fun observe(): Flow<NetworkStatus> = callbackFlow {
        val manager = cm
        if (manager == null) {
            trySend(NetworkStatus()) // can't observe -> fail open
            awaitClose { }
            return@callbackFlow
        }
        trySend(current())
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                trySend(current())
            }

            override fun onLost(network: Network) {
                trySend(current())
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                trySend(statusOf(caps, manager.restrictBackgroundStatus))
            }
        }
        manager.registerDefaultNetworkCallback(callback)
        awaitClose { manager.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged().conflate()

    private fun statusOf(caps: NetworkCapabilities?, restrictBackgroundStatus: Int): NetworkStatus {
        // Absent capabilities -> no active network -> fail open (not metered).
        val metered = caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val dataSaver = restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        return NetworkStatus(isMetered = metered, dataSaverActive = dataSaver)
    }
}

/** AND-169 — binds the metered-network observer seam. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MeteredNetworkObserverModule {
    @Binds
    @Singleton
    abstract fun bindMeteredNetworkObserver(impl: MeteredNetworkObserverImpl): MeteredNetworkObserver
}
