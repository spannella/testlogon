package com.testlogon.android.core.network.health

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.distinctUntilChanged
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Observes OS-level network transport availability via [ConnectivityManager].
 * Emits `true` while a validated, internet-capable transport is present.
 */
@Singleton
class ConnectivityMonitor @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    val isOnline: Flow<Boolean> = callbackFlow {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        if (cm == null) {
            trySend(true) // can't observe -> assume online
            awaitClose { }
            return@callbackFlow
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                trySend(true)
            }

            override fun onLost(network: Network) {
                trySend(cm.activeNetwork != null)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                trySend(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(request, callback)
        trySend(cm.activeNetwork != null)
        awaitClose { cm.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged().conflate()
}
