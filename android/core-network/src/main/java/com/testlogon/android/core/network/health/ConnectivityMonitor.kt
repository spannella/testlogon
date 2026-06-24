package com.testlogon.android.core.network.health

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.callbackFlow
import java.util.Collections
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Observes OS-level network transport availability via [ConnectivityManager] and emits a single
 * authoritative `true`/`false`.
 *
 * Source-of-truth design (fixes the historical "jumps offline while actually online" flap):
 *
 * - We keep a **set** of currently-usable [Network]s instead of reacting to the last callback only.
 *   A network counts as usable once it is `onAvailable` and (when we have caps for it) has
 *   `NET_CAPABILITY_INTERNET`. We DELIBERATELY do **not** treat a transient loss of
 *   `NET_CAPABILITY_VALIDATED` as "offline": Android re-validates constantly (captive-portal probes,
 *   Wi-Fi roaming, cellular handoff) and `VALIDATED` flickers off for fully-connected users. Using
 *   validation as the offline trigger was the root cause of the random offline flapping.
 * - Online == the usable set is non-empty. We only fall to `false` once the set is truly empty
 *   (every transport is gone), so a Wi-Fi→cellular handoff (one `onLost` while another network is
 *   present) never reports offline.
 * - The state seed and every transition are recomputed from the set, so recovery is automatic: the
 *   moment any network is `onAvailable` again we emit `true`.
 *
 * Debouncing of the visible transition (so even a true-but-momentary blip doesn't surface) is layered
 * in [HealthProbe]/the banner ViewModel; this flow stays the raw, correct transport signal.
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

        // Set of networks the OS currently considers usable. Mutated only from callback threads,
        // which ConnectivityManager serializes, but guard with synchronization to be safe.
        val usable = Collections.synchronizedSet(HashSet<Network>())

        fun emitState() {
            // Cross-check against the OS in case our set drifted (process was idle, etc.).
            trySend(usable.isNotEmpty() || cm.activeNetwork != null)
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                usable.add(network)
                emitState()
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                // Only INTERNET capability gates membership. VALIDATED is intentionally ignored as a
                // trigger (it flaps); a network that has INTERNET but is briefly un-validated is still
                // "online" from the user's point of view and avoids the false-offline jump.
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    usable.add(network)
                } else {
                    usable.remove(network)
                }
                emitState()
            }

            override fun onLost(network: Network) {
                usable.remove(network)
                emitState()
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(request, callback)
        // Seed from the current OS state so we don't start "offline" before the first callback.
        trySend(cm.activeNetwork != null)
        awaitClose { cm.unregisterNetworkCallback(callback) }
    }.distinctUntilChanged().conflate()
}
