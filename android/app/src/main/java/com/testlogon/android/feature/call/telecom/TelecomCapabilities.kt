package com.testlogon.android.feature.call.telecom

import android.os.Build
import android.telecom.TelecomManager
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-304 — capability probe gating the entire self-managed Telecom integration.
 *
 * Self-managed PhoneAccounts (CAPABILITY_SELF_MANAGED / Connection.PROPERTY_SELF_MANAGED) are API 26+, and a
 * device with no TelecomManager (some OEM/region SKUs return null) cannot host a ConnectionService at all.
 * [isSupported] therefore requires BOTH; when it is false every Telecom call site no-ops and the AND-297
 * FCM + full-screen fallback runs unchanged. The result is cached (it cannot change at runtime).
 *
 * The decision logic is factored into the pure [supported] function so it is unit-testable without a device;
 * the injected probe just feeds it Build.VERSION.SDK_INT and whether the injected [TelecomManager] is null.
 */
@Singleton
class TelecomCapabilities @Inject constructor(
    private val telecomManager: TelecomManager?,
) {

    private var cached: Boolean? = null

    /** True iff self-managed Telecom can be used on this device. Cached after the first probe. */
    fun isSupported(): Boolean {
        cached?.let { return it }
        val result = supported(sdkInt = Build.VERSION.SDK_INT, telecomAvailable = telecomManager != null)
        cached = result
        return result
    }

    companion object {
        /** Pure decision: API 26+ AND a TelecomManager is available. Exposed for unit tests. */
        fun supported(sdkInt: Int, telecomAvailable: Boolean): Boolean =
            sdkInt >= Build.VERSION_CODES.O && telecomAvailable
    }
}
