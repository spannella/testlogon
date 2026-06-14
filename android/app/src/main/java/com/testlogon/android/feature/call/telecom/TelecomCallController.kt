package com.testlogon.android.feature.call.telecom

import android.content.ComponentName
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import androidx.annotation.RequiresApi
import com.testlogon.android.data.call.CallMode
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-304 — the app-facing facade over [TelecomManager] for the self-managed call integration.
 *
 * GRACEFUL DEGRADATION is the contract: every public method is gated on [isTelecomSupported] and wraps the
 * underlying TelecomManager call in try/catch (OEMs are known to throw from registerPhoneAccount / placeCall
 * / addNewIncomingCall). On unsupported devices or ANY failure the method no-ops / returns false, and the
 * caller falls back to the AND-296/297 flow. Nothing here runs at construction — registration is lazy
 * ([ensurePhoneAccountRegistered], idempotent) so app startup stays safe.
 *
 * The PhoneAccount is self-managed (CAPABILITY_SELF_MANAGED, API 26+): the app owns its own in-call UI
 * (AND-298) and call audio; we do not surface in the system dialer. STOP-AND-FLAG: real call MEDIA is
 * FLAGGED — Telecom models the call to the OS (audio focus, do-not-disturb, headset buttons) but no WebRTC
 * audio actually flows yet.
 */
@Singleton
class TelecomCallController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val telecomManager: TelecomManager?,
    private val capabilities: TelecomCapabilities,
    private val registry: ConnectionRegistry,
) {

    @Volatile
    private var phoneAccountRegistered = false

    /** True iff self-managed Telecom can be used on this device (delegates to the cached capability probe). */
    fun isTelecomSupported(): Boolean = capabilities.isSupported()

    /** The registry of live OS connections (exposed so callers can correlate a call id post-placement). */
    fun connections(): ConnectionRegistry = registry

    /**
     * Idempotently registers the self-managed PhoneAccount. No-op on unsupported devices; wrapped in
     * try/catch because OEM TelecomManager implementations throw here. Safe to call on every call start.
     */
    fun ensurePhoneAccountRegistered() {
        if (!isTelecomSupported() || phoneAccountRegistered) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val tm = telecomManager ?: return
        runCatching {
            tm.registerPhoneAccount(buildPhoneAccount())
            phoneAccountRegistered = true
        }
    }

    /**
     * Places an outgoing call through Telecom. Returns true if the OS accepted the placement; false on any
     * failure (unsupported, missing manage-own-calls grant, OEM throw) so the caller runs the AND-296 flow.
     */
    fun placeOutgoing(callId: String, displayName: String?, video: Boolean): Boolean {
        if (!isTelecomSupported()) return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
        val tm = telecomManager ?: return false
        ensurePhoneAccountRegistered()
        if (!phoneAccountRegistered) return false
        return runCatching {
            val extras = Bundle().apply {
                putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, phoneAccountHandle())
                putBoolean(EXTRA_IS_VIDEO, video)
                putBundle(
                    TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS,
                    Bundle().apply {
                        putString(EXTRA_CALL_ID, callId)
                        displayName?.let { putString(EXTRA_DISPLAY_NAME, it) }
                    },
                )
            }
            tm.placeCall(selfManagedAddress(callId), extras)
            true
        }.getOrDefault(false)
    }

    /**
     * Reports an incoming call to Telecom (so the OS arbitrates focus / DND / wired-headset answer). Returns
     * true if accepted; false on any failure so the caller uses the AND-297 notification path instead.
     */
    fun reportIncoming(callId: String, displayName: String?, video: Boolean): Boolean {
        if (!isTelecomSupported()) return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
        val tm = telecomManager ?: return false
        ensurePhoneAccountRegistered()
        if (!phoneAccountRegistered) return false
        return runCatching {
            val extras = Bundle().apply {
                putParcelable(
                    TelecomManager.EXTRA_INCOMING_CALL_ADDRESS,
                    selfManagedAddress(callId),
                )
                putBoolean(EXTRA_IS_VIDEO, video)
                putString(EXTRA_CALL_ID, callId)
                displayName?.let { putString(EXTRA_DISPLAY_NAME, it) }
            }
            tm.addNewIncomingCall(phoneAccountHandle(), extras)
            true
        }.getOrDefault(false)
    }

    /** The stable [PhoneAccountHandle] for this app's ConnectionService. */
    fun phoneAccountHandle(): PhoneAccountHandle = PhoneAccountHandle(
        ComponentName(context, TestLogonConnectionService::class.java),
        PHONE_ACCOUNT_ID,
    )

    @RequiresApi(Build.VERSION_CODES.O)
    private fun buildPhoneAccount(): PhoneAccount = PhoneAccount.builder(
        phoneAccountHandle(),
        ACCOUNT_LABEL,
    )
        .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
        .build()

    /**
     * The self-managed Uri carrying the [callId]. A self-managed account is not tel-routed; we use the app's
     * custom scheme so the address is opaque to the dialer and the call id round-trips via the host.
     */
    private fun selfManagedAddress(callId: String): Uri =
        Uri.fromParts(SELF_MANAGED_SCHEME, callId, null)

    companion object {
        /** Stable PhoneAccount id (single self-managed account for the whole app). */
        const val PHONE_ACCOUNT_ID = "testlogon-self-managed"
        private const val ACCOUNT_LABEL = "TestLogon"

        /** Custom Uri scheme for self-managed call addresses (opaque to the system dialer). */
        const val SELF_MANAGED_SCHEME = "testlogon"

        /** Extras keys round-tripped through the ConnectionRequest into [TestLogonConnection]. */
        const val EXTRA_CALL_ID = "com.testlogon.android.telecom.CALL_ID"
        const val EXTRA_DISPLAY_NAME = "com.testlogon.android.telecom.DISPLAY_NAME"
        const val EXTRA_IS_VIDEO = "com.testlogon.android.telecom.IS_VIDEO"
    }
}

/** Maps a [CallMode] to the Telecom video flag the controller carries in its extras. */
fun CallMode.isVideo(): Boolean = this == CallMode.VIDEO
