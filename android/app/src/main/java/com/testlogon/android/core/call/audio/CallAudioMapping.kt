package com.testlogon.android.core.call.audio

/**
 * AND-304 — PURE (android-free) mapping from Telecom audio-state PRIMITIVES to [CallAudioStateUi].
 *
 * The android telecom `CallAudioState` type can only be constructed on a device, so this object never
 * imports it: it takes the raw `route` / `supportedRouteMask` ints and the mute flag the (android)
 * [CallAudioRouter] reads off the real CallAudioState, and resolves them against the well-known
 * `android.telecom.CallAudioState` route constants redeclared here as plain Int literals. That keeps the
 * bit -> route translation fully JVM-unit-testable without Robolectric or a device.
 *
 * Constants mirror the platform values verbatim:
 *   ROUTE_EARPIECE = 1, ROUTE_BLUETOOTH = 2, ROUTE_WIRED_HEADSET = 4, ROUTE_SPEAKER = 8.
 */
object CallAudioMapping {

    private const val ROUTE_EARPIECE = 1
    private const val ROUTE_BLUETOOTH = 2
    private const val ROUTE_WIRED_HEADSET = 4
    private const val ROUTE_SPEAKER = 8

    /**
     * Maps a Telecom audio state to the UI snapshot.
     *
     * @param activeRouteBit the single active route bit (CallAudioState.route).
     * @param supportedRouteMask the OR of routes the call can switch to (CallAudioState.supportedRouteMask).
     * @param isMuted whether the call is muted (CallAudioState.isMuted).
     */
    fun map(activeRouteBit: Int, supportedRouteMask: Int, isMuted: Boolean): CallAudioStateUi {
        val available = buildSet {
            if (supportedRouteMask and ROUTE_EARPIECE != 0) add(CallAudioRoute.EARPIECE)
            if (supportedRouteMask and ROUTE_SPEAKER != 0) add(CallAudioRoute.SPEAKER)
            if (supportedRouteMask and ROUTE_BLUETOOTH != 0) add(CallAudioRoute.BLUETOOTH)
            if (supportedRouteMask and ROUTE_WIRED_HEADSET != 0) add(CallAudioRoute.WIRED)
        }
        return CallAudioStateUi(
            active = toRoute(activeRouteBit),
            // Defensive: a route the OS reports active is always offered, even if the mask omitted it.
            available = (available + toRoute(activeRouteBit)).ifEmpty {
                setOf(CallAudioRoute.EARPIECE)
            },
            muted = isMuted,
        )
    }

    /** Translates a single active route bit to a [CallAudioRoute]; an unknown bit defaults to EARPIECE. */
    private fun toRoute(routeBit: Int): CallAudioRoute = when (routeBit) {
        ROUTE_SPEAKER -> CallAudioRoute.SPEAKER
        ROUTE_BLUETOOTH -> CallAudioRoute.BLUETOOTH
        ROUTE_WIRED_HEADSET -> CallAudioRoute.WIRED
        ROUTE_EARPIECE -> CallAudioRoute.EARPIECE
        else -> CallAudioRoute.EARPIECE
    }
}
