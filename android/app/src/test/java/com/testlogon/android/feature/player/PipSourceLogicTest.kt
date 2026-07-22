package com.testlogon.android.feature.player

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CALL-PiP — pure JVM tests for the Picture-in-Picture SOURCE-selection + call-eligibility decisions
 * that gate the new live-video-call PiP branch. No Android runtime; complements PipParamsLogicTest.
 */
class PipSourceLogicTest {

    // --- selectSource: which content the PiP window collapses to -----------------------------------

    @Test
    fun selectSource_videoCallConnected_selectsCall() {
        // A connected video call is registered as active -> the CALL branch is chosen (native WebRTC surface).
        assertEquals(
            PipSourceLogic.PipSourceKind.CALL,
            PipSourceLogic.selectSource(callActive = true, media3Active = false),
        )
    }

    @Test
    fun selectSource_media3Active_stillSelectsPlayerBranch_noRegression() {
        // VOD / broadcast / messaging / feed player active + no call -> the existing MEDIA3 branch (unchanged).
        assertEquals(
            PipSourceLogic.PipSourceKind.MEDIA3,
            PipSourceLogic.selectSource(callActive = false, media3Active = true),
        )
    }

    @Test
    fun selectSource_callTakesPrecedenceOverMedia3() {
        // If both are somehow registered, the live call wins (higher-intent foreground activity).
        assertEquals(
            PipSourceLogic.PipSourceKind.CALL,
            PipSourceLogic.selectSource(callActive = true, media3Active = true),
        )
    }

    @Test
    fun selectSource_nothingActive_isNone() {
        assertEquals(
            PipSourceLogic.PipSourceKind.NONE,
            PipSourceLogic.selectSource(callActive = false, media3Active = false),
        )
    }

    // --- isCallPipEligible: only a CONNECTED VIDEO call floats -------------------------------------

    @Test
    fun isCallPipEligible_videoConnected_true() {
        assertTrue(PipSourceLogic.isCallPipEligible(isVideoCall = true, isConnected = true))
    }

    @Test
    fun isCallPipEligible_audioOnly_false() {
        // Audio-only call: nothing to show -> NOT eligible; it keeps running in the ConnectionService.
        assertFalse(PipSourceLogic.isCallPipEligible(isVideoCall = false, isConnected = true))
    }

    @Test
    fun isCallPipEligible_videoNotYetConnected_false() {
        // Connecting/ringing video call: no remote frames yet -> not eligible (do not arm auto-enter).
        assertFalse(PipSourceLogic.isCallPipEligible(isVideoCall = true, isConnected = false))
    }

    // --- shouldAutoEnterCallOnLeave: mirrors the media3 predicate ----------------------------------

    @Test
    fun shouldAutoEnterCallOnLeave_requiresEligibleAndSupported() {
        assertTrue(PipSourceLogic.shouldAutoEnterCallOnLeave(callPipEligible = true, pipSupported = true))
        assertFalse(PipSourceLogic.shouldAutoEnterCallOnLeave(callPipEligible = true, pipSupported = false))
        assertFalse(PipSourceLogic.shouldAutoEnterCallOnLeave(callPipEligible = false, pipSupported = true))
    }

    // --- call-ends-in-PiP: source clears -> selection falls back off the call branch ---------------

    @Test
    fun callEnds_sourceCleared_selectionLeavesCallBranch() {
        // While connected: CALL. After the call ends and the source unregisters (callActive=false), the
        // selection returns to NONE (or MEDIA3 if a player is up) so PiP exits the call branch.
        assertEquals(
            PipSourceLogic.PipSourceKind.CALL,
            PipSourceLogic.selectSource(callActive = true, media3Active = false),
        )
        assertEquals(
            PipSourceLogic.PipSourceKind.NONE,
            PipSourceLogic.selectSource(callActive = false, media3Active = false),
        )
    }
}
