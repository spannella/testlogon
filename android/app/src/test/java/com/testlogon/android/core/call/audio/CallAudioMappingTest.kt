package com.testlogon.android.core.call.audio

import com.testlogon.android.feature.call.incall.AudioRoute
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-304 — pure JVM tests for [CallAudioMapping.map] (Telecom route-bit primitives -> [CallAudioStateUi]).
 * No android.telecom types: the mapping redeclares the platform route constants as plain Int literals
 * (ROUTE_EARPIECE=1, ROUTE_BLUETOOTH=2, ROUTE_WIRED_HEADSET=4, ROUTE_SPEAKER=8), so this is fully device-free.
 */
class CallAudioMappingTest {

    private val earpiece = 1
    private val bluetooth = 2
    private val wired = 4
    private val speaker = 8

    @Test
    fun earpieceActive_earpieceAndSpeakerSupported() {
        val ui = CallAudioMapping.map(
            activeRouteBit = earpiece,
            supportedRouteMask = earpiece or speaker,
            isMuted = false,
        )
        assertEquals(AudioRoute.EARPIECE, ui.active)
        assertEquals(setOf(AudioRoute.EARPIECE, AudioRoute.SPEAKER), ui.available)
        assertEquals(false, ui.muted)
    }

    @Test
    fun speakerActive_mapsToSpeaker() {
        val ui = CallAudioMapping.map(speaker, earpiece or speaker, false)
        assertEquals(AudioRoute.SPEAKER, ui.active)
    }

    @Test
    fun bluetoothActive_mapsToBluetooth() {
        val ui = CallAudioMapping.map(bluetooth, earpiece or bluetooth, false)
        assertEquals(AudioRoute.BLUETOOTH, ui.active)
        assertTrue(ui.available.contains(AudioRoute.BLUETOOTH))
    }

    @Test
    fun wiredActive_mapsToWired() {
        val ui = CallAudioMapping.map(wired, earpiece or wired, false)
        assertEquals(AudioRoute.WIRED, ui.active)
        assertTrue(ui.available.contains(AudioRoute.WIRED))
    }

    @Test
    fun mutedTrue_isReported() {
        val ui = CallAudioMapping.map(earpiece, earpiece, true)
        assertTrue(ui.muted)
    }

    @Test
    fun allFourRoutesSupported_allAvailable() {
        val ui = CallAudioMapping.map(
            activeRouteBit = speaker,
            supportedRouteMask = earpiece or bluetooth or wired or speaker,
            isMuted = false,
        )
        assertEquals(
            setOf(AudioRoute.EARPIECE, AudioRoute.SPEAKER, AudioRoute.BLUETOOTH, AudioRoute.WIRED),
            ui.available,
        )
    }

    @Test
    fun unknownActiveBit_defaultsToEarpiece() {
        val ui = CallAudioMapping.map(activeRouteBit = 0, supportedRouteMask = 0, isMuted = false)
        assertEquals(AudioRoute.EARPIECE, ui.active)
        // Defensive default: never an empty available set.
        assertEquals(setOf(AudioRoute.EARPIECE), ui.available)
    }

    @Test
    fun activeRouteAlwaysAvailable_evenIfMaskOmitsIt() {
        // Mask only lists earpiece but the OS reports speaker active -> speaker still offered.
        val ui = CallAudioMapping.map(activeRouteBit = speaker, supportedRouteMask = earpiece, isMuted = false)
        assertTrue(ui.available.contains(AudioRoute.SPEAKER))
        assertTrue(ui.available.contains(AudioRoute.EARPIECE))
    }
}
