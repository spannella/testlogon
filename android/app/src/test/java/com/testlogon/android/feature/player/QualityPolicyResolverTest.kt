package com.testlogon.android.feature.player

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-169 / AND-172 — pure JVM tests for the adaptive-quality / data-saver cap mapping. No Android /
 * Media3 on the classpath; the full matrix {quality} x {metered/unmetered/dataSaver} x {capOn/capOff}
 * is asserted via the pure [QualityPolicyResolver].
 */
class QualityPolicyResolverTest {

    private fun policy(
        q: VideoQuality,
        cap: Boolean = true,
        meteredMax: Int = 480,
    ) = QualityPolicy(userSelection = q, capOnMetered = cap, meteredMaxHeightPx = meteredMax)

    private val unmetered = NetworkStatus(isMetered = false, dataSaverActive = false)
    private val metered = NetworkStatus(isMetered = true, dataSaverActive = false)
    private val dataSaverOs = NetworkStatus(isMetered = false, dataSaverActive = true)

    // TC-AND-169-01 — metered cap wins over AUTO; cap wins over higher user choice.
    @Test
    fun meteredCap_winsOverAuto_andHigherChoice() {
        assertEquals(480, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.AUTO), metered))
        assertEquals(480, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.P720), metered))
        assertEquals(480, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.P1080), metered))
    }

    // TC-AND-169-02 — user choice below cap wins (more restrictive).
    @Test
    fun userChoiceBelowCap_wins() {
        assertEquals(360, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.P360), metered))
        assertEquals(360, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.P360), unmetered))
    }

    // TC-AND-169-03 — DATA_SAVER always forces lowest; AUTO unmetered unbounded; cap-off allows high.
    @Test
    fun dataSaver_forcesLowest_onAnyNetwork() {
        listOf(metered, unmetered, dataSaverOs).forEach { net ->
            assertEquals(0, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.DATA_SAVER), net))
            assertTrue(QualityPolicyResolver.resolve(policy(VideoQuality.DATA_SAVER), net).forceLowest)
        }
    }

    @Test
    fun auto_unmetered_isUnbounded() {
        assertNull(QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.AUTO), unmetered))
        assertNull(QualityPolicyResolver.resolve(policy(VideoQuality.AUTO), unmetered).maxHeightPx)
    }

    @Test
    fun capOff_metered_allowsHigh() {
        assertNull(
            QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.AUTO, cap = false), metered),
        )
    }

    // TC-AND-169-04 — OS Data Saver triggers cap even on an unmetered network.
    @Test
    fun osDataSaver_triggersCap_onUnmetered() {
        assertEquals(480, QualityPolicyResolver.resolveMaxHeightPx(policy(VideoQuality.AUTO), dataSaverOs))
    }

    @Test
    fun resolve_projectsCappedFlagAndSelection() {
        val capped = QualityPolicyResolver.resolve(policy(VideoQuality.AUTO), metered)
        assertEquals(VideoQuality.AUTO, capped.selection)
        assertEquals(480, capped.maxHeightPx)
        assertTrue(capped.capped)
        assertFalse(capped.forceLowest)

        val free = QualityPolicyResolver.resolve(policy(VideoQuality.AUTO), unmetered)
        assertFalse(free.capped)
        assertNull(free.maxHeightPx)
    }

    @Test
    fun toTrackParams_mapsCorrectly() {
        // Force-lowest -> (1,1) intent.
        val lowest = EffectiveQuality(forceLowest = true).toTrackParams()
        assertTrue(lowest.forceLowest)
        assertNull(lowest.maxHeightPx)

        // Height ceiling -> max-height.
        val capped = EffectiveQuality(maxHeightPx = 480).toTrackParams()
        assertFalse(capped.forceLowest)
        assertEquals(480, capped.maxHeightPx)

        // Auto -> clear constraints.
        val auto = EffectiveQuality(maxHeightPx = null).toTrackParams()
        assertFalse(auto.forceLowest)
        assertNull(auto.maxHeightPx)
    }

    @Test
    fun videoQuality_fromName_isForwardCompatible() {
        assertEquals(VideoQuality.P720, VideoQuality.fromName("P720"))
        assertEquals(VideoQuality.DEFAULT, VideoQuality.fromName("UNKNOWN_FUTURE"))
        assertEquals(VideoQuality.DEFAULT, VideoQuality.fromName(null))
    }

    // AND-169 — data-saver disables autoplay; honored only when cap is off.
    @Test
    fun autoplay_disabledByDataSaver() {
        assertFalse(PlaybackPolicy.autoplayEnabled(userAutoplay = true, capOnMetered = true))
        assertTrue(PlaybackPolicy.autoplayEnabled(userAutoplay = true, capOnMetered = false))
        assertFalse(PlaybackPolicy.autoplayEnabled(userAutoplay = false, capOnMetered = false))
    }
}
