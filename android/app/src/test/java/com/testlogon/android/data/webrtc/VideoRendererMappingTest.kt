package com.testlogon.android.data.webrtc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-293/294 — pure video-renderer mapping tests (scaling -> ScalingType, track-swap identity, default
 * mirroring). No SDK, no Compose: these are the JVM-testable helpers the FLAGGED renderer placeholder and a
 * future real SurfaceViewRenderer-backed renderer both share.
 */
class VideoRendererMappingTest {

    @Test
    fun fitScaling_mapsToAspectFit_forBothComponents() {
        assertEquals(
            RendererScalingType.SCALE_ASPECT_FIT,
            VideoRendererMapping.toFitType(VideoScaling.FIT),
        )
        assertEquals(
            RendererScalingType.SCALE_ASPECT_FIT,
            VideoRendererMapping.toFillType(VideoScaling.FIT),
        )
    }

    @Test
    fun fillScaling_mapsToBalancedAndFill() {
        assertEquals(
            RendererScalingType.SCALE_ASPECT_BALANCED,
            VideoRendererMapping.toFitType(VideoScaling.FILL),
        )
        assertEquals(
            RendererScalingType.SCALE_ASPECT_FILL,
            VideoRendererMapping.toFillType(VideoScaling.FILL),
        )
    }

    @Test
    fun shouldSwap_byReferenceIdentity() {
        val a = Any()
        val b = Any()
        assertFalse(VideoRendererMapping.shouldSwap(a, a))
        assertTrue(VideoRendererMapping.shouldSwap(a, b))
        assertTrue(VideoRendererMapping.shouldSwap(a, null))
        assertTrue(VideoRendererMapping.shouldSwap(null, b))
        assertFalse(VideoRendererMapping.shouldSwap(null, null))
    }

    @Test
    fun defaultMirror_localMirrored_remoteNot() {
        assertTrue(VideoRendererMapping.defaultMirror(VideoRole.LOCAL))
        assertFalse(VideoRendererMapping.defaultMirror(VideoRole.REMOTE))
    }
}
