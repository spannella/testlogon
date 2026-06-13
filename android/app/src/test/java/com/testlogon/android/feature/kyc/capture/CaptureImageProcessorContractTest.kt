package com.testlogon.android.feature.kyc.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-330 — JVM-testable contract for [DefaultCaptureImageProcessor] (AND-321).
 *
 * The actual decode/rotate/downscale/encode pipeline relies on android.graphics (Bitmap / BitmapFactory /
 * Matrix), android.media.ExifInterface and android.util.Base64 — none of which run on a plain JVM, and the
 * project runs NO Robolectric in app/src/test (the existing capture coverage uses a fake processor in the
 * ViewModel test). So the bitmap/EXIF/base64 behavior (orientation rotation, the <=2048 long-edge
 * downscale, JPEG quality, the NO_WRAP base64) is exercised by the instrumented/androidTest layer.
 *
 * What IS JVM-testable and locked here: the documented size-cap / quality / edge CONSTANTS that form the
 * processor's contract, and the typed [CaptureError] surface (the TooLarge size + message the ViewModel
 * relays inline as "too large", and the Unreadable singleton).
 */
class CaptureImageProcessorContractTest {

    @Test
    fun sizeAndQualityConstants_matchTheDocumentedContract() {
        // Longest edge downscaled to <= 2048 px.
        assertEquals(2048, DefaultCaptureImageProcessor.MAX_EDGE_PX)
        // Re-encoded at JPEG quality 85.
        assertEquals(85, DefaultCaptureImageProcessor.JPEG_QUALITY)
        // Encoded payload rejected above 4 MB.
        assertEquals(4L * 1024 * 1024, DefaultCaptureImageProcessor.MAX_BYTES)
        assertEquals("kyc-capture", DefaultCaptureImageProcessor.CACHE_SUBDIR)
    }

    @Test
    fun tooLarge_carriesSize_andMessageTheViewModelSurfaces() {
        val error = CaptureError.TooLarge(sizeBytes = 9_000_000)
        assertEquals(9_000_000L, error.sizeBytes)
        // The ViewModel relays error.message verbatim; its inline-error assertion checks for "too large".
        assertTrue(error.message!!.contains("too large"))
    }

    @Test
    fun unreadable_isASingletonCaptureError() {
        val a: CaptureError = CaptureError.Unreadable
        val b: CaptureError = CaptureError.Unreadable
        assertTrue(a === b)
        assertTrue(a is CaptureError)
    }
}
