package com.testlogon.android.feature.messaging.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-130/131 — pure JVM tests for attachment MIME / quality decisions. */
class AttachmentMimeTest {

    @Test
    fun isImage_isVideo() {
        assertTrue(AttachmentMime.isImage("image/jpeg"))
        assertTrue(AttachmentMime.isImage("image/png"))
        assertFalse(AttachmentMime.isImage("video/mp4"))
        assertTrue(AttachmentMime.isVideo("video/mp4"))
        assertFalse(AttachmentMime.isVideo("image/jpeg"))
        assertFalse(AttachmentMime.isImage(null))
    }

    @Test
    fun outputImageMime_preservesAlphaPngOnly() {
        assertEquals("image/png", AttachmentMime.outputImageMime("image/png", sourceHasAlpha = true))
        // No alpha -> re-encode to JPEG even for PNG source.
        assertEquals("image/jpeg", AttachmentMime.outputImageMime("image/png", sourceHasAlpha = false))
        // JPEG source stays JPEG regardless of alpha flag.
        assertEquals("image/jpeg", AttachmentMime.outputImageMime("image/jpeg", sourceHasAlpha = true))
    }

    @Test
    fun extensionMatchesMime() {
        assertEquals("jpg", AttachmentMime.extensionFor("image/jpeg"))
        assertEquals("png", AttachmentMime.extensionFor("image/png"))
    }

    @Test
    fun qualityStepsDownAndFloorsAt50() {
        assertEquals(80, AttachmentMime.qualityForPass(0))
        assertEquals(70, AttachmentMime.qualityForPass(1))
        assertEquals(60, AttachmentMime.qualityForPass(2))
        assertEquals(50, AttachmentMime.qualityForPass(3))
        assertEquals(50, AttachmentMime.qualityForPass(9))
    }
}
