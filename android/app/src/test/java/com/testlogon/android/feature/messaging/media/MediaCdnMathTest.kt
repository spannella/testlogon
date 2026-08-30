package com.testlogon.android.feature.messaging.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-141 — pure JVM tests for media-CDN url resolution + upload retry/progress math. */
class MediaCdnMathTest {

    // ---- resolveMediaUrl ----

    @Test
    fun resolve_prefersAbsoluteApiUrl() {
        val out = MediaCdnMath.resolveMediaUrl(
            url = "https://cdn.example.com/a/b.jpg",
            bucket = "media",
            key = "conv/1/x.jpg",
            cdnBase = "https://other.cdn",
        )
        assertEquals("https://cdn.example.com/a/b.jpg", out)
    }

    @Test
    fun resolve_trimsAndPrefersUrl() {
        val out = MediaCdnMath.resolveMediaUrl("  https://x/y.jpg  ", "m", "k", null)
        assertEquals("https://x/y.jpg", out)
    }

    @Test
    fun resolve_blankUrl_usesCdnBaseWhenAbsolute() {
        val out = MediaCdnMath.resolveMediaUrl(
            url = "   ",
            bucket = "media-bucket",
            key = "conv/1/photo name.jpg",
            cdnBase = "https://cdn.bitbazaar.cc/",
        )
        assertEquals("https://cdn.bitbazaar.cc/media-bucket/conv/1/photo%20name.jpg", out)
    }

    @Test
    fun resolve_nullUrl_usesCdnBaseNoTrailingSlash() {
        val out = MediaCdnMath.resolveMediaUrl(null, "b", "k1/k2.png", "https://cdn.io")
        assertEquals("https://cdn.io/b/k1/k2.png", out)
    }

    @Test
    fun resolve_noCdnBase_fallsBackToMockRelative() {
        val out = MediaCdnMath.resolveMediaUrl(null, "media", "conv/1/x.jpg", null)
        assertEquals("/mock/s3/media/conv/1/x.jpg", out)
    }

    @Test
    fun resolve_relativeCdnBase_fallsBackToMockRelative() {
        // A non-absolute cdnBase is not usable as an origin -> mock fallback (dev/mock unchanged).
        val out = MediaCdnMath.resolveMediaUrl(null, "media", "k.jpg", "/mock/s3")
        assertEquals("/mock/s3/media/k.jpg", out)
    }

    @Test
    fun resolve_bucketless_mockRelative() {
        val out = MediaCdnMath.resolveMediaUrl(null, null, "bare-key.jpg", null)
        assertEquals("/mock/s3/bare-key.jpg", out)
    }

    @Test
    fun resolve_cdnBaseButNoBucket_fallsBackToMockRelative() {
        // Without a bucket we cannot build a CDN object url -> mock fallback.
        val out = MediaCdnMath.resolveMediaUrl(null, "", "k.jpg", "https://cdn.io")
        assertEquals("/mock/s3/k.jpg", out)
    }

    @Test
    fun resolve_noUrlNoKey_null() {
        assertNull(MediaCdnMath.resolveMediaUrl(null, "bucket", null, "https://cdn.io"))
        assertNull(MediaCdnMath.resolveMediaUrl("", "bucket", "  ", null))
    }

    // ---- encodeMediaKey ----

    @Test
    fun encode_keepsSlashes_encodesSpecials() {
        assertEquals("a/b%20c/d%2Be.jpg", MediaCdnMath.encodeMediaKey("a/b c/d+e.jpg"))
    }

    @Test
    fun encode_plainKeyUnchanged() {
        assertEquals("conv/1/photo.jpg", MediaCdnMath.encodeMediaKey("conv/1/photo.jpg"))
    }

    // ---- isRetryableUploadStatus ----

    @Test
    fun retryable_transportAndThrottleAnd5xx() {
        assertTrue(MediaCdnMath.isRetryableUploadStatus(0))
        assertTrue(MediaCdnMath.isRetryableUploadStatus(408))
        assertTrue(MediaCdnMath.isRetryableUploadStatus(429))
        assertTrue(MediaCdnMath.isRetryableUploadStatus(500))
        assertTrue(MediaCdnMath.isRetryableUploadStatus(503))
    }

    @Test
    fun notRetryable_permanent4xx() {
        assertFalse(MediaCdnMath.isRetryableUploadStatus(400))
        assertFalse(MediaCdnMath.isRetryableUploadStatus(403)) // expired presign -> restart, not auto-retry
        assertFalse(MediaCdnMath.isRetryableUploadStatus(404))
        assertFalse(MediaCdnMath.isRetryableUploadStatus(422))
        assertFalse(MediaCdnMath.isRetryableUploadStatus(200))
    }

    // ---- uploadBackoffMs ----

    @Test
    fun backoff_exponentialThenCapped() {
        assertEquals(0L, MediaCdnMath.uploadBackoffMs(0))
        assertEquals(0L, MediaCdnMath.uploadBackoffMs(-3))
        assertEquals(1_000L, MediaCdnMath.uploadBackoffMs(1))
        assertEquals(2_000L, MediaCdnMath.uploadBackoffMs(2))
        assertEquals(4_000L, MediaCdnMath.uploadBackoffMs(3))
        assertEquals(8_000L, MediaCdnMath.uploadBackoffMs(4))
        assertEquals(16_000L, MediaCdnMath.uploadBackoffMs(5))
        assertEquals(30_000L, MediaCdnMath.uploadBackoffMs(6)) // 32s -> capped
        assertEquals(30_000L, MediaCdnMath.uploadBackoffMs(100)) // no overflow
    }

    // ---- uploadProgressPct ----

    @Test
    fun progress_clampAndUnknown() {
        assertEquals(0, MediaCdnMath.uploadProgressPct(0, 0))
        assertEquals(0, MediaCdnMath.uploadProgressPct(50, 0))
        assertEquals(0, MediaCdnMath.uploadProgressPct(0, 200))
        assertEquals(50, MediaCdnMath.uploadProgressPct(100, 200))
        assertEquals(100, MediaCdnMath.uploadProgressPct(200, 200))
        assertEquals(100, MediaCdnMath.uploadProgressPct(300, 200)) // loaded>total race
    }

    @Test
    fun maxRetriesConstant() {
        assertEquals(5, MediaCdnMath.MAX_UPLOAD_RETRIES)
    }
}
