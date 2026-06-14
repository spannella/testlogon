package com.testlogon.android.feature.player

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-166/167/168 — pure JVM tests for the player logic: ms->mm:ss formatting, Media3 state->UI
 * mapping, error retryability, HLS detection, host-scoped headers, redaction, token append, and
 * quality labels. No Media3/Android types touched.
 */
class PlayerLogicTest {

    // ---- AND-168 time formatting ----

    @Test
    fun timeFormat_msToMmSs() {
        assertEquals("0:00", PlayerTimeFormat.format(0L))
        assertEquals("0:05", PlayerTimeFormat.format(5_000L))
        assertEquals("0:59", PlayerTimeFormat.format(59_000L))
        assertEquals("1:00", PlayerTimeFormat.format(60_000L))
        assertEquals("2:05", PlayerTimeFormat.format(125_000L))
        // Sub-second truncates toward the floor second.
        assertEquals("0:01", PlayerTimeFormat.format(1_999L))
    }

    @Test
    fun timeFormat_hoursWhenPastAnHour() {
        assertEquals("1:00:00", PlayerTimeFormat.format(3_600_000L))
        assertEquals("1:01:05", PlayerTimeFormat.format(3_665_000L))
    }

    @Test
    fun timeFormat_negativeClampsToZero() {
        assertEquals("0:00", PlayerTimeFormat.format(-5_000L))
    }

    @Test
    fun positionLabel_withAndWithoutDuration() {
        assertEquals("0:05 / 2:05", PlayerTimeFormat.positionLabel(5_000L, 125_000L))
        // Unknown duration shows elapsed only.
        assertEquals("0:05", PlayerTimeFormat.positionLabel(5_000L, 0L))
        assertEquals("0:05", PlayerTimeFormat.positionLabel(5_000L, PlayerUiState.DURATION_UNSET))
    }

    // ---- AND-166 state mapping ----

    @Test
    fun stateMapper_mediaStateToPhase() {
        assertEquals(PlaybackPhase.IDLE, PlayerStateMapper.toPhase(PlayerStateMapper.STATE_IDLE))
        assertEquals(PlaybackPhase.BUFFERING, PlayerStateMapper.toPhase(PlayerStateMapper.STATE_BUFFERING))
        assertEquals(PlaybackPhase.READY, PlayerStateMapper.toPhase(PlayerStateMapper.STATE_READY))
        assertEquals(PlaybackPhase.ENDED, PlayerStateMapper.toPhase(PlayerStateMapper.STATE_ENDED))
        // Unknown ints fall back to IDLE.
        assertEquals(PlaybackPhase.IDLE, PlayerStateMapper.toPhase(99))
    }

    @Test
    fun stateMapper_retryability() {
        // Transient IO + behind-live -> retryable.
        assertTrue(PlayerStateMapper.isRetryable(2001)) // network connection failed
        assertTrue(PlayerStateMapper.isRetryable(2002)) // network timeout
        assertTrue(PlayerStateMapper.isRetryable(2004)) // bad http status
        assertTrue(PlayerStateMapper.isRetryable(1002)) // behind live window
        // Decode/parse/source -> not retryable.
        assertFalse(PlayerStateMapper.isRetryable(4003)) // decoding failed
        assertFalse(PlayerStateMapper.isRetryable(3001)) // parsing manifest malformed
    }

    @Test
    fun stateMapper_toError() {
        val net = PlayerStateMapper.toError(2002, "ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT")
        assertEquals(2002, net.code)
        assertEquals("ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT", net.codeName)
        assertTrue(net.isRetryable)

        val decode = PlayerStateMapper.toError(4003, "ERROR_CODE_DECODING_FAILED")
        assertFalse(decode.isRetryable)
    }

    // ---- AND-166 UI state derived helpers ----

    @Test
    fun uiState_progressAndSeekable() {
        val vod = PlayerUiState(positionMs = 5_000L, durationMs = 10_000L, isLive = false)
        assertEquals(0.5f, vod.progressFraction, 0.001f)
        assertTrue(vod.isSeekable)

        val live = PlayerUiState(positionMs = 5_000L, durationMs = PlayerUiState.DURATION_UNSET, isLive = true)
        assertEquals(0f, live.progressFraction, 0.001f)
        assertFalse(live.isSeekable)

        // Unknown duration never divides by zero.
        assertEquals(0f, PlayerUiState(positionMs = 100L, durationMs = 0L).progressFraction, 0.001f)
    }

    // ---- AND-167 source resolution ----

    @Test
    fun resolver_isHlsUri() {
        assertTrue(MediaSourceResolver.isHlsUri("https://h/x.m3u8"))
        assertTrue(MediaSourceResolver.isHlsUri("https://h/x.M3U8?token=abc"))
        assertFalse(MediaSourceResolver.isHlsUri("https://h/x.mp4"))
        assertFalse(MediaSourceResolver.isHlsUri("https://h/x.mp4?a=.m3u8"))
    }

    @Test
    fun resolver_resolveType() {
        assertEquals(PlayerMediaType.HLS, MediaSourceResolver.resolveType("https://h/x.m3u8", PlayerMediaType.AUTO))
        assertEquals(PlayerMediaType.PROGRESSIVE, MediaSourceResolver.resolveType("https://h/x.mp4", PlayerMediaType.AUTO))
        // Explicit type wins over the heuristic.
        assertEquals(PlayerMediaType.HLS, MediaSourceResolver.resolveType("https://h/x.mp4", PlayerMediaType.HLS))
        assertEquals(PlayerMediaType.PROGRESSIVE, MediaSourceResolver.resolveType("https://h/x.m3u8", PlayerMediaType.PROGRESSIVE))
    }

    @Test
    fun resolver_hostOf() {
        assertEquals("api.example.com", MediaSourceResolver.hostOf("https://api.example.com/v/x.m3u8?token=z"))
        assertEquals("cdn.foo", MediaSourceResolver.hostOf("http://user@cdn.foo:8443/seg.ts"))
        assertEquals("18.222.237.167", MediaSourceResolver.hostOf("http://18.222.237.167:8000/x.m3u8"))
        assertNull(MediaSourceResolver.hostOf("not-a-url"))
    }

    @Test
    fun resolver_headerScoping() {
        val headers = mapOf("Authorization" to "Bearer t", "X-CSRF-Token" to "c")
        // Same host as API -> headers attached.
        assertEquals(
            headers,
            MediaSourceResolver.scopedHeaders("https://api.example.com/x.m3u8", "api.example.com", headers),
        )
        // Foreign CDN host -> no app headers.
        assertTrue(
            MediaSourceResolver.scopedHeaders("https://cdn.other.net/x.m3u8", "api.example.com", headers).isEmpty(),
        )
        // No configured API host -> nothing attached.
        assertTrue(
            MediaSourceResolver.scopedHeaders("https://api.example.com/x.m3u8", null, headers).isEmpty(),
        )
        // Empty headers -> empty result.
        assertTrue(
            MediaSourceResolver.scopedHeaders("https://api.example.com/x.m3u8", "api.example.com", emptyMap()).isEmpty(),
        )
    }

    @Test
    fun resolver_redactForLog() {
        assertEquals(
            "https://h/x.m3u8",
            MediaSourceResolver.redactForLog("https://h/x.m3u8?token=secret"),
        )
        assertEquals("https://h/x.m3u8", MediaSourceResolver.redactForLog("https://h/x.m3u8"))
    }

    // ---- AND-131/167 token append (the verified web contract) ----

    @Test
    fun resolver_tokenizedManifestUrl() {
        assertEquals(
            "https://h/x.m3u8?token=abc",
            MediaSourceResolver.tokenizedManifestUrl("https://h/x.m3u8", "abc"),
        )
        // Existing query uses & separator.
        assertEquals(
            "https://h/x.m3u8?v=1&token=abc",
            MediaSourceResolver.tokenizedManifestUrl("https://h/x.m3u8?v=1", "abc"),
        )
        // Null url -> null; null/blank token -> base unchanged.
        assertNull(MediaSourceResolver.tokenizedManifestUrl(null, "abc"))
        assertEquals("https://h/x.m3u8", MediaSourceResolver.tokenizedManifestUrl("https://h/x.m3u8", null))
        assertEquals("https://h/x.m3u8", MediaSourceResolver.tokenizedManifestUrl("https://h/x.m3u8", "  "))
    }

    // ---- AND-167/169 quality labels ----

    @Test
    fun quality_labels() {
        assertEquals("1080p", PlayerQuality.heightLabel(1080))
        assertEquals("Auto", PlayerQuality.heightLabel(0))
        assertEquals("Auto", PlayerQuality.heightLabel(PlayerUiState.VALUE_UNSET))
        assertEquals("2.5 Mbps", PlayerQuality.bitrateLabel(2_500_000))
        assertEquals("", PlayerQuality.bitrateLabel(0))
        assertEquals("", PlayerQuality.bitrateLabel(PlayerUiState.VALUE_UNSET))
    }
}
