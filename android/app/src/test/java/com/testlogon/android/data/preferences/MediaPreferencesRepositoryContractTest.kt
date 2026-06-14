package com.testlogon.android.data.preferences

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.MediaPreferences
import com.testlogon.android.core.model.VideoResolution
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-083 — media preferences round-trip (PUT, full-state body, local mirror). */
class MediaPreferencesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private class FakeMirror : MediaPreferencesMirror {
        var stored: MediaPreferences? = null
        override fun read(): MediaPreferences? = stored
        override fun write(value: MediaPreferences) { stored = value }
    }

    private fun repo(mirror: FakeMirror = FakeMirror()): Pair<MediaPreferencesRepositoryImpl, FakeMirror> {
        val api = backend.retrofit(moshi).create(MediaPreferencesApi::class.java)
        return MediaPreferencesRepositoryImpl(api, mirror, ApiErrorParser(moshi)) to mirror
    }

    @Test
    fun refresh_mapsOut_andMirrors() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"user_sub":"u","default_audio_muted":true,"default_video_off":false,""" +
                    """"video_resolution":"1080","preferred_audio_input_id":"mic-2"}""",
            ),
        )
        val (r, mirror) = repo()
        val result = r.refresh()
        assertTrue(result is ApiResult.Success)
        val prefs = (result as ApiResult.Success).data
        assertTrue(prefs.defaultAudioMuted)
        assertEquals(VideoResolution.P1080, prefs.videoResolution)
        assertEquals("mic-2", prefs.preferredAudioInputId)
        assertNotNull(mirror.stored)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/media/preferences", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun update_usesPut_withFullStateBody_andMirrors() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"user_sub":"u","default_audio_muted":true,"default_video_off":false,"video_resolution":"720"}""",
            ),
        )
        val (r, mirror) = repo()
        val result = r.update(
            MediaPreferences(defaultAudioMuted = true, videoResolution = VideoResolution.P720),
        )
        assertTrue(result is ApiResult.Success)

        val recorded = backend.takeRequest()
        assertEquals("PUT", recorded.method)
        assertEquals("/ui/media/preferences", recorded.requestUrl?.encodedPath)
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"default_audio_muted\":true"))
        assertTrue(body.contains("\"video_resolution\":\"720\""))
        assertNotNull(mirror.stored)
    }

    @Test
    fun cached_readsMirror() {
        val mirror = FakeMirror().apply { stored = MediaPreferences(defaultVideoOff = true) }
        val (r, _) = repo(mirror)
        assertEquals(true, r.cached()?.defaultVideoOff)
    }

    @Test
    fun refresh_transportFailure_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val (r, _) = repo()
        assertTrue(r.refresh() is ApiResult.NetworkError)
    }
}
