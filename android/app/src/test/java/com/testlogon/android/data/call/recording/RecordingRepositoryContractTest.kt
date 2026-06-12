package com.testlogon.android.data.call.recording

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-302 — contract tests for [RecordingRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 *
 * Verifies the recording wire contract: verbs/paths (call_id substituted), the presign request body
 * (content_type="video/mp4", file_size_bytes), the complete body (recording_id, duration_seconds), DTO ->
 * domain mapping (epoch seconds, Float duration), and error/timeout folding. Body JSON is read ONCE per
 * request. Mirrors the AND-295 CallRepositoryContractTest idiom.
 */
class RecordingRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): RecordingRepositoryImpl {
        val api = backend.retrofit(moshi).create(RecordingApi::class.java)
        return RecordingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun request_postsToRequestPath_mapsDomain() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"recording_id":"rec_1","status":"requested","created_at":1733400000}"""),
        )
        val result = repo().request("c1")
        assertTrue(result is ApiResult.Success)
        val req = (result as ApiResult.Success).data
        assertEquals("rec_1", req.recordingId)
        assertEquals(1733400000L, req.createdAtEpochSeconds)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messages/calls/c1/recording/request", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun consent_mapsGrantedGate() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"recording_id":"rec_1","status":"granted","started_at":1733400100}"""),
        )
        val result = repo().consent("c1")
        assertTrue(result is ApiResult.Success)
        val consent = (result as ApiResult.Success).data
        assertEquals(1733400100L, consent.startedAtEpochSeconds)
        assertTrue(consent.isGranted)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messages/calls/c1/recording/consent", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun decline_mapsOk() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().decline("c1")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messages/calls/c1/recording/decline", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun presign_sendsContentTypeAndFileSize_mapsDomain() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"upload_url":"https://s3/put","recording_id":"rec_1","s3_key":"calls/rec_1.mp4",
                    "expires_at":1733400500}""",
            ),
        )
        val result = repo().presign("c1", contentType = "video/mp4", fileSizeBytes = 2048)
        assertTrue(result is ApiResult.Success)
        val presign = (result as ApiResult.Success).data
        assertEquals("https://s3/put", presign.uploadUrl)
        assertEquals("calls/rec_1.mp4", presign.s3Key)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messages/calls/c1/recording/upload/presign", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("video/mp4", body["content_type"])
        // file_size_bytes (NOT size_bytes); Moshi decodes JSON numbers to Double.
        assertEquals(2048.0, body["file_size_bytes"])
        assertTrue(!body.containsKey("size_bytes"))
        // No duration on presign.
        assertTrue(!body.containsKey("duration_seconds"))
    }

    @Test
    fun complete_sendsRecordingIdAndDuration_mapsDownloadUrl() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"recording_id":"rec_1","status":"ready","download_url":"https://s3/get",
                    "download_expires_at":1733400900}""",
            ),
        )
        val result = repo().complete("c1", recordingId = "rec_1", durationSeconds = 12.5f)
        assertTrue(result is ApiResult.Success)
        val complete = (result as ApiResult.Success).data
        assertEquals("ready", complete.status)
        assertEquals("https://s3/get", complete.downloadUrl)
        assertEquals(1733400900L, complete.downloadExpiresAtEpochSeconds)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/messages/calls/c1/recording/upload/complete", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("rec_1", body["recording_id"])
        assertEquals(12.5, body["duration_seconds"])
    }

    @Test
    fun complete_nullDownloadUrl_decodes() = runTest {
        backend.enqueue(Fixtures.okBody("""{"recording_id":"rec_1","status":"processing"}"""))
        val result = repo().complete("c1", "rec_1", 1.0f)
        assertTrue(result is ApiResult.Success)
        val complete = (result as ApiResult.Success).data
        assertEquals(null, complete.downloadUrl)
        assertEquals(null, complete.downloadExpiresAtEpochSeconds)
    }

    @Test
    fun request_422_mapsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"field required","type":"value_error.missing"}]""", 422))
        val result = repo().request("c1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun consent_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().consent("c1")
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }
}
