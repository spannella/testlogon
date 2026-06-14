package com.testlogon.android.data.privacy

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-385 - contract tests for [DefaultPrivacyExportRepository] against MockWebServer
 * (TC-AND-385-01..03, 06). Asserts the REAL wire contract:
 *  - POST ui/privacy/account-deletion/export with a { categories } body + CSRF header on the mutating verb,
 *  - 201 -> Success mapped to a domain ExportRequest (epoch SECONDS -> ms, status mapping),
 *  - GET ui/privacy/requests -> filter request_type=="export", newest-first, envelope key `requests`,
 *  - offline (transport error) keeps cached rows visible and returns NetworkError.
 */
class PrivacyExportRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun csrfClient(): OkHttpClient {
        val csrf = Interceptor { chain ->
            val req = chain.request()
            val out = if (req.method in MUTATING) {
                req.newBuilder().header("X-CSRF-Token", CSRF).build()
            } else {
                req
            }
            chain.proceed(out)
        }
        return defaultTestClient().newBuilder().addInterceptor(csrf).build()
    }

    private fun repo(
        client: OkHttpClient = csrfClient(),
        dao: FakeExportRequestDao = FakeExportRequestDao(),
    ): DefaultPrivacyExportRepository {
        val rf = backend.retrofit(moshi, client)
        val r = DefaultPrivacyExportRepository(
            api = rf.create(PrivacyApi::class.java),
            dao = dao,
            downloader = FakeExportDownloader(),
            errorParser = ApiErrorParser(moshi),
        )
        r.now = { FIXED_NOW }
        return r
    }

    // TC-AND-385-01
    @Test
    fun requestExport_postsCorrectPathBodyAndCsrf_andMapsResponse() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"request_id":"exp_8f2c1","status":"completed","created_at":1749132191,
                   "completed_at":1749132195,
                   "download_url":"/ui/privacy/account-deletion/export/exp_8f2c1/download",
                   "download_expires_at":1749736991,"file_size_bytes":184320,
                   "categories_requested":2,"data":null}""",
                code = 201,
            ),
        )

        val result = repo().requestExport(mapOf("profile" to true, "billing" to false))
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/privacy/account-deletion/export", req.requestUrl?.encodedPath)
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        val body = req.bodyJson()
        @Suppress("UNCHECKED_CAST")
        val categories = body["categories"] as Map<String, Any?>
        assertEquals(true, categories["profile"])
        assertEquals(false, categories["billing"])

        val domain = (result as ApiResult.Success).data
        assertEquals("exp_8f2c1", domain.id)
        assertEquals(ExportStatus.COMPLETED, domain.status)
        // epoch SECONDS -> ms.
        assertEquals(1749132191L * 1000L, domain.createdAtEpochMs)
        assertEquals(1749736991L * 1000L, domain.downloadExpiresAtEpochMs)
        assertEquals(184320L, domain.sizeBytes)
        assertTrue(domain.isTerminal)
    }

    // TC-AND-385-03
    @Test
    fun refresh_listsExportsOnly_newestFirst_envelopeKeyRequests() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"requests":[
                   {"request_id":"exp_old","request_type":"export","status":"completed",
                    "created_at":1749045600,"export_size_bytes":100,
                    "export_download_url":"/ui/privacy/account-deletion/export/exp_old/download"},
                   {"request_id":"del_7a9","request_type":"deletion","status":"pending",
                    "created_at":1746090000},
                   {"request_id":"exp_new","request_type":"export","status":"processing",
                    "created_at":1749132191}
                  ],"next_cursor":null}""",
            ),
        )

        val result = repo().refresh()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        // Only the two export rows, newest-first.
        assertEquals(listOf("exp_new", "exp_old"), list.map { it.id })
        assertEquals(ExportStatus.PROCESSING, list[0].status)
        assertEquals(ExportStatus.COMPLETED, list[1].status)
        val get = backend.takeRequest()
        assertEquals("GET", get.method)
        assertEquals("/ui/privacy/requests", get.requestUrl?.encodedPath)
    }

    // TC-AND-385-06
    @Test
    fun refresh_offline_keepsCache_andReturnsNetworkError() = runTest {
        val seeded = FakeExportRequestDao(
            listOf(
                com.testlogon.android.core.data.privacy.ExportRequestEntity(
                    id = "exp_cached", status = ExportStatus.COMPLETED.name,
                    requestedAt = 1_000L, expiresAt = null, sizeBytes = 10L,
                    downloadUrl = null, syncedAt = 0L,
                ),
            ),
        )
        // No enqueued response -> the short-timeout client throws a transport error.
        val r = repo(dao = seeded)
        val result = r.refresh()
        assertTrue(result is ApiResult.NetworkError)
        // Cache still visible (no false empty).
        val cached = r.observeRequests().first()
        assertEquals(listOf("exp_cached"), cached.map { it.id })
        assertFalse(cached.isEmpty())
    }

    // TC-AND-385-02 (mapping incl. UNKNOWN, via the single-request GET)
    @Test
    fun getExport_mapsKnownAndUnknownStatuses() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"request_id":"exp_w","status":"wibble","created_at":1749132191}""",
            ),
        )
        val result = repo().refreshOne("exp_w")
        assertTrue(result is ApiResult.Success)
        assertEquals(ExportStatus.UNKNOWN, (result as ApiResult.Success).data.status)
        assertFalse(result.data.isDownloadable(FIXED_NOW))
    }

    private companion object {
        const val CSRF = "csrf-test-token"
        val MUTATING = setOf("POST", "PUT", "PATCH", "DELETE")
        const val FIXED_NOW = 1_800_000_000_000L
    }
}
