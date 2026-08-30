package com.testlogon.android.data.tradingdocs

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * FE-170 — contract tests for [TradingDocsRepositoryImpl] against MockWebServer. Covers the list path +
 * type query param + newest-first sort, download-URL resolution, and the DEGRADE-ON-404 tolerance
 * (404 / 500 -> empty list / null, never an exception).
 */
class TradingDocsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): TradingDocsRepositoryImpl {
        val api = backend.retrofit(moshi).create(TradingDocsApi::class.java)
        return TradingDocsRepositoryImpl(api = api)
    }

    @Test
    fun listTradingDocuments_sortsNewestFirst_andSendsTypeQuery() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"documents":[
                   {"doc_id":"old","type":"statement","created_at":10},
                   {"doc_id":"new","type":"statement","created_at":99},
                   {"doc_id":"mid","type":"statement","created_at":50}
                ]}""",
            ),
        )
        val list = repo().listTradingDocuments("statement")
        assertEquals(listOf("new", "mid", "old"), list.map { it.docId })

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/trading-documents", req.requestUrl?.encodedPath)
        assertEquals("statement", req.requestUrl?.queryParameter("type"))
    }

    @Test
    fun listTradingDocuments_noType_omitsQuery() = runTest {
        backend.enqueue(Fixtures.okBody("""{"documents":[]}"""))
        val list = repo().listTradingDocuments(null)
        assertTrue(list.isEmpty())
        val req = backend.takeRequest()
        assertNull(req.requestUrl?.query)
    }

    @Test
    fun listTradingDocuments_404_degradesToEmpty() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        assertTrue(repo().listTradingDocuments().isEmpty())
    }

    @Test
    fun listTradingDocuments_500_degradesToEmpty() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        assertTrue(repo().listTradingDocuments("1099").isEmpty())
    }

    @Test
    fun getDownloadUrl_resolvesPresignedUrl() = runTest {
        backend.enqueue(Fixtures.okBody("""{"download_url":"https://s3.example/x.pdf?sig=1"}"""))
        assertEquals("https://s3.example/x.pdf?sig=1", repo().getDownloadUrl("doc-1"))
        val req = backend.takeRequest()
        assertEquals("/ui/trading-documents/doc-1/download", req.requestUrl?.encodedPath)
    }

    @Test
    fun getDownloadUrl_404_degradesToNull() = runTest {
        backend.enqueue(Fixtures.error("\"nope\"", 404))
        assertNull(repo().getDownloadUrl("doc-1"))
    }

    @Test
    fun getDownloadUrl_blankUrl_isNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"download_url":""}"""))
        assertNull(repo().getDownloadUrl("doc-1"))
    }
}
