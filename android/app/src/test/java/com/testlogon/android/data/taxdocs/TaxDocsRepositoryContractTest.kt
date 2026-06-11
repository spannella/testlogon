package com.testlogon.android.data.taxdocs

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * AND-246 — contract tests for [TaxDocsRepositoryImpl] against MockWebServer. Covers list (path, no query
 * params, year-desc/nulls-last sort), the year-keyed PDF URL builder, and 422 mapping.
 */
class TaxDocsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(baseUrl: String = "http://dev.example/"): TaxDocsRepositoryImpl {
        val api = backend.retrofit(moshi).create(TaxDocsApi::class.java)
        return TaxDocsRepositoryImpl(
            api = api,
            errorParser = ApiErrorParser(moshi),
            baseUrlProvider = { baseUrl },
        )
    }

    @Test
    fun listTaxDocuments_noQueryParams_sortsYearDescNullsLast() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"documents":[
                   {"doc_id":"a","year":2023,"grand_total_cents":1,"created_at":1},
                   {"doc_id":"b","year":null,"grand_total_cents":2,"created_at":2},
                   {"doc_id":"c","year":2025,"grand_total_cents":3,"created_at":3},
                   {"doc_id":"d","year":2024,"grand_total_cents":4,"created_at":4}
                ]}""",
            ),
        )
        val result = repo().listTaxDocuments()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals(listOf(2025, 2024, 2023, null), list.map { it.year })

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/tax-documents/history", req.requestUrl?.encodedPath)
        assertNull(req.requestUrl?.query)
    }

    @Test
    fun pdfUrl_buildsAbsoluteYearKeyedUrl() {
        assertEquals(
            "http://dev.example/ui/tax-documents/document/2024/pdf",
            repo().pdfUrl(2024),
        )
    }

    @Test
    fun list_422_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"bad\"", 422))
        val result = repo().listTaxDocuments()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
