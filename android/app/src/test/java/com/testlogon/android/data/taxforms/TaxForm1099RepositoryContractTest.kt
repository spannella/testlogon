package com.testlogon.android.data.taxforms

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-247/250 — contract tests for [TaxForm1099RepositoryImpl] against MockWebServer using the production
 * Moshi/Retrofit config. Covers: list round-trip (`items` envelope + newest-year-first sort + epoch/
 * minor-unit mapping), year-keyed detail path, the JSON download_url resolution (NOT raw PDF bytes), and
 * 422 mapping.
 */
class TaxForm1099RepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): TaxForm1099RepositoryImpl {
        val api = backend.retrofit(moshi).create(TaxForm1099Api::class.java)
        return TaxForm1099RepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun list1099s_parsesItemsEnvelope_mapsFields_sortsNewestYearFirst() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"form_id":"a","tax_year":2023,"total_earnings_cents":100,"status":"generated",
                    "correction_count":0,"payer_name":"TestLogon, Inc.","payer_tin_last4":"6789",
                    "generated_at":1700000000,"updated_at":1700000000},
                   {"form_id":"b","tax_year":2025,"total_earnings_cents":1284500,"status":"generated",
                    "correction_count":1,"payer_name":"TestLogon, Inc.","payer_tin_last4":"6789",
                    "generated_at":1738310400,"updated_at":1738310400}
                ]}""",
            ),
        )
        val result = repo().list1099s()
        assertTrue(result is ApiResult.Success)
        val forms = (result as ApiResult.Success).data
        assertEquals(listOf(2025, 2023), forms.map { it.taxYear })
        assertEquals(1_284_500L, forms[0].totalEarnings.cents)
        assertEquals(Form1099Status.CORRECTED, forms[0].status) // correction_count=1
        assertEquals(1_738_310_400L, forms[0].generatedAtEpochSeconds)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/tax-forms/1099s", req.requestUrl?.encodedPath)
    }

    @Test
    fun get1099_usesYearKeyedPath() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"form_id":"a","tax_year":2025,"total_earnings_cents":1284500,
                   "status":"generated","correction_count":0,"payer_tin_last4":"6789",
                   "generated_at":1738310400,"updated_at":1738310400}""",
            ),
        )
        val result = repo().get1099(2025)
        assertTrue(result is ApiResult.Success)
        assertEquals(2025, (result as ApiResult.Success).data.taxYear)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/tax-forms/1099s/2025", req.requestUrl?.encodedPath)
    }

    @Test
    fun downloadUrl_resolvesJsonUrl_notRawPdf() = runTest {
        backend.enqueue(Fixtures.okBody("""{"download_url":"https://files.example/1099/2025.pdf?sig=abc"}"""))
        val result = repo().downloadUrl(2025)
        assertTrue(result is ApiResult.Success)
        assertEquals("https://files.example/1099/2025.pdf?sig=abc", (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/tax-forms/1099s/2025/download", req.requestUrl?.encodedPath)
    }

    @Test
    fun get1099_422_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"bad year\"", 422))
        val result = repo().get1099(9999)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun list1099s_malformedBody_neverCrashes() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().list1099s()
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }
}
