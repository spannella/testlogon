package com.testlogon.android.data.billing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ErrorDetailMapper
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
 * AND-233 — FastAPI `detail` mapping matrix + transport failures at the [BillingRepositoryImpl]
 * boundary (gap not covered by BillingRepositoryContractTest's single 422 case). Verified against
 * src/api/client.ts normalizeErrorDetail: string verbatim; array joins `msg`; object maps by `code`
 * (geo_blocked / role_required_scope) with a generic fallback for unknown codes. Transport failures
 * (timeout, connection-refused) become ApiResult.NetworkError with exactly ONE request (no POST/GET
 * auto-retry at this layer).
 */
class BillingErrorMappingTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BillingRepositoryImpl {
        val api = backend.retrofit(moshi).create(BillingApi::class.java)
        return BillingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun stringDetail_usedVerbatim() = runTest {
        backend.enqueue(Fixtures.error("\"Card declined.\"", 402))
        val r = repo().getPaymentMethods()
        assertTrue(r is ApiResult.Failure)
        val err = (r as ApiResult.Failure).error
        assertEquals(402, err.status)
        assertEquals("Card declined.", err.message)
    }

    @Test
    fun arrayDetail_joinsMsgFields() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","amount_cents"],"msg":"field required","type":"value_error.missing"}]""",
                422,
            ),
        )
        val err = (repo().getPaymentMethods() as ApiResult.Failure).error
        assertEquals(422, err.status)
        assertEquals("field required", err.message)
    }

    @Test
    fun objectDetail_knownCode_mapsCannedCopy_andExtractsCode() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"role_required_scope","required_scope":"billing_support"}""", 403))
        val err = (repo().getPaymentMethods() as ApiResult.Failure).error
        assertEquals(403, err.status)
        assertEquals("role_required_scope", err.code)
        assertTrue(err.message.contains("permission"))
    }

    @Test
    fun objectDetail_unknownCode_fallsBackToGeneric_noRawLeak() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"totally_unknown","secret":"should_not_leak"}""", 400))
        val err = (repo().getPaymentMethods() as ApiResult.Failure).error
        assertEquals(400, err.status)
        assertEquals("totally_unknown", err.code)
        assertEquals(ErrorDetailMapper.GENERIC, err.message)
        assertTrue(!err.message.contains("should_not_leak"))
    }

    @Test
    fun emptyBody_5xx_genericFallback_carriesStatus() = runTest {
        backend.enqueue(Fixtures.okBody("", code = 500))
        val err = (repo().getPaymentMethods() as ApiResult.Failure).error
        assertEquals(500, err.status)
    }

    @Test
    fun timeout_mapsToNetworkError_singleRequest_noRetry() = runTest {
        backend.enqueue(Fixtures.timeout())
        val r = repo().getPaymentMethods()
        assertTrue(r is ApiResult.NetworkError)
        assertTrue((r as ApiResult.NetworkError).isTimeout)
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun connectionRefused_mapsToNetworkError_noCrash() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val r = repo().getPaymentMethods()
        assertTrue(r is ApiResult.NetworkError)
    }
}
