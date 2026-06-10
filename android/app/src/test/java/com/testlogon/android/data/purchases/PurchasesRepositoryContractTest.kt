package com.testlogon.android.data.purchases

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.math.BigDecimal

/**
 * AND-218 / AND-222 — contract tests for [PurchasesRepositoryImpl]: DTO->domain success mapping for
 * list/search/detail, the FastAPI detail error shapes -> ApiResult.Failure, and timeout ->
 * ApiResult.NetworkError. Wired through MockWebServer with the real Retrofit/Moshi so mapping +
 * error parsing run end-to-end.
 */
class PurchasesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().add(BigDecimalAdapter).build()

    private fun repo(): PurchasesRepositoryImpl {
        val api = backend.retrofit(moshi).create(PurchasesApi::class.java)
        return PurchasesRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun list_mapsSuccess_bareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"txn_id":"txn_1","created_at":1746100800,"updated_at":1746187200,
                    "status":"COMPLETED","amount":42.99,"currency":"USD","merchant_id":"m","description":"x"}]""",
            ),
        )
        val rows = (repo().list(limit = 50) as ApiResult.Success).data
        assertEquals("txn_1", rows.single().id)
        assertEquals(0, BigDecimal("42.99").compareTo(rows.single().money.amount))
        assertEquals(OrderStatus.Completed, rows.single().status)
        assertEquals("/ui/purchase-history/transactions", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun search_sendsQ_mapsSuccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"txn_id":"t","created_at":1,"updated_at":2,"status":"pending","amount":1.0,"currency":"USD"}]""",
            ),
        )
        val rows = (repo().search("tee", limit = 50) as ApiResult.Success).data
        assertEquals("t", rows.single().id)
        val req = backend.takeRequest()
        assertEquals("/ui/purchase-history/transactions/search", req.requestUrl?.encodedPath)
        assertEquals("tee", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun detail_mapsShipping_andCartId() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"txn_id":"txn_1","created_at":1,"updated_at":2,"status":"COMPLETED","amount":49.0,
                 "currency":"USD","buyer_id":"u","version":1,
                 "shipping":{"carrier":"ups","tracking_number":"1Z","tracking_url":"https://t/1Z","carrier_events":[]},
                 "metadata":{"cart_id":"cart_55"}}
                """.trimIndent(),
            ),
        )
        val detail = (repo().detail("txn_1") as ApiResult.Success).data
        assertEquals("ups", detail.shipping?.carrier)
        assertEquals("cart_55", detail.cartId)
    }

    @Test
    fun detail_noShipping_yieldsNull() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"txn_id":"t","created_at":1,"updated_at":2,"status":"PENDING","amount":1.0,
                   "currency":"USD","buyer_id":"u","version":1}""",
            ),
        )
        val detail = (repo().detail("t") as ApiResult.Success).data
        assertNull(detail.shipping)
    }

    @Test
    fun detail_422_foldsToFailure_withStatus() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["path","txn_id"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().detail("nope")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun list_string_detail_error_foldsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"bad request\"", 400))
        val result = repo().list()
        assertTrue(result is ApiResult.Failure)
        assertEquals(400, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun list_timeout_foldsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().list()
        assertTrue(result is ApiResult.NetworkError)
    }
}
