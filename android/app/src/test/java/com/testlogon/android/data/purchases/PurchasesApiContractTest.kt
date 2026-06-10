package com.testlogon.android.data.purchases

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import retrofit2.HttpException
import java.math.BigDecimal

/**
 * AND-218 / AND-222 — contract tests for [PurchasesApi] against MockWebServer with the production-style
 * Moshi (BigDecimalAdapter + codegen). Verifies verb/path/query for all three endpoints, the BARE-array
 * decode for list/search, path-param interpolation + nested shipping decode for detail, q URL-encoding,
 * and non-2xx propagation as HttpException (not swallowed; left for AND-015).
 */
class PurchasesApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().add(BigDecimalAdapter).build()

    private fun api(): PurchasesApi = backend.retrofit(moshi).create(PurchasesApi::class.java)

    @Test
    fun listTransactions_sendsQuery_decodesBareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[
                   {"txn_id":"txn_001","created_at":1747836191,"updated_at":1747922600,
                    "status":"completed","amount":45.97,"currency":"USD","description":"Logo Tee x2"}
                ]""",
            ),
        )
        val rows = api().listTransactions(limit = 10, status = "completed")
        assertEquals(1, rows.size)
        assertEquals("completed", rows.first().status)
        assertEquals(0, BigDecimal("45.97").compareTo(rows.first().amount))
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/purchase-history/transactions", req.requestUrl?.encodedPath)
        assertEquals("10", req.requestUrl?.queryParameter("limit"))
        assertEquals("completed", req.requestUrl?.queryParameter("status"))
    }

    @Test
    fun listTransactions_nullParams_areOmitted() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val rows = api().listTransactions(limit = null, status = null)
        assertTrue(rows.isEmpty())
        val req = backend.takeRequest()
        assertNull(req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("status"))
        assertEquals("/ui/purchase-history/transactions", req.requestUrl?.encodedPath)
    }

    @Test
    fun searchTransactions_encodesQuery_decodesBareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"txn_id":"t","created_at":1,"updated_at":2,"status":"completed","amount":1.0,"currency":"USD"}]""",
            ),
        )
        val rows = api().searchTransactions(q = "logo tee", limit = 20)
        assertEquals("t", rows.single().txnId)
        val req = backend.takeRequest()
        assertEquals("/ui/purchase-history/transactions/search", req.requestUrl?.encodedPath)
        assertEquals("logo tee", req.requestUrl?.queryParameter("q"))
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getTransaction_interpolatesPath_decodesDetailWithShipping() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"txn_id":"txn_001","created_at":1,"updated_at":2,"status":"COMPLETED","amount":49.57,
                 "currency":"USD","buyer_id":"usr_42","version":3,
                 "shipping":{"carrier":"ups","tracking_number":"1Z999","tracking_url":"https://t/1Z999",
                   "carrier_events":[{"timestamp":"2026-05-21T18:00:00Z","description":"Shipped"}]},
                 "metadata":{"cart_id":"cart_77"}}
                """.trimIndent(),
            ),
        )
        val detail = api().getTransaction("txn_001")
        assertEquals("usr_42", detail.buyerId)
        assertEquals("ups", detail.shipping?.carrier)
        assertEquals(1, detail.shipping?.carrierEvents?.size)
        val req = backend.takeRequest()
        assertEquals("/ui/purchase-history/transactions/txn_001", req.requestUrl?.encodedPath)
    }

    @Test
    fun getTransaction_404_propagatesAsHttpException() {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val ex = assertThrows(HttpException::class.java) {
            runBlocking { api().getTransaction("nope") }
        }
        assertEquals(404, ex.code())
    }

    @Test
    fun listTransactions_401_notSwallowed() {
        backend.enqueue(Fixtures.error("\"unauthorized\"", 401))
        val ex = assertThrows(HttpException::class.java) {
            runBlocking { api().listTransactions() }
        }
        assertEquals(401, ex.code())
    }
}
