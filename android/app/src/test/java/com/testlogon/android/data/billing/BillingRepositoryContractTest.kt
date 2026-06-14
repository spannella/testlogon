package com.testlogon.android.data.billing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-223 / AND-224 — contract tests for [BillingRepositoryImpl] against MockWebServer.
 *
 * Covers: payment-methods list (BARE ARRAY) parse + default-first/priority-asc ordering, set-default
 * (body id + re-fetch reconcile), delete (OkResp@200 + re-fetch), config/balance/subscriptions/ledger
 * parse + mapping, and 422 validation mapping. Money is integer cents; timestamps are epoch Longs.
 */
class BillingRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BillingRepositoryImpl {
        val api = backend.retrofit(moshi).create(BillingApi::class.java)
        return BillingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private val methodsArray = """
        [
          {"payment_method_id":"pm_2","method_type":"card","brand":"mastercard","last4":"4444",
           "exp_month":1,"exp_year":2030,"priority":2,"provider":"stripe","is_default":false},
          {"payment_method_id":"pm_1","method_type":"card","brand":"visa","last4":"4242",
           "exp_month":12,"exp_year":2027,"priority":5,"provider":"stripe","is_default":true},
          {"payment_method_id":"pm_3","method_type":"us_bank_account","priority":1,"is_default":false}
        ]
    """.trimIndent()

    @Test
    fun getPaymentMethods_parsesBareArray_andOrdersDefaultFirstThenPriority() = runTest {
        backend.enqueue(Fixtures.okBody(methodsArray))
        val result = repo().getPaymentMethods()
        assertTrue(result is ApiResult.Success)
        val methods = (result as ApiResult.Success).data
        // default-first (pm_1), then priority asc among the rest (pm_3 prio 1, pm_2 prio 2).
        assertEquals(listOf("pm_1", "pm_3", "pm_2"), methods.map { it.id })
        assertEquals(CardBrand.VISA, methods[0].brand)
        assertEquals("4242", methods[0].last4)
        assertTrue(methods[0].isDefault)
        // bank account: no brand/last4/exp -> defensive nulls, brand UNKNOWN.
        assertEquals(CardBrand.UNKNOWN, methods[1].brand)
        assertNull(methods[1].last4)
        assertNull(methods[1].expMonth)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/billing/payment-methods", req.requestUrl?.encodedPath)
    }

    @Test
    fun setDefault_postsBodyId_thenRefetches() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))   // set-default
        backend.enqueue(Fixtures.okBody(methodsArray))         // re-fetch
        val result = repo().setDefaultPaymentMethod("pm_1")
        assertTrue(result is ApiResult.Success)
        assertEquals("pm_1", (result as ApiResult.Success).data.first().id)

        val setReq = backend.takeRequest()
        assertEquals("POST", setReq.method)
        assertEquals("/ui/billing/payment-methods/default", setReq.requestUrl?.encodedPath)
        assertTrue(setReq.body.readUtf8().contains("\"payment_method_id\":\"pm_1\""))

        val getReq = backend.takeRequest()
        assertEquals("GET", getReq.method)
        assertEquals("/ui/billing/payment-methods", getReq.requestUrl?.encodedPath)
    }

    @Test
    fun remove_deletesById_okRespAt200_thenRefetches() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 200))  // delete
        backend.enqueue(Fixtures.okBody(methodsArray))                   // re-fetch
        val result = repo().removePaymentMethod("pm_2")
        assertTrue(result is ApiResult.Success)

        val delReq = backend.takeRequest()
        assertEquals("DELETE", delReq.method)
        assertEquals("/ui/billing/payment-methods/pm_2", delReq.requestUrl?.encodedPath)
    }

    @Test
    fun setDefault_mutationFailure_doesNotRefetch() = runTest {
        backend.enqueue(Fixtures.error("\"nope\"", 422))
        val result = repo().setDefaultPaymentMethod("pm_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        // Only the set-default POST should have been issued; no re-fetch.
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun getBalance_mapsCentsAndCurrency() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"currency":"USD","owed_pending_cents":0,"owed_settled_cents":4900,
                   "payments_pending_cents":0,"payments_settled_cents":4900,"updated_at":1746057600}""",
            ),
        )
        val result = repo().getBalance()
        assertTrue(result is ApiResult.Success)
        val balance = (result as ApiResult.Success).data
        assertEquals(4900L, balance.owedSettled.cents)
        assertEquals("USD", balance.owedSettled.currency)
        assertEquals(1746057600L, balance.updatedAtEpochSeconds)
        assertNull(balance.duePending)
    }

    @Test
    fun getSubscriptions_parsesItemsWrapper_andMapsStatus() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"subscription_id":"sub_9f2","plan_id":"plan_pro","status":"active",
                   "billing_cycle":"monthly","next_billing_date":"2026-07-01T00:00:00Z"},
                   {"subscription_id":"sub_x","plan_id":"p","status":"weird_value"}]}""",
            ),
        )
        val result = repo().getSubscriptions()
        assertTrue(result is ApiResult.Success)
        val subs = (result as ApiResult.Success).data
        assertEquals(2, subs.size)
        assertEquals(SubscriptionStatus.ACTIVE, subs[0].status)
        // 2026-07-01T00:00:00Z == 1782864000 epoch seconds.
        assertEquals(1782864000L, subs[0].nextBillingDateEpochSeconds)
        assertEquals(SubscriptionStatus.UNKNOWN, subs[1].status)
        assertNull(subs[1].nextBillingDateEpochSeconds)

        val req = backend.takeRequest()
        assertEquals("/ui/billing/subscriptions", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getLedger_threadsBalanceCurrency_andMapsEpoch() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"sk":"L#001","type":"charge","amount_cents":4900,"state":"settled",
                   "reason":"Pro plan","ts":1746057600}]}""",
            ),
        )
        // accountCurrency() fetches balance.
        backend.enqueue(
            Fixtures.okBody(
                """{"currency":"EUR","owed_pending_cents":0,"owed_settled_cents":0,
                   "payments_pending_cents":0,"payments_settled_cents":0}""",
            ),
        )
        val result = repo().getLedger()
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(1, page.items.size)
        assertEquals(4900L, page.items[0].amount.cents)
        assertEquals("EUR", page.items[0].amount.currency)
        assertEquals(1746057600L, page.items[0].timestampEpochSeconds)
    }

    @Test
    fun getConfig_mapsPublishableKey() = runTest {
        backend.enqueue(Fixtures.okBody("""{"publishable_key":"pk_test_x","currency":"usd"}"""))
        val result = repo().getConfig()
        assertTrue(result is ApiResult.Success)
        assertEquals("pk_test_x", (result as ApiResult.Success).data.publishableKey)
    }

    @Test
    fun getPaymentMethods_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().getPaymentMethods()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun emptyMethods_mapsToEmptyList() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val result = repo().getPaymentMethods()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty())
        assertFalse(result.data.isNotEmpty())
    }
}
