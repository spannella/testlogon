package com.testlogon.android.data.subscriptions

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
 * AND-234 — contract tests for [SubscriptionsRepositoryImpl] against MockWebServer using the production
 * Moshi/Retrofit config. Covers: plans list (bare array, flat price, perks from assets[].name, enum
 * mapping), my-subscriptions (X-User-Id header + current-period epoch), summary, subscribe (plan id in
 * PATH, optional body), change-plan (plan_id in body), cancel (POST .../cancel -> SubscriptionOut),
 * unauthenticated guard, and 422 mapping.
 */
class SubscriptionsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(userSub: String? = "usr_me"): SubscriptionsRepositoryImpl {
        val api = backend.retrofit(moshi).create(SubscriptionsApi::class.java)
        return SubscriptionsRepositoryImpl(
            api = api,
            errorParser = ApiErrorParser(moshi),
            authStateStore = FakeAuthStateStore(userSub),
        )
    }

    private val plansArray = """
        [
          {"plan_id":"plan_basic","creator_id":"usr_42","name":"Supporter",
           "description":"Early access","price_cents":499,"currency":"usd","interval":"month",
           "annual_price_cents":4990,"status":"active","metadata":{},
           "assets":[{"name":"Early access","path":"p","type":"t","size":0,"content_type":"c"},
                     {"name":"Monthly Q&A","path":"p2","type":"t","size":0,"content_type":"c"}],
           "created_at":1749124800,"updated_at":1749124800,"server_time":"ignored"},
          {"plan_id":"plan_pro","creator_id":"usr_42","name":"Pro","price_cents":0,
           "currency":"usd","interval":"weird_interval","status":"archived","created_at":1,"updated_at":2}
        ]
    """.trimIndent()

    @Test
    fun getCreatorTiers_parsesBareArray_flatPrice_perksFromAssets_andEnumFallback() = runTest {
        backend.enqueue(Fixtures.okBody(plansArray))
        val result = repo().getCreatorTiers("usr_42")
        assertTrue(result is ApiResult.Success)
        val tiers = (result as ApiResult.Success).data
        assertEquals(2, tiers.size)
        val basic = tiers[0]
        assertEquals("plan_basic", basic.planId)
        assertEquals(499L, basic.priceCents)
        assertEquals("usd", basic.currency)
        assertEquals(BillingInterval.MONTH, basic.interval)
        assertEquals(listOf("Early access", "Monthly Q&A"), basic.perks)
        assertTrue(basic.isActive)
        // unknown interval -> UNKNOWN, archived status not active, no assets -> empty perks.
        assertEquals(BillingInterval.UNKNOWN, tiers[1].interval)
        assertTrue(tiers[1].perks.isEmpty())
        assertTrue(!tiers[1].isActive)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/api/creators/usr_42/plans", req.requestUrl?.encodedPath)
    }

    @Test
    fun getMySubscriptions_sendsUserIdHeader_andMapsEpochAndStatus() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[{"subscription_id":"sub_1","plan_id":"plan_basic","creator_id":"usr_42",
                   "subscriber_id":"usr_me","interval":"month","provider":"ccbill",
                   "provider_subscription_id":"ccb_1","status":"active","start_at":1749124800,
                   "current_period_end":1751716800,"cancel_at_period_end":false,"price_cents":499,
                   "currency":"usd","auto_renew":true}]""",
            ),
        )
        val result = repo("usr_me").getMySubscriptions()
        assertTrue(result is ApiResult.Success)
        val subs = (result as ApiResult.Success).data
        assertEquals(1, subs.size)
        assertEquals("plan_basic", subs[0].planId)
        assertEquals(SubscriptionState.ACTIVE, subs[0].status)
        assertEquals(1751716800L, subs[0].currentPeriodEndEpochSeconds)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/api/subscriptions", req.requestUrl?.encodedPath)
        assertEquals("usr_me", req.getHeader("X-User-Id"))
    }

    @Test
    fun getMySubscriptions_unauthenticated_failsWithoutRequest() = runTest {
        val result = repo(userSub = null).getMySubscriptions()
        assertTrue(result is ApiResult.Failure)
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun getSubscriptionSummary_decodesProjection() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"subscription_id":"sub_1","status":"active","cancel_at_period_end":true,
                   "total_paid_cents":1497,"currency":"usd","next_amount_cents":499,
                   "next_renewal_at":1751716800}""",
            ),
        )
        val result = repo().getSubscriptionSummary("sub_1")
        assertTrue(result is ApiResult.Success)
        val summary = (result as ApiResult.Success).data
        assertEquals(1497L, summary.totalPaidCents)
        assertTrue(summary.cancelAtPeriodEnd)
        assertEquals(1751716800L, summary.nextRenewalAtEpochSeconds)
        assertNull(summary.lastInvoiceAtEpochSeconds)

        val req = backend.takeRequest()
        assertEquals("/api/subscriptions/sub_1/summary", req.requestUrl?.encodedPath)
        assertEquals("usr_me", req.getHeader("X-User-Id"))
    }

    @Test
    fun subscribe_putsPlanIdInPath_postsBody_andDecodes() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"subscription_id":"sub_new","plan_id":"plan_basic","creator_id":"usr_42",
                   "status":"active"}""",
            ),
        )
        val result = repo("usr_me").subscribe("plan_basic", SubscribeReqDto(interval = "month"))
        assertTrue(result is ApiResult.Success)
        assertEquals("sub_new", (result as ApiResult.Success).data.subscriptionId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/plans/plan_basic/subscribe", req.requestUrl?.encodedPath)
        assertEquals("usr_me", req.getHeader("X-User-Id"))
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"interval\":\"month\""))
    }

    @Test
    fun changePlan_serializesPlanIdSnakeCase() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"subscription_id":"sub_1","plan_id":"plan_pro","creator_id":"usr_42","status":"active"}""",
            ),
        )
        val api = backend.retrofit(moshi).create(SubscriptionsApi::class.java)
        val result = api.changePlan("usr_me", "sub_1", ChangePlanReqDto(planId = "plan_pro"))
        assertEquals("plan_pro", result.planId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/subscriptions/sub_1/change-plan", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue("must use snake_case plan_id", body.contains("\"plan_id\":\"plan_pro\""))
        assertTrue("must not use camelCase planId", !body.contains("\"planId\""))
    }

    @Test
    fun cancel_postsToCancelPath_returnsSubscriptionOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"subscription_id":"sub_1","plan_id":"plan_basic","creator_id":"usr_42",
                   "status":"active","cancel_at_period_end":true}""",
            ),
        )
        val result = repo("usr_me").cancel("sub_1", CancelSubscriptionReqDto(cancelAtPeriodEnd = true))
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.cancelAtPeriodEnd)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/subscriptions/sub_1/cancel", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"cancel_at_period_end\":true"))
    }

    @Test
    fun getCreatorTiers_422_mapsFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["query","x"],"msg":"bad","type":"value_error"}]""", 422),
        )
        val result = repo().getCreatorTiers("usr_42")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun emptyPlans_mapsToEmptyList() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val result = repo().getCreatorTiers("usr_42")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty())
    }
}
