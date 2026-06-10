package com.testlogon.android.data.vod.purchase

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.feed.FakeAuthStateStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import com.testlogon.android.data.paywall.FakeEntitlementDao
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.feature.messaging.FakeBillingAuthorizer
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-193 — contract tests for [VodPurchaseRepositoryImpl] against MockWebServer.
 *
 * Covers: access mapping, purchase happy path (idempotency_key in BODY, entitlement persisted -> unlock),
 * already_owned == true 200 treated as success, the stubbed-billing STOP-AND-FLAG path (no HTTP, no
 * charge), and 422 leaving content locked.
 */
class VodPurchaseRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(
        billing: BillingAuthorizer,
        auth: AuthStateStore = FakeAuthStateStore(userSub = "user_a"),
        dao: FakeEntitlementDao = FakeEntitlementDao(),
    ): Pair<VodPurchaseRepositoryImpl, FakeEntitlementDao> {
        val api = backend.retrofit(moshi).create(VodPurchaseApi::class.java)
        return VodPurchaseRepositoryImpl(api, billing, dao, auth, ApiErrorParser(moshi)) to dao
    }

    @Test
    fun getOffer_mapsAccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"entitled":false,"purchase_available":true,"price_cents":1499,
                   "purchase_type":"permanent","views_remaining":-1,"reason":"not_purchased"}""".trimIndent(),
            ),
        )
        val r = repo(FakeBillingAuthorizer()).first.getOffer("v1")
        assertTrue(r is ApiResult.Success)
        val offer = (r as ApiResult.Success).data
        assertEquals(1499L, offer.priceCents)
        assertEquals(PurchaseTypeOption.PERMANENT, offer.defaultType)
        assertEquals("/ui/videos/v1/access", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun purchase_withStubBilling_paymentsUnavailable_noHttp() = runTest {
        val (r, dao) = repo(StubBillingAuthorizer())
        val outcome = r.purchase("v1", "permanent")
        assertEquals(PurchaseOutcome.PaymentsUnavailable, outcome)
        assertEquals(0, backend.requestCount)
        assertTrue(dao.snapshot().isEmpty())
    }

    @Test
    fun purchase_success_unlocks_andSendsIdempotencyKeyInBody() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","already_owned":false,"granted_at":1749120000,
                   "grant_type":"purchase","amount_cents":1499,"purchase_type":"permanent",
                   "views_remaining":-1,"expires_at":null}""".trimIndent(),
            ),
        )
        val (r, dao) = repo(FakeBillingAuthorizer())
        val outcome = r.purchase("v1", "permanent")
        assertTrue(outcome is PurchaseOutcome.Unlocked)
        assertTrue(r.isEntitled("v1").first())
        assertTrue(dao.snapshot().any { it.postId == "v1" && it.userSub == "user_a" })

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/videos/v1/purchase", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("permanent", body["purchase_type"])
        val idem = body["idempotency_key"] as? String
        assertTrue(idem != null && idem.startsWith("vodpur:v1:permanent:"))
        // No Idempotency-Key header (the video endpoint uses the body field only).
        assertNull(req.getHeader("Idempotency-Key"))
        assertNull(req.getHeader("X-Idempotency-Key"))
    }

    @Test
    fun purchase_alreadyOwned200_isIdempotentSuccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","already_owned":true,"granted_at":1749120000,
                   "grant_type":"purchase","amount_cents":0}""".trimIndent(),
            ),
        )
        val (r, _) = repo(FakeBillingAuthorizer())
        val outcome = r.purchase("v1", "permanent")
        assertTrue(outcome is PurchaseOutcome.Unlocked)
        assertTrue((outcome as PurchaseOutcome.Unlocked).entitlement.alreadyOwned)
    }

    @Test
    fun purchase_422_leavesLocked() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["body","purchase_type"],"msg":"invalid","type":"value_error"}]""", 422))
        val (r, dao) = repo(FakeBillingAuthorizer())
        val outcome = r.purchase("v1", "permanent")
        assertTrue(outcome is PurchaseOutcome.Failure)
        assertTrue(dao.snapshot().isEmpty())
    }

    @Test
    fun purchase_401_requiresReauth() = runTest {
        backend.enqueue(Fixtures.error("\"unauthorized\"", 401))
        val (r, _) = repo(FakeBillingAuthorizer())
        assertEquals(PurchaseOutcome.RequireReauth, r.purchase("v1", "permanent"))
    }
}
