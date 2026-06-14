package com.testlogon.android.data.paywall

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.feed.FakeAuthStateStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** A billing authorizer that always returns an authorized method (simulates AND-031 wired). */
private class FakeAuthorizedBilling(private val pmId: String = "pm_test") : BillingAuthorizer {
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult =
        BillingResult.Authorized(pmId, amountMinorUnits)
}

/**
 * AND-177 — contract + entitlement-flow tests for [PaywallRepositoryImpl].
 *
 * Covers: the STOP-AND-FLAG stubbed-billing path (NotConfigured -> PaymentsUnavailable, NO HTTP call),
 * the happy unlock path through a wired (fake) authorizer (POST body + entitlement cache + idempotency
 * key), already-entitled short-circuit, 409 -> AlreadyEntitled, and per-user cache isolation.
 */
class PaywallRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(
        billing: BillingAuthorizer,
        auth: AuthStateStore = FakeAuthStateStore(userSub = "user_a"),
        dao: FakeEntitlementDao = FakeEntitlementDao(),
    ): Pair<PaywallRepositoryImpl, FakeEntitlementDao> {
        val api = backend.retrofit(moshi).create(PaywallApi::class.java)
        return PaywallRepositoryImpl(api, billing, dao, auth, ApiErrorParser(moshi)) to dao
    }

    @Test
    fun unlock_withStubBilling_returnsPaymentsUnavailable_andNeverCallsServer() = runTest {
        val (r, dao) = repo(StubBillingAuthorizer())
        val outcome = r.unlock("post_1")
        assertEquals(UnlockOutcome.PaymentsUnavailable, outcome)
        assertEquals(0, backend.requestCount) // STOP-AND-FLAG: no /posts/unlock call, no charge
        assertTrue(dao.snapshot().isEmpty())
    }

    @Test
    fun unlock_withWiredBilling_success_cachesEntitlement_andSendsBody() = runTest {
        backend.enqueue(Fixtures.okBody("""{"post_id":"post_1","payment_intent":{"status":"succeeded"}}"""))
        val (r, dao) = repo(FakeAuthorizedBilling())
        val outcome = r.unlock("post_1")

        assertTrue(outcome is UnlockOutcome.Success)
        assertTrue(r.isEntitled("post_1").first())
        assertEquals("user_a", dao.snapshot().first().userSub)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/posts/unlock", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("post_1", body["post_id"])
        assertEquals("pm_test", body["payment_method_id"])
        val idem = body["idempotency_key"] as? String
        assertTrue(idem != null && idem.startsWith("unlock:post_1:"))
    }

    @Test
    fun unlock_alreadyEntitled_shortCircuits_noHttp() = runTest {
        backend.enqueue(Fixtures.okBody("""{"post_id":"post_1","payment_intent":{"status":"succeeded"}}"""))
        val (r, _) = repo(FakeAuthorizedBilling())
        r.unlock("post_1") // first unlock caches
        backend.takeRequest()

        val outcome = r.unlock("post_1") // second is a cache short-circuit
        assertEquals(UnlockOutcome.AlreadyEntitled, outcome)
        assertEquals(1, backend.requestCount) // no second HTTP call
    }

    @Test
    fun unlock_409_mapsToAlreadyEntitled_andCaches() = runTest {
        backend.enqueue(Fixtures.error("\"already unlocked\"", 409))
        val (r, dao) = repo(FakeAuthorizedBilling())
        val outcome = r.unlock("post_1")
        assertEquals(UnlockOutcome.AlreadyEntitled, outcome)
        assertTrue(dao.snapshot().any { it.postId == "post_1" })
    }

    @Test
    fun unlock_402_declined_isRetryableFailure() = runTest {
        backend.enqueue(Fixtures.error("\"card declined\"", 402))
        val (r, _) = repo(FakeAuthorizedBilling())
        val outcome = r.unlock("post_1")
        assertTrue(outcome is UnlockOutcome.Failure)
        assertTrue((outcome as UnlockOutcome.Failure).retryable)
    }

    @Test
    fun isEntitled_isPerUser() = runTest {
        backend.enqueue(Fixtures.okBody("""{"post_id":"post_1","payment_intent":{"status":"succeeded"}}"""))
        val dao = FakeEntitlementDao()
        val (rA, _) = repo(FakeAuthorizedBilling(), FakeAuthStateStore(userSub = "user_a"), dao)
        rA.unlock("post_1")
        backend.takeRequest()

        // A different user sharing the same DAO must not see user_a's entitlement.
        val (rB, _) = repo(FakeAuthorizedBilling(), FakeAuthStateStore(userSub = "user_b"), dao)
        assertFalse(rB.isEntitled("post_1").first())
    }
}
