package com.testlogon.android.data.payouts

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
 * AND-259 — contract tests for [KycRepositoryImpl]: tier + requirements composition (correct paths,
 * no /api prefix), evaluate POST, and the tolerant requirements leg (a failed reqs call leaves
 * eligible=null rather than failing the whole load).
 */
class KycRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): KycRepositoryImpl {
        val api = backend.retrofit(moshi).create(KycApi::class.java)
        return KycRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun loadTierStatus_readsTier_andRequirements_eligibility() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"user_sub":"u1","current_tier":1,"tier_name":"basic","updated_at":1733000000}"""),
        )
        backend.enqueue(
            Fixtures.okBody("""{"target_tier":1,"current_tier":1,"met":["email_verified"],"unmet":[],"eligible":true}"""),
        )
        val result = repo().loadTierStatus(requiredTier = 1)
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertEquals(1, status.currentTier.rank)
        assertEquals("basic", status.tierName)
        assertEquals(true, status.eligibleForPayoutTier)

        val tierReq = backend.takeRequest()
        assertEquals("/v1/kyc/tiers/me", tierReq.requestUrl?.encodedPath)
        val reqsReq = backend.takeRequest()
        assertEquals("/v1/kyc/tiers/me/requirements/1", reqsReq.requestUrl?.encodedPath)
    }

    @Test
    fun loadTierStatus_blockedBranch_carriesUnmet() = runTest {
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","current_tier":0,"tier_name":"none"}"""))
        backend.enqueue(
            Fixtures.okBody("""{"target_tier":1,"current_tier":0,"met":[],"unmet":["gov_id"],"eligible":false}"""),
        )
        val status = (repo().loadTierStatus(requiredTier = 1) as ApiResult.Success).data
        assertEquals(false, status.eligibleForPayoutTier)
        assertEquals(listOf("gov_id"), status.unmetRequirements)
    }

    @Test
    fun loadTierStatus_requirementsLegFails_eligibleNull_tierStillSucceeds() = runTest {
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","current_tier":2,"tier_name":"verified"}"""))
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().loadTierStatus(requiredTier = 1)
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertEquals(2, status.currentTier.rank)
        assertNull(status.eligibleForPayoutTier)
    }

    @Test
    fun loadTierStatus_tierLegFails_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"nope\"", 500))
        val result = repo().loadTierStatus(requiredTier = 1)
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun evaluateTierStatus_postsToEvaluate_thenReadsRequirements() = runTest {
        backend.enqueue(Fixtures.okBody("""{"user_sub":"u1","current_tier":1,"tier_name":"basic"}"""))
        backend.enqueue(
            Fixtures.okBody("""{"target_tier":1,"current_tier":1,"met":[],"unmet":[],"eligible":true}"""),
        )
        val result = repo().evaluateTierStatus(requiredTier = 1)
        assertTrue(result is ApiResult.Success)

        val evalReq = backend.takeRequest()
        assertEquals("POST", evalReq.method)
        assertEquals("/v1/kyc/tiers/me/evaluate", evalReq.requestUrl?.encodedPath)
    }
}
