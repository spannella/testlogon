package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.feature.payouts.FakePayoutsRepository
import com.testlogon.android.feature.payouts.FakeKycRepository
import com.testlogon.android.feature.payouts.samplePayout
import com.testlogon.android.feature.payouts.sampleTierStatus
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-259 — [PayoutSetupRepositoryImpl]: parallel load composition, fail-closed tier handling, and the
 * STOP-AND-FLAG payout gate — with the BillingAuthorizer stub (NotConfigured) the backend payout is
 * NEVER reached (requestPayoutCalls stays 0), so no real payout is executed.
 */
class PayoutSetupRepositoryTest {

    private class StubAuthorizer(private val result: BillingResult) : BillingAuthorizer {
        override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult = result
    }

    private fun repo(
        payouts: FakePayoutsRepository = FakePayoutsRepository(),
        kyc: FakeKycRepository = FakeKycRepository(),
        authorizer: BillingAuthorizer = StubAuthorizer(BillingResult.NotConfigured),
    ) = PayoutSetupRepositoryImpl(payouts, kyc, authorizer)

    @Test
    fun loadSetup_composesBalanceRecentAndTier() = runTest {
        val payouts = FakePayoutsRepository().apply {
            pages = mutableMapOf(null to ApiResult.Success(PayoutPage(listOf(samplePayout("po_9")), null)))
        }
        val kyc = FakeKycRepository().apply { loadResult = ApiResult.Success(sampleTierStatus(eligible = true)) }
        val result = repo(payouts, kyc).loadSetup()
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals(50000L, data.balance.availableCents)
        assertEquals(listOf("po_9"), data.recentPayouts.map { it.payoutId })
        assertEquals(true, data.tierStatus?.eligibleForPayoutTier)
    }

    @Test
    fun loadSetup_kycLegFails_tierNull_failClosed() = runTest {
        val kyc = FakeKycRepository().apply { loadResult = ApiResult.Failure(ApiError(status = 500, message = "x")) }
        val data = (repo(kyc = kyc).loadSetup() as ApiResult.Success).data
        assertEquals(null, data.tierStatus) // gate evaluator will treat null -> Unknown
    }

    @Test
    fun loadSetup_balanceLegFails_isFailure() = runTest {
        val payouts = FakePayoutsRepository().apply {
            balanceResult = ApiResult.Failure(ApiError(status = 500, message = "balance down"))
        }
        assertTrue(repo(payouts = payouts).loadSetup() is ApiResult.Failure)
    }

    @Test
    fun requestPayout_stubAuthorizer_NotConfigured_neverCallsBackend() = runTest {
        val payouts = FakePayoutsRepository()
        val outcome = repo(payouts = payouts).requestPayout(PayoutRequestDraft(amountCents = 5000), currency = "USD")
        assertEquals(PayoutRequestOutcome.NotConfigured, outcome)
        // CRITICAL: no real payout executed — the backend request method was never called.
        assertEquals(0, payouts.requestPayoutCalls)
    }

    @Test
    fun requestPayout_authorized_reachesBackend_returnsCreated() = runTest {
        val payouts = FakePayoutsRepository()
        val authorizer = StubAuthorizer(BillingResult.Authorized(paymentMethodId = "pm_1", authorizedMinorUnits = 5000))
        val outcome = repo(payouts = payouts, authorizer = authorizer)
            .requestPayout(PayoutRequestDraft(amountCents = 5000), currency = "USD")
        assertTrue(outcome is PayoutRequestOutcome.Created)
        assertEquals(1, payouts.requestPayoutCalls)
    }

    @Test
    fun requestPayout_declined_doesNotReachBackend() = runTest {
        val payouts = FakePayoutsRepository()
        val authorizer = StubAuthorizer(BillingResult.Declined("nope"))
        val outcome = repo(payouts = payouts, authorizer = authorizer)
            .requestPayout(PayoutRequestDraft(amountCents = 5000), currency = "USD")
        assertTrue(outcome is PayoutRequestOutcome.Declined)
        assertEquals(0, payouts.requestPayoutCalls)
    }

    @Test
    fun refreshTier_delegatesToEvaluate() = runTest {
        val kyc = FakeKycRepository().apply { evaluateResult = ApiResult.Success(sampleTierStatus(eligible = true)) }
        assertTrue(repo(kyc = kyc).refreshTier() is ApiResult.Success)
    }
}
