package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.payouts.FakePayoutsRepository
import com.testlogon.android.feature.payouts.FakeKycRepository
import com.testlogon.android.feature.payouts.FakePayoutMethodsRepository
import com.testlogon.android.feature.payouts.FakeKycCaseRepository
import com.testlogon.android.feature.payouts.FakeTaxInfoRepository
import com.testlogon.android.feature.payouts.samplePayout
import com.testlogon.android.feature.payouts.sampleTierStatus
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-259 / PAY-52 — [PayoutSetupRepositoryImpl]: parallel load composition, fail-closed tier handling,
 * and the payout request path. PAY-52 made payouts REAL: the client-side BillingAuthorizer short-circuit
 * (NotConfigured/Declined) is gone; requestPayout now calls the gate-enforced backend directly and maps
 * Success -> Created / any failure -> Error (the server re-checks KYC + W-9 + balance + method).
 */
class PayoutSetupRepositoryTest {

    private fun repo(
        payouts: FakePayoutsRepository = FakePayoutsRepository(),
        kyc: FakeKycRepository = FakeKycRepository(),
        methods: FakePayoutMethodsRepository = FakePayoutMethodsRepository(),
        kycCases: FakeKycCaseRepository = FakeKycCaseRepository(),
        tax: FakeTaxInfoRepository = FakeTaxInfoRepository(),
    ) = PayoutSetupRepositoryImpl(payouts, kyc, methods, kycCases, tax)

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
    fun requestPayout_success_reachesBackend_returnsCreated() = runTest {
        // PAY-52: the real gate-enforced backend is called directly; a 2xx maps to Created.
        val payouts = FakePayoutsRepository()
        val outcome = repo(payouts = payouts).requestPayout(PayoutRequestDraft(amountCents = 5000), currency = "USD")
        assertTrue(outcome is PayoutRequestOutcome.Created)
        assertEquals("po_new", (outcome as PayoutRequestOutcome.Created).result.payoutId)
        assertEquals(1, payouts.requestPayoutCalls)
    }

    @Test
    fun requestPayout_backendGateRejects_mapsToError() = runTest {
        // Server-side gate rejection (e.g. KYC/W-9 403 or balance/method 400) folds to Error for the VM.
        val payouts = FakePayoutsRepository().apply {
            createResult = ApiResult.Failure(ApiError(status = 403, message = "kyc_required"))
        }
        val outcome = repo(payouts = payouts).requestPayout(PayoutRequestDraft(amountCents = 5000), currency = "USD")
        assertTrue(outcome is PayoutRequestOutcome.Error)
        // The backend WAS reached — the gate lives server-side now, not a client short-circuit.
        assertEquals(1, payouts.requestPayoutCalls)
    }

    @Test
    fun refreshTier_delegatesToEvaluate() = runTest {
        val kyc = FakeKycRepository().apply { evaluateResult = ApiResult.Success(sampleTierStatus(eligible = true)) }
        assertTrue(repo(kyc = kyc).refreshTier() is ApiResult.Success)
    }
}
