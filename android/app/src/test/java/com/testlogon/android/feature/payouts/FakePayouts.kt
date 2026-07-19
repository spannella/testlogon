package com.testlogon.android.feature.payouts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payouts.BulkPayoutsRepository
import com.testlogon.android.data.payouts.KycRepository
import com.testlogon.android.data.payouts.KycTier
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutBatch
import com.testlogon.android.data.payouts.PayoutBatchItem
import com.testlogon.android.data.payouts.PayoutBatchStatus
import com.testlogon.android.data.payouts.AddPayoutMethodInput
import com.testlogon.android.data.payouts.ConnectAccount
import com.testlogon.android.data.payouts.ConnectOnboarding
import com.testlogon.android.data.payouts.PayoutMethod
import com.testlogon.android.data.payouts.PayoutMethodStatus
import com.testlogon.android.data.payouts.RoutableMethodType
import com.testlogon.android.data.payouts.PayoutActionResult
import com.testlogon.android.data.payouts.PayoutBalance
import com.testlogon.android.data.payouts.PayoutCreateResult
import com.testlogon.android.data.payouts.PayoutMoney
import com.testlogon.android.data.payouts.PayoutPage
import com.testlogon.android.data.payouts.PayoutRequestDraft
import com.testlogon.android.data.payouts.PayoutRequestOutcome
import com.testlogon.android.data.payouts.PayoutSetupData
import com.testlogon.android.data.payouts.PayoutSetupRepository
import com.testlogon.android.data.payouts.PayoutTaxInfo
import com.testlogon.android.data.payouts.W9Submission
import com.testlogon.android.data.payouts.WithdrawGateInputs
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.data.payouts.PayoutStatus
import com.testlogon.android.data.payouts.PayoutsRepository
import com.testlogon.android.data.payouts.TierStatus

/**
 * AND-258/259/260 — configurable test doubles for the payout repositories. Sample builders are named
 * [samplePayout] / [sampleBalance] / [sampleTierStatus] (NOT after interface members, per the gotcha).
 */
class FakePayoutsRepository : PayoutsRepository {

    /** cursor -> page result. null key is the first page. */
    var pages: MutableMap<String?, ApiResult<PayoutPage>> = mutableMapOf(
        null to ApiResult.Success(PayoutPage(emptyList(), null)),
    )
    var balanceResult: ApiResult<PayoutBalance> = ApiResult.Success(sampleBalance())
    var createResult: ApiResult<PayoutCreateResult> = ApiResult.Success(
        PayoutCreateResult(ok = true, payoutId = "po_new", amount = PayoutMoney(50000, "USD"), status = PayoutStatus.REQUESTED),
    )
    var cancelResult: ApiResult<PayoutActionResult> =
        ApiResult.Success(PayoutActionResult(ok = true, payoutId = "po_1", status = PayoutStatus.CANCELLED))

    val requestedCursors = mutableListOf<String?>()
    var requestPayoutCalls = 0
        private set

    override suspend fun getBalance(): ApiResult<PayoutBalance> = balanceResult

    override suspend fun getPayouts(cursor: String?, limit: Int): ApiResult<PayoutPage> {
        requestedCursors += cursor
        return pages[cursor] ?: ApiResult.Failure(ApiError(status = 500, message = "no page for $cursor"))
    }

    override suspend fun requestPayout(
        amountCents: Long,
        method: String,
        methodId: String?,
        notes: String,
        currency: String,
    ): ApiResult<PayoutCreateResult> {
        requestPayoutCalls++
        return createResult
    }

    override suspend fun cancelPayout(payoutId: String): ApiResult<PayoutActionResult> = cancelResult

    // PAY-50/51 additions (wallet summary + payout detail). Programmable; default not-configured.
    var walletResult: ApiResult<com.testlogon.android.data.payouts.WalletSummary> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var payoutDetailResult: ApiResult<com.testlogon.android.data.payouts.PayoutDetail> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))

    override suspend fun getWallet() = walletResult
    override suspend fun getPayoutDetail(payoutId: String) = payoutDetailResult
}

/**
 * AND-259 — a [PayoutSetupRepository] double that records whether the backend payout was reached. The
 * default [requestOutcome] is [PayoutRequestOutcome.Error] (unset). PAY-52 removed the former
 * BillingAuthorizer NotConfigured short-circuit; requestPayout now hits the real gate-enforced backend,
 * so the outcome is Created on success or Error otherwise. A test opting into the payout path programs it.
 */
class FakePayoutSetupRepository : PayoutSetupRepository {

    var setupResult: ApiResult<PayoutSetupData> = ApiResult.Success(
        PayoutSetupData(balance = sampleBalance(), recentPayouts = emptyList(), tierStatus = sampleTierStatus(eligible = true)),
    )
    var refreshResult: ApiResult<TierStatus> = ApiResult.Success(sampleTierStatus(eligible = true))
    var requestOutcome: PayoutRequestOutcome =
        PayoutRequestOutcome.Error(ApiResult.Failure(ApiError(status = 500, message = "not configured")))

    var requestPayoutCalls = 0
        private set
    var lastDraft: PayoutRequestDraft? = null
        private set

    override suspend fun loadSetup(requiredTier: Int): ApiResult<PayoutSetupData> = setupResult

    override suspend fun refreshTier(requiredTier: Int): ApiResult<TierStatus> = refreshResult

    override suspend fun requestPayout(draft: PayoutRequestDraft, currency: String): PayoutRequestOutcome {
        requestPayoutCalls++
        lastDraft = draft
        return requestOutcome
    }

    // PAY-22 - pre-withdrawal gate doubles (default: both satisfied -> gate open).
    var withdrawGateResult: ApiResult<WithdrawGateInputs> = ApiResult.Success(
        WithdrawGateInputs(kycApproved = true, kycStatus = KycCaseStatus.APPROVED, taxInfo = sampleTaxInfo()),
    )
    var submitTaxResult: ApiResult<PayoutTaxInfo> = ApiResult.Success(sampleTaxInfo())
    var submitTaxCalls = 0
        private set

    override suspend fun loadWithdrawGate(): ApiResult<WithdrawGateInputs> = withdrawGateResult
    override suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo> {
        submitTaxCalls++
        return submitTaxResult
    }

    // ---- PAY-13: routable payout-method doubles ----

    // PAY-52: default to ONE verified destination so the withdraw form auto-selects it and submit() is
    // not (correctly) blocked on a missing payout method. Tests that exercise the empty/unverified paths
    // override this.
    var methodsResult: ApiResult<List<PayoutMethod>> =
        ApiResult.Success(listOf(sampleMethod(status = PayoutMethodStatus.VERIFIED, isDefault = true)))
    var addMethodResult: ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod())
    var verifyResult: ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod(status = PayoutMethodStatus.VERIFIED))
    var setDefaultResult: ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod(isDefault = true))
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var connectResult: ApiResult<ConnectAccount> = ApiResult.Success(ConnectAccount("acct_mock_x", "complete", true))
    var onboardingResult: ApiResult<ConnectOnboarding> =
        ApiResult.Success(ConnectOnboarding("acct_mock_x", "", "complete", true, false))

    var addMethodCalls = 0
        private set
    var lastAddInput: AddPayoutMethodInput? = null
        private set
    var verifyCalls = 0
        private set

    override suspend fun loadMethods(): ApiResult<List<PayoutMethod>> = methodsResult
    override suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod> {
        addMethodCalls++
        lastAddInput = input
        return addMethodResult
    }
    override suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod> {
        verifyCalls++
        return verifyResult
    }
    override suspend fun setDefaultMethod(methodId: String): ApiResult<PayoutMethod> = setDefaultResult
    override suspend fun deleteMethod(methodId: String): ApiResult<Unit> = deleteResult
    override suspend fun getConnect(): ApiResult<ConnectAccount> = connectResult
    override suspend fun createConnectAccount(): ApiResult<ConnectAccount> = connectResult
    override suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding> = onboardingResult
}

/**
 * AND-261/263 — a [BulkPayoutsRepository] double. Programmable list/detail results + call counts so
 * the VM stale/retry/empty/error transitions are assertable. The builder is named [sampleBatch] (NOT
 * after an interface member, per the gotcha).
 */
class FakeBulkPayoutsRepository : BulkPayoutsRepository {

    var batchesResult: ApiResult<List<PayoutBatch>> = ApiResult.Success(listOf(sampleBatch()))
    var batchResult: ApiResult<PayoutBatch> = ApiResult.Success(sampleBatch())

    var getBatchesCalls = 0
        private set
    var getBatchCalls = 0
        private set
    var lastBatchId: String? = null
        private set

    override suspend fun getBatches(): ApiResult<List<PayoutBatch>> {
        getBatchesCalls++
        return batchesResult
    }

    override suspend fun getBatch(batchId: String): ApiResult<PayoutBatch> {
        getBatchCalls++
        lastBatchId = batchId
        return batchResult
    }
}

class FakeKycRepository : KycRepository {
    var loadResult: ApiResult<TierStatus> = ApiResult.Success(sampleTierStatus(eligible = true))
    var evaluateResult: ApiResult<TierStatus> = ApiResult.Success(sampleTierStatus(eligible = true))
    override suspend fun loadTierStatus(requiredTier: Int): ApiResult<TierStatus> = loadResult
    override suspend fun evaluateTierStatus(requiredTier: Int): ApiResult<TierStatus> = evaluateResult
}

/**
 * PAY-13 — [PayoutMethodsRepository] double. Default success/empty; the setup-repo composition test only
 * needs it to satisfy the ctor (methods not exercised in the loadSetup/requestPayout paths under test).
 */
class FakePayoutMethodsRepository : com.testlogon.android.data.payouts.PayoutMethodsRepository {
    var methodsResult: ApiResult<List<PayoutMethod>> = ApiResult.Success(emptyList())
    override suspend fun listMethods(): ApiResult<List<PayoutMethod>> = methodsResult
    override suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod())
    override suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod(status = PayoutMethodStatus.VERIFIED))
    override suspend fun setDefault(methodId: String): ApiResult<PayoutMethod> = ApiResult.Success(sampleMethod(isDefault = true))
    override suspend fun deleteMethod(methodId: String): ApiResult<Unit> = ApiResult.Success(Unit)
    override suspend fun getConnect(): ApiResult<ConnectAccount> = ApiResult.Success(ConnectAccount("acct_mock_x", "complete", true))
    override suspend fun createConnectAccount(): ApiResult<ConnectAccount> = ApiResult.Success(ConnectAccount("acct_mock_x", "complete", true))
    override suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding> =
        ApiResult.Success(ConnectOnboarding("acct_mock_x", "", "complete", true, false))
}

/** PAY-22 — [KycCaseRepository] double for the withdraw-gate leg. Default: no cases (fail-closed). */
class FakeKycCaseRepository : com.testlogon.android.feature.kyc.cases.data.KycCaseRepository {
    var casesResult: ApiResult<List<com.testlogon.android.feature.kyc.cases.model.KycCaseSummary>> = ApiResult.Success(emptyList())
    override suspend fun cases() = casesResult
    override suspend fun caseDetail(caseId: String) = ApiResult.Failure(ApiError(status = 404, message = "no case"))
    override suspend fun monitoring() = ApiResult.Failure(ApiError(status = 500, message = "stub"))
}

/** PAY-22 — [TaxInfoRepository] double for the withdraw-gate W-9 leg. Default: certified on file. */
class FakeTaxInfoRepository : com.testlogon.android.data.payouts.TaxInfoRepository {
    var taxResult: ApiResult<PayoutTaxInfo> = ApiResult.Success(sampleTaxInfo())
    override suspend fun getTaxInfo(): ApiResult<PayoutTaxInfo> = taxResult
    override suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo> = taxResult
}

fun samplePayout(id: String = "po_1", status: PayoutStatus = PayoutStatus.COMPLETED): Payout = Payout(
    payoutId = id,
    userId = "usr_1",
    amount = PayoutMoney(4500, "USD"),
    status = status,
    method = "bank_transfer",
    createdAtEpochSeconds = 1_748_628_251L,
    updatedAtEpochSeconds = 1_748_800_800L,
    completedAtEpochSeconds = if (status == PayoutStatus.COMPLETED) 1_748_800_800L else null,
    notes = "",
    rejectReason = if (status == PayoutStatus.REJECTED) "insufficient docs" else "",
    approvedBy = "admin_1",
)

fun samplePayoutDetail(
    id: String = "po_1",
    status: PayoutStatus = PayoutStatus.COMPLETED,
): com.testlogon.android.data.payouts.PayoutDetail = com.testlogon.android.data.payouts.PayoutDetail(
    payoutId = id,
    userId = "usr_1",
    amount = PayoutMoney(4500, "USD"),
    status = status,
    method = "bank_transfer",
    methodId = "pm_1",
    methodLast4 = "6789",
    createdAtEpochSeconds = 1_748_628_251L,
    updatedAtEpochSeconds = 1_748_800_800L,
    completedAtEpochSeconds = if (status == PayoutStatus.COMPLETED) 1_748_800_800L else null,
    notes = "",
    rejectReason = "",
    failReason = "",
    approvedBy = "admin_1",
    manualHold = false,
    holdReason = "",
    debitReversed = false,
    transferProvider = "stripe",
    transferRef = "tr_mock_1",
    transferAttempts = 1,
    timeline = emptyList(),
)

fun sampleBalance(available: Long = 50000, min: Long = 1000): PayoutBalance = PayoutBalance(
    availableCents = available,
    pendingCents = 0,
    totalEarnedCents = 120000,
    holdCents = 0,
    currency = "USD",
    minimumPayoutCents = min,
)

fun sampleBatch(
    id: String = "bat_1",
    status: PayoutBatchStatus = PayoutBatchStatus.COMPLETED,
    items: List<PayoutBatchItem> = listOf(
        PayoutBatchItem(
            refId = "po_1",
            amount = com.testlogon.android.data.payouts.PayoutMoney(4500, "USD"),
            status = PayoutStatus.COMPLETED,
            recipient = "creator_88",
            reason = "",
        ),
    ),
): PayoutBatch = PayoutBatch(
    id = id,
    kind = "payout",
    status = status,
    itemCount = items.size,
    total = com.testlogon.android.data.payouts.PayoutMoney(5_764_500, "USD"),
    successCount = 124,
    failureCount = 4,
    createdAtEpochSeconds = 1_748_729_400L,
    createdBy = "admin_42",
    items = items,
)

fun sampleTierStatus(
    current: Int = 1,
    required: Int = 1,
    eligible: Boolean? = null,
    unmet: List<String> = emptyList(),
): TierStatus = TierStatus(
    currentTier = KycTier(current),
    tierName = "basic",
    requiredTierForPayouts = KycTier(required),
    eligibleForPayoutTier = eligible,
    unmetRequirements = unmet,
)


fun sampleMethod(
    id: String = "pm_1",
    type: RoutableMethodType = RoutableMethodType.BANK_ACH,
    status: PayoutMethodStatus = PayoutMethodStatus.UNVERIFIED,
    isDefault: Boolean = false,
): PayoutMethod = PayoutMethod(
    methodId = id,
    type = type,
    rawType = type.wire,
    accountLast4 = if (type.isBank) "6789" else "",
    routingLast4 = if (type.isBank) "0021" else "",
    paypalEmail = if (type == RoutableMethodType.PAYPAL) "creator@example.com" else "",
    nickname = "Primary",
    isDefault = isDefault,
    status = status,
    connectAccountId = if (type == RoutableMethodType.STRIPE_CONNECT) "acct_mock_x" else "",
    externalAccountRef = "btok_mock_abc",
    createdAtEpochSeconds = 1_748_628_251L,
    updatedAtEpochSeconds = 1_748_800_800L,
)

fun sampleTaxInfo(
    onFile: Boolean = true,
    certified: Boolean = true,
    tinLast4: String = "6789",
): PayoutTaxInfo = PayoutTaxInfo(
    onFile = onFile,
    legalName = "Jane Creator",
    tinLast4 = tinLast4,
    tinType = "ssn",
    addressLine1 = "1 Main St",
    city = "Austin",
    state = "TX",
    zipCode = "78701",
    certified = certified,
    certifiedAt = 1_748_800_800L,
)
