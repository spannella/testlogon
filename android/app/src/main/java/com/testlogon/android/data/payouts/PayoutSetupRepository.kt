package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.feature.kyc.cases.data.KycCaseRepository
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** AND-259 — the combined initial-load payload for the payout-setup screen. */
data class PayoutSetupData(
    val balance: PayoutBalance,
    val recentPayouts: List<Payout>,
    /** null when the KYC leg failed -> gate fails closed to Unknown. */
    val tierStatus: TierStatus?,
)

/** AND-259 — a validated payout-request draft (amount in cents, free-string method, optional notes). */
data class PayoutRequestDraft(
    val amountCents: Long,
    val method: String = DEFAULT_PAYOUT_METHOD,
    val notes: String = "",
)

/**
 * AND-259 — the outcome of a (gated) payout-request attempt.
 *
 * STOP-AND-FLAG (payouts decision): the actual money-movement is authorized by the
 * [BillingAuthorizer] vendor seam, which is the FLAGGED stub ([NotConfigured]) — so a real payout is
 * NEVER executed by this app. When the authorizer is NotConfigured the repository short-circuits with
 * [NotConfigured] and DOES NOT call POST ui/payouts/request.
 */
sealed interface PayoutRequestOutcome {
    /** The (authorized) request reached the backend and returned a created payout. */
    data class Created(val result: PayoutCreateResult) : PayoutRequestOutcome

    /** The backend request itself failed (mapped error result preserved for the ViewModel). */
    data class Error(val result: ApiResult<PayoutCreateResult>) : PayoutRequestOutcome

    /** The user dismissed the (scaffolded) authorization sheet. */
    data object Cancelled : PayoutRequestOutcome

    /** The authorizer declined / failed (vendor-level). */
    data class Declined(val reason: String) : PayoutRequestOutcome

    /**
     * Billing/payout authorization is not configured (the [BillingAuthorizer] stub). No payout was
     * requested; the UI surfaces a "payouts unavailable" state. This is the always-returned outcome
     * until the real authorizer is wired.
     */
    data object NotConfigured : PayoutRequestOutcome
}

/**
 * AND-259 — payout-setup use cases: composes [PayoutsRepository] (AND-258) + [KycRepository] (tier) and
 * gates the payout-request mutation through the [BillingAuthorizer] stub.
 *
 * STOP-AND-FLAG: [requestPayout] FIRST asks the [BillingAuthorizer] to authorize the amount. The bound
 * [com.testlogon.android.data.messaging.StubBillingAuthorizer] always returns
 * [BillingResult.NotConfigured], so the backend POST is never reached and no real payout is executed.
 * The call path is fully wired so the real authorizer can drop in later.
 */
interface PayoutSetupRepository {

    /** Loads balance + recent payouts + tier status in parallel. Tier-leg failure -> tierStatus = null. */
    suspend fun loadSetup(requiredTier: Int = PAYOUT_REQUIRED_TIER): ApiResult<PayoutSetupData>

    /** Refresh tier after a (scaffolded) KYC return (POST .../me/evaluate, then re-resolve reqs). */
    suspend fun refreshTier(requiredTier: Int = PAYOUT_REQUIRED_TIER): ApiResult<TierStatus>

    /**
     * Authorize (via the BillingAuthorizer stub) then request a payout. Returns [PayoutRequestOutcome].
     * While the stub is NotConfigured this NEVER calls the backend / executes a payout.
     */
    suspend fun requestPayout(draft: PayoutRequestDraft, currency: String): PayoutRequestOutcome

    /**
     * PAY-22 - resolve the PRE-WITHDRAWAL gate: reads the EXISTING kyc_cases status + the W-9 tax-info
     * status and folds them into [WithdrawGateInputs]. Either read failing -> the failure passes through
     * (the gate fails closed to Unresolved). Reuses the existing KYC system (does NOT rebuild it).
     */
    suspend fun loadWithdrawGate(): ApiResult<WithdrawGateInputs>

    /** PAY-22 - submit the W-9 (raw TIN tokenized+masked server-side); returns the masked view. */
    suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo>

    // ---- PAY-13: routable payout-method management (delegated to PayoutMethodsRepository) ----

    /** List the creator's routable payout methods (status + default flag). */
    suspend fun loadMethods(): ApiResult<List<PayoutMethod>>

    /** Add a routable destination (bank tokenized server-side / paypal email / connect id). */
    suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod>

    /** PAY-12 — verify a method so a payout may target it. */
    suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod>

    /** Set the default payout destination. */
    suspend fun setDefaultMethod(methodId: String): ApiResult<PayoutMethod>

    /** Remove a method. */
    suspend fun deleteMethod(methodId: String): ApiResult<Unit>

    /** PAY-11 — the creator's Stripe Connect account status. */
    suspend fun getConnect(): ApiResult<ConnectAccount>

    /** PAY-11 — create (or return) the creator's Connect account id. */
    suspend fun createConnectAccount(): ApiResult<ConnectAccount>

    /** PAY-11 — a Connect onboarding link (real when keyed; mock self-completes). */
    suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding>
}

@Singleton
class PayoutSetupRepositoryImpl @Inject constructor(
    private val payoutsRepository: PayoutsRepository,
    private val kycRepository: KycRepository,
    private val billingAuthorizer: BillingAuthorizer,
    private val methodsRepository: PayoutMethodsRepository,
    private val kycCaseRepository: KycCaseRepository,
    private val taxInfoRepository: TaxInfoRepository,
) : PayoutSetupRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadSetup(requiredTier: Int): ApiResult<PayoutSetupData> = withContext(io) {
        coroutineScope {
            val balanceDeferred = async { payoutsRepository.getBalance() }
            val payoutsDeferred = async { payoutsRepository.getPayouts() }
            val tierDeferred = async { kycRepository.loadTierStatus(requiredTier) }

            val balanceResult = balanceDeferred.await()
            val payoutsResult = payoutsDeferred.await()
            val tierResult = tierDeferred.await()

            // Balance is required; surface its failure verbatim.
            when (balanceResult) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> return@coroutineScope balanceResult
                is ApiResult.NetworkError -> return@coroutineScope balanceResult
            }
            val balance = balanceResult.data
            val recent = (payoutsResult as? ApiResult.Success)?.data?.items.orEmpty()
            // Fail-closed: a tier-leg failure leaves tierStatus null -> gate Unknown.
            val tier = (tierResult as? ApiResult.Success)?.data

            ApiResult.Success(
                PayoutSetupData(balance = balance, recentPayouts = recent, tierStatus = tier),
            )
        }
    }

    override suspend fun refreshTier(requiredTier: Int): ApiResult<TierStatus> = withContext(io) {
        kycRepository.evaluateTierStatus(requiredTier)
    }

    override suspend fun requestPayout(draft: PayoutRequestDraft, currency: String): PayoutRequestOutcome =
        withContext(io) {
            // GATE: authorize via the BillingAuthorizer stub BEFORE any backend call. The bound stub
            // returns NotConfigured, so the backend POST below is never reached (no real payout).
            when (val auth = billingAuthorizer.authorize(draft.amountCents, currency, draft.notes.ifBlank { null })) {
                is BillingResult.Authorized -> {
                    when (val result = payoutsRepository.requestPayout(
                        amountCents = draft.amountCents,
                        method = draft.method,
                        notes = draft.notes,
                        currency = currency,
                    )) {
                        is ApiResult.Success -> PayoutRequestOutcome.Created(result.data)
                        else -> PayoutRequestOutcome.Error(result)
                    }
                }
                BillingResult.Cancelled -> PayoutRequestOutcome.Cancelled
                is BillingResult.Declined -> PayoutRequestOutcome.Declined(auth.reason)
                is BillingResult.Failed -> PayoutRequestOutcome.Declined(auth.cause.message ?: "")
                BillingResult.NotConfigured -> PayoutRequestOutcome.NotConfigured
            }
        }

    // ---- PAY-22: pre-withdrawal gate (KYC + W-9) ----

    override suspend fun loadWithdrawGate(): ApiResult<WithdrawGateInputs> = withContext(io) {
        coroutineScope {
            val casesDeferred = async { kycCaseRepository.cases() }
            val taxDeferred = async { taxInfoRepository.getTaxInfo() }
            val casesResult = casesDeferred.await()
            val taxResult = taxDeferred.await()

            // Fail closed: a failure in either leg passes through so the gate cannot open.
            when (casesResult) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> return@coroutineScope casesResult
                is ApiResult.NetworkError -> return@coroutineScope casesResult
            }
            when (taxResult) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> return@coroutineScope taxResult
                is ApiResult.NetworkError -> return@coroutineScope taxResult
            }
            val (approved, status) = resolveKyc(casesResult.data)
            ApiResult.Success(
                WithdrawGateInputs(kycApproved = approved, kycStatus = status, taxInfo = taxResult.data),
            )
        }
    }

    override suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo> =
        taxInfoRepository.submitTaxInfo(submission)

    /**
     * Resolve the KYC status from the caller cases (mirrors backend PAY-20 resolve_kyc_status):
     * APPROVED iff ANY owned case is approved; else the most-informative in-progress status; else
     * UNKNOWN (no case = not started).
     */
    private fun resolveKyc(cases: List<KycCaseSummary>): Pair<Boolean, KycCaseStatus> {
        if (cases.any { it.status == KycCaseStatus.APPROVED }) return true to KycCaseStatus.APPROVED
        val order = listOf(
            KycCaseStatus.UNDER_REVIEW,
            KycCaseStatus.NEEDS_MORE_INFO,
            KycCaseStatus.SUBMITTED,
            KycCaseStatus.DRAFT,
            KycCaseStatus.REJECTED,
            KycCaseStatus.EXPIRED,
        )
        val best = order.firstOrNull { st -> cases.any { it.status == st } }
            ?: cases.maxByOrNull { it.updatedAt }?.status
            ?: KycCaseStatus.UNKNOWN
        return false to best
    }

    // ---- PAY-13: pure delegations to the routable payout-methods repository ----

    override suspend fun loadMethods(): ApiResult<List<PayoutMethod>> = methodsRepository.listMethods()

    override suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod> =
        methodsRepository.addMethod(input)

    override suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod> =
        methodsRepository.verifyMethod(methodId)

    override suspend fun setDefaultMethod(methodId: String): ApiResult<PayoutMethod> =
        methodsRepository.setDefault(methodId)

    override suspend fun deleteMethod(methodId: String): ApiResult<Unit> =
        methodsRepository.deleteMethod(methodId)

    override suspend fun getConnect(): ApiResult<ConnectAccount> = methodsRepository.getConnect()

    override suspend fun createConnectAccount(): ApiResult<ConnectAccount> =
        methodsRepository.createConnectAccount()

    override suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding> =
        methodsRepository.createConnectOnboardingLink()
}
