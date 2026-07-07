package com.testlogon.android.data.messaging

import com.testlogon.android.data.billing.BillingApi
import kotlinx.coroutines.CancellationException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * TIP-103 (AND-031) — the real [BillingAuthorizer] that replaces [StubBillingAuthorizer]'s release
 * `NotConfigured`, so tips/unlocks POST a real `payment_method_id` in a RELEASE build.
 *
 * DEBUG: preserves the dev/demo BLANK payment-method path — the dev backend skips PM validation for a
 * blank id and mock-completes the charge, so on-device pay-to-unlock + tips keep working without a
 * real vendor. (Identical to the old stub's debug branch.)
 *
 * RELEASE: resolves a REAL `payment_method_id` from the saved wallet, mirroring the backend
 * `resolve_tip_payment_method` chain: tip-default -> general default (is_default) -> first saved
 * method. When the user has NO saved method it returns [BillingResult.NotConfigured] so the flow
 * routes to "add a card" and never fakes a charge. A network/read failure surfaces as
 * [BillingResult.Failed] (retryable), never a silent success.
 *
 * No charge happens here — the backend captures on unlock/tip; this only selects the instrument.
 */
@Singleton
class RealBillingAuthorizer @Inject constructor(
    private val billingApi: BillingApi,
) : BillingAuthorizer {

    override suspend fun authorize(
        amountMinorUnits: Long,
        currency: String,
        memo: String?,
    ): BillingResult {
        if (com.testlogon.android.BuildConfig.DEBUG) {
            // DEV/DEMO bypass (unchanged): authorize with a BLANK payment-method id.
            return BillingResult.Authorized(paymentMethodId = "", authorizedMinorUnits = amountMinorUnits)
        }
        return try {
            when (val pmId = resolvePaymentMethodId()) {
                null -> BillingResult.NotConfigured
                else -> BillingResult.Authorized(paymentMethodId = pmId, authorizedMinorUnits = amountMinorUnits)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            BillingResult.Failed(e)
        }
    }

    /**
     * TIP-102/103 resolve chain: tip-default (when it still names a saved method) -> the wallet's
     * general default (is_default) -> the first saved method. Returns null only when the wallet is
     * empty (routes to add-card).
     */
    private suspend fun resolvePaymentMethodId(): String? {
        val methods = billingApi.getPaymentMethods()
        if (methods.isEmpty()) return null
        val savedIds = methods.mapTo(HashSet()) { it.paymentMethodId }
        val tipDefault = runCatching { billingApi.getTipDefault().tipDefaultPaymentMethodId }.getOrNull()
        if (tipDefault != null && tipDefault in savedIds) return tipDefault
        return methods.firstOrNull { it.isDefault }?.paymentMethodId ?: methods.first().paymentMethodId
    }
}
