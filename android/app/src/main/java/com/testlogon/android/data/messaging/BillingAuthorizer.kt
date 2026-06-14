package com.testlogon.android.data.messaging

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-139 — billing seam. The actual payment-method selection + processor charge is owned by the
 * billing dependency (AND-031); this interface is the integration contract the real implementation
 * will satisfy. It yields an opaque `payment_method_id` (NOT card data) which the unlock/tip POST
 * forwards to the backend.
 *
 * STOP-AND-FLAG (payments decision): there is NO backend endpoint that completes a charge purely
 * server-side from a wallet/balance for fixed-price unlock/tip — both require a `payment_method_id`
 * obtained from a payment-method picker (web uses `getPaymentMethods` + a selected method). That is a
 * payments-vendor / flow concern (AND-031). This module therefore ships [StubBillingAuthorizer],
 * which returns [BillingResult.NotConfigured] and never fakes a charge. The unlock/tip CALL paths are
 * fully wired; the real authorizer must be supplied by AND-031 before monetization is enabled.
 * (Lottery unlock takes NO billing-authorize step — the server draws + reveals atomically.)
 */
sealed interface BillingResult {
    /** A selected payment method authorized for [authorizedMinorUnits]; carries the opaque id. */
    data class Authorized(val paymentMethodId: String, val authorizedMinorUnits: Long) : BillingResult

    /** User dismissed the payment sheet (no error surfaced). */
    data object Cancelled : BillingResult

    /** Processor/vendor declined the instrument. */
    data class Declined(val reason: String) : BillingResult

    /** A non-decline failure (network/processor error). */
    data class Failed(val cause: Throwable) : BillingResult

    /**
     * No real billing provider is wired (AND-031 not yet integrated). The flow must surface a
     * "payments unavailable" state and MUST NOT call the unlock/tip endpoint or fake a charge.
     */
    data object NotConfigured : BillingResult
}

interface BillingAuthorizer {
    /**
     * Obtain a payment-method id authorized for [amountMinorUnits] in [currency]. No charge to
     * TestLogon happens here; the backend captures on unlock/tip. [memo] is an optional UX hint.
     */
    suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String? = null): BillingResult
}

/**
 * AND-139 — default (debug/until-AND-031) authorizer. Never fakes a charge: always returns
 * [BillingResult.NotConfigured] so the UI shows a clear "payments unavailable" state and no server
 * unlock/tip call is made. AND-031 replaces this binding with the real vendor-backed implementation.
 */
@Singleton
class StubBillingAuthorizer @Inject constructor() : BillingAuthorizer {
    override suspend fun authorize(
        amountMinorUnits: Long,
        currency: String,
        memo: String?,
    ): BillingResult = BillingResult.NotConfigured
}
