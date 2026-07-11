package com.testlogon.android.feature.billing.error

import com.testlogon.android.core.ui.i18n.UiText

/**
 * AND-232 — recoverability classification for a billing failure. Drives the UI affordance:
 *  - [RETRYABLE]: transient (timeout/5xx/processing) — offer a manual retry.
 *  - [REQUIRES_NEW_METHOD]: instrument-level decline — prompt for a different payment method.
 *  - [REQUIRES_ACTION]: 3DS/SCA — launch an authentication step.
 *  - [FATAL]: validation/auth/geo/unknown — no retry; surface the message only.
 */
enum class Recoverability { RETRYABLE, REQUIRES_NEW_METHOD, REQUIRES_ACTION, FATAL }

/**
 * AND-232 — provider decline codes (client-owned dictionary; UNVERIFIED against the backend — these
 * strings do not appear in the OpenAPI/web source, so an UNKNOWN -> FATAL fallback is the contract).
 */
enum class DeclineCode {
    CARD_DECLINED,
    INSUFFICIENT_FUNDS,
    EXPIRED_CARD,
    INCORRECT_CVC,
    PROCESSING_ERROR,
    AUTHENTICATION_REQUIRED,
    MICRODEPOSITS_PENDING,
    // SUB-E0: subscription (and any real-charge) money-path 402 codes.
    NO_PAYMENT_METHOD,
    PAYMENT_FAILED,
    UNKNOWN,
    ;

    companion object {
        fun fromCode(code: String?): DeclineCode? = when (code?.lowercase()) {
            "card_declined" -> CARD_DECLINED
            "insufficient_funds" -> INSUFFICIENT_FUNDS
            "expired_card" -> EXPIRED_CARD
            "incorrect_cvc" -> INCORRECT_CVC
            "processing_error" -> PROCESSING_ERROR
            "authentication_required" -> AUTHENTICATION_REQUIRED
            "microdeposits_pending" -> MICRODEPOSITS_PENDING
            "no_payment_method" -> NO_PAYMENT_METHOD
            "payment_failed" -> PAYMENT_FAILED
            else -> null
        }
    }
}

/**
 * AND-232 — a screen-ready billing failure. The ViewModel never surfaces a raw Throwable/ApiError;
 * every failure becomes a [BillingError] carrying a localizable [message], a [recoverability]
 * classification, and (for logging/analytics only) the raw detail code + http status.
 *
 * @param retryable convenience flag == (recoverability == RETRYABLE) for the screen layer.
 */
data class BillingError(
    val message: UiText,
    val recoverability: Recoverability,
    val declineCode: DeclineCode? = null,
    val rawDetailCode: String? = null,
    val httpStatus: Int? = null,
) {
    val retryable: Boolean get() = recoverability == Recoverability.RETRYABLE
}
