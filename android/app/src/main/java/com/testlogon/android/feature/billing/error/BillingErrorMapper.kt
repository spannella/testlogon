package com.testlogon.android.feature.billing.error

import com.testlogon.android.R
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-232 — the single billing error-mapping layer. Translates a repository [ApiResult] failure (or a
 * raw [ApiError]) into a screen-ready [BillingError] with a localizable message + a [Recoverability]
 * classification.
 *
 * It REUSES the central FastAPI detail normalization ([ApiError.message] is already produced by
 * core-network's ApiErrorParser via ErrorDetailMapper) — no detail-shape parsing is duplicated here.
 * On top of that it layers a billing decline-code dictionary ([DeclineCode]) for instrument-level
 * failures and a deterministic status -> recoverability classification.
 *
 * Classification rules (per AND-232 §4.4):
 *  - network/timeout, 5xx, `processing_error`            -> RETRYABLE
 *  - `authentication_required`                           -> REQUIRES_ACTION
 *  - card_declined / insufficient_funds / expired_card / incorrect_cvc -> REQUIRES_NEW_METHOD
 *  - everything else (422 validation, 401/403 auth, geo) -> FATAL
 */
@Singleton
class BillingErrorMapper @Inject constructor() {

    /** Maps any failed [ApiResult] variant. (Success is a programming error -> generic FATAL.) */
    fun map(result: ApiResult<*>): BillingError = when (result) {
        is ApiResult.Failure -> map(result.error)
        is ApiResult.NetworkError -> BillingError(
            message = UiText.Res(if (result.isTimeout) R.string.billing_err_timeout else R.string.billing_err_offline),
            recoverability = Recoverability.RETRYABLE,
            httpStatus = ApiError.STATUS_NETWORK,
        )
        is ApiResult.Success -> BillingError(
            message = UiText.Res(R.string.billing_err_generic),
            recoverability = Recoverability.FATAL,
        )
    }

    /** Maps a structured [ApiError]. */
    fun map(error: ApiError): BillingError {
        // Transport sentinels first.
        when (error.status) {
            ApiError.STATUS_NETWORK -> return BillingError(
                message = UiText.Res(R.string.billing_err_offline),
                recoverability = Recoverability.RETRYABLE,
                httpStatus = error.status,
            )
            ApiError.STATUS_PARSE -> return BillingError(
                message = UiText.Res(R.string.billing_err_generic),
                recoverability = Recoverability.FATAL,
                httpStatus = error.status,
            )
        }

        // Billing decline dictionary (instrument-level), keyed off the normalized detail code.
        val decline = DeclineCode.fromCode(error.code)
        if (decline != null) {
            return BillingError(
                message = UiText.Res(decline.messageRes()),
                recoverability = decline.recoverability(),
                declineCode = decline,
                rawDetailCode = error.code,
                httpStatus = error.status,
            )
        }

        // 5xx -> retryable transient; surface a stable resource string (not the raw 500 body).
        if (error.status in 500..599) {
            return BillingError(
                message = UiText.Res(R.string.billing_err_server),
                recoverability = Recoverability.RETRYABLE,
                rawDetailCode = error.code,
                httpStatus = error.status,
            )
        }

        // Everything else (422 validation, 401/403 auth, geo_blocked, unknown codes) -> FATAL.
        // The server-normalized message is already user-facing copy (ErrorDetailMapper), so pass it
        // through verbatim as Raw (localized backend strings survive); raw provider blobs are stripped.
        return BillingError(
            message = UiText.Raw(error.message),
            recoverability = Recoverability.FATAL,
            rawDetailCode = error.code,
            httpStatus = error.status,
        )
    }

    private fun DeclineCode.recoverability(): Recoverability = when (this) {
        DeclineCode.PROCESSING_ERROR -> Recoverability.RETRYABLE
        DeclineCode.AUTHENTICATION_REQUIRED -> Recoverability.REQUIRES_ACTION
        DeclineCode.CARD_DECLINED,
        DeclineCode.INSUFFICIENT_FUNDS,
        DeclineCode.EXPIRED_CARD,
        DeclineCode.INCORRECT_CVC,
        DeclineCode.NO_PAYMENT_METHOD,
        DeclineCode.PAYMENT_FAILED,
        -> Recoverability.REQUIRES_NEW_METHOD
        DeclineCode.MICRODEPOSITS_PENDING -> Recoverability.REQUIRES_ACTION
        DeclineCode.UNKNOWN -> Recoverability.FATAL
    }

    private fun DeclineCode.messageRes(): Int = when (this) {
        DeclineCode.CARD_DECLINED -> R.string.billing_err_card_declined
        DeclineCode.INSUFFICIENT_FUNDS -> R.string.billing_err_insufficient_funds
        DeclineCode.EXPIRED_CARD -> R.string.billing_err_expired_card
        DeclineCode.INCORRECT_CVC -> R.string.billing_err_incorrect_cvc
        DeclineCode.PROCESSING_ERROR -> R.string.billing_err_processing
        DeclineCode.AUTHENTICATION_REQUIRED -> R.string.billing_err_auth_required
        DeclineCode.MICRODEPOSITS_PENDING -> R.string.billing_err_microdeposits_pending
        DeclineCode.NO_PAYMENT_METHOD -> R.string.billing_err_no_payment_method
        DeclineCode.PAYMENT_FAILED -> R.string.billing_err_payment_failed
        DeclineCode.UNKNOWN -> R.string.billing_err_generic
    }
}
