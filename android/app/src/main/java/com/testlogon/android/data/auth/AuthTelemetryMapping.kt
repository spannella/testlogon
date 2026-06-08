package com.testlogon.android.data.auth

import com.testlogon.android.core.data.telemetry.AuthFactor
import com.testlogon.android.core.data.telemetry.AuthFailureReason
import com.testlogon.android.core.data.telemetry.AuthStage
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** AND-052 — map a domain [MfaFactor] to the coarse telemetry [AuthFactor] label. */
fun MfaFactor.toTelemetry(): AuthFactor = when (this) {
    MfaFactor.Totp -> AuthFactor.TOTP
    MfaFactor.Sms -> AuthFactor.SMS
    MfaFactor.Email -> AuthFactor.EMAIL
    MfaFactor.Recovery -> AuthFactor.RECOVERY
    is MfaFactor.Unknown -> AuthFactor.UNKNOWN
}

/**
 * AND-052 — derive a typed [AuthFailureReason] from a failed [ApiResult]. Only the numeric status
 * and the transport shape are used; raw `detail`/`message` text is never read into telemetry.
 */
fun ApiResult<*>.toAuthReason(stage: AuthStage): AuthFailureReason = when (this) {
    is ApiResult.NetworkError ->
        if (isTimeout) AuthFailureReason.TIMEOUT else AuthFailureReason.CONNECT_FAILED
    is ApiResult.Failure -> error.toAuthReason(stage)
    is ApiResult.Success -> AuthFailureReason.UNKNOWN
}

private fun ApiError.toAuthReason(stage: AuthStage): AuthFailureReason = when {
    status == ApiError.STATUS_PARSE -> AuthFailureReason.MALFORMED_RESPONSE
    status == ApiError.STATUS_NETWORK -> AuthFailureReason.CONNECT_FAILED
    status == 401 && stage == AuthStage.LOGIN -> AuthFailureReason.INVALID_CREDENTIALS
    status == 401 -> AuthFailureReason.SESSION_EXPIRED
    status == 403 && code == "csrf" -> AuthFailureReason.CSRF_MISSING
    (status == 400 || status == 422) && stage == AuthStage.MFA_VERIFY -> AuthFailureReason.MFA_REJECTED
    status in 500..599 -> AuthFailureReason.SERVER_5XX
    else -> AuthFailureReason.UNKNOWN
}
