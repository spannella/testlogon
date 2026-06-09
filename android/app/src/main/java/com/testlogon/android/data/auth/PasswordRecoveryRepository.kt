package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Unauthenticated password-recovery repository (AND-057/058/059).
 *
 * Wraps the `ui/password-recovery/` endpoints of [AuthApi], folding transport/HTTP failures into
 * [ApiResult] (via [ApiErrorParser]) exactly like [AuthRepository]/[RegisterRepository]. No Retrofit/
 * OkHttp types leak through this interface.
 *
 * SECURITY / CONTRACT NOTES:
 *  - These are non-idempotent POSTs that mutate challenge state (send a code, burn an attempt). They
 *    are NEVER auto-retried; retry is user-driven only.
 *  - The flow does NOT auto-login. On a successful confirm the caller routes back to Login — recovery
 *    never writes [AuthStateStore].
 *  - `username` is required on every challenge/confirm body and is carried from the start step.
 */
interface PasswordRecoveryRepository {

    /** `POST /ui/password-recovery/start` — issue/refresh a recovery challenge (AND-057). */
    suspend fun start(username: String): ApiResult<RecoveryStartOutcome>

    /**
     * `POST /ui/password-recovery/challenge/{email,sms}/begin` — deliver a code (AND-058).
     * No-ops with an empty outcome for factors that do not require a begin (totp/recovery).
     */
    suspend fun beginChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
    ): ApiResult<RecoveryBeginOutcome>

    /**
     * Verify the active factor (AND-058). Dispatches to the per-factor endpoint/body. A blank code is
     * short-circuited to a typed `invalid_code` [ApiResult.Failure] without a network call.
     */
    suspend fun verifyChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
        code: String,
    ): ApiResult<RecoveryVerifyOutcome>

    /**
     * `POST /ui/password-recovery/confirm` — set the new password (AND-059). Returns [Unit] on a 200;
     * does NOT establish a session. `challengeId` is optional per the schema.
     */
    suspend fun confirmNewPassword(
        username: String,
        confirmationCode: String,
        newPassword: String,
        challengeId: String? = null,
    ): ApiResult<Unit>
}

@Singleton
class PasswordRecoveryRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val errorParser: ApiErrorParser,
) : PasswordRecoveryRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun start(username: String): ApiResult<RecoveryStartOutcome> =
        when (val r = apiCall { api.passwordRecoveryStart(PasswordRecoveryStartReq(username.trim())) }) {
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
            is ApiResult.Success -> ApiResult.Success(r.data.toStartOutcome())
        }

    private fun PasswordRecoveryStartResp.toStartOutcome(): RecoveryStartOutcome =
        if (!challengeId.isNullOrBlank() && requiredFactors.isNotEmpty()) {
            RecoveryStartOutcome.Challenge(
                challengeId = challengeId,
                requiredFactors = requiredFactors.map(RecoveryFactor::fromWire),
                deliveryMedium = deliveryMedium,
                deliveryDestination = deliveryDestination,
            )
        } else {
            RecoveryStartOutcome.Sent(
                deliveryMedium = deliveryMedium,
                deliveryDestination = deliveryDestination,
            )
        }

    override suspend fun beginChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
    ): ApiResult<RecoveryBeginOutcome> {
        if (!factor.requiresBegin) return ApiResult.Success(RecoveryBeginOutcome())
        return apiCall {
            api.passwordRecoveryBegin(
                factor.wire,
                RecoveryChallengeBeginReq(username = username, challengeId = challengeId),
            )
        }.map { RecoveryBeginOutcome(maskedDestinations = it.sentTo.orEmpty()) }
    }

    override suspend fun verifyChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
        code: String,
    ): ApiResult<RecoveryVerifyOutcome> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) return invalidCode()
        return apiCall {
            when (factor) {
                RecoveryFactor.Email, RecoveryFactor.Sms ->
                    api.passwordRecoveryVerifyEmailOrSms(
                        factor.wire,
                        RecoveryEmailSmsVerifyReq(username, challengeId, trimmed),
                    )
                RecoveryFactor.Totp ->
                    api.passwordRecoveryVerifyTotp(RecoveryTotpVerifyReq(username, challengeId, trimmed))
                RecoveryFactor.Recovery ->
                    api.passwordRecoveryVerifyRecovery(
                        RecoveryCodeVerifyReq(username, challengeId, factor = "recovery", recoveryCode = trimmed),
                    )
                is RecoveryFactor.Unknown ->
                    // Forward-compat: try the email/sms verify shape; the server rejects if wrong.
                    api.passwordRecoveryVerifyEmailOrSms(
                        factor.wire,
                        RecoveryEmailSmsVerifyReq(username, challengeId, trimmed),
                    )
            }
        }.map {
            // MfaVerifyResp is reused; it carries no recovery_token field, so forward null. The
            // challenge_id stays the carried token across to AND-059.
            RecoveryVerifyOutcome(challengeId = challengeId, recoveryToken = null)
        }
    }

    override suspend fun confirmNewPassword(
        username: String,
        confirmationCode: String,
        newPassword: String,
        challengeId: String?,
    ): ApiResult<Unit> = apiCall {
        api.passwordRecoveryConfirm(
            PasswordRecoveryConfirmReq(
                username = username,
                confirmationCode = confirmationCode.trim(),
                newPassword = newPassword,
                challengeId = challengeId,
            ),
        )
    }.map { }

    private fun invalidCode(): ApiResult<RecoveryVerifyOutcome> =
        ApiResult.Failure(ApiError(status = ApiError.STATUS_NETWORK, message = "Enter your code", code = "invalid_code"))

    /**
     * Folds [block] into an [ApiResult] on [io]: IO failures → [ApiResult.NetworkError],
     * [HttpException] → [ApiResult.Failure] (via [ApiErrorParser]); [CancellationException] re-thrown.
     * Mirrors [AuthRepositoryImpl.apiCall]. Note: no retry — these POSTs mutate challenge state.
     */
    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is java.net.SocketTimeoutException)
        }
    }
}
