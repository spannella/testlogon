package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiResult
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
 * Self-service registration repository (AND-053..056).
 *
 * Wraps the `ui/register/` (start, confirm, resend, check) endpoints of [AuthApi], folding transport/HTTP failures into [ApiResult]
 * (via [ApiErrorParser]) exactly like [AuthRepository]. On the auto-login branches (a response that
 * carries a `session_id`) it delegates to [AuthRepository.getMe] so the durable [AuthStateStore] is
 * written and the nav gate swaps to the authenticated graph — registration never writes auth state
 * directly. No Retrofit/OkHttp types leak through this interface.
 */
interface RegisterRepository {

    /** `POST /ui/register/start`; branches into [RegisterStartOutcome] (AND-053). */
    suspend fun registerStart(req: RegisterStartReq): ApiResult<RegisterStartOutcome>

    /** `POST /ui/register/confirm`; on `session_id` performs getMe + MFA handoff (AND-054/056). */
    suspend fun confirm(req: RegisterConfirmReq): ApiResult<RegisterConfirmOutcome>

    /** `POST /ui/register/resend`; re-issues the verification code (AND-054). */
    suspend fun resend(req: RegisterResendReq): ApiResult<RegisterResendResp>

    /**
     * `POST /ui/register/check`; advisory email-availability (AND-055). Success → true when the
     * email is free (available), false when taken. Failures stay as [ApiResult.Failure]/[NetworkError]
     * for the caller to collapse into an advisory `Error`.
     */
    suspend fun checkEmail(email: String): ApiResult<Boolean>
}

@Singleton
class RegisterRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authRepository: AuthRepository,
    private val errorParser: ApiErrorParser,
) : RegisterRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun registerStart(req: RegisterStartReq): ApiResult<RegisterStartOutcome> =
        when (val r = apiCall { api.registerStart(req) }) {
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
            is ApiResult.Success -> r.data.toStartOutcome(req.email)
        }

    private suspend fun RegisterStartResp.toStartOutcome(email: String): ApiResult<RegisterStartOutcome> =
        when {
            verificationRequired -> ApiResult.Success(
                RegisterStartOutcome.VerificationRequired(
                    email = email,
                    deliveryMedium = deliveryMedium,
                    deliveryDestination = deliveryDestination,
                ),
            )
            !sessionId.isNullOrBlank() -> when (val me = authRepository.getMe()) {
                is ApiResult.Success -> ApiResult.Success(RegisterStartOutcome.Authenticated(me.data))
                is ApiResult.Failure -> me
                is ApiResult.NetworkError -> me
            }
            else -> ApiResult.Success(RegisterStartOutcome.VerifiedSignIn)
        }

    override suspend fun confirm(req: RegisterConfirmReq): ApiResult<RegisterConfirmOutcome> =
        when (val r = apiCall { api.registerConfirm(req) }) {
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
            is ApiResult.Success -> r.data.toConfirmOutcome(req.email)
        }

    private suspend fun RegisterConfirmResp.toConfirmOutcome(
        email: String,
    ): ApiResult<RegisterConfirmOutcome> = when {
        sessionId.isNullOrBlank() -> ApiResult.Success(RegisterConfirmOutcome.VerifiedSignIn(email))
        else -> when (val me = authRepository.getMe()) {
            is ApiResult.Success -> ApiResult.Success(
                RegisterConfirmOutcome.Authenticated(me.data, toMfaSetupHandoff(email)),
            )
            is ApiResult.Failure -> me
            is ApiResult.NetworkError -> me
        }
    }

    override suspend fun resend(req: RegisterResendReq): ApiResult<RegisterResendResp> =
        apiCall { api.registerResend(req) }

    override suspend fun checkEmail(email: String): ApiResult<Boolean> =
        when (val r = apiCall { api.registerCheck(RegisterEmailCheckReq(email)) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.available)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }

    /**
     * Folds [block] into an [ApiResult] on [io]: IO failures → [ApiResult.NetworkError],
     * [HttpException] → [ApiResult.Failure]; [CancellationException] re-thrown. Mirrors
     * [AuthRepositoryImpl.apiCall].
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
