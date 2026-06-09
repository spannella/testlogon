package com.testlogon.android.data.auth

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
 * Unauthenticated passwordless / magic-link repository (AND-060/061).
 *
 * Wraps the `ui/passwordless/` endpoints of [AuthApi], folding transport/HTTP failures into
 * [ApiResult] (via [ApiErrorParser]) exactly like [AuthRepository]/[PasswordRecoveryRepository]. No
 * Retrofit/OkHttp types leak through this interface.
 *
 * SECURITY / CONTRACT NOTES:
 *  - Both endpoints are non-idempotent POSTs (start dispatches an email, verify burns a one-time
 *    token). They are NEVER auto-retried; retry is user-driven only.
 *  - On a full-session [PasswordlessVerified.Authenticated] outcome the repository finalizes auth by
 *    calling `GET /ui/me` through [AuthRepository], which populates the durable [AuthStateStore] so the
 *    nav gate swaps to the authenticated graph. The session itself rides the shared cookie jar.
 *  - The token / username are never logged (request DTOs redact them in toString).
 */
interface PasswordlessRepository {

    /** `POST /ui/passwordless/start` — request a magic-link email (AND-060). */
    suspend fun start(identifier: String): ApiResult<PasswordlessStarted>

    /**
     * `POST /ui/passwordless/verify` — exchange a one-time link [token] for a session or an MFA
     * challenge (AND-061). A blank token is short-circuited to a typed failure without a network call.
     * On the full-session branch this additionally calls `getMe` to set the authenticated state.
     */
    suspend fun verify(token: String): ApiResult<PasswordlessVerified>
}

@Singleton
class PasswordlessRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authRepository: AuthRepository,
    private val errorParser: ApiErrorParser,
) : PasswordlessRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun start(identifier: String): ApiResult<PasswordlessStarted> =
        apiCall {
            api.passwordlessStart(PasswordlessStartReq(username = identifier.trim()))
        }.map { it.toDomain() }

    private fun PasswordlessStartResp.toDomain() =
        PasswordlessStarted(status = status, sentTo = sentTo.orEmpty())

    override suspend fun verify(token: String): ApiResult<PasswordlessVerified> {
        val trimmed = token.trim()
        if (trimmed.isEmpty()) return invalidToken()
        return when (val r = apiCall { api.passwordlessVerify(PasswordlessVerifyReq(trimmed)) }) {
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
            is ApiResult.Success -> r.data.toVerified()
        }
    }

    /**
     * Branches the verify response exactly like the web client (src/pages/MagicLinkVerify.tsx):
     *  - `status == "ok"` AND `session_id` present → full session → confirm via getMe → Authenticated.
     *  - `auth_required` AND `challenge_id` present → MfaRequired (hand off to the MFA flow).
     *  - otherwise → Invalid (treated by the UI as an expired/invalid link).
     */
    private suspend fun PasswordlessVerifyResp.toVerified(): ApiResult<PasswordlessVerified> = when {
        status == "ok" && !sessionId.isNullOrBlank() ->
            // The verify response already authenticated the cookie jar; getMe populates the durable
            // auth state so the nav gate swaps graphs. Surface getMe transport/HTTP failures as-is.
            when (val me = authRepository.getMe()) {
                is ApiResult.Success -> ApiResult.Success(PasswordlessVerified.Authenticated)
                is ApiResult.Failure -> me
                is ApiResult.NetworkError -> me
            }
        authRequired && !challengeId.isNullOrBlank() ->
            ApiResult.Success(
                PasswordlessVerified.MfaRequired(
                    challengeId = challengeId,
                    requiredFactors = requiredFactors,
                ),
            )
        else -> ApiResult.Success(PasswordlessVerified.Invalid)
    }

    private fun invalidToken(): ApiResult<PasswordlessVerified> =
        ApiResult.Failure(
            com.testlogon.android.core.model.ApiError(
                status = com.testlogon.android.core.model.ApiError.STATUS_NETWORK,
                message = "This sign-in link is invalid.",
                code = "missing_token",
            ),
        )

    /**
     * Folds [block] into an [ApiResult] on [io]: IO failures → [ApiResult.NetworkError],
     * [HttpException] → [ApiResult.Failure] (via [ApiErrorParser]); [CancellationException] re-thrown.
     * Mirrors [AuthRepositoryImpl.apiCall]. No retry — these POSTs mutate server state.
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
