package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Cookie-based authentication repository (AND-028/029/032/034-038).
 *
 * Drives the full login + MFA + session-bootstrap flow on top of [AuthApi], folding transport/HTTP
 * failures into [ApiResult] (via [ApiErrorParser]) and writing the durable [AuthStateStore] on the
 * authenticated/logged-out transitions. No Retrofit/OkHttp types leak through this interface.
 *
 * Session identity rides entirely on the persistent cookie jar (core-network); this class never
 * reads or writes cookies directly.
 */
interface AuthRepository {

    /** In-memory principal for the current process; null until a successful getMe / login. */
    val cachedUser: StateFlow<User?>

    /** Step 1 of login: `POST /ui/session/start`, branched into [LoginOutcome]. */
    suspend fun login(username: String, password: String): ApiResult<LoginOutcome>

    /** `GET /ui/me`; populates [cachedUser] + auth state on 200, clears them on a definitive 401. */
    suspend fun getMe(): ApiResult<User>

    /** TOTP verify (no begin step). */
    suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyOutcome>

    /** SMS code delivery; returns masked destinations from `sent_to`. */
    suspend fun beginSms(challengeId: String): ApiResult<List<String>>
    suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyOutcome>

    /** Email code delivery; returns masked destinations from `sent_to`. */
    suspend fun beginEmail(challengeId: String): ApiResult<List<String>>
    suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyOutcome>

    /** Recovery-code redemption against `POST /ui/mfa/recovery/{factor}`. */
    suspend fun useRecovery(
        challengeId: String,
        recoveryCode: String,
        factor: MfaFactor = MfaFactor.Recovery,
    ): ApiResult<MfaVerifyOutcome>

    /** Best-effort `POST /ui/session/logout` + guaranteed local teardown (cookies + auth state). */
    suspend fun logout(): ApiResult<Unit>
}

/** Seam for wiping local session cookies on logout; satisfied by the persistent cookie jar. */
fun interface SessionCookieCleaner {
    fun clear()
}

@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authStateStore: AuthStateStore,
    private val cookieCleaner: SessionCookieCleaner,
    private val errorParser: ApiErrorParser,
) : AuthRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val _cachedUser = MutableStateFlow<User?>(null)
    override val cachedUser: StateFlow<User?> = _cachedUser.asStateFlow()

    override suspend fun login(username: String, password: String): ApiResult<LoginOutcome> =
        apiCall {
            api.sessionStart(
                SessionStartReq(challengeContext = mapOf("username" to username, "password" to password)),
            )
        }.flatMapSuspend { resp -> resp.toLoginOutcome() }

    private suspend fun SessionStartResp.toLoginOutcome(): ApiResult<LoginOutcome> {
        val authenticated = !authRequired && !sessionId.isNullOrBlank()
        return when {
            authenticated -> when (val me = getMe()) {
                is ApiResult.Success -> ApiResult.Success(LoginOutcome.Authenticated(me.data))
                is ApiResult.Failure -> me
                is ApiResult.NetworkError -> me
            }
            !challengeId.isNullOrBlank() ->
                ApiResult.Success(
                    LoginOutcome.MfaRequired(
                        challengeId = challengeId,
                        factors = requiredFactors.map(MfaFactor::fromWire),
                    ),
                )
            else -> ApiResult.Failure(
                ApiError(
                    status = 200,
                    message = "MFA required but no challenge_id returned",
                    code = "malformed_mfa",
                ),
            )
        }
    }

    override suspend fun getMe(): ApiResult<User> = when (val r = apiCall { api.me().toDomain() }) {
        is ApiResult.Success -> {
            _cachedUser.value = r.data
            authStateStore.setAuthenticated(r.data.userSub)
            r
        }
        is ApiResult.Failure -> {
            // A definitive 401 (post-refresh) is the canonical "not logged in" signal.
            if (r.error.status == 401) {
                _cachedUser.value = null
                authStateStore.clear()
            }
            r // network / 5xx: persisted auth flag untouched (flaky host must not log out).
        }
        is ApiResult.NetworkError -> r
    }

    override suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) return invalidCode()
        return apiCall { api.verifyTotp(TotpVerifyReq(challengeId, trimmed)) }
            .toMfaOutcome(challengeId)
    }

    override suspend fun beginSms(challengeId: String): ApiResult<List<String>> =
        apiCall { api.beginSms(SmsBeginReq(challengeId)).sentTo.orEmpty() }

    override suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) return invalidCode()
        return apiCall { api.verifySms(SmsVerifyReq(challengeId, trimmed)) }
            .toMfaOutcome(challengeId)
    }

    override suspend fun beginEmail(challengeId: String): ApiResult<List<String>> =
        apiCall { api.beginEmail(EmailBeginReq(challengeId)).sentTo.orEmpty() }

    override suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) return invalidCode()
        return apiCall { api.verifyEmail(EmailVerifyReq(challengeId, trimmed)) }
            .toMfaOutcome(challengeId)
    }

    override suspend fun useRecovery(
        challengeId: String,
        recoveryCode: String,
        factor: MfaFactor,
    ): ApiResult<MfaVerifyOutcome> {
        val trimmed = recoveryCode.trim()
        if (trimmed.isEmpty()) return invalidCode()
        return apiCall {
            api.useRecovery(factor.wire, RecoveryReq(challengeId = challengeId, recoveryCode = trimmed))
        }.toMfaOutcome(challengeId)
    }

    override suspend fun logout(): ApiResult<Unit> = withContext(io) {
        // (a) best-effort server invalidation
        runCatching { api.sessionLogout() }
        // (b-c) guaranteed local teardown regardless of (a)
        cookieCleaner.clear()
        authStateStore.clear()
        _cachedUser.value = null
        ApiResult.Success(Unit)
    }

    /**
     * Maps a verify/recovery response into [MfaVerifyOutcome]. When no factors remain, finalizes the
     * session (`session/finalize`) and confirms it via `getMe()` to reach [Authenticated].
     */
    private suspend fun ApiResult<MfaVerifyResp>.toMfaOutcome(
        challengeId: String,
    ): ApiResult<MfaVerifyOutcome> = when (this) {
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
        is ApiResult.Success -> {
            if (data.remainingFactors.isEmpty()) {
                finalizeAndLoadMe(challengeId)
            } else {
                ApiResult.Success(
                    MfaVerifyOutcome.FactorsRemaining(data.remainingFactors.map(MfaFactor::fromWire)),
                )
            }
        }
    }

    private suspend fun finalizeAndLoadMe(challengeId: String): ApiResult<MfaVerifyOutcome> =
        when (val fin = apiCall { api.sessionFinalize(SessionFinalizeReq(challengeId)) }) {
            is ApiResult.Failure -> fin
            is ApiResult.NetworkError -> fin
            is ApiResult.Success -> {
                val resp = fin.data
                if (resp.status == "ok" && !resp.sessionId.isNullOrBlank()) {
                    when (val me = getMe()) {
                        is ApiResult.Success -> ApiResult.Success(MfaVerifyOutcome.Authenticated(me.data))
                        is ApiResult.Failure -> me
                        is ApiResult.NetworkError -> me
                    }
                } else {
                    // finalize reported "pending": resync remaining factors instead of failing hard.
                    ApiResult.Success(
                        MfaVerifyOutcome.FactorsRemaining(resp.requiredFactors.map(MfaFactor::fromWire)),
                    )
                }
            }
        }

    private fun invalidCode(): ApiResult<MfaVerifyOutcome> =
        ApiResult.Failure(ApiError(status = 0, message = "Enter your code", code = "invalid_code"))

    /**
     * Folds [block] into an [ApiResult] on [io]: IO failures → [ApiResult.NetworkError],
     * [HttpException] → [ApiResult.Failure] (via [ApiErrorParser]); [CancellationException] re-thrown.
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

    private suspend fun <T, R> ApiResult<T>.flatMapSuspend(
        transform: suspend (T) -> ApiResult<R>,
    ): ApiResult<R> = when (this) {
        is ApiResult.Success -> transform(data)
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
    }

    private fun MeResp.toDomain() = User(userSub = userSub, sessionId = sessionId, ip = ip)
}
