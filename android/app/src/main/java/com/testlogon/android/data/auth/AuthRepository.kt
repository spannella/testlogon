package com.testlogon.android.data.auth

import com.testlogon.android.core.data.cache.UserScopedCacheCleaner
import com.testlogon.android.core.data.delegates.DelegationStateStore
import com.testlogon.android.core.data.telemetry.AuthEvent
import com.testlogon.android.core.data.telemetry.AuthOutcome
import com.testlogon.android.core.data.telemetry.AuthTelemetry
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.delegates.DelegateRoutingStore
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

/**
 * AND-109 — seam invoked at the FRONT of logout, while the session cookies + CSRF header are still
 * live, so the push deregister call (`POST /ui/push/revoke`) is authenticated. Implementations must
 * be best-effort and self-bounded: logout MUST NOT be blocked or failed by a deregister failure
 * (FR-5). The real impl (PushLogoutHandlerImpl) revokes server-side with a short timeout, enqueues a
 * retry worker on failure, and clears local push state. Defaulted to a no-op so direct-construction
 * AuthRepository tests are unaffected.
 */
fun interface PushLogoutHandler {
    suspend fun onLogout()

    companion object {
        val NOOP = PushLogoutHandler {}
    }
}

/**
 * Seam invoked on every auth-state boundary (fresh login / logout) to drop any in-memory identity
 * cache keyed to the PRIOR session — notably the cached `GET /ui/me.is_admin` signal. Without this,
 * an in-session account switch keeps serving the previous user's admin flag, so a freshly signed-in
 * moderator cannot see the Admin/Moderation hub until a full process restart. Defaulted to a no-op so
 * direct-construction AuthRepository tests are unaffected; Hilt binds it to [CurrentUserRepository].
 */
fun interface IdentityCacheInvalidator {
    fun invalidate()

    companion object {
        val NOOP = IdentityCacheInvalidator {}
    }
}

@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authStateStore: AuthStateStore,
    private val cookieCleaner: SessionCookieCleaner,
    private val errorParser: ApiErrorParser,
    private val authAreaCache: AuthAreaCache,
    // AND-052: defaulted to no-op so direct-construction tests are unaffected; Hilt injects real.
    private val telemetry: AuthTelemetry = com.testlogon.android.core.data.telemetry.NoopAuthTelemetry,
    // AND-109: defaulted to no-op so direct-construction tests are unaffected; Hilt injects real.
    private val pushLogoutHandler: PushLogoutHandler = PushLogoutHandler.NOOP,
    // AND-118: per-user Room cache purge on logout; defaulted no-op so direct-construction tests
    // are unaffected. Hilt injects the real CacheManager-backed cleaner.
    private val cacheCleaner: UserScopedCacheCleaner = UserScopedCacheCleaner.NOOP,
    // AND-359 (FR-7): clear the manage-as-creator selection on auth reset / logout so it never leaks
    // across sessions. Defaulted to a fresh in-memory store so direct-construction tests are unaffected;
    // Hilt injects the process-global singleton.
    private val delegationStateStore: DelegationStateStore = DelegationStateStore(),
    // AND-359 (FR-7) hardening: also clear the NETWORK-layer delegate routing so account B never POSTs
    // to /messaging/delegate/{A_creator}/... The DelegationContextProvider bridges this asynchronously
    // off DelegationStateStore only while it is alive; clearing it here directly closes the leak on
    // logout / session-expiry / account-switch. Defaulted for direct-construction tests; Hilt injects
    // the process-global singleton.
    private val delegateRoutingStore: DelegateRoutingStore = DelegateRoutingStore(),
    // More-hub discoverability: drop the cached /ui/me admin signal on login/logout so an in-session
    // account switch re-resolves the role. Defaulted no-op for direct-construction tests; Hilt binds real.
    private val identityCacheInvalidator: IdentityCacheInvalidator = IdentityCacheInvalidator.NOOP,
) : AuthRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val _cachedUser = MutableStateFlow<User?>(null)
    override val cachedUser: StateFlow<User?> = _cachedUser.asStateFlow()

    override suspend fun login(username: String, password: String): ApiResult<LoginOutcome> {
        // Account-switch boundary: a fresh credential entry may be a DIFFERENT user. Drop any stale
        // manage-as-creator delegate context NOW so the new session never routes sends to the previous
        // creator delegate endpoints (login-of-a-different-user leak).
        resetDelegateContext()
        // Drop the prior session's cached /ui/me (incl. is_admin) so the new user's role re-resolves.
        identityCacheInvalidator.invalidate()
        return apiCall {
            api.sessionStart(
                SessionStartReq(challengeContext = mapOf("username" to username, "password" to password)),
            )
        }.flatMapSuspend { resp -> resp.toLoginOutcome() }
    }

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
            authAreaCache.putMe(r.data) // AND-045 last-known-good /ui/me
            authStateStore.setAuthenticated(r.data.userSub)
            r
        }
        is ApiResult.Failure -> {
            // A definitive 401 (post-refresh) is the canonical "not logged in" signal.
            if (r.error.status == 401) {
                _cachedUser.value = null
                authStateStore.clear(com.testlogon.android.core.model.LogoutReason.SESSION_EXPIRED)
                resetDelegateContext() // AND-359 FR-7: drop manage-as selection + routing on auth reset.
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
        // AND-109: deregister this device for push BEFORE the session is torn down, so the revoke
        // call (POST /ui/push/revoke) is still authenticated (cookies + CSRF). Best-effort and
        // self-bounded — never blocks or fails logout (FR-5).
        runCatching { pushLogoutHandler.onLogout() }
        // (a) best-effort server invalidation
        runCatching { api.sessionLogout() }
        // (b-c) guaranteed local teardown regardless of (a)
        cookieCleaner.clear()
        authStateStore.clear()
        resetDelegateContext() // AND-359 FR-7: drop manage-as selection + routing on logout.
        authAreaCache.clear() // AND-045 per-identity cache cleared on logout
        // AND-118: wipe all user-scoped Room cache rows so account B never sees account A's content.
        // Best-effort and self-bounded — never blocks or fails logout.
        runCatching { cacheCleaner.clearAllUserScopedCache() }
        // Drop the cached /ui/me admin signal so a later sign-in never inherits this session's role.
        identityCacheInvalidator.invalidate()
        _cachedUser.value = null
        telemetry.log(AuthEvent.LogoutResult(outcome = AuthOutcome.SUCCESS))
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
            is ApiResult.Failure -> {
                telemetry.log(
                    AuthEvent.FinalizeResult(
                        outcome = AuthOutcome.FAILURE,
                        reason = fin.toAuthReason(com.testlogon.android.core.data.telemetry.AuthStage.FINALIZE),
                    ),
                )
                fin
            }
            is ApiResult.NetworkError -> {
                telemetry.log(
                    AuthEvent.FinalizeResult(
                        outcome = AuthOutcome.FAILURE,
                        reason = fin.toAuthReason(com.testlogon.android.core.data.telemetry.AuthStage.FINALIZE),
                    ),
                )
                fin
            }
            is ApiResult.Success -> {
                val resp = fin.data
                if (resp.status == "ok" && !resp.sessionId.isNullOrBlank()) {
                    telemetry.log(AuthEvent.FinalizeResult(outcome = AuthOutcome.SUCCESS))
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

    /**
     * Clears the manage-as-creator delegate context in BOTH the source-of-truth [DelegationStateStore]
     * and the network-layer [DelegateRoutingStore], so no subsequent request is re-targeted onto a stale
     * creator delegate route. Synchronous + direct (does not rely on the async DelegationContextProvider
     * bridge, which is only alive after a delegate feature has been opened). Called on logout,
     * session-expiry (definitive 401), and each fresh login (account switch).
     */
    private fun resetDelegateContext() {
        delegationStateStore.clear()
        delegateRoutingStore.activeCreatorId = null
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
