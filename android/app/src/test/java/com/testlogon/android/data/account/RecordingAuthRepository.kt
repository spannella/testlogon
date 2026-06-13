package com.testlogon.android.data.account

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthRepository
import com.testlogon.android.data.auth.LoginOutcome
import com.testlogon.android.data.auth.MfaFactor
import com.testlogon.android.data.auth.MfaVerifyOutcome
import com.testlogon.android.data.auth.User
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * AND-387 - a recording [AuthRepository] for the lifecycle contract test. Only [logout] (the AND-032
 * teardown seam) and [getMe] (the reactivate refresh) are exercised by the repository under test; the
 * remaining auth methods are stubbed with inert defaults. Counters record invocations BEFORE returning.
 */
class RecordingAuthRepository : AuthRepository {

    var logoutCalls = 0
    var getMeCalls = 0

    override val cachedUser: StateFlow<User?> = MutableStateFlow(null)

    override suspend fun logout(): ApiResult<Unit> {
        logoutCalls++
        return ApiResult.Success(Unit)
    }

    override suspend fun getMe(): ApiResult<User> {
        getMeCalls++
        return ApiResult.Success(User("usr_1", "sess_1", "1.2.3.4"))
    }

    override suspend fun login(username: String, password: String): ApiResult<LoginOutcome> =
        ApiResult.Failure(ApiError(0, "unused"))

    override suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> =
        ApiResult.Failure(ApiError(0, "unused"))

    override suspend fun beginSms(challengeId: String): ApiResult<List<String>> =
        ApiResult.Success(emptyList())

    override suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> =
        ApiResult.Failure(ApiError(0, "unused"))

    override suspend fun beginEmail(challengeId: String): ApiResult<List<String>> =
        ApiResult.Success(emptyList())

    override suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> =
        ApiResult.Failure(ApiError(0, "unused"))

    override suspend fun useRecovery(
        challengeId: String,
        recoveryCode: String,
        factor: MfaFactor,
    ): ApiResult<MfaVerifyOutcome> = ApiResult.Failure(ApiError(0, "unused"))
}
