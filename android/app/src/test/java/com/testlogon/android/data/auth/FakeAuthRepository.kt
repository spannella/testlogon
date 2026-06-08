package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Scriptable [AuthRepository] for ViewModel tests. */
class FakeAuthRepository : AuthRepository {

    var loginResult: ApiResult<LoginOutcome> = ApiResult.Failure(
        com.testlogon.android.core.model.ApiError(0, "unset"),
    )
    var verifyResult: ApiResult<MfaVerifyOutcome> = ApiResult.Failure(
        com.testlogon.android.core.model.ApiError(0, "unset"),
    )
    var beginResult: ApiResult<List<String>> = ApiResult.Success(emptyList())

    var loginCalls = 0
    var verifyTotpCalls = 0
    var verifySmsCalls = 0
    var beginSmsCalls = 0
    var logoutCalls = 0
    var lastUsername: String? = null

    override val cachedUser: StateFlow<User?> = MutableStateFlow(null)

    override suspend fun login(username: String, password: String): ApiResult<LoginOutcome> {
        loginCalls++
        lastUsername = username
        return loginResult
    }

    override suspend fun getMe(): ApiResult<User> =
        ApiResult.Success(User("usr_1", "sess_1", "1.2.3.4"))

    override suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> {
        verifyTotpCalls++
        return verifyResult
    }

    override suspend fun beginSms(challengeId: String): ApiResult<List<String>> {
        beginSmsCalls++
        return beginResult
    }

    override suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> {
        verifySmsCalls++
        return verifyResult
    }

    override suspend fun beginEmail(challengeId: String): ApiResult<List<String>> = beginResult

    override suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyOutcome> =
        verifyResult

    override suspend fun useRecovery(
        challengeId: String,
        recoveryCode: String,
        factor: MfaFactor,
    ): ApiResult<MfaVerifyOutcome> = verifyResult

    override suspend fun logout(): ApiResult<Unit> {
        logoutCalls++
        return ApiResult.Success(Unit)
    }
}
