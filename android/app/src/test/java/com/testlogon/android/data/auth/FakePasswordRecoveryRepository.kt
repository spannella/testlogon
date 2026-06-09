package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** Scriptable [PasswordRecoveryRepository] for recovery ViewModel tests (AND-057/058/059). */
class FakePasswordRecoveryRepository : PasswordRecoveryRepository {

    var startResult: ApiResult<RecoveryStartOutcome> = ApiResult.Failure(ApiError(0, "unset"))
    var beginResult: ApiResult<RecoveryBeginOutcome> = ApiResult.Success(RecoveryBeginOutcome())
    var verifyResult: ApiResult<RecoveryVerifyOutcome> = ApiResult.Failure(ApiError(0, "unset"))
    var confirmResult: ApiResult<Unit> = ApiResult.Failure(ApiError(0, "unset"))

    var startCalls = 0
    var beginCalls = 0
    var verifyCalls = 0
    var confirmCalls = 0

    var lastStartUsername: String? = null
    val beginFactors = mutableListOf<RecoveryFactor>()
    var lastVerifyFactor: RecoveryFactor? = null
    var lastVerifyUsername: String? = null
    var lastVerifyChallengeId: String? = null
    var lastVerifyCode: String? = null
    var lastConfirmUsername: String? = null
    var lastConfirmCode: String? = null
    var lastConfirmNewPassword: String? = null
    var lastConfirmChallengeId: String? = null

    override suspend fun start(username: String): ApiResult<RecoveryStartOutcome> {
        startCalls++
        lastStartUsername = username
        return startResult
    }

    override suspend fun beginChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
    ): ApiResult<RecoveryBeginOutcome> {
        beginCalls++
        beginFactors += factor
        return beginResult
    }

    override suspend fun verifyChallenge(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
        code: String,
    ): ApiResult<RecoveryVerifyOutcome> {
        verifyCalls++
        lastVerifyFactor = factor
        lastVerifyUsername = username
        lastVerifyChallengeId = challengeId
        lastVerifyCode = code
        return verifyResult
    }

    override suspend fun confirmNewPassword(
        username: String,
        confirmationCode: String,
        newPassword: String,
        challengeId: String?,
    ): ApiResult<Unit> {
        confirmCalls++
        lastConfirmUsername = username
        lastConfirmCode = confirmationCode
        lastConfirmNewPassword = newPassword
        lastConfirmChallengeId = challengeId
        return confirmResult
    }
}
