package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** Scriptable [PasswordlessRepository] for passwordless ViewModel tests (AND-060/061). */
class FakePasswordlessRepository : PasswordlessRepository {

    var startResult: ApiResult<PasswordlessStarted> = ApiResult.Failure(ApiError(0, "unset"))
    var verifyResult: ApiResult<PasswordlessVerified> = ApiResult.Failure(ApiError(0, "unset"))

    var startCalls = 0
    var verifyCalls = 0
    var lastStartIdentifier: String? = null
    var lastVerifyToken: String? = null

    override suspend fun start(identifier: String): ApiResult<PasswordlessStarted> {
        startCalls++
        lastStartIdentifier = identifier
        return startResult
    }

    override suspend fun verify(token: String): ApiResult<PasswordlessVerified> {
        verifyCalls++
        lastVerifyToken = token
        return verifyResult
    }
}
