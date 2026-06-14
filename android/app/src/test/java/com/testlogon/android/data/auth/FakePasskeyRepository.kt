package com.testlogon.android.data.auth

import android.content.Context
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** Scriptable [PasskeyRepository] for ViewModel tests. */
class FakePasskeyRepository : PasskeyRepository {

    var supported = true
    var registerResult: ApiResult<RegisteredPasskey> = ApiResult.Failure(ApiError(0, "unset"))
    var authResult: ApiResult<PasskeyAuthResult> = ApiResult.Failure(ApiError(0, "unset"))

    var registerCalls = 0
    var authCalls = 0
    var lastAuthUsername: String? = null

    override suspend fun isSupported(): Boolean = supported

    override suspend fun registerPasskey(activity: Context, label: String?): ApiResult<RegisteredPasskey> {
        registerCalls++
        return registerResult
    }

    override suspend fun authenticateWithPasskey(activity: Context, username: String): ApiResult<PasskeyAuthResult> {
        authCalls++
        lastAuthUsername = username
        return authResult
    }
}
