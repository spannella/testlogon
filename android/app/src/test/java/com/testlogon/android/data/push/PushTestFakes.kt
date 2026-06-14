package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.push.PushTokenProvider

/** AND-110 — in-memory [PushRegistrationStore] for JVM tests (no DataStore I/O). */
class FakePushRegistrationStore : PushRegistrationStore {
    var tuple: RegisteredTuple? = null
    var deviceId: String? = null
    var pending: String? = null
    var clearCalls = 0

    override suspend fun lastRegistered(): RegisteredTuple? = tuple
    override suspend fun setLastRegistered(tuple: RegisteredTuple) {
        this.tuple = tuple
    }

    override suspend fun deviceId(): String? = deviceId
    override suspend fun setDeviceId(deviceId: String?) {
        this.deviceId = deviceId
    }

    override suspend fun pendingToken(): String? = pending
    override suspend fun cachePendingToken(token: String?) {
        pending = token
    }

    override suspend fun clear() {
        clearCalls++
        tuple = null
        deviceId = null
        pending = null
    }
}

/** AND-110 — fake [PushTokenProvider] returning a fixed token (or a failure) — no live Firebase. */
class FakePushTokenProvider(
    private val result: ApiResult<String> = ApiResult.Success("fcm-token-from-firebase"),
) : PushTokenProvider {
    override suspend fun currentToken(): ApiResult<String> = result

    companion object {
        fun failing(): FakePushTokenProvider =
            FakePushTokenProvider(ApiResult.Failure(ApiError(ApiError.STATUS_NETWORK, "no token")))
    }
}

/** AND-110 — records scheduler calls. */
class FakePushWorkScheduler : PushWorkScheduler {
    var registerCalls = 0
    var deregisterCalls = 0
    override fun enqueueRegister() {
        registerCalls++
    }

    override fun enqueueDeregister() {
        deregisterCalls++
    }
}
