package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** Scriptable [MfaDeviceRepository] for MfaDevicesViewModel tests. */
class FakeMfaDeviceRepository : MfaDeviceRepository {

    var listResult: ApiResult<List<MfaDevice>> = ApiResult.Success(emptyList())
    var beginTotpResult: ApiResult<TotpEnrollment> = ApiResult.Failure(ApiError(0, "unset"))
    var confirmTotpResult: ApiResult<EnrollResult> = ApiResult.Failure(ApiError(0, "unset"))
    var beginCodeResult: ApiResult<DeviceChallenge> = ApiResult.Failure(ApiError(0, "unset"))
    var confirmCodeResult: ApiResult<EnrollResult> = ApiResult.Failure(ApiError(0, "unset"))
    var removeTotpResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var beginRemoveCodeResult: ApiResult<DeviceChallenge> = ApiResult.Failure(ApiError(0, "unset"))
    var confirmRemoveCodeResult: ApiResult<Unit> = ApiResult.Success(Unit)

    var listCalls = 0
    var beginTotpCalls = 0
    var confirmTotpCalls = 0
    var beginCodeCalls = 0
    var confirmCodeCalls = 0
    var removeTotpCalls = 0
    var beginRemoveCodeCalls = 0
    var confirmRemoveCodeCalls = 0

    override suspend fun list(): ApiResult<List<MfaDevice>> {
        listCalls++
        return listResult
    }

    override suspend fun beginTotp(label: String?): ApiResult<TotpEnrollment> {
        beginTotpCalls++
        return beginTotpResult
    }

    override suspend fun confirmTotp(deviceId: String, totpCode: String, totpCode2: String): ApiResult<EnrollResult> {
        confirmTotpCalls++
        return confirmTotpResult
    }

    override suspend fun beginCode(type: MfaFactorType, destination: String, label: String?): ApiResult<DeviceChallenge> {
        beginCodeCalls++
        return beginCodeResult
    }

    override suspend fun confirmCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<EnrollResult> {
        confirmCodeCalls++
        return confirmCodeResult
    }

    override suspend fun removeTotp(deviceId: String, totpCode: String): ApiResult<Unit> {
        removeTotpCalls++
        return removeTotpResult
    }

    override suspend fun beginRemoveCode(type: MfaFactorType, deviceId: String): ApiResult<DeviceChallenge> {
        beginRemoveCodeCalls++
        return beginRemoveCodeResult
    }

    override suspend fun confirmRemoveCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<Unit> {
        confirmRemoveCodeCalls++
        return confirmRemoveCodeResult
    }
}
