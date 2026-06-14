package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/** Scriptable [RegisterRepository] for ViewModel tests (AND-053..056). */
class FakeRegisterRepository : RegisterRepository {

    var startResult: ApiResult<RegisterStartOutcome> = ApiResult.Failure(ApiError(0, "unset"))
    var confirmResult: ApiResult<RegisterConfirmOutcome> = ApiResult.Failure(ApiError(0, "unset"))
    var resendResult: ApiResult<RegisterResendResp> = ApiResult.Success(RegisterResendResp("sent"))
    var checkResult: ApiResult<Boolean> = ApiResult.Success(true)

    var startCalls = 0
    var confirmCalls = 0
    var resendCalls = 0
    var checkCalls = 0
    var lastStartReq: RegisterStartReq? = null
    var lastConfirmReq: RegisterConfirmReq? = null
    var lastResendReq: RegisterResendReq? = null
    val checkedEmails = mutableListOf<String>()

    override suspend fun registerStart(req: RegisterStartReq): ApiResult<RegisterStartOutcome> {
        startCalls++
        lastStartReq = req
        return startResult
    }

    override suspend fun confirm(req: RegisterConfirmReq): ApiResult<RegisterConfirmOutcome> {
        confirmCalls++
        lastConfirmReq = req
        return confirmResult
    }

    override suspend fun resend(req: RegisterResendReq): ApiResult<RegisterResendResp> {
        resendCalls++
        lastResendReq = req
        return resendResult
    }

    override suspend fun checkEmail(email: String): ApiResult<Boolean> {
        checkCalls++
        checkedEmails += email
        return checkResult
    }
}
