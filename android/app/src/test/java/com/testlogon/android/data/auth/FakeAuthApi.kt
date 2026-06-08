package com.testlogon.android.data.auth

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * Hand-written [AuthApi] fake for pure-JVM repository tests. Each endpoint returns a queued result
 * or throws a queued [HttpException]/[Throwable], and records its invocation for assertions.
 */
class FakeAuthApi : AuthApi {

    // Queued canned responses / errors. Use the setters to script a test.
    var sessionStartResult: () -> SessionStartResp = { error("not scripted") }
    var finalizeResult: () -> SessionFinalizeResp = { error("not scripted") }
    var meResult: () -> MeResp = { error("not scripted") }
    var totpResult: () -> MfaVerifyResp = { error("not scripted") }
    var smsBeginResult: () -> ChallengeResp = { error("not scripted") }
    var smsVerifyResult: () -> MfaVerifyResp = { error("not scripted") }
    var emailBeginResult: () -> ChallengeResp = { error("not scripted") }
    var emailVerifyResult: () -> MfaVerifyResp = { error("not scripted") }
    var recoveryResult: () -> MfaVerifyResp = { error("not scripted") }
    var logoutResult: () -> StatusResp = { StatusResp("ok") }

    var verifyTotpCalls = 0
    var finalizeCalls = 0
    var meCalls = 0
    var beginSmsCalls = 0
    var logoutCalls = 0
    var lastTotpBody: TotpVerifyReq? = null
    var lastStartBody: SessionStartReq? = null

    override suspend fun sessionStart(body: SessionStartReq): SessionStartResp {
        lastStartBody = body
        return sessionStartResult()
    }

    override suspend fun sessionFinalize(body: SessionFinalizeReq): SessionFinalizeResp {
        finalizeCalls++
        return finalizeResult()
    }

    override suspend fun sessionRefresh(): StatusResp = StatusResp("ok")

    override suspend fun sessionLogout(): StatusResp {
        logoutCalls++
        return logoutResult()
    }

    override suspend fun me(): MeResp {
        meCalls++
        return meResult()
    }

    override suspend fun listSessions(): SessionsResp = SessionsResp()

    override suspend fun revokeSession(body: RevokeSessionReq): StatusResp = StatusResp("ok")

    override suspend fun revokeOtherSessions(): StatusResp = StatusResp("ok")

    override suspend fun verifyTotp(body: TotpVerifyReq): MfaVerifyResp {
        verifyTotpCalls++
        lastTotpBody = body
        return totpResult()
    }

    override suspend fun beginSms(body: SmsBeginReq): ChallengeResp {
        beginSmsCalls++
        return smsBeginResult()
    }

    override suspend fun verifySms(body: SmsVerifyReq): MfaVerifyResp = smsVerifyResult()

    override suspend fun beginEmail(body: EmailBeginReq): ChallengeResp = emailBeginResult()

    override suspend fun verifyEmail(body: EmailVerifyReq): MfaVerifyResp = emailVerifyResult()

    override suspend fun useRecovery(factor: String, body: RecoveryReq): MfaVerifyResp =
        recoveryResult()

    companion object {
        /** Builds an [HttpException] with the given status + JSON error body. */
        fun httpError(status: Int, body: String = """{"detail":"error"}"""): HttpException =
            HttpException(
                Response.error<Any>(
                    status,
                    body.toResponseBody("application/json".toMediaType()),
                ),
            )
    }
}
