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

    // ── Registration (AND-053/054/055): scriptable stubs ──

    var registerStartResult: () -> RegisterStartResp = { error("not scripted") }
    var registerConfirmResult: () -> RegisterConfirmResp = { error("not scripted") }
    var registerResendResult: () -> RegisterResendResp = { RegisterResendResp("sent") }
    var registerCheckResult: () -> RegisterEmailCheckResp = { RegisterEmailCheckResp(true, "ok") }

    override suspend fun registerStart(body: RegisterStartReq): RegisterStartResp = registerStartResult()

    override suspend fun registerConfirm(body: RegisterConfirmReq): RegisterConfirmResp =
        registerConfirmResult()

    override suspend fun registerResend(body: RegisterResendReq): RegisterResendResp =
        registerResendResult()

    override suspend fun registerCheck(body: RegisterEmailCheckReq): RegisterEmailCheckResp =
        registerCheckResult()

    // ── Password recovery (AND-057/058/059): scriptable stubs ──

    var pwRecoveryStartResult: () -> PasswordRecoveryStartResp = { error("not scripted") }
    var pwRecoveryBeginResult: () -> ChallengeResp = { error("not scripted") }
    var pwRecoveryVerifyResult: () -> MfaVerifyResp = { error("not scripted") }
    var pwRecoveryConfirmResult: () -> OkResp = { error("not scripted") }

    override suspend fun passwordRecoveryStart(body: PasswordRecoveryStartReq): PasswordRecoveryStartResp =
        pwRecoveryStartResult()

    override suspend fun passwordRecoveryBegin(factor: String, body: RecoveryChallengeBeginReq): ChallengeResp =
        pwRecoveryBeginResult()

    override suspend fun passwordRecoveryVerifyEmailOrSms(factor: String, body: RecoveryEmailSmsVerifyReq): MfaVerifyResp =
        pwRecoveryVerifyResult()

    override suspend fun passwordRecoveryVerifyTotp(body: RecoveryTotpVerifyReq): MfaVerifyResp =
        pwRecoveryVerifyResult()

    override suspend fun passwordRecoveryVerifyRecovery(body: RecoveryCodeVerifyReq): MfaVerifyResp =
        pwRecoveryVerifyResult()

    override suspend fun passwordRecoveryConfirm(body: PasswordRecoveryConfirmReq): OkResp =
        pwRecoveryConfirmResult()

    // ── Passwordless / magic-link (AND-060/061): scriptable stubs ──

    var passwordlessStartResult: () -> PasswordlessStartResp = { error("not scripted") }
    var passwordlessVerifyResult: () -> PasswordlessVerifyResp = { error("not scripted") }

    var passwordlessStartCalls = 0
    var passwordlessVerifyCalls = 0
    var lastPasswordlessStartBody: PasswordlessStartReq? = null
    var lastPasswordlessVerifyBody: PasswordlessVerifyReq? = null

    override suspend fun passwordlessStart(body: PasswordlessStartReq): PasswordlessStartResp {
        passwordlessStartCalls++
        lastPasswordlessStartBody = body
        return passwordlessStartResult()
    }

    override suspend fun passwordlessVerify(body: PasswordlessVerifyReq): PasswordlessVerifyResp {
        passwordlessVerifyCalls++
        lastPasswordlessVerifyBody = body
        return passwordlessVerifyResult()
    }

    // ── WebAuthn / passkeys (AND-062): scriptable stubs ──

    var webauthnRegisterBeginResult: () -> WebAuthnRegisterBeginResp = { error("not scripted") }
    var webauthnRegisterFinishResult: () -> WebAuthnRegisterFinishResp = { error("not scripted") }
    var webauthnAuthBeginResult: () -> WebAuthnAuthBeginResp = { error("not scripted") }
    var webauthnAuthFinishResult: () -> WebAuthnAuthFinishResp = { error("not scripted") }

    var webauthnRegisterBeginCalls = 0
    var webauthnRegisterFinishCalls = 0
    var webauthnAuthBeginCalls = 0
    var webauthnAuthFinishCalls = 0
    var lastWebauthnRegisterFinishBody: WebAuthnRegisterFinishReq? = null
    var lastWebauthnAuthBeginBody: WebAuthnAuthBeginReq? = null
    var lastWebauthnAuthFinishBody: WebAuthnAuthFinishReq? = null

    override suspend fun webauthnRegisterBegin(body: WebAuthnRegisterBeginReq): WebAuthnRegisterBeginResp {
        webauthnRegisterBeginCalls++
        return webauthnRegisterBeginResult()
    }

    override suspend fun webauthnRegisterFinish(body: WebAuthnRegisterFinishReq): WebAuthnRegisterFinishResp {
        webauthnRegisterFinishCalls++
        lastWebauthnRegisterFinishBody = body
        return webauthnRegisterFinishResult()
    }

    override suspend fun webauthnAuthenticateBegin(body: WebAuthnAuthBeginReq): WebAuthnAuthBeginResp {
        webauthnAuthBeginCalls++
        lastWebauthnAuthBeginBody = body
        return webauthnAuthBeginResult()
    }

    override suspend fun webauthnAuthenticateFinish(body: WebAuthnAuthFinishReq): WebAuthnAuthFinishResp {
        webauthnAuthFinishCalls++
        lastWebauthnAuthFinishBody = body
        return webauthnAuthFinishResult()
    }

    // ── SSO discovery (AND-063): scriptable stub ──

    var ssoInfoResult: () -> SsoInfoDto = { SsoInfoDto() }
    var lastSsoTenant: String? = null

    override suspend fun getSsoInfo(tenant: String): SsoInfoDto {
        lastSsoTenant = tenant
        return ssoInfoResult()
    }

    // ── MFA device management (AND-064): scriptable stubs ──

    var totpDevicesResult: () -> TotpDeviceListDto = { TotpDeviceListDto() }
    var smsDevicesResult: () -> SmsDeviceListDto = { SmsDeviceListDto() }
    var emailDevicesResult: () -> EmailDeviceListDto = { EmailDeviceListDto() }
    var beginTotpDeviceResult: () -> TotpEnrollDto = { error("not scripted") }
    var confirmTotpDeviceResult: () -> EnrollResultDto = { error("not scripted") }
    var beginSmsDeviceResult: () -> DeviceChallengeDto = { error("not scripted") }
    var beginEmailDeviceResult: () -> DeviceChallengeDto = { error("not scripted") }
    var confirmCodeDeviceResult: () -> EnrollResultDto = { error("not scripted") }
    var removeTotpDeviceResult: () -> OkResp = { OkResp(true) }
    var beginRemoveCodeDeviceResult: () -> DeviceChallengeDto = { error("not scripted") }
    var confirmRemoveCodeDeviceResult: () -> OkResp = { OkResp(true) }

    var lastTotpConfirmBody: TotpDeviceConfirmReq? = null
    var lastSmsBeginBody: SmsDeviceBeginReq? = null
    var lastEmailBeginBody: EmailDeviceBeginReq? = null
    var lastCodeConfirmBody: DeviceConfirmReq? = null
    var lastCodeConfirmType: String? = null
    var lastTotpRemoveBody: TotpDeviceRemoveReq? = null
    var lastTotpRemoveDeviceId: String? = null
    var lastRemoveBeginType: String? = null
    var lastRemoveBeginDeviceId: String? = null
    var lastRemoveConfirmBody: DeviceConfirmReq? = null
    var lastRemoveConfirmType: String? = null

    override suspend fun listTotpDevices(): TotpDeviceListDto = totpDevicesResult()

    override suspend fun listSmsDevices(): SmsDeviceListDto = smsDevicesResult()

    override suspend fun listEmailDevices(): EmailDeviceListDto = emailDevicesResult()

    override suspend fun beginTotpDevice(body: TotpDeviceBeginReq): TotpEnrollDto = beginTotpDeviceResult()

    override suspend fun confirmTotpDevice(body: TotpDeviceConfirmReq): EnrollResultDto {
        lastTotpConfirmBody = body
        return confirmTotpDeviceResult()
    }

    override suspend fun beginSmsDevice(body: SmsDeviceBeginReq): DeviceChallengeDto {
        lastSmsBeginBody = body
        return beginSmsDeviceResult()
    }

    override suspend fun beginEmailDevice(body: EmailDeviceBeginReq): DeviceChallengeDto {
        lastEmailBeginBody = body
        return beginEmailDeviceResult()
    }

    override suspend fun confirmCodeDevice(type: String, body: DeviceConfirmReq): EnrollResultDto {
        lastCodeConfirmType = type
        lastCodeConfirmBody = body
        return confirmCodeDeviceResult()
    }

    override suspend fun removeTotpDevice(deviceId: String, body: TotpDeviceRemoveReq): OkResp {
        lastTotpRemoveDeviceId = deviceId
        lastTotpRemoveBody = body
        return removeTotpDeviceResult()
    }

    override suspend fun beginRemoveCodeDevice(type: String, deviceId: String): DeviceChallengeDto {
        lastRemoveBeginType = type
        lastRemoveBeginDeviceId = deviceId
        return beginRemoveCodeDeviceResult()
    }

    override suspend fun confirmRemoveCodeDevice(type: String, body: DeviceConfirmReq): OkResp {
        lastRemoveConfirmType = type
        lastRemoveConfirmBody = body
        return confirmRemoveCodeDeviceResult()
    }

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
