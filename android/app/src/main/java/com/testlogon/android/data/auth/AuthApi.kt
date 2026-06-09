package com.testlogon.android.data.auth

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the cookie-based session + MFA surface (AND-027, AND-033).
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies + `X-CSRF-Token` are attached by the core-network interceptor chain. All methods are
 * `suspend` and return the typed DTO body; non-2xx surfaces as `retrofit2.HttpException`.
 */
interface AuthApi {

    @Headers("Content-Type: application/json")
    @POST("ui/session/start")
    suspend fun sessionStart(@Body body: SessionStartReq): SessionStartResp

    @Headers("Content-Type: application/json")
    @POST("ui/session/finalize")
    suspend fun sessionFinalize(@Body body: SessionFinalizeReq): SessionFinalizeResp

    @POST("ui/session/refresh")
    suspend fun sessionRefresh(): StatusResp

    @POST("ui/session/logout")
    suspend fun sessionLogout(): StatusResp

    @GET("ui/me")
    suspend fun me(): MeResp

    @GET("ui/sessions")
    suspend fun listSessions(): SessionsResp

    @Headers("Content-Type: application/json")
    @POST("ui/sessions/revoke")
    suspend fun revokeSession(@Body body: RevokeSessionReq): StatusResp

    @Headers("Content-Type: application/json")
    @POST("ui/sessions/revoke_others")
    suspend fun revokeOtherSessions(): StatusResp

    // ── MFA ──

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/totp/verify")
    suspend fun verifyTotp(@Body body: TotpVerifyReq): MfaVerifyResp

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/sms/begin")
    suspend fun beginSms(@Body body: SmsBeginReq): ChallengeResp

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/sms/verify")
    suspend fun verifySms(@Body body: SmsVerifyReq): MfaVerifyResp

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/email/begin")
    suspend fun beginEmail(@Body body: EmailBeginReq): ChallengeResp

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/email/verify")
    suspend fun verifyEmail(@Body body: EmailVerifyReq): MfaVerifyResp

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/recovery/{factor}")
    suspend fun useRecovery(
        @Path("factor") factor: String,
        @Body body: RecoveryReq,
    ): MfaVerifyResp

    // ── Registration (AND-053/054/055) ──

    @Headers("Content-Type: application/json")
    @POST("ui/register/start")
    suspend fun registerStart(@Body body: RegisterStartReq): RegisterStartResp

    @Headers("Content-Type: application/json")
    @POST("ui/register/confirm")
    suspend fun registerConfirm(@Body body: RegisterConfirmReq): RegisterConfirmResp

    @Headers("Content-Type: application/json")
    @POST("ui/register/resend")
    suspend fun registerResend(@Body body: RegisterResendReq): RegisterResendResp

    @Headers("Content-Type: application/json")
    @POST("ui/register/check")
    suspend fun registerCheck(@Body body: RegisterEmailCheckReq): RegisterEmailCheckResp

    // ── Password recovery (AND-057/058/059) ──
    //
    // Unauthenticated namespace. The whole flow is bound by the start-issued challenge_id PLUS the
    // username (required on every challenge/confirm body per OpenAPI). See AuthDtos for shapes.

    /** AND-057: begin recovery; returns the challenge + delivery descriptor. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/start")
    suspend fun passwordRecoveryStart(@Body body: PasswordRecoveryStartReq): PasswordRecoveryStartResp

    /** AND-058: email/sms begin (deliver a code). Reuses MFA-style ChallengeResp. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/challenge/{factor}/begin")
    suspend fun passwordRecoveryBegin(
        @Path("factor") factor: String, // "email" | "sms"
        @Body body: RecoveryChallengeBeginReq,
    ): ChallengeResp

    /** AND-058: email/sms verify; both share a {username, challenge_id, code} body. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/challenge/{factor}/verify")
    suspend fun passwordRecoveryVerifyEmailOrSms(
        @Path("factor") factor: String, // "email" | "sms"
        @Body body: RecoveryEmailSmsVerifyReq,
    ): MfaVerifyResp

    /** AND-058: totp verify; distinct `totp_code` body field. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/challenge/totp/verify")
    suspend fun passwordRecoveryVerifyTotp(@Body body: RecoveryTotpVerifyReq): MfaVerifyResp

    /** AND-058: backup recovery code; FLAT path (no /verify), `recovery_code` + `factor` body. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/challenge/recovery")
    suspend fun passwordRecoveryVerifyRecovery(@Body body: RecoveryCodeVerifyReq): MfaVerifyResp

    /** AND-059: set the new password; returns OkResp. */
    @Headers("Content-Type: application/json")
    @POST("ui/password-recovery/confirm")
    suspend fun passwordRecoveryConfirm(@Body body: PasswordRecoveryConfirmReq): OkResp

    // ── Passwordless / magic-link (AND-060/061) ──
    //
    // Unauthenticated namespace. start dispatches a sign-in link to the user's email; verify exchanges
    // the one-time token from that link for a session (or an MFA challenge). Both are non-idempotent
    // POSTs and are never auto-retried. See AuthDtos for the verified shapes.

    /** AND-060: request a magic-link email; returns a status + optional masked destinations. */
    @Headers("Content-Type: application/json")
    @POST("ui/passwordless/start")
    suspend fun passwordlessStart(@Body body: PasswordlessStartReq): PasswordlessStartResp

    /** AND-061: exchange a one-time link token for a session or an MFA challenge. */
    @Headers("Content-Type: application/json")
    @POST("ui/passwordless/verify")
    suspend fun passwordlessVerify(@Body body: PasswordlessVerifyReq): PasswordlessVerifyResp

    // ── WebAuthn / passkeys (AND-062) ──
    //
    // register endpoints ride the authenticated transport (Bearer + cookie + X-CSRF-Token attached by
    // the shared interceptor chain); authenticate endpoints are public. The begin/finish JSON carries
    // opaque WebAuthn options/credential payloads. Endpoint refs use the path form ui/webauthn/...
    // (never the slash-star form, to keep this comment safe).

    /** AND-062: register begin (authenticated); returns the opaque creation-options object. */
    @Headers("Content-Type: application/json")
    @POST("ui/webauthn/register/begin")
    suspend fun webauthnRegisterBegin(@Body body: WebAuthnRegisterBeginReq): WebAuthnRegisterBeginResp

    /** AND-062: register finish (authenticated); posts the Credential Manager registration response. */
    @Headers("Content-Type: application/json")
    @POST("ui/webauthn/register/finish")
    suspend fun webauthnRegisterFinish(@Body body: WebAuthnRegisterFinishReq): WebAuthnRegisterFinishResp

    /** AND-062: authenticate begin (public); requires a username, returns request-options. */
    @Headers("Content-Type: application/json")
    @POST("ui/webauthn/authenticate/begin")
    suspend fun webauthnAuthenticateBegin(@Body body: WebAuthnAuthBeginReq): WebAuthnAuthBeginResp

    /** AND-062: authenticate finish (public); posts the assertion, returns {status, session_id?}. */
    @Headers("Content-Type: application/json")
    @POST("ui/webauthn/authenticate/finish")
    suspend fun webauthnAuthenticateFinish(@Body body: WebAuthnAuthFinishReq): WebAuthnAuthFinishResp

    // ── SSO / SAML discovery (AND-063) ──

    /** AND-063: tenant-scoped SSO discovery (idempotent GET). The /saml/login URL is opened in a tab. */
    @GET("ui/sso/info")
    suspend fun getSsoInfo(@Query("tenant") tenant: String = "default"): SsoInfoDto

    // ── MFA device management (AND-064) ──
    //
    // Three per-type list endpoints (no unified /ui/mfa/devices). TOTP enroll/remove differ from
    // SMS/email: TOTP confirm uses device_id + two codes, TOTP remove is single-step with a re-auth
    // code; SMS/email enroll keys on phone_e164/email then confirm on challenge_id, and removal is a
    // two-step begin/confirm challenge. All are authenticated mutating POSTs (lists are GETs).

    @GET("ui/mfa/totp/devices")
    suspend fun listTotpDevices(): TotpDeviceListDto

    @GET("ui/mfa/sms/devices")
    suspend fun listSmsDevices(): SmsDeviceListDto

    @GET("ui/mfa/email/devices")
    suspend fun listEmailDevices(): EmailDeviceListDto

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/totp/devices/begin")
    suspend fun beginTotpDevice(@Body body: TotpDeviceBeginReq): TotpEnrollDto

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/totp/devices/confirm")
    suspend fun confirmTotpDevice(@Body body: TotpDeviceConfirmReq): EnrollResultDto

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/sms/devices/begin")
    suspend fun beginSmsDevice(@Body body: SmsDeviceBeginReq): DeviceChallengeDto

    @Headers("Content-Type: application/json")
    @POST("ui/mfa/email/devices/begin")
    suspend fun beginEmailDevice(@Body body: EmailDeviceBeginReq): DeviceChallengeDto

    /** SMS/email enroll confirm; [type] is "sms" or "email". Body keys on challenge_id. */
    @Headers("Content-Type: application/json")
    @POST("ui/mfa/{type}/devices/confirm")
    suspend fun confirmCodeDevice(
        @Path("type") type: String,
        @Body body: DeviceConfirmReq,
    ): EnrollResultDto

    /** TOTP remove — single-step, requires a current TOTP code (re-auth). */
    @Headers("Content-Type: application/json")
    @POST("ui/mfa/totp/devices/{deviceId}/remove")
    suspend fun removeTotpDevice(
        @Path("deviceId") deviceId: String,
        @Body body: TotpDeviceRemoveReq,
    ): OkResp

    /** SMS/email remove begin — delivers a remove-challenge code; [type] is "sms" or "email". */
    @POST("ui/mfa/{type}/devices/{deviceId}/remove/begin")
    suspend fun beginRemoveCodeDevice(
        @Path("type") type: String,
        @Path("deviceId") deviceId: String,
    ): DeviceChallengeDto

    /** SMS/email remove confirm — keys on challenge_id; [type] is "sms" or "email". */
    @Headers("Content-Type: application/json")
    @POST("ui/mfa/{type}/devices/remove/confirm")
    suspend fun confirmRemoveCodeDevice(
        @Path("type") type: String,
        @Body body: DeviceConfirmReq,
    ): OkResp
}
