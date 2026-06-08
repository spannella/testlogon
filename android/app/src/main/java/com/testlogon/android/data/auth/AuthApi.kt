package com.testlogon.android.data.auth

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

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
}
