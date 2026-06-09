package com.testlogon.android.data.alerts

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-086 — Retrofit interface for EMAIL alert-target management.
 *
 * Verified against OpenAPI index (lines 1118-1122) and reference/src/api/endpoints/alerts.ts:
 *  - getEmailPrefs -> GET  ui/alerts/email_prefs       (AlertPreferences)
 *  - begin         -> POST ui/alerts/emails/begin      (AlertEmailBeginReq {email} -> {challenge_id, sent_to})
 *  - confirm       -> POST ui/alerts/emails/confirm    (AlertEmailConfirmReq {challenge_id, code} -> AlertPreferences)
 *  - remove        -> POST ui/alerts/emails/remove     (AlertEmailRemoveReq {email} -> AlertPreferences)
 *
 * CSRF / cookies / Bearer are attached by the core-network interceptor chain.
 */
interface EmailAlertApi {

    @GET("ui/alerts/email_prefs")
    suspend fun getEmailPrefs(): AlertPrefsDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/emails/begin")
    suspend fun begin(@Body body: EmailBeginRequest): AlertBeginResponseDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/emails/confirm")
    suspend fun confirm(@Body body: EmailConfirmRequest): AlertPrefsDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/emails/remove")
    suspend fun remove(@Body body: EmailRemoveRequest): AlertPrefsDto
}

/**
 * AND-087 — Retrofit interface for SMS alert-target management.
 *
 * Verified against OpenAPI index (lines 1129-1132) and reference/src/api/endpoints/alerts.ts:
 *  - getSmsPrefs -> GET  ui/alerts/sms_prefs      (AlertPreferences)
 *  - begin       -> POST ui/alerts/sms/begin      (AlertSmsBeginReq {phone} -> {challenge_id, sent_to})
 *  - confirm     -> POST ui/alerts/sms/confirm    (AlertSmsConfirmReq {challenge_id, code} -> AlertPreferences)
 *  - remove      -> POST ui/alerts/sms/remove     (AlertSmsRemoveReq {phone} -> AlertPreferences)
 */
interface SmsAlertApi {

    @GET("ui/alerts/sms_prefs")
    suspend fun getSmsPrefs(): AlertPrefsDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/sms/begin")
    suspend fun begin(@Body body: SmsBeginRequest): AlertBeginResponseDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/sms/confirm")
    suspend fun confirm(@Body body: SmsConfirmRequest): AlertPrefsDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/sms/remove")
    suspend fun remove(@Body body: SmsRemoveRequest): AlertPrefsDto
}
