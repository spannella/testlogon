package com.testlogon.android.core.network.msgprivacy

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * TIP-B4 (TIP-401) — Retrofit interface for the caller's MessagePrivacy (pay-to-message gate +
 * tip-free allowlist).
 *
 * Transport only; the :app repository folds these into ApiResult. Paths have NO leading slash; the
 * shared authenticated client attaches cookies + Authorization + X-CSRF-Token globally.
 */
interface MessagePrivacyApi {

    /** GET the caller's own message-privacy settings. Idempotent. */
    @GET("messaging/privacy/message")
    suspend fun get(): MessagePrivacyDto

    /** PUT (partial) update require_tip_to_message / min_tip_cents / tip_free_allowlist. */
    @PUT("messaging/privacy/message")
    suspend fun update(@Body body: MessagePrivacyUpdateDto): MessagePrivacyDto

    /** POST add one user_sub to the tip-free allowlist. */
    @POST("messaging/privacy/message/allowlist")
    suspend fun addAllowlist(@Body body: MessagePrivacyAllowlistEntryDto): MessagePrivacyDto

    /** DELETE one user_sub from the tip-free allowlist. */
    @DELETE("messaging/privacy/message/allowlist/{allow_user_id}")
    suspend fun removeAllowlist(@Path("allow_user_id") allowUserId: String): MessagePrivacyDto
}
