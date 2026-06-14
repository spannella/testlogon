package com.testlogon.android.data.upload

import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Url

/**
 * AND-129 — Retrofit interface for the authenticated presign/confirm calls.
 *
 * The concrete route is passed per-call via `@Url` because the backend exposes NO generic
 * attachments endpoint (presign/confirm are per-domain). Both calls ride the shared core-network
 * client, so cookies + `X-CSRF-Token` + the 401-refresh authenticator are applied automatically;
 * the storage PUT is a SEPARATE cookieless call (see [StorageUploadClient]).
 */
interface AttachmentApi {

    /** Presign upload. Consumer supplies the concrete route (image/fs/video). Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST
    suspend fun presign(@Url path: String, @Body body: PresignBody): PresignResponse

    /** Confirm/complete upload (fs flow). Non-idempotent. */
    @Headers("Content-Type: application/json")
    @POST
    suspend fun confirm(@Url path: String, @Body body: ConfirmBody): ConfirmResponse
}
