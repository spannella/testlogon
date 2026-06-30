package com.testlogon.android.core.network.customemojis

import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path

/**
 * Retrofit interface for personal custom emojis (web parity: src/api/endpoints/customEmojis.ts).
 *
 * Transport only; the :app repository folds these into ApiResult. Paths have NO leading slash; the shared
 * authenticated client attaches cookies + Authorization + X-CSRF-Token globally. The admin/global-emoji surface
 * (/v1/admin/emojis) is intentionally NOT exposed here — the in-app settings screen manages only personal emojis.
 *
 * The POST is multipart: the boundary is emitted by OkHttp; text fields go as form-data parts and the image as a
 * file part named `file` (mirrors ProfileApi.uploadPhoto).
 */
interface CustomEmojiApi {

    /** GET the caller's visible emojis (personal + global). Idempotent. */
    @GET("ui/emojis/custom")
    suspend fun list(): CustomEmojiListDto

    /** POST a new personal emoji (multipart). NON-idempotent. */
    @Multipart
    @POST("ui/emojis/custom")
    suspend fun upload(
        @Part("shortcode") shortcode: RequestBody,
        @Part("name") name: RequestBody,
        @Part("alt_text") altText: RequestBody,
        @Part("category") category: RequestBody,
        @Part file: MultipartBody.Part,
    ): CustomEmojiDto

    /** DELETE one of the caller's personal emojis. */
    @DELETE("ui/emojis/custom/{emoji_id}")
    suspend fun delete(@Path("emoji_id") emojiId: String): DeleteEmojiResultDto
}
