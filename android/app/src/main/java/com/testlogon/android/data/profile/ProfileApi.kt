package com.testlogon.android.data.profile

import okhttp3.MultipartBody
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Multipart
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path

/**
 * AND-070 / AND-072 / AND-074 — Retrofit interface for the profile surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies, Authorization and `X-CSRF-Token` are attached by the core-network interceptor chain.
 * All methods are `suspend` and return the typed DTO body; non-2xx surfaces as HttpException.
 *
 * Endpoints verified against src/api/endpoints/profile.ts and the OpenAPI index:
 *  - getMyProfile        -> GET   ui/profile                         (op ui_get_profile_ui_profile_get)
 *  - patchMyProfile      -> PATCH ui/profile                         (op ui_patch_profile_ui_profile_patch)
 *  - getProfileByIdentifier -> GET ui/profiles/{identifier}          (op ui_get_profile_by_identifier_...)
 *  - getPublicProfile    -> GET   ui/profile/public/{identifier}     (op get_public_profile_...)
 *  - uploadPhoto         -> POST  ui/profile/photos/{kind}/upload    (op ui_upload_profile_photo_...)
 *
 * Note: both /ui/profile and PATCH /ui/profile return the ENVELOPE { "profile": Profile }.
 * `getProfileByIdentifier` uses the PLURAL path `ui/profiles/{identifier}`.
 */
interface ProfileApi {

    /** Own profile. Idempotent GET. */
    @GET("ui/profile")
    suspend fun getMyProfile(): ProfileEnvelopeDto

    /** Partial own-profile update. Non-idempotent; never auto-retried. */
    @PATCH("ui/profile")
    suspend fun patchMyProfile(@Body body: ProfilePatchReqDto): ProfileEnvelopeDto

    /** Cross-user profile by identifier (plural path). Idempotent GET. */
    @GET("ui/profiles/{identifier}")
    suspend fun getProfileByIdentifier(@Path("identifier") identifier: String): CrossUserProfileDto

    /** Storefront public profile. Idempotent GET; auth optional. */
    @GET("ui/profile/public/{identifier}")
    suspend fun getPublicProfile(@Path("identifier") identifier: String): PublicProfileDataDto

    /**
     * Single authenticated multipart upload of an avatar (kind=profile) or cover (kind=cover).
     * The boundary is emitted by OkHttp; the per-part Content-Type is set on [file]. Non-idempotent.
     */
    @Multipart
    @POST("ui/profile/photos/{kind}/upload")
    suspend fun uploadPhoto(
        @Path("kind") kind: String,
        @Part file: MultipartBody.Part,
    ): ProfilePhotoUploadRespDto
}
