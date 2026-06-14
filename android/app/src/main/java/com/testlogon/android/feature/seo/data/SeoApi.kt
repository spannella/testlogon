package com.testlogon.android.feature.seo.data

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-400 - Retrofit interface + Moshi DTOs for the PUBLIC read-only SEO metadata surface (the native
 * port of the web reference src/api/endpoints/seoMetadata.ts).
 *
 * CORRECTED contract (spec sections 4, 5, 16): the operation is a single
 * `GET /seo/metadata` (operationId get_seo_metadata_seo_metadata_get) taking QUERY params
 * type / id / secondary_id / path - NOT a path-templated `/ui/seo/{assetType}/{assetId}`. It is a
 * PUBLIC endpoint (no security block, no auth required); the shared core-network interceptors still
 * attach the session cookie + X-CSRF-Token globally but they are not semantically required here.
 * Documented responses are only 200 (free-form JSON; client shape from the web SeoMetadata type) and
 * 422 HTTPValidationError - there is NO 401/403/404. The GET is idempotent.
 *
 * Both variants return Response<...> so the repository can treat an empty / 204 body and the
 * field-bearing 200 uniformly (Retrofit deserializes the body via the shared codegen Moshi adapter).
 */
interface SeoApi {

    /** Resource-addressed lookup: type + id (+ secondary_id for events). */
    @GET("seo/metadata")
    suspend fun getSeoMetadata(
        @Query("type") type: String,
        @Query("id") id: String,
        @Query("secondary_id") secondaryId: String? = null,
    ): Response<SeoMetadataDto>

    /** Path-addressed lookup (mirrors getSeoMetadataForPath in the web client). */
    @GET("seo/metadata")
    suspend fun getSeoMetadataForPath(
        @Query("path") path: String,
    ): Response<SeoMetadataDto>
}

/**
 * AND-400 - the SEO metadata payload. Codegen adapter (resolves on the unit-test classpath WITHOUT the
 * reflection factory). All scalar fields are nullable and `available` defaults to false so a partial /
 * `200 {}` body decodes safely and degrades to the empty state.
 *
 * CORRECTED shape (spec section 16): `og`/`twitter` are FLAT maps of prefixed string keys
 * (og:* / twitter:*), `image`/og:image are string URLs (no width/height/alt object), `json_ld` is a
 * SINGLE nullable object (not a list), and there is NO `robots` field. Extra/unknown keys are tolerated
 * (the OpenAPI 200 body is untyped).
 */
@JsonClass(generateAdapter = true)
data class SeoMetadataDto(
    @Json(name = "resource_type") val resourceType: String? = null,
    @Json(name = "resource_id") val resourceId: String? = null,
    val available: Boolean = false,
    val title: String? = null,
    val description: String? = null,
    @Json(name = "canonical_url") val canonicalUrl: String? = null,
    @Json(name = "site_name") val siteName: String? = null,
    val locale: String? = null,
    val og: Map<String, String?>? = null,
    val twitter: Map<String, String?>? = null,
    val image: String? = null,
    @Json(name = "json_ld") val jsonLd: Map<String, Any?>? = null,
)
