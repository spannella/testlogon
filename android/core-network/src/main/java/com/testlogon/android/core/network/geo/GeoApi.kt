package com.testlogon.android.core.network.geo

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * Retrofit interface for the geo-blocking settings surface (web parity: src/api/endpoints/geo.ts).
 *
 * Transport only; the :app repository wraps these RAW DTO returns into ApiResult via the established call{} fold
 * (mirrors GeoRulesApi <- ApiKeysApi). Paths have NO leading slash (relative to the shared Retrofit base URL).
 * The shared authenticated client attaches the session cookie, Authorization bearer and X-CSRF-Token globally.
 *
 * Only the page-level (settings) reads + the dry-run check + clear-cache are exposed here; the per-video/broadcast
 * geo CRUD lives with the content editors (out of scope for the settings screen).
 */
interface GeoApi {

    /** GET the ISO country list for the picker. Idempotent. */
    @GET("ui/geo/countries")
    suspend fun listCountries(): GeoCountriesListDto

    /** GET the viewer's detected country/IP/source. Idempotent. */
    @GET("ui/geo/my-country")
    suspend fun getMyCountry(): MyCountryDto

    /** GET a dry-run geo-check against the caller's current IP. Idempotent. */
    @GET("ui/geo/check")
    suspend fun check(
        @Query("geo_mode") geoMode: String? = null,
        @Query("geo_countries") geoCountries: String? = null,
    ): GeoCheckResultDto
}
