package com.testlogon.android.core.network.geo

import com.squareup.moshi.Json

/**
 * Geo-blocking settings transport DTOs (web parity: src/api/endpoints/geo.ts + src/pages/settings/GeoRulesPage.tsx).
 *
 * CODEGEN NOTE: core-network does NOT apply the Moshi KSP codegen plugin, so these DTOs decode via the reflective
 * KotlinJsonAdapterFactory registered on the shared Moshi in NetworkModule.provideMoshi. Every wire key is pinned
 * with an explicit @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED (mirrors ApiKeyDtos).
 *
 * WIRE CONTRACT (verified against app/routers/geo_rules.py, prefix /ui/geo; relative paths, NO leading slash):
 *   GET ui/geo/countries  -> { "countries": [ { code, name } ] }
 *   GET ui/geo/my-country -> { country: string|null, ip, source }
 *   GET ui/geo/check?geo_mode=&geo_countries=CSV -> { allowed, country, geo_mode, matched_rule }
 *   POST ui/geo/clear-cache -> { ok, evicted }
 */

data class GeoCountryDto(
    @Json(name = "code") val code: String = "",
    @Json(name = "name") val name: String = "",
)

data class GeoCountriesListDto(
    @Json(name = "countries") val countries: List<GeoCountryDto> = emptyList(),
)

data class MyCountryDto(
    @Json(name = "country") val country: String? = null,
    @Json(name = "ip") val ip: String? = null,
    @Json(name = "source") val source: String? = null,
)

data class GeoCheckResultDto(
    @Json(name = "allowed") val allowed: Boolean = false,
    @Json(name = "country") val country: String? = null,
    @Json(name = "geo_mode") val geoMode: String? = null,
    @Json(name = "matched_rule") val matchedRule: String? = null,
)

data class GeoClearCacheResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "evicted") val evicted: Int = 0,
)
