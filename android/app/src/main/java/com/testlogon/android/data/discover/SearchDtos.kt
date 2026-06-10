package com.testlogon.android.data.discover

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-185 — wire DTOs for global multi-entity search (GET /ui/search).
 *
 * Verified against reference/src/api/endpoints/search.ts (authoritative — the OpenAPI 200 schema is
 * empty). The body is { query, results, partial? } where `results` is a KEYED object of (up to) nine
 * optional sections, each { items, total_estimate, has_more }, and every item shares ONE uniform shape
 * { type, id, title, snippet, thumbnail_url?, url, meta? }.
 *
 * `results` is modelled as nine nullable fields rather than a Map so Moshi codegen handles it directly;
 * the section order the UI shows is fixed by [SearchMapper.SECTION_ORDER]. An unrecognized item `type`
 * maps to SearchEntityType.OTHER (forward-compat). `meta` is intentionally dropped at the wire layer
 * (we never render it) so we avoid a Map<String, Any?> Moshi adapter requirement.
 */

@JsonClass(generateAdapter = true)
data class SearchResponseDto(
    @Json(name = "query") val query: String = "",
    @Json(name = "results") val results: SearchResultsDto = SearchResultsDto(),
    @Json(name = "partial") val partial: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class SearchResultsDto(
    @Json(name = "users") val users: SearchSectionDto? = null,
    @Json(name = "posts") val posts: SearchSectionDto? = null,
    @Json(name = "catalog") val catalog: SearchSectionDto? = null,
    @Json(name = "files") val files: SearchSectionDto? = null,
    @Json(name = "messages") val messages: SearchSectionDto? = null,
    @Json(name = "tickets") val tickets: SearchSectionDto? = null,
    @Json(name = "contacts") val contacts: SearchSectionDto? = null,
    @Json(name = "videos") val videos: SearchSectionDto? = null,
    @Json(name = "calendar") val calendar: SearchSectionDto? = null,
)

@JsonClass(generateAdapter = true)
data class SearchSectionDto(
    @Json(name = "items") val items: List<SearchItemDto> = emptyList(),
    @Json(name = "total_estimate") val totalEstimate: Int = 0,
    @Json(name = "has_more") val hasMore: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class SearchItemDto(
    @Json(name = "type") val type: String = "",
    @Json(name = "id") val id: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "snippet") val snippet: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "url") val url: String = "",
)
