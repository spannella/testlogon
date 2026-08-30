package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * Ad TARGETING transport DTOs (web parity: /ads/targeting -> ads_targeting.py, prefix /ui/ads).
 *
 * Mirrors the backend pydantic TargetingCreateIn / TargetingOut / AudienceEstimateOut shapes EXACTLY.
 * Reflective Moshi (no @JsonClass codegen, matching the rest of core-network/ads): explicit @Json on every
 * wire key, nullable-with-default optionals, required structural keys with no default. All list fields are
 * optional snake_case arrays; timestamps are epoch-second Longs.
 */

/** One targeting set returned by GET/POST/PUT targeting endpoints. */
data class AdTargetingDto(
    @Json(name = "target_set_id") val targetSetId: String,
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "name") val name: String = "Default",
    @Json(name = "age_ranges") val ageRanges: List<String>? = null,
    @Json(name = "genders") val genders: List<String>? = null,
    @Json(name = "country_codes") val countryCodes: List<String>? = null,
    @Json(name = "regions") val regions: List<String>? = null,
    @Json(name = "cities") val cities: List<String>? = null,
    @Json(name = "content_categories") val contentCategories: List<String>? = null,
    @Json(name = "active_hours") val activeHours: List<Int>? = null,
    @Json(name = "device_types") val deviceTypes: List<String>? = null,
    @Json(name = "new_user_only") val newUserOnly: Boolean = false,
    @Json(name = "creator_ids") val creatorIds: List<String>? = null,
    @Json(name = "content_types") val contentTypes: List<String>? = null,
    @Json(name = "exclude_creator_ids") val excludeCreatorIds: List<String>? = null,
    @Json(name = "exclude_categories") val excludeCategories: List<String>? = null,
    // FE-162 (EPIC G, <- BE-162) - entity-scoped targeting (additive, tolerated on read).
    @Json(name = "market_ids") val marketIds: List<String>? = null,
    @Json(name = "token_ids") val tokenIds: List<String>? = null,
    @Json(name = "product_ids") val productIds: List<String>? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * Request body for create / update / estimate (backend TargetingCreateIn). Only non-null fields are sent;
 * Moshi omits nulls by default with serializeNulls off (the shared Moshi does not serialize nulls).
 */
data class AdTargetingCreateIn(
    @Json(name = "name") val name: String = "Default",
    @Json(name = "age_ranges") val ageRanges: List<String>? = null,
    @Json(name = "genders") val genders: List<String>? = null,
    @Json(name = "country_codes") val countryCodes: List<String>? = null,
    @Json(name = "content_categories") val contentCategories: List<String>? = null,
    @Json(name = "active_hours") val activeHours: List<Int>? = null,
    @Json(name = "device_types") val deviceTypes: List<String>? = null,
    @Json(name = "new_user_only") val newUserOnly: Boolean = false,
    // FE-162 (EPIC G, <- BE-162) - entity-scoped targeting. Additive + OPTIONAL: promote a specific
    // market / creator-token / product to the segmented audience. A backend that ignores these keys still
    // applies the demographic/behavioral segments (degrade-gracefully).
    @Json(name = "market_ids") val marketIds: List<String>? = null,
    @Json(name = "token_ids") val tokenIds: List<String>? = null,
    @Json(name = "product_ids") val productIds: List<String>? = null,
)

/** Audience estimate returned by POST .../targeting/estimate. */
data class AudienceEstimateDto(
    @Json(name = "estimated_reach") val estimatedReach: Long = 0L,
    @Json(name = "targeting_summary") val targetingSummary: Map<String, Any?> = emptyMap(),
)
