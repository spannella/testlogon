package com.testlogon.android.core.network.sponsorship

import com.squareup.moshi.Json

/**
 * AND-365 - transport DTO for the READ-ONLY sponsorship inbox (inbound brand deals).
 *
 * CODEGEN NOTE (identical to AND-363 AdsDtos): core-network does NOT apply the Moshi KSP codegen plugin, so
 * this DTO decodes via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM (Moshi
 * does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * The only required structural wire key is `deal_id` (no default, so a missing key surfaces a
 * JsonDataException). Everything else is nullable with a null default; extra / unknown wire keys are
 * tolerated leniently by the reflective adapter. `status` is decoded as a RAW String here (the typed enum +
 * UNKNOWN fallback lives in core-model SponsorshipDealStatus, parsed in the feature mapper) so no Moshi enum
 * adapter is registered and NO provideMoshi change is needed (mirrors AND-364 ContentBoost).
 *
 * MONEY / TIME (OpenAPI / frontend-verified against the web sponsorshipDeals types):
 *   compensation_cents is a FLAT integer typed as Long (avoid Int overflow; implicit USD; NO currency on
 *   the wire). created_at is an EPOCH integer typed as Long. deadline is an ISO date STRING on the wire (the
 *   web type ships `deadline: string`), kept as String here - NOT an epoch Long.
 *
 * WIRE CONTRACT (verified against reference web src/api/endpoints/sponsorshipDeals.ts + types.ts):
 *   GET ui/ads/sponsorships -> BARE ARRAY of SponsorshipDealDto (no envelope, no cursor / paging).
 *
 * READ-ONLY: NO read_at / unread, NO sponsor_name / avatar, NO title, NO currency (the wire carries none of
 * these). The advertiser is an opaque `advertiser_sub` subject id rendered "From <sub>" with no display-name
 * lookup (deferred).
 */
data class SponsorshipDealDto(
    @Json(name = "deal_id") val dealId: String,
    @Json(name = "advertiser_sub") val advertiserSub: String? = null,
    @Json(name = "brief") val brief: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "compensation_cents") val compensationCents: Long? = null,
    @Json(name = "deadline") val deadline: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)
