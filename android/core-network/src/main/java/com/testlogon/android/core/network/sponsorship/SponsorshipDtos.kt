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

/**
 * AND-366 - transport DTO for the FULL sponsorship deal (GET ui/ads/sponsorships/{deal_id}).
 *
 * Decodes reflectively VERBATIM (same factory / no codegen as [SponsorshipDealDto]); every wire key is pinned
 * with @Json. `deal_id` is the only structural required key; everything else is nullable with a null default
 * (extra / unknown keys tolerated leniently). This is a SUPERSET of the inbox row (it adds creator_sub,
 * deliverables, cpm_bonus_cents, platform_commission_bps, content_id and the opaque payment_details) - a
 * SEPARATE detail DTO is used so the lean inbox row stays untouched. The deal does NOT embed offers[]
 * (negotiation history is a separate /history call).
 *
 * MONEY / TIME (OpenAPI / frontend-verified): compensation_cents + cpm_bonus_cents are flat *_cents [Long]
 * (implicit USD, NO currency on the wire); platform_commission_bps is basis points [Int]; deadline is an ISO
 * date STRING (YYYY-MM-DD), NOT an epoch. payment_details is an OPAQUE object retained only as a presence
 * flag (decoded as a loose Map; never rendered field-by-field).
 */
data class SponsorshipDealDetailDto(
    @Json(name = "deal_id") val dealId: String,
    @Json(name = "advertiser_sub") val advertiserSub: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "brief") val brief: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "compensation_cents") val compensationCents: Long? = null,
    @Json(name = "deliverables") val deliverables: List<String>? = null,
    @Json(name = "deadline") val deadline: String? = null,
    @Json(name = "cpm_bonus_cents") val cpmBonusCents: Long? = null,
    @Json(name = "platform_commission_bps") val platformCommissionBps: Int? = null,
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "payment_details") val paymentDetails: Map<String, Any?>? = null,
)

/**
 * AND-366 - one negotiation / lifecycle event from the deal history (GET .../{deal_id}/history -> bare array).
 *
 * `event_id` is the only structural required key; everything else is nullable. `details` is an OPAQUE payload
 * (the server may ship an object map OR a plain string), decoded loosely as Any so the mapper can stringify
 * it for display without a fixed schema. `created_at` is an EPOCH [Long] (NOT an ISO string), unlike the
 * deal's `deadline`.
 */
data class SponsorshipDealEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "event_type") val eventType: String? = null,
    @Json(name = "actor_sub") val actorSub: String? = null,
    @Json(name = "details") val details: Any? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * AND-366 - request body for POST .../{deal_id}/reject (the backlog's "decline"). The wire field is `reason`
 * (NOT "decline"); it is OPTIONAL with a "" default and capped at 500 chars (server-authoritative; the client
 * trims / truncates as UX only). No other fields.
 */
data class SponsorshipRejectReq(
    @Json(name = "reason") val reason: String = "",
)

/**
 * AND-366 - request body for POST .../{deal_id}/counter (the NEGOTIATE counter-offer). BOTH fields are
 * OPTIONAL (nullable, null default - an omitted field is dropped by Moshi's serializeNulls=false default):
 * `compensation_cents` is a flat *_cents [Long] (min 1000 when present, server-authoritative); `note` is a
 * free string capped at 2000 chars. There is intentionally NO currency / deliverables on the counter.
 */
data class SponsorshipCounterReq(
    @Json(name = "compensation_cents") val compensationCents: Long? = null,
    @Json(name = "note") val note: String? = null,
)
