package com.testlogon.android.core.network.donation

import com.squareup.moshi.Json

/**
 * AND-393 - transport DTOs for the PUBLIC (session-free) fundraiser-donation surface.
 *
 * CODEGEN NOTE (identical to AND-355 GroupDtos / AND-353 OrgDtos): core-network does NOT apply the Moshi
 * KSP codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the
 * shared Moshi (NetworkModule.provideMoshi). The reflective factory maps Kotlin property names to JSON
 * keys VERBATIM (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Required wire fields have NO default so a missing key surfaces as a JsonDataException; optional wire
 * fields are nullable (or have a sensible default). Extra/unknown wire keys are tolerated leniently by the
 * reflective adapter. Money is carried as integer cents (Long, overflow-proof); timestamps are epoch
 * seconds (Long) per the verified contract.
 *
 * WIRE CONTRACT (OpenAPI / web-frontend verified, §5/§16 of the spec):
 *   GET  public/fundraisers/{fundraiser_id}                                   -> GroupPublicFundraiserOut
 *   POST public/fundraisers/{fundraiser_id}/donate            body GroupDonateIn -> 201 GroupDonationOut
 *   GET  public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt   -> GroupDonationReceiptOut
 *
 * STATUS NOTE: fundraiser open/closed is DERIVED from the `status` enum ("active" => open); donation
 * status is `pending|completed|failed|refunded`. Both are kept as raw Strings on the wire; the typed
 * domain mapping (with an UNKNOWN-tolerant fallback) lives in the :app feature layer (DonationDomain).
 */

/**
 * GET public/fundraisers/{fundraiser_id} response (`GroupPublicFundraiserOut`, session-free).
 *
 * Required wire fields: `fundraiser_id`, `group_id`, `group_name`, `title`, `status` (NO default ->
 * JsonDataException when absent). `currency` defaults to "usd"; `raised_cents` / `donation_count` default
 * to 0; `goal_cents`, `cover_image_url`, `description` and `ends_at` are nullable. There is NO
 * `hero_image_url` or `accepts_donations` boolean (the prior draft invented them, §16/7-8).
 */
data class PublicFundraiserDto(
    @Json(name = "fundraiser_id") val fundraiserId: String,
    @Json(name = "group_id") val groupId: String,
    @Json(name = "group_name") val groupName: String,
    @Json(name = "title") val title: String,
    @Json(name = "status") val status: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "goal_cents") val goalCents: Long? = null,
    @Json(name = "raised_cents") val raisedCents: Long = 0L,
    @Json(name = "donation_count") val donationCount: Int = 0,
    @Json(name = "cover_image_url") val coverImageUrl: String? = null,
    @Json(name = "ends_at") val endsAt: Long? = null,
)

/**
 * Body for POST public/fundraisers/{fundraiser_id}/donate (`GroupDonateIn`).
 *
 * `amount_cents` is the ONLY required field (integer cents, minimum 100 / maximum 10000000, validated in
 * the domain layer before the request is built). `donor_email` (<=254 chars) and `donor_name` (<=100
 * chars) are BOTH optional/nullable - omit them (null) for a truly anonymous donation. There is NO
 * `currency`, `display_anonymous` or `message` field on this schema (§16/5-6).
 */
data class DonateRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "donor_name") val donorName: String? = null,
    @Json(name = "donor_email") val donorEmail: String? = null,
)

/**
 * 201 response for the donate POST (`GroupDonationOut`).
 *
 * Required: `donation_id`, `amount_cents`, `status`, `created_at`. `status` is
 * `pending|completed|failed|refunded` (kept raw). `is_external` defaults true; `checkout_url` is nullable
 * (a non-null value implies an external payment step that is OUT OF SCOPE here). The response carries NO
 * `fundraiser_id`, `currency` or `receipt_url` (§16/10).
 */
data class DonationDto(
    @Json(name = "donation_id") val donationId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "donor_name") val donorName: String? = null,
    @Json(name = "is_external") val isExternal: Boolean = true,
    @Json(name = "checkout_url") val checkoutUrl: String? = null,
)

/**
 * GET .../donations/{donation_id}/receipt response (`GroupDonationReceiptOut`), fetched as a SECOND call
 * after a successful donate (mirroring the web client). Required: `donation_id`, `amount_cents`,
 * `group_name`, `fundraiser_title`, `created_at`, `status`. `currency` defaults to "usd"; `donor_name` is
 * nullable (§16/11). A transient receipt failure is tolerated by the repository's soft-fallback.
 */
data class DonationReceiptDto(
    @Json(name = "donation_id") val donationId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "group_name") val groupName: String,
    @Json(name = "fundraiser_title") val fundraiserTitle: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "status") val status: String,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "donor_name") val donorName: String? = null,
)
