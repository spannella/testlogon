package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * ADV2-709/710/711 (F7) — transport DTOs for the SYNDICATE-owned advertiser surface: a syndicate-level ad
 * account (created + funded + campaigned by a syndicate admin) and the per-syndicate ad-placement split
 * config (the member's share of the 70% content-owner cut when the SYNDICATE ITSELF advertises in front of
 * a member's content; the remainder funds the treasury; platform 30% is unchanged).
 *
 * Same reflective-Moshi rules as the ADV-107 account DTOs: explicit @Json on every wire key, nullable
 * optionals with null defaults, the one required structural key with NO default. status is a RAW String
 * (the syndicate account is created pending_review). The create body REUSES [AdAccountCreateIn]; the create
 * response + list rows share [SyndicateAdAccountDto]. No @JsonClass codegen.
 */

/**
 * ADV2-709 — a syndicate-owned advertiser account (the POST create response AND each GET list row; the
 * server returns the full account item). `account_id` is the required structural key; the money fields are
 * optional flat *_cents Longs; `owner_syndicate_id` echoes the owning syndicate. Extra keys are tolerated.
 */
data class SyndicateAdAccountDto(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "company_name") val companyName: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "balance_cents") val balanceCents: Long? = null,
    @Json(name = "lifetime_spend_cents") val lifetimeSpendCents: Long? = null,
    @Json(name = "owner_syndicate_id") val ownerSyndicateId: String? = null,
)

/**
 * ADV2-710 — the per-syndicate ad-placement split config. member_share_bps is the member's cut of the 70%
 * content-owner share (0..10000); treasury_share_bps is the remainder that funds the syndicate treasury.
 * default_member_share_bps is the server default (7000). Platform 30% of the gross charge is unchanged.
 */
data class SyndicateAdPlacementConfigDto(
    @Json(name = "syndicate_id") val syndicateId: String? = null,
    @Json(name = "member_share_bps") val memberShareBps: Int,
    @Json(name = "treasury_share_bps") val treasuryShareBps: Int? = null,
    @Json(name = "default_member_share_bps") val defaultMemberShareBps: Int? = null,
    @Json(name = "platform_share_note") val platformShareNote: String? = null,
)

/** ADV2-710 — the PUT body to set the member's share (bps) of the content-owner split. embed=true server-side. */
data class SyndicateAdPlacementConfigIn(
    @Json(name = "member_share_bps") val memberShareBps: Int,
)
