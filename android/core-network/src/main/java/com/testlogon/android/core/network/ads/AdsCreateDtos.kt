package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * ADV-107/108/109 - transport DTOs for the MUTATING advertiser create flow (create ad account -> create
 * campaign -> create creative + asset upload -> submit-for-review) layered on the AND-363 [AdsAccountsApi].
 *
 * Same reflective-Moshi rules as the AND-363 account DTOs: explicit @Json on every wire key, nullable
 * optionals with null defaults, required structural keys with NO default. NO @JsonClass codegen. Status is a
 * RAW String on these mutation responses (create returns pending_review / draft; the lenient enum adapters
 * are for the read surface) so the create screens can show the exact server lifecycle label.
 *
 * MONEY: flat *_cents integers (budget as Long, bid as Int within the server's 50..20000 bound). TIME:
 * start/end dates are optional EPOCH Longs (server field start_date / end_date).
 */

/** ADV-107 - create-ad-account request body. Mirrors backend AdAccountCreateIn (company_name, billing_email). */
data class AdAccountCreateIn(
    @Json(name = "company_name") val companyName: String,
    @Json(name = "billing_email") val billingEmail: String,
)

/**
 * ADV-107 - create-ad-account response. The server returns the full account item; the create screen needs
 * the new id + the (raw) pending_review status + the echoed company name. Extra keys are tolerated.
 */
data class AdAccountMutationDto(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "company_name") val companyName: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "balance_cents") val balanceCents: Long? = null,
)

/**
 * ADV-108 - create-campaign request body. Mirrors backend CampaignCreateIn: name, objective
 * (awareness|traffic|conversions), budget_cents (>=100), budget_type (daily|lifetime), optional epoch
 * start/end dates, bid_cpm_cents (50..20000), category (default "general" applied server-side when null).
 */
data class AdCampaignCreateIn(
    @Json(name = "name") val name: String,
    @Json(name = "objective") val objective: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "budget_type") val budgetType: String,
    @Json(name = "bid_cpm_cents") val bidCpmCents: Int,
    @Json(name = "category") val category: String? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
)

/**
 * ADV-109 - create-creative request body. Mirrors backend CreativeCreateIn: format
 * (native_post|image|video|carousel), title, optional headline / body_text / cta_text / cta_url,
 * rotation_weight (0..100, default 50). cta_url must be http(s) (server-validated).
 */
data class AdCreativeCreateIn(
    @Json(name = "format") val format: String,
    @Json(name = "title") val title: String,
    @Json(name = "headline") val headline: String? = null,
    @Json(name = "body_text") val bodyText: String? = null,
    @Json(name = "cta_text") val ctaText: String? = null,
    @Json(name = "cta_url") val ctaUrl: String? = null,
    @Json(name = "rotation_weight") val rotationWeight: Int = 50,
)

/**
 * ADV-109 - creative response (create / submit). The server returns the full creative item; `creative_id`
 * is the required key, everything else is optional (status is the raw draft/pending_review/approved token).
 */
data class AdCreativeDto(
    @Json(name = "creative_id") val creativeId: String,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "format") val format: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
)

/** ADV-109 - asset-upload response ({"url": ...}); the stored asset URL (nullable, lenient). */
data class AdAssetUploadDto(
    @Json(name = "url") val url: String? = null,
)

/**
 * ADV-108/109 - submit-for-review acknowledgement. The backend submit endpoints return a bare {"ok": true}
 * (no id), so every field is optional; the repo maps this to the resulting lifecycle status ("pending_review").
 */
data class AdSubmitAckDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "status") val status: String? = null,
)
