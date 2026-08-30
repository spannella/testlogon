package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

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
 * start/end dates, bid_cpm_cents (50..20000), and the ADV-301 advertiser-set bid_cpc_cents (1..10000) /
 * bid_cpa_cents (1..100000) — nullable so CPM-only clients omit them and the server applies its defaults
 * (50 / 500). category (default "general" applied server-side when null).
 */
data class AdCampaignCreateIn(
    @Json(name = "name") val name: String,
    @Json(name = "objective") val objective: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "budget_type") val budgetType: String,
    // Nullable so a self-promo campaign can OMIT the CPM (the server field floor is >=50c; a self-promo
    // sends null and the server zeroes all bids). Paid campaigns always send a value.
    @Json(name = "bid_cpm_cents") val bidCpmCents: Int? = null,
    @Json(name = "bid_cpc_cents") val bidCpcCents: Int? = null,
    @Json(name = "bid_cpa_cents") val bidCpaCents: Int? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    // ADV2-306 (F3) — free "promote my content" self-advertising. When true the server zeroes all bids,
    // requires no funding, auto-activates, and serves ONLY on the creator own content. self_promo_mode:
    // fill_only (serve only when no paying ad is eligible) vs always_win (always win the own-content slot).
    @Json(name = "is_self_promo") val isSelfPromo: Boolean = false,
    @Json(name = "self_promo_mode") val selfPromoMode: String? = null,
    // FE-162 (EPIC G, <- BE-161) - promote-entity descriptor. Additive + OPTIONAL: the market / creator-token /
    // product this campaign promotes. A backend that does not persist these simply ignores the extra keys
    // (ignore-unknown). Null when the plain create path is used (nothing promoted).
    @Json(name = "promote_kind") val promoteKind: String? = null,
    @Json(name = "promote_entity_id") val promoteEntityId: String? = null,
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
    // ADV2-212 (F2) — structured click-through CTA targets (max 8). Null/empty for a legacy single-CTA
    // creative (which still uses cta_text/cta_url). Mirrors the backend CtaActionIn.
    @Json(name = "ctas") val ctas: List<AdCtaActionCreateDto>? = null,
)

/**
 * ADV2-212 (F2) — one structured click-through CTA target on a creative-create request. cta_type is one
 * of buy_product / view_product / tip / subscribe / subscribe_other; target_id names the product /
 * creator / account (optional for tip / subscribe this-creator); label is the button text.
 */
data class AdCtaActionCreateDto(
    @Json(name = "cta_type") val ctaType: String,
    @Json(name = "target_id") val targetId: String = "",
    @Json(name = "label") val label: String,
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


/**
 * ADV3-4 (B2) - campaign PATCH request body (management: pause/resume/edit/archive). Mirrors backend
 * CampaignUpdateIn: every field is OPTIONAL (null => omitted so the server leaves it unchanged). [status]
 * drives lifecycle transitions (active<->paused, ->archived); budget/bid edits carry their new *_cents.
 * Moshi omits null fields by default here (no @JsonClass codegen), so a pause sends ONLY {"status":"paused"}.
 */
data class AdCampaignUpdateIn(
    @Json(name = "name") val name: String? = null,
    @Json(name = "objective") val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long? = null,
    @Json(name = "budget_type") val budgetType: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "bid_cpm_cents") val bidCpmCents: Int? = null,
    @Json(name = "bid_cpc_cents") val bidCpcCents: Int? = null,
    @Json(name = "bid_cpa_cents") val bidCpaCents: Int? = null,
)

/**
 * ADV3-4 (B2) - campaign PATCH acknowledgement. The backend update endpoint returns {"ok": true} (NOT the
 * updated campaign), so every field is optional; the caller re-reads the campaign via getCampaign.
 */
data class AdCampaignPatchAckDto(
    @Json(name = "ok") val ok: Boolean? = null,
)
