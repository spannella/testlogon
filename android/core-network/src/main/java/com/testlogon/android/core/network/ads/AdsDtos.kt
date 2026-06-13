package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * AND-363 - transport DTOs for the platform ads accounts control plane (ui/ads/accounts).
 *
 * CODEGEN NOTE (identical to AND-353 OrgDtos / AND-339 SigningDtos): core-network does NOT apply the Moshi
 * KSP codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the
 * shared Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON
 * keys VERBATIM (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required structural wire fields have NO default so a
 * missing key surfaces as a JsonDataException. Extra / unknown wire keys are tolerated leniently by the
 * reflective adapter. The status enums decode via the lenient AdAccountStatusAdapter / AdCampaignStatusAdapter
 * (unrecognized token -> UNKNOWN, never throws).
 *
 * MONEY / TIME (wire contract): all monetary amounts are FLAT *_cents integers typed as Long (avoid Int
 * overflow; NO float, NO nested money object, NO currency / display string). Timestamps created_at /
 * updated_at are EPOCH INTEGERS typed as Long (NOT ISO strings).
 *
 * WIRE CONTRACT (OpenAPI / frontend-corrected):
 *   GET ui/ads/accounts                              -> BARE ARRAY of AdAccountDto
 *   GET ui/ads/accounts/{accountId}                  -> AdAccountDto (same shape as a list row)
 *   GET ui/ads/accounts/{accountId}/billing?limit=   -> BARE ARRAY of AdBillingEntryDto
 *   GET ui/ads/accounts/{accountId}/campaigns        -> BARE ARRAY of AdCampaignDto
 *
 * ASSUMPTION (id key name): no ads.ts / OpenAPI reference was present, so the account / campaign / billing
 * identity wire key is assumed to be the explicit snake_case `account_id` / `campaign_id` / `entry_id`
 * (matching the OrgOut org_id convention in this codebase) rather than a bare `id`. Reconcile against the
 * server spec if the wire uses `id`.
 */

/**
 * One advertising account owned by the caller / org. `account_id`, `balance_cents` and
 * `lifetime_spend_cents` are required structural keys; everything else is optional. Returned both by the
 * accounts list (bare array) and as the single-account GET body.
 */
data class AdAccountDto(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "status") val status: AdAccountStatus = AdAccountStatus.UNKNOWN,
    @Json(name = "balance_cents") val balanceCents: Long,
    @Json(name = "lifetime_spend_cents") val lifetimeSpendCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * One advertising campaign under an account. `campaign_id` is the required structural key; every monetary
 * field is an optional flat *_cents Long and the timestamps are optional epoch Longs.
 */
data class AdCampaignDto(
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "status") val status: AdCampaignStatus = AdCampaignStatus.UNKNOWN,
    @Json(name = "budget_cents") val budgetCents: Long? = null,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long? = null,
    @Json(name = "spent_today_cents") val spentTodayCents: Long? = null,
    @Json(name = "lifetime_spent_cents") val lifetimeSpentCents: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * One billing ledger entry for an account. `amount_cents` is the required structural key (flat cents Long);
 * `created_at` is an optional epoch Long.
 *
 * AND-367 (wire correction): the frontend-verified billing-row shape carries `entry_type` / `state` /
 * `reason` (NOT the AND-363-assumed `type` / `description`). The original `type` / `description` keys are
 * KEPT as optional fallbacks so an older-shaped server row still decodes leniently; the AND-367 keys are
 * the canonical ones the repo maps. All keys remain optional except the required `amount_cents`.
 */
data class AdBillingEntryDto(
    @Json(name = "entry_id") val entryId: String? = null,
    @Json(name = "entry_type") val entryType: String? = null,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "state") val state: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * AND-367 - a monthly invoice for an ad account. `month` is the period label (assumed "YYYY-MM"; the wire
 * format is UNVERIFIED). `total_charges_cents` / `total_deposits_cents` are optional flat *_cents Longs
 * (overflow-proof); `entry_count` is an optional Int; `campaigns` is the per-campaign breakdown (defaults to
 * an empty list when omitted). NO currency field (display currency is fixed to USD).
 *
 * WIRE: GET ui/ads/accounts/{accountId}/invoices/{month} -> AdInvoiceDto.
 */
data class AdInvoiceDto(
    @Json(name = "month") val month: String? = null,
    @Json(name = "total_charges_cents") val totalChargesCents: Long? = null,
    @Json(name = "total_deposits_cents") val totalDepositsCents: Long? = null,
    @Json(name = "entry_count") val entryCount: Int? = null,
    @Json(name = "campaigns") val campaigns: List<AdInvoiceCampaignLineDto> = emptyList(),
)

/**
 * AND-367 - one per-campaign line on a monthly [AdInvoiceDto]. Every field is optional: `campaign_id`
 * identifies the campaign, the impression / click / conversion counts are optional Longs (overflow-proof),
 * and `total_cents` is the optional flat charge for the campaign in the period.
 */
data class AdInvoiceCampaignLineDto(
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "impressions") val impressions: Long? = null,
    @Json(name = "clicks") val clicks: Long? = null,
    @Json(name = "conversions") val conversions: Long? = null,
    @Json(name = "total_cents") val totalCents: Long? = null,
)

/**
 * AND-367 - deposit (add-funds) request body. `amount_cents` is the REQUIRED flat amount in integer USD
 * cents (the client enforces 5000..10000000; the service returns 400 "Minimum deposit" below the floor).
 * `payment_method_id` is OPTIONAL (null omits it) - there is NO vendor payment SDK; the server charges the
 * wallet or an existing saved payment method. NO currency field (display currency is fixed to USD).
 *
 * WIRE: POST ui/ads/accounts/{accountId}/deposit body AdDepositIn -> AdDepositOut.
 */
data class AdDepositIn(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/**
 * AND-367 - deposit response. `new_balance_cents` is the account's updated balance after a successful
 * deposit (used to refresh the displayed balance); `status` echoes the outcome. Both are optional since the
 * server response shape is lenient.
 */
data class AdDepositOut(
    @Json(name = "new_balance_cents") val newBalanceCents: Long? = null,
    @Json(name = "status") val status: String? = null,
)
