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
 * `type` / `description` and the `created_at` epoch are optional.
 */
data class AdBillingEntryDto(
    @Json(name = "entry_id") val entryId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "type") val type: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)
