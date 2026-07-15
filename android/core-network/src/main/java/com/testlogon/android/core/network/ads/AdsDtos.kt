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
    // ADV2-R5: the backend account item labels the account with `company_name` (NOT `name`), so the
    // picker label was blank. Read company_name as the primary display name; `name` stays a lenient
    // fallback for any older/alternate wire. owner_type / owner_syndicate_id flag a SYNDICATE account.
    @Json(name = "company_name") val companyName: String? = null,
    @Json(name = "owner_type") val ownerType: String? = null,
    @Json(name = "owner_syndicate_id") val ownerSyndicateId: String? = null,
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

/**
 * AND-368 - READ-ONLY ad-analytics transport DTOs (ui/ads/analytics). Same reflective-Moshi rules as the
 * AND-363 account DTOs: explicit @Json on every wire key, nullable-with-default optionals, required
 * structural keys with no default. NO @JsonClass codegen.
 *
 * MONEY / RATES (frontend-verified wire contract): every monetary amount is a flat *_cents integer typed as
 * Long (overflow-proof; NO float, NO currency field - display is fixed to USD). Every *_pct field is ALREADY
 * a percentage Double (e.g. 1.23 == 1.23 percent) - the mapper keeps it as-is and NEVER multiplies by 100.
 * Counts (impressions / clicks / completes / skips) are Long. There is NO cpc and NO conversions field on
 * the analytics surface.
 *
 * WIRE CONTRACT (OpenAPI / frontend-corrected; endpoints under ui/ads/analytics):
 *   GET ui/ads/analytics/summary?account_id=&from=&to=                     -> AdAnalyticsSummaryDto
 *   GET ui/ads/analytics/timeseries?account_id=&from=&to=                  -> BARE ARRAY of AdTimeSeriesPointDto
 *   GET ui/ads/analytics/breakdown?account_id=&dimension=&from=&to=        -> BARE ARRAY of AdBreakdownEntryDto
 *
 * ASSUMPTION (account selector): the verified web client (ads.ts getAnalyticsSummary) passes account_id as a
 * QUERY param (NOT a path token) and the date range as `from` / `to` strings in YYYY-MM-DD form. Reconcile
 * against the server spec if the wire uses a path token or epoch dates.
 */

/**
 * AND-368 - the KPI summary for an account over a date range. `impressions` / `clicks` / `spend_cents` /
 * `ctr_pct` are required structural keys; everything else is optional. Each `*_pct` is ALREADY a percentage
 * (kept as-is, NO multiply). Each `*_change_pct` is a period-over-period delta percentage (also as-is).
 */
data class AdAnalyticsSummaryDto(
    @Json(name = "impressions") val impressions: Long,
    @Json(name = "clicks") val clicks: Long,
    @Json(name = "spend_cents") val spendCents: Long,
    @Json(name = "ctr_pct") val ctrPct: Double,
    // ADV3-8: cpc_cents (spend/clicks) is the true CPC that was previously
    // mislabeled cpa_cents on the wire; cpa_cents is now the true cost-per-conversion.
    @Json(name = "cpc_cents") val cpcCents: Long? = null,
    @Json(name = "cpa_cents") val cpaCents: Long? = null,
    @Json(name = "effective_cpm_cents") val effectiveCpmCents: Long? = null,
    @Json(name = "conversions") val conversions: Long? = null,
    @Json(name = "conversion_revenue_cents") val conversionRevenueCents: Long? = null,
    @Json(name = "roas") val roas: Double? = null,
    @Json(name = "unique_users") val uniqueUsers: Long? = null,
    @Json(name = "completes") val completes: Long? = null,
    @Json(name = "skips") val skips: Long? = null,
    @Json(name = "completion_rate_pct") val completionRatePct: Double? = null,
    @Json(name = "impressions_change_pct") val impressionsChangePct: Double? = null,
    @Json(name = "clicks_change_pct") val clicksChangePct: Double? = null,
    @Json(name = "spend_change_pct") val spendChangePct: Double? = null,
    @Json(name = "ctr_change_pct") val ctrChangePct: Double? = null,
    @Json(name = "cpc_change_pct") val cpcChangePct: Double? = null,
    @Json(name = "cpa_change_pct") val cpaChangePct: Double? = null,
    @Json(name = "effective_cpm_change_pct") val effectiveCpmChangePct: Double? = null,
    @Json(name = "completion_rate_change_pct") val completionRateChangePct: Double? = null,
)

/**
 * AND-368 - one daily-bucketed time-series point. `impressions` / `clicks` / `spend_cents` are required
 * structural keys. The bucket is identified by either `date` (YYYY-MM-DD string) or `ts` (epoch Long); both
 * are optional and the mapper keeps whichever the server sends.
 */
data class AdTimeSeriesPointDto(
    @Json(name = "date") val date: String? = null,
    @Json(name = "ts") val ts: Long? = null,
    @Json(name = "impressions") val impressions: Long,
    @Json(name = "clicks") val clicks: Long,
    @Json(name = "spend_cents") val spendCents: Long,
)

/**
 * AND-368 - one breakdown row for a dimension (creative / surface / targeting). `impressions` / `clicks` /
 * `spend_cents` are required structural keys. The grouping key arrives as either `key` or `dimension_value`
 * (both optional); the mapper prefers `key` then falls back to `dimension_value`. `ctr_pct` is ALREADY a
 * percentage (kept as-is). Campaign names / status are NOT on this row (joined from the AND-363 campaign list).
 */
data class AdBreakdownEntryDto(
    @Json(name = "key") val key: String? = null,
    @Json(name = "dimension_value") val dimensionValue: String? = null,
    @Json(name = "impressions") val impressions: Long,
    @Json(name = "clicks") val clicks: Long,
    @Json(name = "spend_cents") val spendCents: Long,
    @Json(name = "ctr_pct") val ctrPct: Double? = null,
)

/**
 * ADV-501/503 - the ROAS report (GET ui/ads/roas). [totals] is the account aggregate; [campaigns] is the
 * per-campaign breakdown (each row the same shape). All *_cents are Long; ctr_pct/cpa_cents/roas are Doubles.
 */
data class AdRoasReportDto(
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "days") val days: Int? = null,
    @Json(name = "totals") val totals: AdCampaignRoasDto,
    @Json(name = "campaigns") val campaigns: List<AdCampaignRoasDto> = emptyList(),
)

/** ADV-501/503 - ROAS figures for one campaign (or the account total, campaign_id absent). */
data class AdCampaignRoasDto(
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "impressions") val impressions: Long = 0,
    @Json(name = "clicks") val clicks: Long = 0,
    @Json(name = "conversions") val conversions: Long = 0,
    @Json(name = "spend_cents") val spendCents: Long = 0,
    @Json(name = "conversion_value_cents") val conversionValueCents: Long = 0,
    @Json(name = "ctr_pct") val ctrPct: Double = 0.0,
    @Json(name = "cpa_cents") val cpaCents: Double = 0.0,
    @Json(name = "roas") val roas: Double = 0.0,
)
