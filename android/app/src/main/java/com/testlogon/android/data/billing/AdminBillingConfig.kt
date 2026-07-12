package com.testlogon.android.data.billing

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-248 — Retrofit binding + Moshi DTOs + domain for the read-only ADMIN billing configuration.
 *
 * This is a DISTINCT resource from the AND-223 [BillingApi.getConfig] (`GET ui/billing/config` ->
 * publishable_key/currency, the public Stripe-style config). AND-248 reads the effective platform billing
 * configuration (fees/payouts/deposits/currency/tax) which drives which payment options *could* show —
 * still gated by the BillingAuthorizer stub; this ticket only READS it, never enables real payments.
 *
 * VERIFIED against reference/openapi.index.txt L649 + reference/src/api/endpoints/billingConfig.ts +
 * openapi.pretty.json BillingConfigOut (L7460):
 *  - GET ui/admin/billing-config   op=get_config_ui_admin_billing_config_get   resp=200:BillingConfigOut
 *
 * BillingConfigOut field set (all required except updated_at/updated_by, both nullable):
 *  fees *_bps (int basis points), payouts (*_cents + payout_schedule free string + auto_payout_enabled),
 *  deposits (*_cents/_bps), default_currency + supported_currencies (ISO-4217), tax_enabled +
 *  default_tax_rate_bps, updated_at (epoch SECONDS, nullable) + updated_by (admin sub, nullable).
 *  payout_schedule is an OPEN wire string (daily/weekly/monthly observed) -> modelled with an UNKNOWN
 *  fallback. The endpoint is root-gated server-side: a 403 surfaces as an authorization error.
 */
interface AdminBillingConfigApi {

    /** The effective (override-or-default) platform billing configuration. Idempotent GET, no params. */
    @GET("ui/admin/billing-config")
    suspend fun getAdminBillingConfig(): AdminBillingConfigDto

    /** Change history (ADMIN-drivable: require_admin_or_root). Newest first. */
    @GET("ui/admin/billing-config/audit")
    suspend fun getBillingConfigAudit(@Query("limit") limit: Int = 50): BillingConfigAuditLogDto

    /** Project the impact of proposed changes (ADMIN-drivable: require_admin_or_root). */
    @POST("ui/admin/billing-config/preview")
    suspend fun previewBillingConfig(@Body body: Map<String, @JvmSuppressWildcards Any?>): BillingConfigPreviewDto

    /** Reset keys to defaults (ROOT-only: require_root -> 403 for our admin account). */
    @POST("ui/admin/billing-config/reset")
    suspend fun resetBillingConfig(@Body body: BillingConfigResetReqDto): AdminBillingConfigDto
}

// ---- Billing-config audit / preview / reset (web /admin/billing-config parity) ----

@JsonClass(generateAdapter = true)
data class BillingConfigAuditEntryDto(
    @Json(name = "admin_sub") val adminSub: String = "",
    @Json(name = "changes") val changes: List<Map<String, Any?>> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class BillingConfigAuditLogDto(
    @Json(name = "entries") val entries: List<BillingConfigAuditEntryDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class BillingConfigPreviewDto(
    @Json(name = "affected_tx_types") val affectedTxTypes: List<String> = emptyList(),
    @Json(name = "projected_daily_delta_cents") val projectedDailyDeltaCents: Long = 0,
    @Json(name = "sample_before") val sampleBefore: Map<String, Any?> = emptyMap(),
    @Json(name = "sample_after") val sampleAfter: Map<String, Any?> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class BillingConfigResetReqDto(
    @Json(name = "keys") val keys: List<String>? = null,
)

/** A single audit entry projected to display strings. */
data class BillingConfigAuditEntry(
    val adminSub: String,
    val changeSummary: String,
    val createdAtEpochSeconds: Long,
)

internal fun BillingConfigAuditEntryDto.toDomain(): BillingConfigAuditEntry {
    val summary = changes.joinToString("; ") { c ->
        val field = c["field"]?.toString() ?: "?"
        val old = c["old_value"]?.toString() ?: ""
        val new = c["new_value"]?.toString() ?: ""
        "$field: $old -> $new"
    }
    return BillingConfigAuditEntry(
        adminSub = adminSub,
        changeSummary = summary.ifBlank { "(no field detail)" },
        createdAtEpochSeconds = createdAt,
    )
}

// ---- DTO (AND-248) — field names verified 1:1 against BillingConfigOut ----

@JsonClass(generateAdapter = true)
data class AdminBillingConfigDto(
    @Json(name = "fee_tips_bps") val feeTipsBps: Int = 0,
    @Json(name = "fee_unlocks_bps") val feeUnlocksBps: Int = 0,
    @Json(name = "fee_subscriptions_bps") val feeSubscriptionsBps: Int = 0,
    @Json(name = "fee_catalog_bps") val feeCatalogBps: Int = 0,
    @Json(name = "fee_ad_revenue_bps") val feeAdRevenueBps: Int = 0,
    @Json(name = "min_payout_cents") val minPayoutCents: Long = 0,
    @Json(name = "payout_fee_cents") val payoutFeeCents: Long = 0,
    @Json(name = "payout_schedule") val payoutSchedule: String = "",
    @Json(name = "auto_payout_enabled") val autoPayoutEnabled: Boolean = false,
    @Json(name = "min_deposit_cents") val minDepositCents: Long = 0,
    @Json(name = "max_deposit_cents") val maxDepositCents: Long = 0,
    @Json(name = "deposit_fee_bps") val depositFeeBps: Int = 0,
    @Json(name = "default_currency") val defaultCurrency: String = "usd",
    @Json(name = "supported_currencies") val supportedCurrencies: List<String> = emptyList(),
    @Json(name = "tax_enabled") val taxEnabled: Boolean = false,
    @Json(name = "default_tax_rate_bps") val defaultTaxRateBps: Int = 0,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "updated_by") val updatedBy: String? = null,
)

// ---- Domain (AND-248) ----

/** payout_schedule is an OPEN wire string; modelled with an UNKNOWN(raw) fallback. */
sealed interface PayoutSchedule {
    data object Daily : PayoutSchedule
    data object Weekly : PayoutSchedule
    data object Monthly : PayoutSchedule
    data class Unknown(val raw: String) : PayoutSchedule

    companion object {
        fun from(value: String?): PayoutSchedule = when (value?.lowercase()) {
            "daily" -> Daily
            "weekly" -> Weekly
            "monthly" -> Monthly
            else -> Unknown(value.orEmpty())
        }
    }
}

/** The read-only effective billing configuration. Bps are basis points; cents are integer minor units. */
data class AdminBillingConfig(
    val feeTipsBps: Int,
    val feeUnlocksBps: Int,
    val feeSubscriptionsBps: Int,
    val feeCatalogBps: Int,
    val feeAdRevenueBps: Int,
    val minPayoutCents: Long,
    val payoutFeeCents: Long,
    val payoutSchedule: PayoutSchedule,
    val autoPayoutEnabled: Boolean,
    val minDepositCents: Long,
    val maxDepositCents: Long,
    val depositFeeBps: Int,
    val defaultCurrency: String,
    val supportedCurrencies: List<String>,
    val taxEnabled: Boolean,
    val defaultTaxRateBps: Int,
    val updatedAtEpochSeconds: Long?,
    val updatedBy: String?,
)

// ---- Mapper (DTO -> domain). TOTAL: unknown schedule -> Unknown(raw), no throws. ----

internal fun AdminBillingConfigDto.toDomain(): AdminBillingConfig = AdminBillingConfig(
    feeTipsBps = feeTipsBps,
    feeUnlocksBps = feeUnlocksBps,
    feeSubscriptionsBps = feeSubscriptionsBps,
    feeCatalogBps = feeCatalogBps,
    feeAdRevenueBps = feeAdRevenueBps,
    minPayoutCents = minPayoutCents,
    payoutFeeCents = payoutFeeCents,
    payoutSchedule = PayoutSchedule.from(payoutSchedule),
    autoPayoutEnabled = autoPayoutEnabled,
    minDepositCents = minDepositCents,
    maxDepositCents = maxDepositCents,
    depositFeeBps = depositFeeBps,
    defaultCurrency = defaultCurrency,
    supportedCurrencies = supportedCurrencies,
    taxEnabled = taxEnabled,
    defaultTaxRateBps = defaultTaxRateBps,
    updatedAtEpochSeconds = updatedAt?.takeIf { it > 0 },
    updatedBy = updatedBy?.takeIf { it.isNotBlank() },
)
