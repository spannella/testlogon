package com.testlogon.android.core.model.ads

/**
 * AND-367 - domain models for the ADS-ACCOUNT BILLING surface (balance / lifetime-spend summary, the
 * billing-history ledger, the monthly invoice) and the DEPOSIT (add-funds) outcome.
 *
 * core-model has NO Moshi dependency: these are plain domain types. The transport DTOs (core-network
 * AdAccountDto / AdBillingEntryDto / AdInvoiceDto / AdDepositOut) are mapped to these by the feature-layer
 * AdsBillingMappers (core-model cannot see core-network's DTOs).
 *
 * MONEY: every monetary field is a flat *_cents [Long] (overflow-proof). The display currency is fixed to
 * USD (there is NO currency field on the wire) and formatted via core-model formatCents.
 * TIME: [AdBillingEntry.createdAt] is an EPOCH [Long] (NOT an ISO string).
 */

/**
 * The account-level billing summary, derived from the single-account GET (there is NO separate billing
 * summary object on the wire). [balanceCents] / [lifetimeSpendCents] are the headline figures; the company
 * name + status are display context.
 */
data class AdAccountSummary(
    val accountId: String? = null,
    val companyName: String? = null,
    val status: String? = null,
    val balanceCents: Long,
    val lifetimeSpendCents: Long,
)

/**
 * One row of the billing-history ledger. [amountCents] is the flat signed amount; [entryType] / [state] /
 * [reason] are display fields; [createdAt] is the epoch timestamp (nullable - the server may omit it).
 */
data class AdBillingEntry(
    val entryType: String? = null,
    val amountCents: Long,
    val state: String? = null,
    val reason: String? = null,
    val createdAt: Long? = null,
)

/**
 * A monthly invoice. [month] is the period label (assumed "YYYY-MM"). [totalChargesCents] /
 * [totalDepositsCents] are non-null totals (a missing wire total maps to 0). [entryCount] is optional;
 * [campaigns] is the per-campaign breakdown (possibly empty).
 */
data class AdInvoice(
    val month: String? = null,
    val totalChargesCents: Long,
    val totalDepositsCents: Long,
    val entryCount: Int? = null,
    val campaigns: List<AdInvoiceLine> = emptyList(),
)

/**
 * One per-campaign line on an [AdInvoice]. The impression / click / conversion counts default to 0 when the
 * wire omits them; [totalCents] is the campaign's charge for the period (0 when omitted).
 */
data class AdInvoiceLine(
    val campaignId: String? = null,
    val impressions: Long = 0L,
    val clicks: Long = 0L,
    val conversions: Long = 0L,
    val totalCents: Long = 0L,
)

/**
 * The outcome of a successful deposit. [newBalanceCents] is the account's updated balance (used to refresh
 * the displayed balance); nullable since the server response shape is lenient.
 */
data class DepositResult(
    val newBalanceCents: Long? = null,
)
