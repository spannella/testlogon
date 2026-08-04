package com.testlogon.android.data.taxdocs

/**
 * AND-246 — framework-free tax-document domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/invoices):
 *  - Money is integer cents + ISO-4217 currency. No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time); created_at == 0 -> null.
 *  - `year` is nullable (the backend allows a null year — rows with a null year cannot be downloaded by
 *    the year-keyed PDF endpoint; the UI disables that affordance — AND-246 FR-4).
 *
 * Mapping is TOTAL: no exceptions thrown.
 */

/** Integer cents + ISO-4217 currency. */
data class TaxMoney(val cents: Long, val currency: String)

/** A single generated tax document (annual earnings summary). */
data class TaxDocument(
    val docId: String,
    val docType: String,
    val year: Int?,
    val grandTotal: TaxMoney,
    val transactionCount: Int,
    val createdAtEpochSeconds: Long?,
) {
    /** True only when a `year` is present (the PDF endpoint is keyed by year). */
    val isDownloadable: Boolean get() = year != null
}

/**
 * PAR-24 — an earnings-summary category row (FIN-004). Reuses [TaxMoney]. `transactionCount` is the
 * per-category count.
 */
data class TaxSpendingCategory(
    val category: String,
    val total: TaxMoney,
    val transactionCount: Int,
)

/**
 * PAR-24 — the earnings summary for a period (a single year, here). Reuses [TaxMoney]. Rendered as a
 * card above the documents list; a null summary (fetch failed) simply hides the card — it never fails
 * the screen (mirrors iOS tolerance).
 */
data class TaxSpendingSummary(
    val grandTotal: TaxMoney,
    val transactionCount: Int,
    val categories: List<TaxSpendingCategory>,
) {
    /** True when there is genuinely nothing earned in the period (all-zero). */
    val isEmpty: Boolean get() = grandTotal.cents == 0L && transactionCount == 0
}

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun TaxDocumentDto.toDomain(): TaxDocument = TaxDocument(
    docId = docId,
    docType = docType,
    year = year,
    grandTotal = TaxMoney(grandTotalCents, currency),
    transactionCount = transactionCount,
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
)

internal fun SpendingCategoryDto.toDomain(currency: String): TaxSpendingCategory = TaxSpendingCategory(
    category = category,
    total = TaxMoney(totalCents, currency),
    transactionCount = transactionCount,
)

internal fun TaxSpendingSummaryDto.toDomain(): TaxSpendingSummary = TaxSpendingSummary(
    grandTotal = TaxMoney(grandTotalCents, currency),
    transactionCount = transactionCount,
    // Drop all-zero category rows so the card shows only categories with earnings.
    categories = categories
        .filter { it.totalCents != 0L || it.transactionCount != 0 }
        .map { it.toDomain(currency) },
)
