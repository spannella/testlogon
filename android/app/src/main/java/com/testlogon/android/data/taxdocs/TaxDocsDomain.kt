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
