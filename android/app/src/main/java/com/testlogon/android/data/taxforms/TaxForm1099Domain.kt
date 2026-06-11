package com.testlogon.android.data.taxforms

/**
 * AND-247 — framework-free 1099-NEC domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/invoices + data/taxdocs):
 *  - Money is integer cents + an implicit USD currency (the wire carries no currency; IRS 1099-NEC is
 *    US-only). No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time); generated_at/updated_at == 0 -> null.
 *  - Status is a free string on the wire (default "generated"). It is modelled defensively with an
 *    UNKNOWN fallback PLUS the raw string preserved for forward-compatible display. A correction_count
 *    > 0 promotes the status to CORRECTED regardless of the raw string.
 *
 * Mapping is TOTAL: no exceptions thrown.
 */

/** Integer cents; currency is implicit USD for 1099-NEC. */
data class Form1099Money(val cents: Long, val currency: String = USD) {
    companion object {
        const val USD = "usd"
    }
}

/**
 * 1099-NEC status. The wire default is "generated"; a corrected form is signalled by correction_count
 * > 0 (there is no "corrected"/"voided" enum on the wire). UNKNOWN preserves forward compatibility.
 */
enum class Form1099Status {
    GENERATED,
    CORRECTED,
    UNKNOWN,
    ;

    companion object {
        /** Maps the free-string [status] + [correctionCount]; a correction wins over the raw string. */
        fun from(status: String?, correctionCount: Int): Form1099Status = when {
            correctionCount > 0 -> CORRECTED
            status?.lowercase() == "generated" -> GENERATED
            status?.lowercase() == "corrected" -> CORRECTED
            else -> UNKNOWN
        }
    }
}

/**
 * A single 1099-NEC form. [taxYear] is the stable row identity AND the fetch/download path key (one
 * 1099-NEC per user per year). [downloadUrl] from the list is usually null — the bytes are fetched via
 * the dedicated /download call (the presigned URL expires, so it is re-requested per download).
 */
data class Form1099(
    val taxYear: Int,
    val formId: String,
    val totalEarnings: Form1099Money,
    val qualifies: Boolean,
    val status: Form1099Status,
    val statusRaw: String,
    val correctionCount: Int,
    val payerName: String,
    val payerTinLast4: String,
    val generatedAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
    val downloadUrl: String?,
) {
    /** True when the form was corrected at least once (drives the "Corrected" chip). */
    val isCorrected: Boolean get() = correctionCount > 0
}

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun Form1099Dto.toDomain(): Form1099 = Form1099(
    taxYear = taxYear,
    formId = formId,
    totalEarnings = Form1099Money(totalEarningsCents),
    qualifies = qualifies,
    status = Form1099Status.from(status, correctionCount),
    statusRaw = status,
    correctionCount = correctionCount,
    payerName = payerName,
    payerTinLast4 = payerTinLast4,
    generatedAtEpochSeconds = generatedAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt.epochSecondsOrNull(),
    downloadUrl = downloadUrl?.takeIf { it.isNotBlank() },
)
