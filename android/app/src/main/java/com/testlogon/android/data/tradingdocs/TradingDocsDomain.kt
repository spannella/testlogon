package com.testlogon.android.data.tradingdocs

/**
 * FE-170 — framework-free trading-document domain models + DTO -> domain mappers.
 *
 * Conventions (matching data/taxdocs):
 *  - Timestamps are epoch-seconds Longs (NOT java.time); 0/absent -> null.
 *  - size in bytes is nullable (server may omit it, e.g. while generating).
 *  - Mapping is TOTAL: no exceptions thrown.
 */

/** A single trading document (statement / 1099 / trade confirmation / fills / pnl). */
data class TradingDocument(
    val docId: String,
    val type: String,
    val rawTitle: String?,
    val periodStartEpochSeconds: Long?,
    val periodEndEpochSeconds: Long?,
    val taxYear: Int?,
    val format: String,
    val sizeBytes: Long?,
    val status: String,
    val createdAtEpochSeconds: Long?,
    val downloadUrl: String?,
)

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun TradingDocDto.toDomain(): TradingDocument = TradingDocument(
    docId = docId,
    type = type,
    rawTitle = title?.takeIf { it.isNotBlank() },
    periodStartEpochSeconds = periodStart?.epochSecondsOrNull(),
    periodEndEpochSeconds = periodEnd?.epochSecondsOrNull(),
    taxYear = taxYear,
    format = format,
    sizeBytes = sizeBytes?.takeIf { it > 0 },
    status = status,
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    downloadUrl = downloadUrl?.takeIf { it.isNotBlank() },
)
