package com.testlogon.android.feature.tradingdocs

import com.testlogon.android.data.tradingdocs.TradingDocument
import java.util.Locale

/**
 * FE-170 — PURE (no Android deps), JVM-testable helpers for the Trading Documents screen: type
 * ordering, grouping, titles, safe filenames, downloadability + human meta. Kept framework-free so the
 * grouping/labelling logic is unit-tested without Robolectric (mirrors the AND-246 TaxDocsFormat idiom).
 */

/** Canonical, display-ordered trading-document type codes (BE-171 `type` values). */
val TRADING_DOC_TYPES: List<String> = listOf(
    "statement",
    "1099",
    "confirmation",
    "fills",
    "pnl",
)

private const val STATUS_GENERATING = "generating"

/** A group of documents sharing one [type], with the type kept for headers. Newest-first within a group. */
data class TradingDocGroup(
    val type: String,
    val documents: List<TradingDocument>,
)

/** Human label for a document [type] code; unknown codes fall back to a title-cased raw code. */
fun docTypeLabel(type: String): String = when (type.lowercase(Locale.ROOT)) {
    "statement" -> "Statements"
    "1099" -> "1099 Tax Forms"
    "confirmation" -> "Trade Confirmations"
    "fills" -> "Fills"
    "pnl" -> "Profit & Loss"
    else -> type.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.ROOT) else it.toString() }
}

/**
 * Group [docs] by type, newest-first WITHIN each group (created_at desc), with GROUPS themselves ordered
 * by [TRADING_DOC_TYPES] (known types first, in canonical order; any unknown types appended
 * alphabetically). Empty groups are omitted.
 */
fun groupDocuments(docs: List<TradingDocument>): List<TradingDocGroup> {
    if (docs.isEmpty()) return emptyList()
    val byType: Map<String, List<TradingDocument>> = docs.groupBy { it.type.lowercase(Locale.ROOT) }
    val known = TRADING_DOC_TYPES.mapNotNull { type ->
        byType[type]?.let { TradingDocGroup(type, it.sortedByDescending { d -> d.createdAtEpochSeconds ?: 0L }) }
    }
    val unknown = byType.keys
        .filter { it !in TRADING_DOC_TYPES }
        .sorted()
        .map { type ->
            TradingDocGroup(type, byType.getValue(type).sortedByDescending { d -> d.createdAtEpochSeconds ?: 0L })
        }
    return known + unknown
}

/** Best display title for a [doc]: the server title if present, else a derived "<Type> <year|period>". */
fun docTitle(doc: TradingDocument): String {
    doc.rawTitle?.let { return it }
    val label = docTypeLabel(doc.type).removeSuffix("s")
    val period = when {
        doc.taxYear != null -> doc.taxYear.toString()
        doc.periodStartEpochSeconds != null -> "period"
        else -> null
    }
    return if (period != null) "$label $period" else label
}

/** File extension implied by the document [format] (defaults to pdf). */
private fun docExtension(doc: TradingDocument): String = when (doc.format.lowercase(Locale.ROOT)) {
    "csv" -> "csv"
    "pdf" -> "pdf"
    else -> "pdf"
}

private val UNSAFE_FILENAME = Regex("[^A-Za-z0-9._-]+")

/**
 * A SAFE, portable download filename for [doc]: derived from the title (or type + id), stripped of
 * filesystem-unsafe characters, collapsed underscores, with the correct extension for its format.
 */
fun docFilename(doc: TradingDocument): String {
    val base = (doc.rawTitle ?: "${doc.type}_${doc.docId}")
        .trim()
        .replace(UNSAFE_FILENAME, "_")
        .trim('_')
        .ifBlank { "trading_document" }
    return "$base.${docExtension(doc)}"
}

/** A document is downloadable only when it is READY (not still generating). */
fun isDownloadable(doc: TradingDocument): Boolean =
    !doc.status.equals(STATUS_GENERATING, ignoreCase = true)

/**
 * Compact human meta line for a row: uppercased format + optional size (KB/MB) + a "Generating…" tag
 * while pending. E.g. "PDF · 1.2 MB" or "CSV · Generating…".
 */
fun formatDocMeta(doc: TradingDocument): String {
    val parts = mutableListOf(doc.format.uppercase(Locale.ROOT))
    doc.sizeBytes?.let { parts += formatSize(it) }
    if (!isDownloadable(doc)) parts += "Generating…"
    return parts.joinToString(" · ")
}

/** Bytes -> a compact "B / KB / MB / GB" string (1024-based, one decimal for KB+). */
internal fun formatSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KB", "MB", "GB", "TB")
    var value = bytes.toDouble() / 1024.0
    var unitIndex = 0
    while (value >= 1024.0 && unitIndex < units.size - 1) {
        value /= 1024.0
        unitIndex++
    }
    return String.format(Locale.US, "%.1f %s", value, units[unitIndex])
}
