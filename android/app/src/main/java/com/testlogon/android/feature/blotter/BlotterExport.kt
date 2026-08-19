package com.testlogon.android.feature.blotter

/**
 * Pure (no Android imports) export logic for the Trading Blotter Orders/Fills view.
 *
 * The export is a VIEW-DERIVED, read-only transform: it reuses the exact same display derivation
 * the table renders ([BlotterUiState.ordersRows] / [BlotterUiState.fillsRows]) and the exact same
 * per-cell/per-header formatters the cells use ([cellText] / [headerLabel]) so an export can never
 * diverge from what the user sees. It never mutates orders and never touches the ticker.
 */

/** Cap for the EXTRA_TEXT fast-path — larger exports are shared as a file stream only. */
const val EXPORT_TEXT_MAX_CHARS = 4000

/** The delivery formats offered by the blotter Export sheet (delimited text or a rendered PDF). */
enum class BlotterExportFormat { CSV, TSV, PDF }

/**
 * The filtered + sorted orders currently visible in the given tab, in display order.
 *
 * Reuses the same public row derivation the table consumes, then keeps only the item rows
 * (dropping group headers). Collapsed groups still export their items: collapse is visual only,
 * so the export is the full filtered set, not the visually-collapsed subset.
 */
fun exportRows(state: BlotterUiState, fillsMode: Boolean): List<BlotterOrder> =
    (if (fillsMode) state.fillsRows else state.ordersRows)
        .filterIsInstance<BlotterRow.Item>()
        .map { it.order }

/**
 * Render [orders] to a delimited document (CSV when [delimiter] is a comma, TSV when a tab).
 *
 * The header line uses [headerLabel] per visible column; each body line uses [cellText] so the
 * exported values are byte-identical to the rendered cells. Columns iterate the caller-supplied
 * [columns] (== state.visibleColumns) so the column chooser and reorder are honored.
 *
 * CSV uses RFC 4180 quoting (a field is wrapped in quotes and embedded quotes doubled when it
 * contains the delimiter, a quote, CR or LF). TSV strips embedded tabs and newlines instead, since
 * TSV has no standard escape. Lines are joined with CRLF.
 */
fun formatDelimited(
    orders: List<BlotterOrder>,
    columns: List<BlotterColumn>,
    fillsMode: Boolean,
    delimiter: Char,
): String {
    val tsv = delimiter == '\t'
    fun field(raw: String): String {
        if (tsv) {
            // TSV has no standard escape: strip the structural characters.
            return raw.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
        }
        // RFC 4180 CSV escaping.
        val needsQuote = raw.any { it == delimiter || it == '"' || it == '\n' || it == '\r' }
        return if (needsQuote) "\"" + raw.replace("\"", "\"\"") + "\"" else raw
    }

    val sb = StringBuilder()
    val header = columns.joinToString(delimiter.toString()) { field(headerLabel(it, fillsMode)) }
    sb.append(header)
    for (o in orders) {
        sb.append("\r\n")
        sb.append(columns.joinToString(delimiter.toString()) { field(cellText(it, o, fillsMode)) })
    }
    return sb.toString()
}
