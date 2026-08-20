package com.testlogon.android.feature.reports

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.pnl.PnlAnalytics
import com.testlogon.android.feature.pnl.PnlStats
import com.testlogon.android.feature.pnl.SymbolRow
import java.util.Locale

/**
 * PURE, unit-testable CSV builders for the Export & Reporting surface. NO Android / coroutine /
 * Compose deps: the ViewModel hands already-fetched, already-period-scoped exchange reads (fills-fees,
 * the derived [PnlAnalytics] roll-up, the margin account) and these functions emit RFC 4180 CSV text.
 *
 * All amounts are raw integer engine units (Long) rendered as plain integers so an export never loses
 * precision to a display scaler. Timestamps are nanosecond ticks formatted human-readably in UTC.
 * CSV escaping matches the blotter's RFC 4180 convention (quote a field containing the delimiter, a
 * quote, CR or LF; embedded quotes doubled); rows join with CRLF so the document opens cleanly in a
 * spreadsheet on any platform.
 */
object ReportCsv {

    /** The delimiter is fixed to a comma for these reports (spreadsheet-friendly). */
    private const val DELIM = ','

    /** RFC 4180 escaping: wrap in quotes + double embedded quotes when the field needs it. */
    fun csvField(raw: String): String {
        val needsQuote = raw.any { it == DELIM || it == '"' || it == '\n' || it == '\r' }
        return if (needsQuote) "\"" + raw.replace("\"", "\"\"") + "\"" else raw
    }

    /** Join a row's cells with the delimiter, escaping each. */
    private fun row(vararg cells: String): String = cells.joinToString(DELIM.toString()) { csvField(it) }

    /** Join header + body lines with CRLF (RFC 4180). */
    private fun document(vararg lines: String): String = lines.joinToString("\r\n")

    private fun sideLabel(side: OrderSide?): String = when (side) {
        OrderSide.BUY -> "BUY"
        OrderSide.SELL -> "SELL"
        null -> "--"
    }

    /** Notional for a fill: |qty| * price, in raw units. */
    private fun notionalOf(f: FillFee): Long = Math.abs(f.qty) * f.price

    /**
     * Format a nanosecond tick as an ISO-8601-ish UTC timestamp (yyyy-MM-dd HH:mm:ss 'UTC'). A tick of
     * 0 (unknown) renders as an empty string so an export never invents a 1970 date.
     */
    fun formatTs(tsNs: Long): String {
        if (tsNs <= 0L) return ""
        val millis = tsNs / 1_000_000L
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        fmt.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return fmt.format(java.util.Date(millis)) + " UTC"
    }

    /**
     * Trade-history CSV: one row per fill (oldest -> newest) with time / symbol / side / price / qty /
     * fee / notional. [symbolNames] resolves symbol ids to names (falls back to '#id'). Always emits a
     * header even when there are no fills.
     */
    fun tradeHistory(fills: List<FillFee>, symbolNames: Map<Int, String>): String {
        val header = row("Time", "Symbol", "Side", "Price", "Qty", "Fee", "Notional")
        val body = fills.sortedBy { it.tsNs }.map { f ->
            row(
                formatTs(f.tsNs),
                symbolNames[f.symbolId] ?: ("#" + f.symbolId),
                sideLabel(f.side),
                f.price.toString(),
                f.qty.toString(),
                f.fee.toString(),
                notionalOf(f).toString(),
            )
        }
        return document(*(listOf(header) + body).toTypedArray())
    }

    /**
     * PnL-summary CSV: one row per symbol (realized / fees / volume / trades) plus a TOTAL row folding
     * the per-symbol figures together with the account-level net (net-of-fees-funding-liquidations),
     * unrealized, funding, and liquidation legs. [symbolNames] resolves ids to names.
     */
    fun pnlSummary(report: PnlAnalytics.PnlReport, symbolNames: Map<Int, String>): String {
        val header = row("Symbol", "Realized", "Fees", "Volume", "Trades")
        val perSymbol = report.bySymbol.map { s ->
            row(
                symbolNames[s.symbolId] ?: ("#" + s.symbolId),
                s.realized.toString(),
                s.fees.toString(),
                s.volume.toString(),
                s.tradeCount.toString(),
            )
        }
        val totalRow = row(
            "TOTAL",
            report.tradeRealized.toString(),
            report.totalFees.toString(),
            report.volume.toString(),
            report.tradeCount.toString(),
        )
        // Account-level legs that are not per-symbol, as labelled key/value rows below the table.
        val legs = listOf(
            row("Net realized", report.netRealized.toString(), "", "", ""),
            row("Unrealized", report.unrealized.toString(), "", "", ""),
            row("Funding", report.fundingTotal.toString(), "", "", ""),
            row("Liquidation PnL", report.liquidationPnl.toString(), "", "", ""),
        )
        return document(*(listOf(header) + perSymbol + listOf(totalRow) + legs).toTypedArray())
    }

    /**
     * PnL-summary CSV built directly from the PnL SCREEN's already-projected [rows] + [stats] (no raw
     * fills needed). Mirrors [pnlSummary] so the PnL screen's Share action reuses this helper without
     * re-deriving. Symbol names are already resolved on [SymbolRow.symbol].
     */
    fun pnlScreenSummary(rows: List<SymbolRow>, stats: PnlStats): String {
        val header = row("Symbol", "Realized", "Fees", "Volume", "Trades")
        val perSymbol = rows.map { r ->
            row(r.symbol, r.realized.toString(), r.fees.toString(), r.volume.toString(), r.tradeCount.toString())
        }
        val legs = listOf(
            row("Net realized", stats.netRealized.toString(), "", "", ""),
            row("Unrealized", stats.unrealized.toString(), "", "", ""),
            row("Total fees", stats.totalFees.toString(), "", "", ""),
            row("Volume", stats.volume.toString(), "", "", ""),
            row("Trades", stats.tradeCount.toString(), "", "", ""),
            row("Funding", stats.fundingTotal.toString(), "", "", ""),
            row("Liquidation PnL", stats.liquidationPnl.toString(), "", "", ""),
        )
        return document(*(listOf(header) + perSymbol + legs).toTypedArray())
    }

    /**
     * Account-statement CSV for a period: a labelled key/value block of the period bounds, the margin
     * account balances (balance / available / reserved margin), the open position (symbol / qty /
     * entry / unrealized), and the period's realized-net roll-up. [margin] may be null when the margin
     * read was unavailable; balances then render as '--'.
     */
    fun accountStatement(
        report: PnlAnalytics.PnlReport,
        margin: MarginAccount?,
        symbolNames: Map<Int, String>,
        periodLabel: String,
        fromTsNs: Long,
        toTsNs: Long,
    ): String {
        val header = row("Field", "Value")
        fun kv(k: String, v: String) = row(k, v)
        val lines = mutableListOf(header)
        lines += kv("Period", periodLabel)
        lines += kv("From", formatTs(fromTsNs))
        lines += kv("To", formatTs(toTsNs))
        lines += kv("Balance", margin?.balance?.toString() ?: "--")
        lines += kv("Available balance", margin?.availableBalance?.toString() ?: "--")
        lines += kv("Reserved margin", margin?.reservedMargin?.toString() ?: "--")
        val pos = margin?.position
        if (pos != null) {
            lines += kv("Position symbol", symbolNames[pos.symbolId] ?: ("#" + pos.symbolId))
            lines += kv("Position qty", pos.qty.toString())
            lines += kv("Position entry", pos.entryPrice.toString())
            lines += kv("Position unrealized", pos.unrealizedPnl.toString())
        } else {
            lines += kv("Position", "flat")
        }
        lines += kv("Realized (net)", report.netRealized.toString())
        lines += kv("Total fees", report.totalFees.toString())
        lines += kv("Funding", report.fundingTotal.toString())
        lines += kv("Liquidation PnL", report.liquidationPnl.toString())
        lines += kv("Trades", report.tradeCount.toString())
        lines += kv("Volume", report.volume.toString())
        return document(*lines.toTypedArray())
    }
}
