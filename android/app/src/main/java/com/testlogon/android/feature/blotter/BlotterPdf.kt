package com.testlogon.android.feature.blotter

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import java.io.ByteArrayOutputStream

/**
 * Pure-ish (only android.graphics) PDF renderer for the Trading Blotter Orders/Fills view.
 *
 * It draws the SAME rows the CSV/TSV export uses ([exportRows]) with the SAME per-cell/per-header
 * formatters ([cellText] / [headerLabel]) and the SAME visible column set + order the table shows,
 * so a PDF can never diverge from what the user sees. No third-party dependency — this uses the
 * built-in [PdfDocument] + [Canvas]/[Paint].
 *
 * Layout: an A4-ish portrait page (595 x 842 pt). A title line, then a header row, then data rows;
 * a new page is started (and the header repeated) whenever rows overflow the page. Column x-spans
 * are proportional to each column's weight ([weightOf], which routes through the resize overrides),
 * numeric columns are right-aligned, and long cell text is clipped to its column so cells never
 * overrun their neighbour. The whole render is wrapped so it can never throw.
 */
private const val PAGE_W = 595
private const val PAGE_H = 842
private const val MARGIN = 32f
private const val TITLE_SIZE = 14f
private const val HEADER_SIZE = 8.5f
private const val CELL_SIZE = 8f
private const val ROW_H = 14f
private const val CELL_PAD = 3f

/**
 * Render [orders] to PDF bytes. Returns an empty [ByteArray] on any failure (caller no-ops).
 *
 * @param weightOf the effective layout weight for a column (defaults to the descriptor weight);
 *   pass state::effectiveWeight to honor user column-resize overrides.
 */
fun renderBlotterPdf(
    orders: List<BlotterOrder>,
    columns: List<BlotterColumn>,
    fillsMode: Boolean,
    title: String,
    weightOf: (BlotterColumn) -> Float = { it.weight },
): ByteArray {
    if (columns.isEmpty()) return ByteArray(0)
    val doc = PdfDocument()
    try {
        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            textSize = TITLE_SIZE
        }
        val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            textSize = HEADER_SIZE
        }
        val cellPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.MONOSPACE
            textSize = CELL_SIZE
        }
        val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            strokeWidth = 0.5f
            color = 0xFFBBBBBB.toInt()
        }

        val contentW = PAGE_W - 2 * MARGIN
        val totalWeight = columns.sumOf { weightOf(it).toDouble() }.toFloat().let { if (it <= 0f) 1f else it }
        // Left x-edge of each column (parallel to [columns]).
        val edges = FloatArray(columns.size + 1)
        edges[0] = MARGIN
        for (i in columns.indices) {
            edges[i + 1] = edges[i] + contentW * (weightOf(columns[i]) / totalWeight)
        }

        var pageNo = 1
        var page = doc.startPage(PdfDocument.PageInfo.Builder(PAGE_W, PAGE_H, pageNo).create())
        var canvas = page.canvas
        var y = MARGIN + TITLE_SIZE

        // Title.
        canvas.drawText(clip(title, titlePaint, contentW), MARGIN, y, titlePaint)
        y += ROW_H + 4f

        fun drawHeader() {
            for (i in columns.indices) {
                val col = columns[i]
                val cellW = edges[i + 1] - edges[i] - 2 * CELL_PAD
                val label = clip(headerLabel(col, fillsMode), headerPaint, cellW)
                drawAligned(canvas, label, headerPaint, edges[i], edges[i + 1], y, col.numeric)
            }
            y += 2f
            canvas.drawLine(MARGIN, y, PAGE_W - MARGIN, y, linePaint)
            y += ROW_H
        }

        drawHeader()

        for (o in orders) {
            if (y > PAGE_H - MARGIN) {
                doc.finishPage(page)
                pageNo += 1
                page = doc.startPage(PdfDocument.PageInfo.Builder(PAGE_W, PAGE_H, pageNo).create())
                canvas = page.canvas
                y = MARGIN + TITLE_SIZE
                drawHeader()
            }
            for (i in columns.indices) {
                val col = columns[i]
                val cellW = edges[i + 1] - edges[i] - 2 * CELL_PAD
                val text = clip(cellText(col, o, fillsMode), cellPaint, cellW)
                drawAligned(canvas, text, cellPaint, edges[i], edges[i + 1], y, col.numeric)
            }
            y += ROW_H
        }

        doc.finishPage(page)

        val out = ByteArrayOutputStream()
        doc.writeTo(out)
        return out.toByteArray()
    } catch (_: Throwable) {
        return ByteArray(0)
    } finally {
        doc.close()
    }
}

/** Draw [text] left- or right-aligned within the [left]..[right] column span at baseline [y]. */
private fun drawAligned(
    canvas: Canvas,
    text: String,
    paint: Paint,
    left: Float,
    right: Float,
    y: Float,
    numeric: Boolean,
) {
    if (numeric) {
        val w = paint.measureText(text)
        canvas.drawText(text, right - CELL_PAD - w, y, paint)
    } else {
        canvas.drawText(text, left + CELL_PAD, y, paint)
    }
}

/** Clip [text] to fit [maxWidth] with the given [paint], appending an ellipsis when truncated. */
private fun clip(text: String, paint: Paint, maxWidth: Float): String {
    if (maxWidth <= 0f) return ""
    if (paint.measureText(text) <= maxWidth) return text
    var end = text.length
    while (end > 0 && paint.measureText(text.substring(0, end) + "…") > maxWidth) {
        end -= 1
    }
    return if (end <= 0) "" else text.substring(0, end) + "…"
}
