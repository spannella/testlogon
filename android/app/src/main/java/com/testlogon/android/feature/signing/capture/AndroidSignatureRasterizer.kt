package com.testlogon.android.feature.signing.capture

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.ui.geometry.Offset
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-342 - the production [SignatureRasterizer] over BUILT-IN android.graphics only.
 *
 * ANDROID-ONLY: this impl uses [Bitmap] / [Canvas] / [Paint] / [Typeface], which are not on the JVM unit
 * classpath, so it is NOT JVM-unit-tested - the ViewModel test injects a fake rasterizer instead. The
 * pure geometry / draft math is covered by JVM tests separately.
 *
 * Dependency-free: transparent ARGB_8888 bitmaps, strokes drawn as anti-aliased polylines, typed mode
 * using the three built-in [Typeface] styles (no bundled font files). PNGs are written under
 * cacheDir/signatures and reused via the FileProvider cache convention (no Room, no migration).
 */
@Singleton
class AndroidSignatureRasterizer @Inject constructor(
    @ApplicationContext private val context: Context,
) : SignatureRasterizer {

    override suspend fun rasterizeStrokes(
        strokes: List<List<Offset>>,
        widthPx: Int,
        heightPx: Int,
    ): File = withContext(Dispatchers.IO) {
        val w = widthPx.coerceAtLeast(1)
        val h = heightPx.coerceAtLeast(1)
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        // Transparent background (no fill); draw each polyline as a connected anti-aliased path.
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.BLACK
            style = Paint.Style.STROKE
            strokeWidth = STROKE_WIDTH_PX
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
        for (polyline in strokes) {
            if (polyline.isEmpty()) continue
            if (polyline.size == 1) {
                val p = polyline.first()
                canvas.drawPoint(p.x, p.y, paint)
                continue
            }
            for (i in 0 until polyline.size - 1) {
                val a = polyline[i]
                val b = polyline[i + 1]
                canvas.drawLine(a.x, a.y, b.x, b.y, paint)
            }
        }
        writePng(bitmap, "sig")
    }

    override suspend fun rasterizeTyped(
        text: String,
        fontStyleIndex: Int,
        widthPx: Int,
        heightPx: Int,
    ): File = withContext(Dispatchers.IO) {
        val w = widthPx.coerceAtLeast(1)
        val h = heightPx.coerceAtLeast(1)
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.BLACK
            typeface = builtInTypeface(fontStyleIndex)
            textAlign = Paint.Align.CENTER
        }
        // Fit the text to the box width by shrinking the text size until it fits (single pass downscale).
        var size = h * TEXT_HEIGHT_FRACTION
        paint.textSize = size
        val safeText = text.ifBlank { " " }
        val maxWidth = w * TEXT_WIDTH_FRACTION
        while (paint.measureText(safeText) > maxWidth && size > MIN_TEXT_SIZE_PX) {
            size -= TEXT_SHRINK_STEP_PX
            paint.textSize = size
        }
        val metrics = paint.fontMetrics
        val baseline = h / 2f - (metrics.ascent + metrics.descent) / 2f
        canvas.drawText(safeText, w / 2f, baseline, paint)
        writePng(bitmap, "typed")
    }

    /** One of the three built-in typed-signature styles (no bundled fonts). */
    private fun builtInTypeface(index: Int): Typeface = when (index.mod(TYPED_FONT_STYLE_COUNT)) {
        0 -> Typeface.create(Typeface.SERIF, Typeface.ITALIC)
        1 -> Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        else -> Typeface.create(Typeface.MONOSPACE, Typeface.BOLD_ITALIC)
    }

    private fun writePng(bitmap: Bitmap, prefix: String): File {
        val dir = File(context.cacheDir, "signatures").apply { mkdirs() }
        val file = File(dir, "${prefix}_${System.nanoTime()}.png")
        FileOutputStream(file).use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, PNG_QUALITY, out)
        }
        bitmap.recycle()
        return file
    }

    private companion object {
        const val STROKE_WIDTH_PX = 6f
        const val TEXT_HEIGHT_FRACTION = 0.6f
        const val TEXT_WIDTH_FRACTION = 0.92f
        const val MIN_TEXT_SIZE_PX = 8f
        const val TEXT_SHRINK_STEP_PX = 2f
        const val PNG_QUALITY = 100
    }
}
