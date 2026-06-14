package com.testlogon.android.feature.signing.capture

import androidx.compose.ui.geometry.Offset

/**
 * AND-342 - rasterizes a captured signature (drawn strokes OR typed text) into a transparent PNG.
 *
 * This is a SEAM: the real [AndroidSignatureRasterizer] uses android.graphics (Bitmap / Canvas / Paint /
 * Typeface), which is android-only and therefore NOT on the JVM unit classpath. The ViewModel depends on
 * this interface so JVM tests can inject a fake that returns a stub File. Dependency-free: no signature /
 * ML / vendor SDK and no bundled font files - typed mode uses BUILT-IN [android.graphics.Typeface]
 * families/styles only.
 */
interface SignatureRasterizer {

    /**
     * Rasterizes [strokes] (a list of polylines; each polyline a list of normalized-to-canvas points) to
     * a transparent ARGB PNG of [widthPx] x [heightPx] and returns the written file.
     */
    suspend fun rasterizeStrokes(
        strokes: List<List<Offset>>,
        widthPx: Int,
        heightPx: Int,
    ): java.io.File

    /**
     * Rasterizes [text] in one of the built-in font styles selected by [fontStyleIndex] to a transparent
     * PNG of [widthPx] x [heightPx] and returns the written file.
     */
    suspend fun rasterizeTyped(
        text: String,
        fontStyleIndex: Int,
        widthPx: Int,
        heightPx: Int,
    ): java.io.File
}

/** The number of built-in typed-signature font styles offered (used to bound [fontStyleIndex]). */
const val TYPED_FONT_STYLE_COUNT: Int = 3
