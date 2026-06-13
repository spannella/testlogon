package com.testlogon.android.feature.signing.document.model

import androidx.compose.ui.geometry.Rect

/**
 * AND-341 - domain + UI state for the packet PDF document viewer (the scrollable, zoomable multi-page
 * viewer opened from the AND-340 packet detail "Open document" affordance).
 *
 * REUSE: the PDF bytes come from AND-339's SigningApi.downloadFinalPdf (the only streamed PDF endpoint);
 * rendering uses the BUILT-IN android.graphics.pdf.PdfRenderer (no third-party PDF dependency). The
 * per-page geometry ([PageOnScreen]) is the seam AND-342 consumes to overlay signature fields.
 */

/** Identifies the document to view: the owning [packetId] plus a human display name for the title. */
data class DocumentRef(
    val packetId: String,
    val displayName: String,
)

/**
 * The intrinsic geometry of one PDF page in PDF points (1 pt == 1/72 inch), read once from the
 * renderer. [index] is 0-based. The width/height drive the correct-aspect placeholder + the rendered
 * bitmap's target height, and are the basis for mapping AND-342 field coordinates onto the page.
 */
data class PageLayout(
    val index: Int,
    val widthPts: Float,
    val heightPts: Float,
) {
    /** Page aspect (height divided by width); guarded against a zero width. */
    val aspectRatio: Float
        get() = if (widthPts > 0f) heightPts / widthPts else 0f

    /** The target render/placeholder height for a given on-screen page width, preserving aspect. */
    fun heightForWidth(targetWidthPx: Int): Int =
        if (widthPts > 0f) (targetWidthPx * aspectRatio).toInt() else 0
}

/**
 * One rendered page's bounds in the scroll content's pixel space (NOT screen space). AND-342 overlays
 * each field by mapping its normalized/point coordinates within this [contentRect]. The list is
 * assembled from each item's onGloballyPositioned bounds and surfaced via the screen's onPageLayout.
 */
data class PageOnScreen(
    val index: Int,
    val contentRect: Rect,
)

/** The sealed UI state for the document viewer. */
sealed interface DocumentUiState {

    /** Downloading the PDF and opening the renderer. */
    data object Loading : DocumentUiState

    /**
     * The PDF is downloaded + opened. [pages] carries one [PageLayout] per page (size == [pageCount]).
     * [isStale] is reserved for a re-download-on-stale-cache hint (kept false here; cache reuse is
     * silent). Individual page bitmaps are requested lazily by the screen as they scroll into view.
     */
    data class Ready(
        val ref: DocumentRef,
        val pageCount: Int,
        val pages: List<PageLayout>,
        val isStale: Boolean = false,
    ) : DocumentUiState

    /** A terminal error (download / corrupt PDF / open failure). [retryable] gates the Retry action. */
    data class Error(
        val message: String,
        val retryable: Boolean,
    ) : DocumentUiState
}
