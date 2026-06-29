package com.testlogon.android.feature.support.ui

import com.testlogon.android.feature.support.data.SupportMediaItem

/**
 * B10 B-HELPMEDIA #5 - one row in a ticket composer's staged-attachment strip. Wraps a resolved
 * [SupportMediaItem] once an upload (or a file-manager pick) succeeds; while a device upload is in
 * flight the row shows a spinner ([uploading]) with no [item] yet. [localId] keys the strip so add /
 * remove are stable across recompositions.
 */
data class StagedMedia(
    val localId: String,
    val uploading: Boolean,
    val item: SupportMediaItem? = null,
    /** A best-effort label shown on the chip while uploading / for non-image files (the file name). */
    val label: String? = null,
    /** The local content-uri string for an image being uploaded, so its preview shows immediately. */
    val localPreview: String? = null,
) {
    /** True when this staged row should render as an inline image thumbnail. */
    val isImage: Boolean get() = item?.isImage ?: (localPreview != null)
}
