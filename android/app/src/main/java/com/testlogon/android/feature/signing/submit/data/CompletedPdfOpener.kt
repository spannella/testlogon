package com.testlogon.android.feature.signing.submit.data

import android.content.Context
import com.testlogon.android.data.files.download.CachedFile
import com.testlogon.android.data.files.download.OpenWithLauncher
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-343 - opens the already-downloaded completed PDF in an external viewer.
 *
 * REUSE: wraps AND-331/AND-334's [OpenWithLauncher] (FileProvider content:// URI + ACTION_VIEW with a
 * transient read grant, chooser then share fallbacks). The PDF bytes are streamed to cache by AND-341's
 * PdfSource (the SAME final-pdf endpoint) BEFORE this is called, so this only builds the open-with
 * intent. This lives on the screen side (it needs a Context); the ViewModel stays Context-free and
 * JVM-testable.
 */
@Singleton
class CompletedPdfOpener @Inject constructor(
    private val openWithLauncher: OpenWithLauncher,
) {

    /** Hands [file] (the cached completed PDF for [packetId]) to an external viewer via FileProvider. */
    fun open(context: Context, packetId: String, file: File): OpenWithLauncher.OpenResult {
        val cached = CachedFile(
            path = packetId,
            file = file,
            mimeType = PDF_MIME,
            displayName = file.name,
        )
        return openWithLauncher.open(context, cached)
    }

    private companion object {
        const val PDF_MIME = "application/pdf"
    }
}
