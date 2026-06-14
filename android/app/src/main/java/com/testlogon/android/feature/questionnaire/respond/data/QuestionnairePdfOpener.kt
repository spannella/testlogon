package com.testlogon.android.feature.questionnaire.respond.data

import android.content.Context
import com.testlogon.android.data.files.download.CachedFile
import com.testlogon.android.data.files.download.OpenWithLauncher
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-349 - opens the downloaded questionnaire-response PDF in an external app via the system chooser.
 *
 * REUSE: wraps AND-334's [OpenWithLauncher] (FileProvider content:// URI + ACTION_VIEW with a transient
 * read grant, chooser then share fallbacks). The PDF bytes are streamed to cacheDir/questionnaire-pdf by
 * RespondentSessionRepository BEFORE this is called, so this only builds the open-with intent. This lives
 * on the screen side (it needs a Context); the ViewModel stays Context-free and JVM-testable.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@Singleton
class QuestionnairePdfOpener @Inject constructor(
    private val openWithLauncher: OpenWithLauncher,
) {

    /** Hands [file] (the cached response PDF) to an external viewer via FileProvider + the system chooser. */
    fun open(context: Context, file: File): OpenWithLauncher.OpenResult {
        val cached = CachedFile(
            path = file.path,
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
