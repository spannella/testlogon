package com.testlogon.android.feature.blotter

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Android side of the Trading Blotter export: writes the rendered CSV/TSV [content] to a shareable
 * cache file and hands it to the system share sheet via [Intent.ACTION_SEND].
 *
 * The file is written under cacheDir/attachments/ — the ONLY appropriate already-declared
 * FileProvider cache-path root (res/xml/file_paths.xml is outside this feature and not edited here).
 * The authority is derived from the package name (== ${applicationId}.fileprovider) so it never
 * drifts from the manifest. FLAG_GRANT_READ_URI_PERMISSION is set so the receiver can read the
 * content:// uri. For small exports the text is also placed in EXTRA_TEXT as a fast path. The whole
 * body is wrapped in try/catch so a missing chooser or provider misconfig never crashes the screen.
 */
fun shareBlotterExport(context: Context, content: String, baseName: String, tsv: Boolean) {
    try {
        val dir = File(context.cacheDir, "attachments").apply { mkdirs() }
        val fileName = baseName + (if (tsv) ".tsv" else ".csv")
        val file = File(dir, fileName)
        file.writeText(content)

        val authority = context.packageName + ".fileprovider"
        val uri = FileProvider.getUriForFile(context, authority, file)
        val mime = if (tsv) "text/tab-separated-values" else "text/csv"

        val send = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            // Fast path for small sets: also carry the text inline for text-only receivers.
            if (content.length < EXPORT_TEXT_MAX_CHARS) {
                putExtra(Intent.EXTRA_TEXT, content)
            }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val chooser = Intent.createChooser(send, "Export blotter")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
    } catch (_: ActivityNotFoundException) {
        // No share target available (e.g. a bare emulator): swallow so we never crash.
    } catch (_: Exception) {
        // Provider misconfig / IO error: fail closed, export is best-effort.
    }
}
