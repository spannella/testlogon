package com.testlogon.android.feature.reports

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/** Cap for the EXTRA_TEXT fast-path — larger exports are shared as a file stream only. */
private const val REPORT_TEXT_MAX_CHARS = 8000

/**
 * Android side of the Export & Reporting surface: writes the built CSV [content] to a shareable cache
 * file and hands it to the system share sheet via [Intent.ACTION_SEND] (mime text/csv).
 *
 * The file is written under cacheDir/attachments/ — an already-declared FileProvider cache-path root
 * (res/xml/file_paths.xml is not edited here). The authority is derived from the package name
 * (== ${applicationId}.fileprovider) so it never drifts from the manifest, mirroring the blotter's
 * share path. FLAG_GRANT_READ_URI_PERMISSION lets the receiver read the content:// uri; for small
 * exports the text is also placed in EXTRA_TEXT as a fast path. If the FileProvider grant fails for
 * any reason we fall back to a plain-text ACTION_SEND (EXTRA_TEXT only) so the export still shares.
 * The whole body is wrapped in try/catch so a missing chooser / provider misconfig never crashes.
 */
fun shareReportCsv(context: Context, content: String, baseName: String) {
    if (content.isEmpty()) return
    try {
        val dir = File(context.cacheDir, "attachments").apply { mkdirs() }
        val file = File(dir, "$baseName.csv")
        file.writeText(content)

        val authority = context.packageName + ".fileprovider"
        val uri = FileProvider.getUriForFile(context, authority, file)

        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            if (content.length < REPORT_TEXT_MAX_CHARS) {
                putExtra(Intent.EXTRA_TEXT, content)
            }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startChooser(context, send)
    } catch (_: ActivityNotFoundException) {
        // No share target available (e.g. a bare emulator): swallow so we never crash.
    } catch (_: Exception) {
        // Provider misconfig / IO error: fall back to plain-text sharing so the export still works.
        shareReportText(context, content)
    }
}

/** Plain-text ACTION_SEND fallback (no FileProvider) — used when the file grant path fails. */
private fun shareReportText(context: Context, content: String) {
    try {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, content)
        }
        startChooser(context, send)
    } catch (_: Exception) {
        // Best-effort: never crash the screen.
    }
}

private fun startChooser(context: Context, send: Intent) {
    val chooser = Intent.createChooser(send, "Export report")
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}
