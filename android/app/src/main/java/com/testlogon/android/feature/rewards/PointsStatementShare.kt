package com.testlogon.android.feature.rewards

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/** Cap for the EXTRA_TEXT fast-path — larger exports are shared as a file stream only. */
private const val STATEMENT_TEXT_MAX_CHARS = 8000

/**
 * Android side of the points-statement export: writes the built CSV [content] to a shareable cache file
 * and hands it to the system share sheet via [Intent.ACTION_SEND] (mime text/csv), mirroring the
 * Tax-report share path exactly. The file lives under cacheDir/attachments/ (an already-declared
 * FileProvider cache-path root; res/xml/file_paths.xml is not edited). The authority is derived from the
 * package name so it never drifts from the manifest. Everything is try/caught so a missing chooser /
 * provider misconfig never crashes; a FileProvider failure falls back to a plain-text ACTION_SEND.
 */
fun sharePointsStatementCsv(context: Context, content: String, baseName: String) {
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
            if (content.length < STATEMENT_TEXT_MAX_CHARS) {
                putExtra(Intent.EXTRA_TEXT, content)
            }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startChooser(context, send)
    } catch (_: ActivityNotFoundException) {
        // No share target available (e.g. a bare emulator): swallow so we never crash.
    } catch (_: Exception) {
        // Provider misconfig / IO error: fall back to plain-text sharing so the export still works.
        sharePointsStatementText(context, content)
    }
}

/** Plain-text ACTION_SEND fallback (no FileProvider) — used when the file grant path fails. */
private fun sharePointsStatementText(context: Context, content: String) {
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
    val chooser = Intent.createChooser(send, "Export points statement")
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}

/** Copy the statement CSV to the clipboard (best-effort; never crashes). */
fun copyPointsStatementCsv(context: Context, content: String) {
    if (content.isEmpty()) return
    try {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        clipboard.setPrimaryClip(ClipData.newPlainText("points_statement", content))
    } catch (_: Exception) {
        // Best-effort: never crash the screen.
    }
}
