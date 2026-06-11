package com.testlogon.android.feature.calendar.detail

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-276 — writes a generated `.ics` document to the app cache and hands back a shareable FileProvider
 * content URI. The serialization itself is the pure
 * [com.testlogon.android.data.calendar.ics.Rfc5545IcsSerializer]; this seam owns only the file I/O and
 * the per-URI read grant, behind an injectable so it is never invoked from a composable body.
 *
 * Files live under `cacheDir/ics/` (mapped in `res/xml/file_paths.xml`) and are namespaced
 * `event-{eventId}.ics`, overwritten on re-export. The FileProvider authority is
 * `${applicationId}.fileprovider` (declared once in the manifest).
 */
@Singleton
class IcsExporter @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /** Writes [ics] to `cacheDir/ics/event-{eventId}.ics` and returns its FileProvider content URI. */
    fun writeToCache(eventId: String, ics: String): Uri {
        val dir = File(context.cacheDir, ICS_DIR).apply { mkdirs() }
        val file = File(dir, fileName(eventId))
        file.writeText(ics, Charsets.UTF_8)
        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    private fun fileName(eventId: String): String {
        val safe = eventId.replace(Regex("[^A-Za-z0-9._-]"), "_").take(64).ifBlank { "event" }
        return "event-$safe.ics"
    }

    private companion object {
        const val ICS_DIR = "ics"
    }
}
