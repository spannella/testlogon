package com.testlogon.android.data.files.download

import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-334 - hands a downloaded [CachedFile] to an external app.
 *
 * OPEN-WITH reuses the existing FileProvider (authority "applicationId.fileprovider", the AND-321 /
 * upload one): a content:// URI is built for the cached file and an ACTION_VIEW intent is launched
 * with a transient read grant. If no activity resolves the typed VIEW, it falls back to a chooser,
 * then to an ACTION_SEND share; if nothing can handle it at all, the caller is told via the returned
 * [OpenResult.NoApp] so the UI can surface a "no app can open this" message.
 *
 * SAVE-TO-DOWNLOADS copies the bytes into the public Downloads collection: via MediaStore.Downloads
 * on Android 10+ (scoped storage, no permission) and the legacy public Downloads directory below 10.
 * Both are best-effort and return success / failure.
 *
 * The MIME type comes from the source node (the download endpoint advertises a misleading
 * application/json content-type), defaulting to a wildcard when blank.
 */
@Singleton
class OpenWithLauncher @Inject constructor() {

    /** Outcome of an open-with attempt. */
    sealed interface OpenResult {
        /** An external activity (view / chooser / share) was launched. */
        data object Launched : OpenResult

        /** No installed app could handle the file at all. */
        data object NoApp : OpenResult
    }

    /** Builds the FileProvider content URI for [cached]. */
    private fun contentUri(context: Context, cached: CachedFile): Uri =
        FileProvider.getUriForFile(context, authority(context), cached.file)

    /** Launches an ACTION_VIEW open-with for [cached], with chooser then share fallbacks. */
    fun open(context: Context, cached: CachedFile): OpenResult {
        val uri = contentUri(context, cached)
        val mime = cached.mimeType.ifBlank { WILDCARD_MIME }

        val view = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, mime)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        if (tryStart(context, view)) return OpenResult.Launched

        // Fall back to an explicit chooser over the same VIEW intent.
        val chooser = Intent.createChooser(view, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (tryStart(context, chooser)) return OpenResult.Launched

        // Last resort: share the file out via ACTION_SEND.
        val send = Intent(Intent.ACTION_SEND)
            .setType(mime)
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val shareChooser = Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (tryStart(context, shareChooser)) return OpenResult.Launched

        return OpenResult.NoApp
    }

    /** Copies [cached] into the public Downloads collection. Best-effort; returns success. */
    fun saveToDownloads(context: Context, cached: CachedFile): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            saveViaMediaStore(context, cached)
        } else {
            saveViaPublicDir(cached)
        }
    } catch (_: IOException) {
        false
    } catch (_: SecurityException) {
        false
    }

    private fun saveViaMediaStore(context: Context, cached: CachedFile): Boolean {
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, cached.displayName)
            if (cached.mimeType.isNotBlank()) put(MediaStore.Downloads.MIME_TYPE, cached.mimeType)
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val target = resolver.insert(collection, values) ?: return false
        resolver.openOutputStream(target)?.use { out ->
            cached.file.inputStream().use { it.copyTo(out) }
        } ?: return false
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(target, values, null, null)
        return true
    }

    private fun saveViaPublicDir(cached: CachedFile): Boolean {
        @Suppress("DEPRECATION")
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!downloads.exists() && !downloads.mkdirs()) return false
        val target = uniqueIn(downloads, cached.displayName)
        cached.file.inputStream().use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return true
    }

    /** Picks a non-colliding file name in [dir] for [name] (appends " (n)" before the extension). */
    private fun uniqueIn(dir: File, name: String): File {
        var candidate = File(dir, name)
        if (!candidate.exists()) return candidate
        val dot = name.lastIndexOf('.')
        val base = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        var n = 1
        while (candidate.exists()) {
            candidate = File(dir, "$base ($n)$ext")
            n++
        }
        return candidate
    }

    private fun tryStart(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    }

    private fun authority(context: Context): String = "${context.packageName}$FILE_PROVIDER_SUFFIX"

    private companion object {
        const val FILE_PROVIDER_SUFFIX = ".fileprovider"
        const val WILDCARD_MIME = "application/octet-stream"
    }
}
