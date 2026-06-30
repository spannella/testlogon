package com.testlogon.android.testseam

import android.content.ContentProvider
import android.content.ContentValues
import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.FileOutputStream

/**
 * DEBUG-ONLY test seam (app/src/debug). Exposes the bundled sample media under
 * app/src/debug/assets/test_media/ as content:// URIs so the apps real upload/read code
 * (which calls contentResolver.openInputStream + queries OpenableColumns) can consume the
 * seeded picker results exactly like a system-picked file.
 *
 * Authority: applicationId + ".testmedia" (declared in app/src/debug/AndroidManifest.xml).
 * URI shape: content://AUTHORITY/assetFileName  e.g. content://...testmedia/sample.jpg
 *
 * This provider has NO gate of its own: it is only present in debug builds, and nothing in
 * the app ever resolves these URIs unless the TestPickRegistry seam (also gated) dispatches
 * them. Resolving a URI here is harmless (just reads a bundled asset).
 */
class TestMediaProvider : ContentProvider() {

    companion object {
        const val ASSET_DIR = "test_media"

        fun uriFor(authority: String, assetName: String): Uri =
            Uri.parse("content://" + authority + "/" + assetName)
    }

    private fun assetName(uri: Uri): String? = uri.lastPathSegment

    private fun mimeOf(name: String): String = when {
        name.endsWith(".jpg", true) || name.endsWith(".jpeg", true) -> "image/jpeg"
        name.endsWith(".png", true) -> "image/png"
        name.endsWith(".mp4", true) -> "video/mp4"
        name.endsWith(".pdf", true) -> "application/pdf"
        else -> "application/octet-stream"
    }

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = assetName(uri)?.let(::mimeOf)

    /**
     * Open the bundled asset for reading. Tries a direct AssetFileDescriptor (uncompressed assets);
     * for compressed assets that cannot return an fd, streams the bytes through a pipe so the
     * caller still gets a readable descriptor.
     */
    override fun openAssetFile(uri: Uri, mode: String): AssetFileDescriptor? {
        val name = assetName(uri) ?: return null
        val am = context!!.assets
        val path = ASSET_DIR + "/" + name
        return try {
            am.openFd(path)
        } catch (_: Throwable) {
            val pipe = ParcelFileDescriptor.createPipe()
            val readSide = pipe[0]
            val writeSide = pipe[1]
            Thread {
                try {
                    FileOutputStream(writeSide.fileDescriptor).use { out ->
                        am.open(path).use { input -> input.copyTo(out) }
                    }
                } catch (_: Throwable) {
                } finally {
                    try { writeSide.close() } catch (_: Throwable) {}
                }
            }.start()
            AssetFileDescriptor(readSide, 0, AssetFileDescriptor.UNKNOWN_LENGTH)
        }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        val name = assetName(uri) ?: return null
        val size: Long = try {
            context!!.assets.openFd(ASSET_DIR + "/" + name).use { it.length }
        } catch (t: Throwable) {
            try {
                context!!.assets.open(ASSET_DIR + "/" + name).use { input ->
                    var total = 0L
                    val buf = ByteArray(8192)
                    while (true) {
                        val r = input.read(buf)
                        if (r < 0) break
                        total += r
                    }
                    total
                }
            } catch (_: Throwable) {
                0L
            }
        }
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = MatrixCursor(cols)
        val row = cursor.newRow()
        for (c in cols) {
            when (c) {
                OpenableColumns.DISPLAY_NAME -> row.add(name)
                OpenableColumns.SIZE -> row.add(size)
                else -> row.add(null)
            }
        }
        return cursor
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
