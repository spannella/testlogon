package com.testlogon.android.feature.signing.submit.data

import com.testlogon.android.feature.signing.submit.model.AssetBytesReader
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-343 - production [AssetBytesReader]: reads a captured signature/initials PNG (an absolute cache
 * path written by the AND-342 rasterizer) into a byte array for base64 encoding in the fill request.
 *
 * It uses ONLY java.io (NO android.graphics / Bitmap / android.util.Base64), so the request-builder it
 * feeds stays dependency-free and JVM-testable. A blank / missing / unreadable path degrades to null
 * (never throws); the request-builder then omits the image from render_payload.
 */
@Singleton
class FileAssetBytesReader @Inject constructor() : AssetBytesReader {

    override fun read(path: String): ByteArray? {
        if (path.isBlank()) return null
        val file = File(path)
        if (!file.isFile) return null
        return try {
            file.readBytes()
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }
}
