package com.testlogon.android.data.messaging

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import com.testlogon.android.feature.messaging.media.AttachmentMime
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import javax.inject.Inject

/** AND-130 — the processed image ready to upload (compressed, EXIF-applied, GPS-stripped). */
data class ProcessedImage(
    /** A `file://` uri the AND-129 uploader streams from. */
    val uri: Uri,
    val mimeType: String,
    val width: Int,
    val height: Int,
    val byteSize: Long,
)

/** AND-130 — image-processing seam, faked in repository unit tests. */
interface MessageImageProcessor {
    /** Returns the processed image, or null if the source cannot be decoded. */
    suspend fun process(source: Uri): ProcessedImage?
}

/**
 * AND-130 — decodes a picked image, applies EXIF orientation, downscales the longest edge to
 * <= 2048 px, re-encodes to JPEG (which drops EXIF GPS/maker tags) stepping quality down until the
 * output is <= 5 MB, and writes it to app-private cacheDir. Returns a [ProcessedImage] referencing
 * the temp file.
 *
 * Runtime-only (BitmapFactory/ExifInterface/ContentResolver); the pure mime/quality rules live in
 * [AttachmentMime] and are unit-tested there. Pixel-level processing is exercised on-device.
 */
class DefaultMessageImageProcessor @Inject constructor(
    @ApplicationContext private val context: Context,
) : MessageImageProcessor {

    override suspend fun process(source: Uri): ProcessedImage? = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver

        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        resolver.openInputStream(source)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return@withContext null

        val sample = computeInSampleSize(bounds.outWidth, bounds.outHeight, MAX_EDGE)
        val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
        val decoded = resolver.openInputStream(source)?.use {
            BitmapFactory.decodeStream(it, null, decodeOpts)
        } ?: return@withContext null

        val rotation = resolver.openInputStream(source)?.use { readExifRotation(it) } ?: 0
        val oriented = applyRotation(decoded, rotation)
        val scaled = scaleToMaxEdge(oriented, MAX_EDGE)

        val mime = AttachmentMime.outputImageMime(resolver.getType(source), sourceHasAlpha = scaled.hasAlpha())
        val out = File(imagesDir(), AttachmentMime.defaultFileName(mime))
        val bytes = encodeUnder(scaled, mime, MAX_BYTES)
        FileOutputStream(out).use { it.write(bytes) }

        val width = scaled.width
        val height = scaled.height
        if (scaled !== decoded) decoded.recycle()

        ProcessedImage(
            uri = Uri.fromFile(out),
            mimeType = mime,
            width = width,
            height = height,
            byteSize = out.length(),
        )
    }

    private fun imagesDir(): File = File(context.cacheDir, "message-images").apply { mkdirs() }

    private fun readExifRotation(input: java.io.InputStream): Int = try {
        when (
            ExifInterface(input)
                .getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
        ) {
            ExifInterface.ORIENTATION_ROTATE_90 -> 90
            ExifInterface.ORIENTATION_ROTATE_180 -> 180
            ExifInterface.ORIENTATION_ROTATE_270 -> 270
            else -> 0
        }
    } catch (_: Exception) {
        0
    }

    private fun applyRotation(bitmap: Bitmap, degrees: Int): Bitmap {
        if (degrees == 0) return bitmap
        val matrix = Matrix().apply { postRotate(degrees.toFloat()) }
        return Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
    }

    private fun scaleToMaxEdge(bitmap: Bitmap, maxEdge: Int): Bitmap {
        val longest = maxOf(bitmap.width, bitmap.height)
        if (longest <= maxEdge) return bitmap
        val factor = maxEdge.toFloat() / longest
        return Bitmap.createScaledBitmap(
            bitmap,
            (bitmap.width * factor).toInt().coerceAtLeast(1),
            (bitmap.height * factor).toInt().coerceAtLeast(1),
            true,
        )
    }

    private fun encodeUnder(bitmap: Bitmap, mime: String, maxBytes: Long): ByteArray {
        if (mime == "image/png") {
            return java.io.ByteArrayOutputStream()
                .also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
                .toByteArray()
        }
        for (pass in 0..3) {
            val out = java.io.ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, AttachmentMime.qualityForPass(pass), out)
            val bytes = out.toByteArray()
            if (bytes.size <= maxBytes) return bytes
        }
        return java.io.ByteArrayOutputStream()
            .also { bitmap.compress(Bitmap.CompressFormat.JPEG, 50, it) }
            .toByteArray()
    }

    private fun computeInSampleSize(width: Int, height: Int, maxEdge: Int): Int {
        if (width <= 0 || height <= 0) return 1
        var sample = 1
        var longest = maxOf(width, height)
        while (longest / 2 >= maxEdge) {
            longest /= 2
            sample *= 2
        }
        return sample
    }

    private companion object {
        const val MAX_EDGE = 2048
        const val MAX_BYTES = 5L * 1024L * 1024L
    }
}
