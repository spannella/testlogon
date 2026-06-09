package com.testlogon.android.feature.profile.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import com.testlogon.android.data.profile.ProfileMediaUploader
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import javax.inject.Inject

/**
 * AND-074 — decodes a picked image, applies EXIF orientation, downscales, and re-encodes to JPEG
 * (which drops EXIF GPS/location tags). Produces a [ProfileMediaUploader.PreparedUpload] of bytes,
 * keeping the network uploader decoupled from Android image APIs.
 *
 * Runtime-only (uses BitmapFactory / ExifInterface), so it is not exercised by JVM unit tests.
 */
class ProfileImageProcessor @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    suspend fun process(
        source: Uri,
        maxEdgePx: Int = DEFAULT_MAX_EDGE,
    ): ProfileMediaUploader.PreparedUpload = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver

        // Pass 1: bounds only, to compute a safe inSampleSize and avoid OOM on large gallery images.
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        resolver.openInputStream(source)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        val sample = computeInSampleSize(bounds.outWidth, bounds.outHeight, maxEdgePx)

        val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
        val decoded = resolver.openInputStream(source)?.use {
            BitmapFactory.decodeStream(it, null, decodeOpts)
        } ?: error("Unable to decode image")

        val rotation = resolver.openInputStream(source)?.use { readExifRotation(it) } ?: 0
        val oriented = applyRotation(decoded, rotation)
        val scaled = scaleToMaxEdge(oriented, maxEdgePx)

        val bytes = encodeJpegUnder(scaled, MAX_BYTES)
        if (scaled !== decoded) decoded.recycle()

        ProfileMediaUploader.PreparedUpload(bytes = bytes, contentType = "image/jpeg", fileName = "photo.jpg")
    }

    private fun readExifRotation(input: java.io.InputStream): Int = try {
        when (ExifInterface(input).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)) {
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

    /** Re-encodes to JPEG, stepping quality down until the result fits under [maxBytes]. */
    private fun encodeJpegUnder(bitmap: Bitmap, maxBytes: Int): ByteArray {
        for (quality in intArrayOf(85, 70, 60)) {
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
            val bytes = out.toByteArray()
            if (bytes.size <= maxBytes) return bytes
        }
        // Final attempt at the lowest quality regardless of size.
        return ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.JPEG, 50, it) }.toByteArray()
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
        const val DEFAULT_MAX_EDGE = 1024
        const val MAX_BYTES = 5 * 1024 * 1024
    }
}
