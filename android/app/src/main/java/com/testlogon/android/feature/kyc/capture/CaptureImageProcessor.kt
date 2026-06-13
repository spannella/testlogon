package com.testlogon.android.feature.kyc.capture

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-321 - processes a captured / picked identity-document image into an upload-ready JPEG.
 *
 * DEPENDENCY-FREE: uses only android.graphics (BitmapFactory / Bitmap / Matrix) and the FRAMEWORK
 * android.media.ExifInterface (NOT androidx.exifinterface, which is NOT a project dependency and is NOT
 * being added this wave). EXIF orientation is best-effort: framework ExifInterface only reads orientation
 * from a file path / FileDescriptor, so for content:// picks we read the stream into a temp file first.
 *
 * Pipeline (all OFF the main thread, Dispatchers.Default for CPU work + Dispatchers.IO for file IO):
 *   1. decode the source (downsampled via inSampleSize for memory safety),
 *   2. rotate per EXIF orientation,
 *   3. downscale so the longest edge is <= [MAX_EDGE_PX] (2048),
 *   4. re-encode JPEG at [JPEG_QUALITY] (85) into the app cache (kyc-capture/),
 *   5. enforce the encoded size is <= [MAX_BYTES] (4 MB) -> otherwise [CaptureError.TooLarge].
 *
 * [encodeBase64] produces the content_b64 body (android.util.Base64 NO_WRAP) off the main thread.
 */
interface CaptureImageProcessor {

    /** Process a [File] source (the live-camera TakePicture output written to a FileProvider Uri). */
    suspend fun process(source: File): ProcessedImage

    /** Process a content:// [Uri] source (the photo-picker / GetContent result). */
    suspend fun process(source: Uri): ProcessedImage

    /** Base64 (NO_WRAP) encode the processed file's bytes for the upload body (off the main thread). */
    suspend fun encodeBase64(file: File): String
}

/** A successfully processed image: the re-encoded JPEG [file] and its encoded [sizeBytes]. */
data class ProcessedImage(
    val file: File,
    val sizeBytes: Long,
)

/** Typed capture/processing failures surfaced inline by the ViewModel (no exception leaks to UI). */
sealed class CaptureError(message: String) : Exception(message) {
    /** The re-encoded image still exceeds [DefaultCaptureImageProcessor.MAX_BYTES]. */
    data class TooLarge(val sizeBytes: Long) : CaptureError("Processed image is too large: $sizeBytes bytes")

    /** The source could not be decoded into a bitmap (corrupt / unsupported / unreadable). */
    data object Unreadable : CaptureError("Could not read the selected image")
}

@Singleton
class DefaultCaptureImageProcessor @Inject constructor(
    @ApplicationContext private val context: Context,
) : CaptureImageProcessor {

    override suspend fun process(source: File): ProcessedImage = withContext(Dispatchers.Default) {
        val bitmap = decodeDownsampled(source.absolutePath) ?: throw CaptureError.Unreadable
        val rotation = orientationDegrees(readExifFromFile(source))
        finish(bitmap, rotation)
    }

    override suspend fun process(source: Uri): ProcessedImage = withContext(Dispatchers.Default) {
        // Framework ExifInterface cannot read a content:// stream's orientation reliably, so copy to a
        // temp file first; decode + EXIF then both work off the same file path.
        val temp = copyToTemp(source)
        try {
            val bitmap = decodeDownsampled(temp.absolutePath) ?: throw CaptureError.Unreadable
            val rotation = orientationDegrees(readExifFromFile(temp))
            finish(bitmap, rotation)
        } finally {
            temp.delete()
        }
    }

    override suspend fun encodeBase64(file: File): String = withContext(Dispatchers.IO) {
        Base64.encodeToString(file.readBytes(), Base64.NO_WRAP)
    }

    /** Rotate (if needed), downscale to MAX_EDGE_PX, re-encode JPEG, enforce the size cap. */
    private suspend fun finish(decoded: Bitmap, rotationDegrees: Int): ProcessedImage {
        val rotated = rotate(decoded, rotationDegrees)
        val scaled = downscale(rotated)
        val out = encodeJpeg(scaled)
        val size = out.length()
        if (size > MAX_BYTES) {
            out.delete()
            throw CaptureError.TooLarge(size)
        }
        return ProcessedImage(file = out, sizeBytes = size)
    }

    private fun decodeDownsampled(path: String): Bitmap? {
        // First pass: bounds only, to compute an inSampleSize that keeps the long edge near MAX_EDGE_PX
        // without decoding a full-resolution bitmap into memory.
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val longEdge = maxOf(bounds.outWidth, bounds.outHeight)
        var sample = 1
        while (longEdge / sample > MAX_EDGE_PX * 2) {
            sample *= 2
        }
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        return BitmapFactory.decodeFile(path, opts)
    }

    private fun rotate(bitmap: Bitmap, degrees: Int): Bitmap {
        if (degrees == 0) return bitmap
        val matrix = Matrix().apply { postRotate(degrees.toFloat()) }
        val rotated = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        if (rotated != bitmap) bitmap.recycle()
        return rotated
    }

    private fun downscale(bitmap: Bitmap): Bitmap {
        val longEdge = maxOf(bitmap.width, bitmap.height)
        if (longEdge <= MAX_EDGE_PX) return bitmap
        val factor = MAX_EDGE_PX.toFloat() / longEdge
        val w = (bitmap.width * factor).toInt().coerceAtLeast(1)
        val h = (bitmap.height * factor).toInt().coerceAtLeast(1)
        val scaled = Bitmap.createScaledBitmap(bitmap, w, h, true)
        if (scaled != bitmap) bitmap.recycle()
        return scaled
    }

    private fun encodeJpeg(bitmap: Bitmap): File {
        val dir = File(context.cacheDir, CACHE_SUBDIR).apply { mkdirs() }
        val out = File(dir, "kyc-doc-${System.currentTimeMillis()}.jpg")
        FileOutputStream(out).use { stream ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, stream)
        }
        return out
    }

    private fun copyToTemp(source: Uri): File {
        val dir = File(context.cacheDir, CACHE_SUBDIR).apply { mkdirs() }
        val temp = File(dir, "kyc-src-${System.currentTimeMillis()}.tmp")
        val input = context.contentResolver.openInputStream(source) ?: throw CaptureError.Unreadable
        input.use { src -> FileOutputStream(temp).use { dst -> src.copyTo(dst) } }
        return temp
    }

    private fun readExifFromFile(file: File): Int = try {
        ExifInterface(file.absolutePath)
            .getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
    } catch (_: Exception) {
        // Best-effort: any EXIF failure degrades to "no rotation" rather than failing the capture.
        ExifInterface.ORIENTATION_NORMAL
    }

    private fun orientationDegrees(exifOrientation: Int): Int = when (exifOrientation) {
        ExifInterface.ORIENTATION_ROTATE_90 -> 90
        ExifInterface.ORIENTATION_ROTATE_180 -> 180
        ExifInterface.ORIENTATION_ROTATE_270 -> 270
        else -> 0
    }

    companion object {
        const val MAX_EDGE_PX = 2048
        const val JPEG_QUALITY = 85
        const val MAX_BYTES = 4L * 1024 * 1024
        const val CACHE_SUBDIR = "kyc-capture"
    }
}
