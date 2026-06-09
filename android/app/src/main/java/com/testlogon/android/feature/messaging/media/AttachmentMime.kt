package com.testlogon.android.feature.messaging.media

/**
 * AND-130 / AND-131 — pure, JVM-testable MIME / type decisions for message attachments. No Android
 * types here so the rules are unit-testable; the runtime processors call into this.
 */
object AttachmentMime {

    private const val JPEG = "image/jpeg"
    private const val PNG = "image/png"

    /** Whether a MIME type is an image we render in an image bubble. */
    fun isImage(mime: String?): Boolean = mime?.startsWith("image/") == true

    /** Whether a MIME type is a video. */
    fun isVideo(mime: String?): Boolean = mime?.startsWith("video/") == true

    /**
     * The output MIME the image processor will encode to. PNG is preserved only for sources that
     * have alpha (so transparency survives); everything else re-encodes to JPEG.
     */
    fun outputImageMime(sourceMime: String?, sourceHasAlpha: Boolean): String =
        if (sourceHasAlpha && sourceMime == PNG) PNG else JPEG

    /** The file extension matching an output image MIME. */
    fun extensionFor(mime: String): String = when (mime) {
        PNG -> "png"
        else -> "jpg"
    }

    /** A safe default filename for an upload of [mime]. */
    fun defaultFileName(mime: String): String = "upload_${System.currentTimeMillis()}.${extensionFor(mime)}"

    /** Picks the JPEG quality tier for a given pass index (0-based), flooring at 50. */
    fun qualityForPass(pass: Int): Int = when (pass) {
        0 -> 80
        1 -> 70
        2 -> 60
        else -> 50
    }
}
