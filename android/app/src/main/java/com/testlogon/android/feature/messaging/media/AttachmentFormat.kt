package com.testlogon.android.feature.messaging.media

import java.util.Locale

/**
 * AND-132 / AND-133 — pure, JVM-testable formatting + type decisions for file & voice messages. No
 * Android types (no android.text.format.Formatter, no java.time) so the rules are unit-testable; the
 * @Composable / runtime code calls into this.
 */
object AttachmentFormat {

    /**
     * Human-readable file size, binary (1024) units, locale-aware decimals. Mirrors the look of
     * android.text.format.Formatter.formatShortFileSize without the Android dependency so it is
     * unit-testable. Negative/unknown sizes render as an empty string.
     */
    fun fileSize(bytes: Long?): String {
        if (bytes == null || bytes < 0L) return ""
        if (bytes < 1024L) return "$bytes B"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble() / 1024.0
        var unitIdx = 0
        while (value >= 1024.0 && unitIdx < units.size - 1) {
            value /= 1024.0
            unitIdx++
        }
        // One decimal under 10, none at/above 10 (matches the common short-form style).
        val pattern = if (value < 10.0) "%.1f %s" else "%.0f %s"
        return String.format(Locale.getDefault(), pattern, value, units[unitIdx])
    }

    /** mm:ss for a clip/playback position in milliseconds (clamped at 0). */
    fun duration(millis: Long): String {
        val totalSeconds = (millis.coerceAtLeast(0L)) / 1000L
        val minutes = totalSeconds / 60L
        val seconds = totalSeconds % 60L
        return String.format(Locale.getDefault(), "%d:%02d", minutes, seconds)
    }

    /** mm:ss for a duration expressed in (possibly fractional) seconds. */
    fun durationSeconds(seconds: Double): String = duration((seconds * 1000.0).toLong())

    /**
     * The wire `kind` for a generic file attachment derived from its MIME type. The backend accepts
     * "file" | "audio" | "video" on the file endpoint; everything that is not audio/video is "file".
     */
    fun fileKindForMime(mime: String?): String = when {
        mime == null -> "file"
        mime.startsWith("audio/") -> "audio"
        mime.startsWith("video/") -> "file" // video uses the dedicated video flow; keep file-only here
        else -> "file"
    }

    /** A coarse icon category for a file MIME, used to pick the bubble icon (no Android types). */
    fun iconCategory(mime: String?, fileName: String?): FileIconCategory {
        val byMime = when {
            mime == null -> null
            mime.startsWith("image/") -> FileIconCategory.IMAGE
            mime.startsWith("audio/") -> FileIconCategory.AUDIO
            mime.startsWith("video/") -> FileIconCategory.VIDEO
            mime == "application/pdf" -> FileIconCategory.PDF
            mime.startsWith("text/") -> FileIconCategory.TEXT
            mime.contains("zip") || mime.contains("compressed") || mime.contains("tar") ->
                FileIconCategory.ARCHIVE
            else -> null
        }
        if (byMime != null) return byMime
        // Fall back to the extension for octet-stream / unknown MIME.
        val ext = fileName?.substringAfterLast('.', "")?.lowercase(Locale.ROOT)
        return when (ext) {
            "pdf" -> FileIconCategory.PDF
            "zip", "rar", "7z", "gz", "tar" -> FileIconCategory.ARCHIVE
            "txt", "md", "csv", "log" -> FileIconCategory.TEXT
            "png", "jpg", "jpeg", "gif", "webp" -> FileIconCategory.IMAGE
            "mp3", "m4a", "aac", "wav", "ogg" -> FileIconCategory.AUDIO
            "mp4", "mov", "mkv", "webm" -> FileIconCategory.VIDEO
            else -> FileIconCategory.GENERIC
        }
    }
}

/** Icon category for a file bubble (mapped to a Material icon by the Composable). */
enum class FileIconCategory { GENERIC, PDF, IMAGE, AUDIO, VIDEO, TEXT, ARCHIVE }
