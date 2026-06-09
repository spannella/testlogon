package com.testlogon.android.feature.messaging.media

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-132/133 — pure formatting + mime/kind mapping (JVM, no Android types). */
class AttachmentFormatTest {

    @Test
    fun fileSize_formatsBinaryUnits() {
        assertEquals("", AttachmentFormat.fileSize(null))
        assertEquals("", AttachmentFormat.fileSize(-5))
        assertEquals("0 B", AttachmentFormat.fileSize(0))
        assertEquals("512 B", AttachmentFormat.fileSize(512))
        assertEquals("1.0 KB", AttachmentFormat.fileSize(1024))
        assertEquals("1.5 KB", AttachmentFormat.fileSize(1536))
        // 12 KB rounds to no-decimal once >= 10.
        assertEquals("12 KB", AttachmentFormat.fileSize(12 * 1024))
        assertEquals("1.0 MB", AttachmentFormat.fileSize(1024L * 1024))
        assertEquals("2.0 GB", AttachmentFormat.fileSize(2L * 1024 * 1024 * 1024))
    }

    @Test
    fun duration_formatsMmSs() {
        assertEquals("0:00", AttachmentFormat.duration(0))
        assertEquals("0:00", AttachmentFormat.duration(-10))
        assertEquals("0:07", AttachmentFormat.duration(7_400))
        assertEquals("1:05", AttachmentFormat.duration(65_000))
        assertEquals("2:00", AttachmentFormat.durationSeconds(120.0))
    }

    @Test
    fun fileKindForMime_audioVsFile() {
        assertEquals("audio", AttachmentFormat.fileKindForMime("audio/mp4"))
        assertEquals("file", AttachmentFormat.fileKindForMime("application/pdf"))
        assertEquals("file", AttachmentFormat.fileKindForMime(null))
    }

    @Test
    fun iconCategory_byMimeThenExtension() {
        assertEquals(FileIconCategory.PDF, AttachmentFormat.iconCategory("application/pdf", "x.pdf"))
        assertEquals(FileIconCategory.AUDIO, AttachmentFormat.iconCategory("audio/mpeg", "x.mp3"))
        assertEquals(FileIconCategory.VIDEO, AttachmentFormat.iconCategory("video/mp4", "x.mp4"))
        assertEquals(FileIconCategory.TEXT, AttachmentFormat.iconCategory("text/plain", "notes.txt"))
        assertEquals(FileIconCategory.ARCHIVE, AttachmentFormat.iconCategory("application/zip", "a.zip"))
        // Unknown MIME -> fall back to extension.
        assertEquals(FileIconCategory.PDF, AttachmentFormat.iconCategory("application/octet-stream", "report.pdf"))
        assertEquals(FileIconCategory.GENERIC, AttachmentFormat.iconCategory("application/octet-stream", "weird.bin"))
    }
}
