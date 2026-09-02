package com.testlogon.android.core.model.files

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * FM-SHARE - pure JVM tests for [FileShareMath] (permission normalisation, expiry evaluation, and
 * usage/quota formatting). No Android, no Moshi: mirrors the server-side share/usage invariants.
 */
class FileShareMathTest {

    private val now = Instant.parse("2026-09-01T00:00:00Z")

    // ---- permission ----

    @Test
    fun parsePermission_normalisesCaseAndWhitespace() {
        assertEquals(SharePermission.READ, FileShareMath.parsePermission("read"))
        assertEquals(SharePermission.WRITE, FileShareMath.parsePermission("  WRITE "))
        assertEquals(SharePermission.UNKNOWN, FileShareMath.parsePermission("admin"))
        assertEquals(SharePermission.UNKNOWN, FileShareMath.parsePermission(null))
    }

    @Test
    fun canWrite_onlyExplicitWriteGrant_isFailClosed() {
        assertTrue(FileShareMath.canWrite("write"))
        assertFalse(FileShareMath.canWrite("read"))
        assertFalse(FileShareMath.canWrite("bogus"))
        assertFalse(FileShareMath.canWrite(SharePermission.UNKNOWN))
    }

    @Test
    fun permissionWire_unknownFallsBackToRead() {
        assertEquals("write", FileShareMath.permissionWire(SharePermission.WRITE))
        assertEquals("read", FileShareMath.permissionWire(SharePermission.READ))
        assertEquals("read", FileShareMath.permissionWire(SharePermission.UNKNOWN))
    }

    // ---- expiry ----

    @Test
    fun expiryStatus_noExpiry_whenBlankOrNull() {
        assertEquals(ShareExpiryStatus.NO_EXPIRY, FileShareMath.expiryStatus(null, now))
        assertEquals(ShareExpiryStatus.NO_EXPIRY, FileShareMath.expiryStatus("   ", now))
    }

    @Test
    fun expiryStatus_activeVsExpired() {
        assertEquals(ShareExpiryStatus.ACTIVE, FileShareMath.expiryStatus("2026-09-02T00:00:00Z", now))
        assertEquals(ShareExpiryStatus.EXPIRED, FileShareMath.expiryStatus("2026-08-31T23:59:59Z", now))
    }

    @Test
    fun expiryStatus_exactlyNow_isExpired_halfOpenWindow() {
        assertEquals(ShareExpiryStatus.EXPIRED, FileShareMath.expiryStatus("2026-09-01T00:00:00Z", now))
    }

    @Test
    fun expiryStatus_malformed_treatedAsNoExpiry_neverCrashes() {
        assertEquals(ShareExpiryStatus.NO_EXPIRY, FileShareMath.expiryStatus("not-a-date", now))
        assertTrue(FileShareMath.isShareActive("not-a-date", now))
        assertFalse(FileShareMath.isShareActive("2000-01-01T00:00:00Z", now))
    }

    @Test
    fun parseInstantOrNull_lenient() {
        assertNull(FileShareMath.parseInstantOrNull(""))
        assertNull(FileShareMath.parseInstantOrNull("garbage"))
        assertEquals(Instant.parse("2026-09-01T00:00:00Z"), FileShareMath.parseInstantOrNull("2026-09-01T00:00:00Z"))
    }

    // ---- byte formatting ----

    @Test
    fun formatBytes_zeroAndNegativeClampToZeroB() {
        assertEquals("0 B", FileShareMath.formatBytes(0))
        assertEquals("0 B", FileShareMath.formatBytes(-5))
    }

    @Test
    fun formatBytes_rawBytesUnderOneKb() {
        assertEquals("512 B", FileShareMath.formatBytes(512))
        assertEquals("1023 B", FileShareMath.formatBytes(1023))
    }

    @Test
    fun formatBytes_scalesAndTrimsWholeNumbers() {
        assertEquals("1 KB", FileShareMath.formatBytes(1024))
        assertEquals("1.5 KB", FileShareMath.formatBytes(1536))
        assertEquals("2 MB", FileShareMath.formatBytes(2L * 1024 * 1024))
        assertEquals("1 GB", FileShareMath.formatBytes(1024L * 1024 * 1024))
    }

    // ---- percent + quota ----

    @Test
    fun percentUsed_clampsAndHandlesUnlimited() {
        assertEquals(50.0, FileShareMath.percentUsed(50, 100), 0.0001)
        assertEquals(100.0, FileShareMath.percentUsed(200, 100), 0.0001)
        assertEquals(0.0, FileShareMath.percentUsed(500, 0), 0.0001)
    }

    @Test
    fun quotaStatus_bands() {
        assertEquals(QuotaStatus.UNLIMITED, FileShareMath.quotaStatus(100, 0))
        assertEquals(QuotaStatus.OK, FileShareMath.quotaStatus(50, 100))
        assertEquals(QuotaStatus.WARNING, FileShareMath.quotaStatus(85, 100))
        assertEquals(QuotaStatus.CRITICAL, FileShareMath.quotaStatus(99, 100))
    }

    @Test
    fun usageLabel_rendersUsedOverLimitOrUnlimited() {
        assertEquals("512 B / 1 KB", FileShareMath.usageLabel(512, 1024))
        assertEquals("512 B / Unlimited", FileShareMath.usageLabel(512, 0))
    }

    @Test
    fun totalTopFileBytes_sumsDefensively() {
        val files = listOf(
            UsageStorageFileDto(path = "/a", size = 100),
            UsageStorageFileDto(path = "/b", size = -50),
            UsageStorageFileDto(path = "/c", size = 25),
        )
        assertEquals(125L, FileShareMath.totalTopFileBytes(files))
    }
}
