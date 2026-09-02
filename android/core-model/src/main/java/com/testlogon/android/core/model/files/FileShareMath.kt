package com.testlogon.android.core.model.files

import java.time.Instant

/**
 * FM-SHARE - pure, dependency-free logic for the user-to-user file sharing + storage-usage surfaces.
 *
 * NO Android, NO Moshi, NO I/O: this mirrors the server-side share/usage invariants
 * (app/routers/filemanager.py share / shared-list / usage-* and app/services/filemanager.py) so the same
 * rules can be unit-tested on the JVM and reused by the ViewModels. Two concern groups:
 *
 *  1. SHARE PERMISSION / EXPIRY - normalise the free-form `permission` string to a typed [SharePermission],
 *     decide whether a "write" affordance is allowed, and evaluate a share's expiry against a clock.
 *  2. USAGE / QUOTA FORMATTING - human-readable byte sizes, safe percent-of-quota, and a coarse quota
 *     status the UI colours by.
 */

/** Access level granted by a direct share. The wire is a free string; UNKNOWN is the safe fallback. */
enum class SharePermission { READ, WRITE, UNKNOWN }

/** Whether a share is still usable relative to a clock. */
enum class ShareExpiryStatus { ACTIVE, EXPIRED, NO_EXPIRY }

/** Coarse quota band the UI colours by (green / amber / red). */
enum class QuotaStatus { OK, WARNING, CRITICAL, UNLIMITED }

object FileShareMath {

    /** The two permission strings the backend accepts. Anything else normalises to [SharePermission.UNKNOWN]. */
    const val PERMISSION_READ = "read"
    const val PERMISSION_WRITE = "write"

    /** Percent-used thresholds (inclusive) for the quota bands. */
    const val QUOTA_WARNING_PERCENT = 80.0
    const val QUOTA_CRITICAL_PERCENT = 95.0

    // ---- Permission ----------------------------------------------------------------------------

    /** Normalise a free-form wire permission (case/whitespace-insensitive) to a typed [SharePermission]. */
    fun parsePermission(raw: String?): SharePermission = when (raw?.trim()?.lowercase()) {
        PERMISSION_READ -> SharePermission.READ
        PERMISSION_WRITE -> SharePermission.WRITE
        else -> SharePermission.UNKNOWN
    }

    /** The canonical wire string for a [SharePermission] (UNKNOWN falls back to the safe "read"). */
    fun permissionWire(permission: SharePermission): String = when (permission) {
        SharePermission.WRITE -> PERMISSION_WRITE
        else -> PERMISSION_READ
    }

    /**
     * Whether a recipient holding [permission] may MUTATE the shared node (upload/rename/move/delete into
     * it). Only an explicit WRITE grant allows it; READ and UNKNOWN are read-only (fail-closed).
     */
    fun canWrite(permission: SharePermission): Boolean = permission == SharePermission.WRITE

    /** Convenience overload from the raw wire string. */
    fun canWrite(rawPermission: String?): Boolean = canWrite(parsePermission(rawPermission))

    // ---- Expiry --------------------------------------------------------------------------------

    /**
     * Evaluate a share's [expiresAtIso] (nullable ISO-8601 instant string) against [now]. A blank/absent
     * value is [ShareExpiryStatus.NO_EXPIRY]; an unparseable value is treated as NO_EXPIRY (never crash,
     * never silently expire). An expiry exactly equal to [now] is considered EXPIRED (half-open window).
     */
    fun expiryStatus(expiresAtIso: String?, now: Instant): ShareExpiryStatus {
        val parsed = parseInstantOrNull(expiresAtIso) ?: return ShareExpiryStatus.NO_EXPIRY
        return if (!parsed.isAfter(now)) ShareExpiryStatus.EXPIRED else ShareExpiryStatus.ACTIVE
    }

    /** A share is USABLE unless it has a parseable expiry that is at/after which is now-or-past. */
    fun isShareActive(expiresAtIso: String?, now: Instant): Boolean =
        expiryStatus(expiresAtIso, now) != ShareExpiryStatus.EXPIRED

    /** Parse an ISO-8601 instant leniently; returns null for blank/malformed input. */
    fun parseInstantOrNull(iso: String?): Instant? {
        val s = iso?.trim().orEmpty()
        if (s.isEmpty()) return null
        return runCatching { Instant.parse(s) }.getOrNull()
    }

    // ---- Usage / quota formatting --------------------------------------------------------------

    private val BYTE_UNITS = listOf("B", "KB", "MB", "GB", "TB", "PB")

    /**
     * Human-readable byte size using 1024-based units, e.g. 0 -> "0 B", 1536 -> "1.5 KB". Negative
     * inputs clamp to 0. Whole numbers render without a trailing ".0" (e.g. "2 MB"); fractional values
     * render with [fractionDigits] (default 1) decimals.
     */
    fun formatBytes(bytes: Long, fractionDigits: Int = 1): String {
        if (bytes <= 0L) return "0 B"
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024.0 && unit < BYTE_UNITS.size - 1) {
            value /= 1024.0
            unit++
        }
        if (unit == 0) return "${bytes} B"
        val rounded = roundTo(value, fractionDigits)
        val text = if (rounded == rounded.toLong().toDouble()) {
            rounded.toLong().toString()
        } else {
            trimTrailingZeros(rounded, fractionDigits)
        }
        return "$text ${BYTE_UNITS[unit]}"
    }

    /**
     * Percent of [used] against [limit], clamped to 0..100 and rounded to one decimal. A non-positive
     * limit means "unlimited" and yields 0.0 (never divide-by-zero, never report over-quota on an
     * unlimited plan).
     */
    fun percentUsed(used: Long, limit: Long): Double {
        if (limit <= 0L) return 0.0
        val pct = used.toDouble() / limit.toDouble() * 100.0
        return roundTo(pct.coerceIn(0.0, 100.0), 1)
    }

    /**
     * Coarse quota band from [used]/[limit]. A non-positive limit is [QuotaStatus.UNLIMITED]. Otherwise
     * >= [QUOTA_CRITICAL_PERCENT] is CRITICAL, >= [QUOTA_WARNING_PERCENT] is WARNING, else OK.
     */
    fun quotaStatus(used: Long, limit: Long): QuotaStatus {
        if (limit <= 0L) return QuotaStatus.UNLIMITED
        val pct = percentUsed(used, limit)
        return when {
            pct >= QUOTA_CRITICAL_PERCENT -> QuotaStatus.CRITICAL
            pct >= QUOTA_WARNING_PERCENT -> QuotaStatus.WARNING
            else -> QuotaStatus.OK
        }
    }

    /**
     * A compact "used / limit" label, e.g. "1.5 MB / 2 GB". A non-positive limit renders the used size
     * followed by " / Unlimited".
     */
    fun usageLabel(used: Long, limit: Long): String {
        val usedText = formatBytes(used)
        return if (limit <= 0L) "$usedText / Unlimited" else "$usedText / ${formatBytes(limit)}"
    }

    /**
     * Sum the sizes of the heaviest-files list (defensive against nulls / negatives), so a
     * usage-storage view can show a "top N accounts for X" figure. Never negative.
     */
    fun totalTopFileBytes(files: List<UsageStorageFileDto>): Long =
        files.sumOf { maxOf(0L, it.size) }

    // ---- helpers -------------------------------------------------------------------------------

    private fun roundTo(value: Double, digits: Int): Double {
        var factor = 1.0
        repeat(maxOf(0, digits)) { factor *= 10.0 }
        return Math.round(value * factor) / factor
    }

    private fun trimTrailingZeros(value: Double, digits: Int): String {
        val text = String.format("%.${maxOf(0, digits)}f", value)
        return text.trimEnd('0').trimEnd('.')
    }
}
