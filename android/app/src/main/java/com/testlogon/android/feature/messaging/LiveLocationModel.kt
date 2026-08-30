package com.testlogon.android.feature.messaging

/**
 * EPIC D (FE-131, <- BE-131) - pure, dependency-free model for LIVE location sharing in chat.
 *
 * Kept Android-free so all of: the duration options, the active/expiry math, the remaining-time
 * labels, the update cadence and the TLLIVE1 encode/parse round-trip are JVM-unit-testable in
 * isolation (LiveLocationModelTest). `nowSec` is always injected (never reads a clock) so the math
 * is deterministic and integer-only.
 *
 * TRANSPORT (mirrors [LocationCardModel] / the TLLOC1 static-pin card - the degrade-safe path): a
 * live share rides a NORMAL text message whose body is encoded behind the TLLIVE1 sentinel. An
 * un-upgraded client just shows the plain text; an upgraded client parses it back into a live card.
 * When BE-131 is present the sharer's periodic `update`s relay a fresh lat/lng to recipients; without
 * it the card degrades to the LAST-KNOWN pin + a LIVE badge + a live countdown + auto-expiry.
 *
 * The message body carries: share_id, lat, lng, started_at, expires_at (+ optional stopped_at when
 * the sharer stops early / a label). Field names mirror the assumed BE-131 wire contract.
 */
object LiveLocationModel {

    const val SENTINEL: String = "TLLIVE1:"

    /** A visible pin marker used in previews (emoji, unicode-escaped for source safety). */
    const val PIN: String = "📍"

    /** How often the sharer posts a position update while the share is active AND foregrounded. */
    const val UPDATE_INTERVAL_SEC: Long = 15L

    /** Selectable share durations (seconds): 15 minutes, 1 hour, 8 hours. */
    val LIVE_DURATION_OPTIONS: List<DurationOption> = listOf(
        DurationOption(15 * 60L, "15 minutes"),
        DurationOption(60 * 60L, "1 hour"),
        DurationOption(8 * 60 * 60L, "8 hours"),
    )

    data class DurationOption(val seconds: Long, val label: String)

    data class LiveShare(
        val shareId: String,
        val lat: Double,
        val lng: Double,
        val startedAtSec: Long,
        val expiresAtSec: Long,
        val stoppedAtSec: Long? = null,
        val label: String? = null,
    )

    /** expires_at = started_at + duration (clamped so a non-positive duration yields started_at). */
    fun computeExpiresAt(startedAtSec: Long, durationSec: Long): Long =
        startedAtSec + (if (durationSec > 0L) durationSec else 0L)

    /**
     * A share is ACTIVE when it has neither been stopped nor expired at [nowSec]. A stop time in the
     * future is ignored (treated as not-yet-stopped) so a clock skew never prematurely ends a share.
     */
    fun isLiveActive(expiresAtSec: Long, stoppedAtSec: Long?, nowSec: Long): Boolean {
        if (stoppedAtSec != null && stoppedAtSec <= nowSec) return false
        return nowSec < expiresAtSec
    }

    fun isLiveActive(share: LiveShare, nowSec: Long): Boolean =
        isLiveActive(share.expiresAtSec, share.stoppedAtSec, nowSec)

    /** Seconds until expiry, clamped to >= 0. */
    fun liveSecondsRemaining(expiresAtSec: Long, nowSec: Long): Long {
        val r = expiresAtSec - nowSec
        return if (r > 0L) r else 0L
    }

    /**
     * The sharer's periodic updater should auto-stop once the share is no longer active (expired OR
     * stopped). Pure predicate so the coroutine loop's exit condition is unit-testable.
     */
    fun shouldAutoStop(expiresAtSec: Long, stoppedAtSec: Long?, nowSec: Long): Boolean =
        !isLiveActive(expiresAtSec, stoppedAtSec, nowSec)

    /** Compact remaining-time label, e.g. "8h 0m left", "14m left", "45s left", "Ended". */
    fun liveRemainingLabel(expiresAtSec: Long, stoppedAtSec: Long?, nowSec: Long): String {
        if (!isLiveActive(expiresAtSec, stoppedAtSec, nowSec)) return "Ended"
        val rem = liveSecondsRemaining(expiresAtSec, nowSec)
        val h = rem / 3600L
        val m = (rem % 3600L) / 60L
        val s = rem % 60L
        return when {
            h > 0L -> "${h}h ${m}m left"
            m > 0L -> "${m}m left"
            else -> "${s}s left"
        }
    }

    fun preview(share: LiveShare?): String = "$PIN Live location"

    /** Conversation-list / reply preview for a live-location body (masks the TLLIVE1 sentinel). */
    fun previewForBody(body: String?): String? = if (isCard(body)) "$PIN Live location" else null

    fun isCard(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    fun encode(share: LiveShare): String {
        val sb = StringBuilder(SENTINEL)
        sb.append(kv("id", share.shareId))
        sb.append(SEP).append(kv("lat", share.lat.toString()))
        sb.append(SEP).append(kv("lng", share.lng.toString()))
        sb.append(SEP).append(kv("start", share.startedAtSec.toString()))
        sb.append(SEP).append(kv("exp", share.expiresAtSec.toString()))
        share.stoppedAtSec?.let { sb.append(SEP).append(kv("stop", it.toString())) }
        share.label?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("label", it)) }
        return sb.toString()
    }

    /**
     * Parse a body into a [LiveShare], or null when not a well-formed live-location card. Required
     * fields: id, lat, lng, start, exp. Out-of-range coords or unparsable numbers reject to null so a
     * malformed body degrades to a plain text bubble (never crashes).
     */
    fun parse(body: String?): LiveShare? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val map = HashMap<String, String>()
        for (seg in payload.split(SEP)) {
            val eq = seg.indexOf(EQ)
            if (eq <= 0) continue
            map[unescape(seg.substring(0, eq))] = unescape(seg.substring(eq + 1))
        }
        val id = map["id"]?.takeIf { it.isNotBlank() } ?: return null
        val lat = map["lat"]?.toDoubleOrNull() ?: return null
        val lng = map["lng"]?.toDoubleOrNull() ?: return null
        if (!LocationCardModel.isValidLatLng(lat, lng)) return null
        val start = map["start"]?.toLongOrNull() ?: return null
        val exp = map["exp"]?.toLongOrNull() ?: return null
        return LiveShare(
            shareId = id,
            lat = lat,
            lng = lng,
            startedAtSec = start,
            expiresAtSec = exp,
            stoppedAtSec = map["stop"]?.toLongOrNull(),
            label = map["label"]?.takeIf { it.isNotBlank() },
        )
    }

    private const val SEP: Char = ';'
    private const val EQ: Char = '='

    private fun kv(k: String, v: String): String = escape(k) + "=" + escape(v)

    private fun escape(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            when (c) {
                '%' -> sb.append("%25")
                ';' -> sb.append("%3B")
                '=' -> sb.append("%3D")
                '\n' -> sb.append("%0A")
                '\r' -> sb.append("%0D")
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun unescape(s: String): String {
        if (s.indexOf('%') < 0) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val code = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (code != null) { sb.append(code.toChar()); i += 3; continue }
            }
            sb.append(c); i++
        }
        return sb.toString()
    }
}
