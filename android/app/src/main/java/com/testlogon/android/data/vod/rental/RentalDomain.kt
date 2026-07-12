package com.testlogon.android.data.vod.rental

/**
 * AND-192 — pure, JVM-unit-testable rental domain model + expiry / countdown logic.
 *
 * Framework-free (no Android, no java.time): all timestamps are epoch SECONDS (Long); the active
 * predicate and the countdown label are pure functions so they are exhaustively unit-tested without an
 * emulator and without API-26 desugaring. The server is the source of truth; the client only
 * INTERPOLATES the countdown between fetches and never extends access on its own.
 */

/** Current rental access state (from VodRentalAccessOut / the embedded access in playback). */
data class RentalAccess(
    val active: Boolean,
    val tier: String?,
    val reason: String?,
    val expiresAt: Long?,        // epoch seconds, nullable
    val remainingSeconds: Long,
    val viewsRemaining: Int,     // -1 = unlimited within the window
    val rentalId: String?,
    val started: Boolean,
) {
    /**
     * AND-192 §6 — the client-side active predicate evaluated at [nowSeconds]:
     * `serverActive && (expiresAt == null || now < expiresAt) && viewsRemaining != 0`.
     * The -1 sentinel (unlimited) is != 0 so it never locks; only a real 0 budget locks.
     */
    fun isActiveAt(nowSeconds: Long): Boolean =
        active && (expiresAt == null || nowSeconds < expiresAt) && viewsRemaining != 0

    /**
     * Seconds remaining until re-lock at [nowSeconds]. Anchors on absolute [expiresAt] when present
     * (re-anchored on every server round-trip), else on the server-provided [remainingSeconds] minus
     * elapsed since the anchor. Never negative.
     */
    fun remainingAt(nowSeconds: Long, anchorSeconds: Long): Long = when {
        expiresAt != null -> (expiresAt - nowSeconds).coerceAtLeast(0L)
        else -> (remainingSeconds - (nowSeconds - anchorSeconds)).coerceAtLeast(0L)
    }
}

/** Outcome of starting a rental (POST start), or the idempotent `already_active` success path. */
data class RentalReceipt(
    val videoId: String,
    val rentalId: String,
    val tier: String,
    val alreadyActive: Boolean,
    val expiresAt: Long?,
    val viewsRemaining: Int,
    val amountCents: Int,
    val durationHours: Int?,
)

/** Short-lived playback grant (POST playback). [playbackUrl] / [tokenExpiresAt] are NEVER persisted. */
data class RentalPlayback(
    val videoId: String,
    val playbackUrl: String,
    val manifestKey: String?,
    val mode: String?,
    val thumbnailUrl: String?,
    val tokenExpiresAt: Long,
    val access: RentalAccess,
)

/** A purchasable rental option surfaced on the locked detail (tier + price). */
data class RentalTierOption(
    val tier: String,            // "rental" | "view_once"
    val amountCents: Int,
    val durationHours: Int?,     // sent only for tier == "rental"
)

/**
 * AND-192 — pure countdown formatting. `HH:MM:SS` for < 1 day, `Nd HH:MM:SS` for longer. Pure Long
 * math (no java.time / android.text.format) so it is JVM-tested on minSdk 24. Negative clamps to 0.
 */
object RentalCountdown {

    fun label(remainingSeconds: Long): String {
        val total = remainingSeconds.coerceAtLeast(0L)
        val days = total / 86_400L
        val hours = (total % 86_400L) / 3_600L
        val minutes = (total % 3_600L) / 60L
        val seconds = total % 60L
        val hms = "%02d:%02d:%02d".format(hours, minutes, seconds)
        return if (days > 0L) "${days}d $hms" else hms
    }

    /** Natural-language a11y description ("2 hours 14 minutes", "expired"). Pure. */
    fun accessibilityLabel(remainingSeconds: Long): String {
        val total = remainingSeconds.coerceAtLeast(0L)
        if (total == 0L) return "expired"
        val days = total / 86_400L
        val hours = (total % 86_400L) / 3_600L
        val minutes = (total % 3_600L) / 60L
        val parts = buildList {
            if (days > 0L) add("$days ${plural(days, "day")}")
            if (hours > 0L) add("$hours ${plural(hours, "hour")}")
            if (minutes > 0L) add("$minutes ${plural(minutes, "minute")}")
            if (isEmpty()) add("less than a minute")
        }
        return parts.joinToString(" ")
    }

    private fun plural(n: Long, unit: String): String = if (n == 1L) unit else "${unit}s"
}

// ---- DTO -> domain mappers ----

fun VodRentalAccessOutDto.toDomain(): RentalAccess = RentalAccess(
    active = active,
    tier = tier?.takeIf { it.isNotBlank() },
    reason = reason.takeIf { it.isNotBlank() },
    expiresAt = expiresAt,
    remainingSeconds = remainingSeconds,
    viewsRemaining = viewsRemaining,
    rentalId = rentalId?.takeIf { it.isNotBlank() },
    started = started,
)

fun VodRentalStatusOutDto.toAccess(): RentalAccess = RentalAccess(
    active = active,
    tier = tier.takeIf { it.isNotBlank() },
    reason = reason.takeIf { it.isNotBlank() },
    expiresAt = expiresAt,
    remainingSeconds = remainingSeconds,
    viewsRemaining = viewsRemaining,
    rentalId = rentalId.takeIf { it.isNotBlank() },
    started = started,
)

fun VodRentalStartOutDto.toReceipt(): RentalReceipt = RentalReceipt(
    videoId = videoId,
    rentalId = rentalId,
    tier = tier,
    alreadyActive = alreadyActive,
    expiresAt = expiresAt,
    viewsRemaining = viewsRemaining,
    amountCents = amountCents,
    durationHours = durationHours,
)

fun VodRentalPlaybackOutDto.toDomain(): RentalPlayback = RentalPlayback(
    videoId = videoId,
    playbackUrl = playbackUrl,
    manifestKey = manifestKey?.takeIf { it.isNotBlank() },
    mode = mode?.takeIf { it.isNotBlank() },
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    tokenExpiresAt = tokenExpiresAt,
    access = access.toDomain(),
)

/**
 * "My Rentals" list row (web VodRentalsPage parity). Carries the fields the list UI needs that are NOT on
 * [RentalAccess]: the [videoId] (row key + link), the [amountCents] paid, plus the status-derivation inputs
 * ([tier], [active], [started], [reason], [viewsRemaining], [remainingSeconds]). Timestamps/seconds are
 * server-authoritative; the UI only formats them.
 */
data class RentalListItem(
    val videoId: String,
    val rentalId: String,
    val tier: String,
    val amountCents: Int,
    val active: Boolean,
    val started: Boolean,
    val reason: String,
    val expiresAt: Long?,
    val remainingSeconds: Long,
    val viewsRemaining: Int,
)

fun VodRentalStatusOutDto.toListItem(): RentalListItem = RentalListItem(
    videoId = videoId,
    rentalId = rentalId,
    tier = tier,
    amountCents = amountCents,
    active = active,
    started = started,
    reason = reason,
    expiresAt = expiresAt,
    remainingSeconds = remainingSeconds,
    viewsRemaining = viewsRemaining,
)
