package com.testlogon.android.feature.player

import java.util.Locale

/**
 * AND-170 — PURE, JVM-unit-testable watermark/overlay policy + motion.
 *
 * Framework-free (no Compose, no Android): the playable-item protection flag, the user identity, the
 * watermark spec, the policy truth table, the spec builder, and the anti-static-crop position
 * scheduler are plain data + functions. The Compose overlay ([WatermarkOverlay]) consumes the
 * decided [WatermarkUiState] and the [WatermarkMotion] cell index; it holds no policy.
 *
 * This is a client-side DETERRENT, not DRM (AND-170 §8): it makes captured copies attributable; it
 * does not prevent screen capture.
 */

/**
 * AND-170 §5 — the signed-in user's identity used for the overlay. Only [userSub] is guaranteed
 * available from `/ui/me` (verified `MeResp = { user_sub, session_id, ip }`); email/username are
 * optional and absent in the current backend (OA-1) so they remain nullable.
 */
data class UserIdentity(
    val userSub: String,
    val email: String? = null,
    val username: String? = null,
    val displayName: String? = null,
)

/**
 * AND-170 §4.3 — the playable item's protection input. [requiresWatermark] is a product/Android-local
 * policy decision (no backend "requires client overlay" flag exists — verified: VideoDetail has only
 * `watermark_downloads`/`drm_enabled`, neither an on-screen-overlay flag, AND-170 §5/OA-2). Safe
 * default false so absence never overlays unprotected content.
 */
data class PlayableItem(
    val mediaId: String,
    val requiresWatermark: Boolean = false,
)

/**
 * AND-170 §4.2 — the pure, Compose-free overlay spec. [primaryLine] prefers email->username->
 * displayName->userSub; [secondaryLine] always carries the user_sub + a coarse HH:mm token.
 */
data class WatermarkSpec(
    val primaryLine: String,
    val secondaryLine: String,
    val opacity: Float = DEFAULT_OPACITY,
    val rotationDeg: Float = DEFAULT_ROTATION_DEG,
    val cellGrid: Int = DEFAULT_CELL_GRID,
    val cycleMillis: Long = DEFAULT_CYCLE_MILLIS,
) {
    companion object {
        const val DEFAULT_OPACITY = 0.16f
        const val DEFAULT_ROTATION_DEG = -18f
        const val DEFAULT_CELL_GRID = 3
        const val DEFAULT_CYCLE_MILLIS = 7_000L
    }
}

/** AND-170 §4.2 — the overlay UI state exposed as a StateFlow by the player ViewModel (FR-7). */
sealed interface WatermarkUiState {
    /** Item not protected -> overlay node absent (zero draw cost, FR-3). */
    data object NotRequired : WatermarkUiState

    /** Protected + identity resolved -> render the moving overlay. */
    data class Required(val spec: WatermarkSpec) : WatermarkUiState

    /** Protected but identity unresolved -> render placeholder, gate protected playback (FR-8). */
    data object PendingIdentity : WatermarkUiState
}

/**
 * AND-170 §4.3 — the policy truth table + spec builder.
 *
 * [nowEpochMs] / [zoneAbbrev] are injected (not java.time / android.text.format) so the HH:mm token
 * is computed by a pure helper and the whole object is JVM-tested without API26/Android on the
 * classpath.
 */
object WatermarkPolicy {

    fun evaluate(
        item: PlayableItem?,
        identity: UserIdentity?,
        nowEpochMs: Long,
        zoneOffsetMinutes: Int = 0,
        zoneAbbrev: String = "UTC",
    ): WatermarkUiState = when {
        item == null || !item.requiresWatermark -> WatermarkUiState.NotRequired
        identity == null -> WatermarkUiState.PendingIdentity
        else -> WatermarkUiState.Required(buildSpec(identity, nowEpochMs, zoneOffsetMinutes, zoneAbbrev))
    }

    fun buildSpec(
        identity: UserIdentity,
        nowEpochMs: Long,
        zoneOffsetMinutes: Int = 0,
        zoneAbbrev: String = "UTC",
    ): WatermarkSpec {
        val primary = identity.email
            ?: identity.username
            ?: identity.displayName
            ?: identity.userSub
        val time = formatHhMm(nowEpochMs, zoneOffsetMinutes)
        return WatermarkSpec(
            primaryLine = primary,
            secondaryLine = "id:${identity.userSub} · $time $zoneAbbrev",
        )
    }

    /**
     * Pure UTC-epoch-ms -> "HH:mm" at the given zone offset, minute granularity. No java.time /
     * android.text.format so it is JVM-unit-tested. Negative ms clamps to 0.
     */
    fun formatHhMm(epochMs: Long, zoneOffsetMinutes: Int): String {
        val totalMinutes = (epochMs.coerceAtLeast(0L) / 60_000L) + zoneOffsetMinutes
        val minuteOfDay = ((totalMinutes % 1440L) + 1440L) % 1440L
        val hours = minuteOfDay / 60L
        val minutes = minuteOfDay % 60L
        return String.format(Locale.ROOT, "%02d:%02d", hours, minutes)
    }
}

/**
 * AND-170 §4.4 — the anti-static-crop position scheduler. The anchor cycles across an NxN grid,
 * dwelling [cycleMillis] per cell, so a single crop cannot reliably remove the overlay across a clip
 * (FR-4). Phase derives from wall-clock ms (passed in) so it is independent of recomposition count
 * and fully JVM-testable.
 */
object WatermarkMotion {

    /** The flat cell index 0..(grid*grid-1) for the given wall-clock ms. */
    fun cellIndex(spec: WatermarkSpec, wallClockMs: Long): Int {
        val cells = (spec.cellGrid * spec.cellGrid).coerceAtLeast(1)
        val cycle = spec.cycleMillis.coerceAtLeast(1L)
        val step = (wallClockMs.coerceAtLeast(0L) / cycle)
        return (step % cells).toInt()
    }

    /** The (col,row) cell coordinate for a flat index, row-major over the NxN grid. */
    fun cellCoord(spec: WatermarkSpec, index: Int): Pair<Int, Int> {
        val grid = spec.cellGrid.coerceAtLeast(1)
        val safe = ((index % (grid * grid)) + (grid * grid)) % (grid * grid)
        return (safe % grid) to (safe / grid)
    }

    /**
     * Fractional 0f..1f horizontal/vertical anchor for a cell (cell center within the grid), used to
     * place the overlay. For a 3x3 grid the centers are 1/6, 3/6, 5/6.
     */
    fun anchorFraction(spec: WatermarkSpec, index: Int): Pair<Float, Float> {
        val grid = spec.cellGrid.coerceAtLeast(1)
        val (col, row) = cellCoord(spec, index)
        val x = (col * 2 + 1).toFloat() / (grid * 2).toFloat()
        val y = (row * 2 + 1).toFloat() / (grid * 2).toFloat()
        return x to y
    }
}
