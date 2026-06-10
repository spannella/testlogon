package com.testlogon.android.feature.stories

/**
 * AND-200 — pure, JVM-testable story timing/progress logic.
 *
 * This class holds NO Android types and NO coroutines — it is a plain state machine over Long
 * milliseconds. The ViewModel feeds it elapsed deltas from a bounded ticking LaunchedEffect (the
 * ticking lives only in the Composable / a bounded VM loop so virtual-time tests never hang on an
 * unbounded while+delay), and reads back [progress] and whether the active segment is [complete].
 *
 * One instance tracks ONE active segment's elapsed time against its [durationMs]; on advance the
 * ViewModel resets it for the next segment via [reset].
 */
class StorySegmentTimer(
    private var durationMs: Long = DEFAULT_DURATION_MS,
) {
    var elapsedMs: Long = 0L
        private set

    /** 0f..1f fill for the active segment; 1f when [durationMs] is non-positive (degenerate). */
    val progress: Float
        get() = if (durationMs <= 0L) 1f else (elapsedMs.toFloat() / durationMs).coerceIn(0f, 1f)

    /** True once the segment has run its full duration. */
    val complete: Boolean
        get() = elapsedMs >= durationMs

    /** Advances elapsed by [deltaMs] (clamped at the duration ceiling). Returns the new [complete]. */
    fun tick(deltaMs: Long): Boolean {
        if (deltaMs > 0L) {
            elapsedMs = (elapsedMs + deltaMs).coerceAtMost(durationMs)
        }
        return complete
    }

    /** Resets to the start of a (possibly new-duration) segment. */
    fun reset(durationMs: Long = this.durationMs) {
        this.durationMs = durationMs.coerceAtLeast(0L)
        elapsedMs = 0L
    }

    /** Sets progress directly (used to drive the bar from a video player's position). */
    fun setProgress(fraction: Float) {
        elapsedMs = (durationMs * fraction.coerceIn(0f, 1f)).toLong()
    }

    companion object {
        const val DEFAULT_DURATION_MS: Long = 5_000L

        /** Frame-ish tick used by the bounded VM loop; small enough for smooth bars, bounded for tests. */
        const val TICK_MS: Long = 50L
    }
}

/**
 * AND-199 / AND-200 — pure navigation math for moving across an author's segments and across authors in
 * tray order. Kept side-effect free so the cross-author rollover, previous-restart, and dismiss rules
 * are unit-tested without coroutines or Android.
 */
object StoryNavigator {

    /** Result of a navigation step. [done] signals the viewer should dismiss (past the last author). */
    data class Position(val authorIndex: Int, val segmentIndex: Int, val done: Boolean = false)

    /**
     * Next segment within the current author, or the first segment of the next author, or [done] when
     * past the last segment of the last author. [segmentCounts] is the per-author segment count in tray
     * order. Authors not yet loaded report a count via [segmentCounts] of >= 1 (the viewer loads lazily).
     */
    fun next(authorIndex: Int, segmentIndex: Int, currentAuthorSegmentCount: Int, authorCount: Int): Position {
        if (segmentIndex + 1 < currentAuthorSegmentCount) {
            return Position(authorIndex, segmentIndex + 1)
        }
        // Past the current author's last segment -> next author, segment 0.
        if (authorIndex + 1 < authorCount) {
            return Position(authorIndex + 1, 0)
        }
        return Position(authorIndex, segmentIndex, done = true)
    }

    /**
     * Previous segment within the current author, or the previous author's LAST segment, or restart the
     * very first segment (no-op author/segment, returns segment 0). [prevAuthorSegmentCount] is the
     * previous author's segment count (>= 1).
     */
    fun previous(authorIndex: Int, segmentIndex: Int, prevAuthorSegmentCount: Int): Position {
        if (segmentIndex > 0) {
            return Position(authorIndex, segmentIndex - 1)
        }
        if (authorIndex > 0) {
            val prevLast = (prevAuthorSegmentCount - 1).coerceAtLeast(0)
            return Position(authorIndex - 1, prevLast)
        }
        // First segment of the first author -> restart it.
        return Position(0, 0)
    }
}
