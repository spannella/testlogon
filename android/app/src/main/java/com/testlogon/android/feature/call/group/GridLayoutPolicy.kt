package com.testlogon.android.feature.call.group

import com.testlogon.android.data.call.group.GroupParticipant

/**
 * AND-299 — PURE (android-free) grid sizing policy for the participant grid.
 *
 * Maps a participant [count] + [GridOrientation] to a [GridSpec] (columns/rows/scrollable). The screen
 * derives orientation from LocalConfiguration and uses [GridSpec.columns] for the LazyVerticalGrid cells.
 * AND-300 extends this with [order] (deterministic pin / active-speaker ordering); kept simple + deterministic.
 *
 * Portrait breakpoints: 1 -> 1x1, 2 -> 1 col x 2 rows, 3-4 -> 2x2, 5-6 -> 2 cols x 3 rows, 7-9 -> 3x3,
 * 10+ -> 3 columns, scrollable. Landscape transposes the small tiles (wider than tall). count <= 0 -> 1x1.
 */
data class GridSpec(val columns: Int, val rows: Int, val scrollable: Boolean)

enum class GridOrientation { Portrait, Landscape }

object GridLayoutPolicy {

    fun spec(count: Int, orientation: GridOrientation): GridSpec {
        if (count <= 0) return GridSpec(columns = 1, rows = 1, scrollable = false)
        return when (orientation) {
            GridOrientation.Portrait -> portrait(count)
            GridOrientation.Landscape -> landscape(count)
        }
    }

    private fun portrait(count: Int): GridSpec = when (count) {
        1 -> GridSpec(1, 1, scrollable = false)
        2 -> GridSpec(columns = 1, rows = 2, scrollable = false)
        3, 4 -> GridSpec(columns = 2, rows = 2, scrollable = false)
        5, 6 -> GridSpec(columns = 2, rows = 3, scrollable = false)
        7, 8, 9 -> GridSpec(columns = 3, rows = 3, scrollable = false)
        else -> GridSpec(columns = 3, rows = rowsFor(count, columns = 3), scrollable = true)
    }

    private fun landscape(count: Int): GridSpec = when (count) {
        1 -> GridSpec(1, 1, scrollable = false)
        2 -> GridSpec(columns = 2, rows = 1, scrollable = false)
        3, 4 -> GridSpec(columns = 2, rows = 2, scrollable = false)
        5, 6 -> GridSpec(columns = 3, rows = 2, scrollable = false)
        7, 8, 9 -> GridSpec(columns = 3, rows = 3, scrollable = false)
        else -> GridSpec(columns = 4, rows = rowsFor(count, columns = 4), scrollable = true)
    }

    private fun rowsFor(count: Int, columns: Int): Int = (count + columns - 1) / columns

    /**
     * AND-300 — deterministic, stable tile ordering for the participant grid / filmstrip.
     *
     * Ordering rules (pure — identical input always yields identical output):
     *  1. The pinned participant first (only if [pinnedUserId] resolves to a participant in [participants]).
     *  2. Then the active speaker (only if [activeSpeakerUserId] resolves to a participant AND is not the
     *     pinned one — a pinned active speaker is not duplicated; it already leads at slot 1).
     *  3. Then the remaining participants in stable join order: sorted by joinedAt, then userId (tie-break).
     *
     * The self/local participant is NOT floated to the front — it keeps its natural join-order slot within
     * the tail (rule 3) unless it happens to be the pinned or active-speaker participant. A [pinnedUserId] /
     * [activeSpeakerUserId] that is absent from [participants] is ignored gracefully (no crash, no gap).
     */
    fun order(
        participants: List<GroupParticipant>,
        pinnedUserId: String?,
        activeSpeakerUserId: String?,
    ): List<GroupParticipant> {
        if (participants.isEmpty()) return participants

        val pinned = pinnedUserId?.let { id -> participants.firstOrNull { it.userId == id } }
        val active = activeSpeakerUserId
            ?.takeIf { it != pinned?.userId }
            ?.let { id -> participants.firstOrNull { it.userId == id } }

        val leadIds = setOfNotNull(pinned?.userId, active?.userId)
        val tail = participants
            .filterNot { it.userId in leadIds }
            .sortedWith(compareBy({ it.joinedAt }, { it.userId }))

        return listOfNotNull(pinned, active) + tail
    }
}
