package com.testlogon.android.feature.call.group

/**
 * AND-299 — PURE (android-free) grid sizing policy for the participant grid.
 *
 * Maps a participant [count] + [GridOrientation] to a [GridSpec] (columns/rows/scrollable). The screen
 * derives orientation from LocalConfiguration and uses [GridSpec.columns] for the LazyVerticalGrid cells.
 * AND-300 will extend this (e.g. spotlight/screen-share layouts); kept simple + deterministic here.
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
}
