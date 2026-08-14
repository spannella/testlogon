package com.testlogon.android.feature.blotter

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A compact, serialized snapshot of the user-customized blotter layout: sort, grouping, which
 * columns are hidden, and the active filters/search. All fields degrade to sensible defaults so a
 * malformed or absent pref can never crash the screen.
 */
data class BlotterLayout(
    val sortColumn: BlotterSortColumn = BlotterSortColumn.SYM,
    val sortDir: BlotterSortDir = BlotterSortDir.ASC,
    val groupBy: BlotterGroupKey? = null,
    val hiddenColumns: Set<BlotterColumn> = emptySet(),
    val filters: BlotterFilters = BlotterFilters(),
)

/**
 * SharedPreferences-backed persistence for [BlotterLayout]. Enums are stored by [Enum.name] and
 * collections as CSV; every read is defensive (unknown enum values are dropped via
 * enumValues().firstOrNull, unparseable numbers become null) so the store NEVER throws on a
 * malformed/absent pref — it just falls back to defaults.
 */
@Singleton
class BlotterLayoutStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Load the persisted layout, merging over defaults. Never throws. */
    fun load(): BlotterLayout {
        return try {
            BlotterLayout(
                sortColumn = enumOrDefault(prefs.getString(KEY_SORT_COL, null), BlotterSortColumn.SYM),
                sortDir = enumOrDefault(prefs.getString(KEY_SORT_DIR, null), BlotterSortDir.ASC),
                groupBy = enumOrNull<BlotterGroupKey>(prefs.getString(KEY_GROUP, null)),
                hiddenColumns = decodeEnumSet(prefs.getString(KEY_HIDDEN, null)) { name ->
                    enumOrNull<BlotterColumn>(name)
                },
                filters = BlotterFilters(
                    search = prefs.getString(KEY_SEARCH, "") ?: "",
                    symbols = decodeStringSet(prefs.getString(KEY_F_SYM, null)),
                    sides = decodeEnumSet(prefs.getString(KEY_F_SIDE, null)) { enumOrNull<BlotterSide>(it) },
                    statuses = decodeEnumSet(prefs.getString(KEY_F_STATUS, null)) { enumOrNull<BlotterStatus>(it) },
                    tifs = decodeEnumSet(prefs.getString(KEY_F_TIF, null)) { enumOrNull<BlotterTif>(it) },
                    pxMin = prefs.getString(KEY_F_PXMIN, null)?.toDoubleOrNull(),
                    pxMax = prefs.getString(KEY_F_PXMAX, null)?.toDoubleOrNull(),
                    qtyMin = prefs.getString(KEY_F_QTYMIN, null)?.toDoubleOrNull(),
                    qtyMax = prefs.getString(KEY_F_QTYMAX, null)?.toDoubleOrNull(),
                ),
            )
        } catch (t: Throwable) {
            BlotterLayout()
        }
    }

    /** Persist the whole layout. Never throws. */
    fun save(layout: BlotterLayout) {
        try {
            prefs.edit()
                .putString(KEY_SORT_COL, layout.sortColumn.name)
                .putString(KEY_SORT_DIR, layout.sortDir.name)
                .putString(KEY_GROUP, layout.groupBy?.name)
                .putString(KEY_HIDDEN, layout.hiddenColumns.joinToString(SEP) { it.name })
                .putString(KEY_SEARCH, layout.filters.search)
                .putString(KEY_F_SYM, layout.filters.symbols.joinToString(SEP))
                .putString(KEY_F_SIDE, layout.filters.sides.joinToString(SEP) { it.name })
                .putString(KEY_F_STATUS, layout.filters.statuses.joinToString(SEP) { it.name })
                .putString(KEY_F_TIF, layout.filters.tifs.joinToString(SEP) { it.name })
                .putString(KEY_F_PXMIN, layout.filters.pxMin?.toString())
                .putString(KEY_F_PXMAX, layout.filters.pxMax?.toString())
                .putString(KEY_F_QTYMIN, layout.filters.qtyMin?.toString())
                .putString(KEY_F_QTYMAX, layout.filters.qtyMax?.toString())
                .apply()
        } catch (t: Throwable) {
            // Best-effort persistence; a failed save must never break the UI.
        }
    }

    private inline fun <reified E : Enum<E>> enumOrNull(name: String?): E? {
        if (name.isNullOrBlank()) return null
        return enumValues<E>().firstOrNull { it.name == name }
    }

    private inline fun <reified E : Enum<E>> enumOrDefault(name: String?, default: E): E =
        enumOrNull<E>(name) ?: default

    private fun decodeStringSet(csv: String?): Set<String> {
        if (csv.isNullOrBlank()) return emptySet()
        return csv.split(SEP).map { it.trim() }.filter { it.isNotEmpty() }.toSet()
    }

    private fun <E> decodeEnumSet(csv: String?, mapper: (String) -> E?): Set<E> {
        if (csv.isNullOrBlank()) return emptySet()
        return csv.split(SEP).mapNotNull { token ->
            val t = token.trim()
            if (t.isEmpty()) null else mapper(t)
        }.toSet()
    }

    private companion object {
        const val PREFS_NAME = "blotter_layout"
        const val SEP = ","
        const val KEY_SORT_COL = "sort_col"
        const val KEY_SORT_DIR = "sort_dir"
        const val KEY_GROUP = "group_by"
        const val KEY_HIDDEN = "hidden_cols"
        const val KEY_SEARCH = "f_search"
        const val KEY_F_SYM = "f_sym"
        const val KEY_F_SIDE = "f_side"
        const val KEY_F_STATUS = "f_status"
        const val KEY_F_TIF = "f_tif"
        const val KEY_F_PXMIN = "f_pxmin"
        const val KEY_F_PXMAX = "f_pxmax"
        const val KEY_F_QTYMIN = "f_qtymin"
        const val KEY_F_QTYMAX = "f_qtymax"
    }
}
