package com.testlogon.android.core.data.broadcast

import androidx.room.TypeConverter

/**
 * AND-310 — Room [TypeConverter]s for the cached layout's ordered input-id list.
 *
 * Stored as a single newline-joined string (input ids are opaque tokens without newlines). An empty list
 * round-trips through the empty string. This keeps the broadcast_layout table additive and avoids a
 * separate join table for a simple ordered id list.
 */
class LayoutListConverters {

    @TypeConverter
    fun fromInputIds(value: List<String>): String = value.joinToString(SEPARATOR)

    @TypeConverter
    fun toInputIds(value: String): List<String> =
        if (value.isEmpty()) emptyList() else value.split(SEPARATOR)

    private companion object {
        const val SEPARATOR = "\n"
    }
}
