package com.testlogon.android.core.data.broadcast

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * AND-310 — durable cache rows for the broadcast inputs-management surface, backed by the shared
 * [com.testlogon.android.core.data.db.TestLogonDatabase] (additive tables, DB v7).
 *
 * Non-authoritative cache: the FastAPI backend is the source of truth. These rows let the inputs list +
 * layout render last-known data while the dev host is slow/offline. No cookies / signed URLs / stream keys
 * are stored here — only display + identity fields. The program input is NOT stored on the input row; it is
 * derived at read time by joining the input id against [BroadcastLayoutEntity.primaryInputId].
 */
@Entity(tableName = "broadcast_input", primaryKeys = ["session_id", "input_id"])
data class BroadcastInputEntity(
    @ColumnInfo(name = "session_id") val sessionId: String,
    @ColumnInfo(name = "input_id") val inputId: String,
    /** Raw wire input_type ("primary"|"guest"|"screen"|...); the enum is derived in the domain. */
    @ColumnInfo(name = "input_type") val inputType: String,
    @ColumnInfo(name = "label") val label: String?,
    @ColumnInfo(name = "is_live") val isLive: Boolean = false,
    @ColumnInfo(name = "position") val position: Int = 0,
    @ColumnInfo(name = "connected_at") val connectedAt: Long? = null,
    @ColumnInfo(name = "disconnected_at") val disconnectedAt: Long? = null,
    @ColumnInfo(name = "created_by") val createdBy: String = "",
    /** ISO-8601 instant string (or null); parsed to Instant in the domain mapper. */
    @ColumnInfo(name = "created_at") val createdAt: String? = null,
    @ColumnInfo(name = "updated_at") val updatedAt: String? = null,
)

/**
 * AND-310 — cached layout for a session (one row per session). [inputIds] / [positions] are stored as a
 * single joined/JSON string via [com.testlogon.android.core.data.broadcast.LayoutListConverters] so the
 * table stays additive and simple. The program input is the one whose id == [primaryInputId].
 */
@Entity(tableName = "broadcast_layout", primaryKeys = ["session_id"])
data class BroadcastLayoutEntity(
    @ColumnInfo(name = "session_id") val sessionId: String,
    @ColumnInfo(name = "mode") val mode: String,
    @ColumnInfo(name = "primary_input_id") val primaryInputId: String? = null,
    /** Newline-joined ordered input ids (empty string == no ids). See LayoutListConverters. */
    @ColumnInfo(name = "input_ids") val inputIds: List<String> = emptyList(),
)
