package com.testlogon.android.core.data.download

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * AND-195 — durable record of a watermarked VOD download, keyed by video_id.
 *
 * Server-side burn-in is the only backend strategy, so [watermarked] is true on completion and
 * [watermarkPayload] holds the forensic per-viewer token. [identityId] is captured at request time and
 * never mutated, so the artifact stays attributable to the user who initiated it. No payment data, no
 * cookies, no signed download URL is ever stored here.
 *
 * Backed by the shared [com.testlogon.android.core.data.db.TestLogonDatabase] (DB v5).
 */
@Entity(tableName = "vod_download", primaryKeys = ["video_id"])
data class DownloadEntity(
    @ColumnInfo(name = "video_id") val videoId: String,
    /** QUEUED | DOWNLOADING | WATERMARKING | COMPLETED | FAILED | CANCELLED */
    @ColumnInfo(name = "status") val status: String,
    @ColumnInfo(name = "percent") val percent: Int = 0,
    @ColumnInfo(name = "local_uri") val localUri: String? = null,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Long = 0L,
    @ColumnInfo(name = "watermarked") val watermarked: Boolean = false,
    @ColumnInfo(name = "strategy") val strategy: String = "SERVER_BURNED_IN",
    @ColumnInfo(name = "identity_id") val identityId: String = "",
    @ColumnInfo(name = "watermark_payload") val watermarkPayload: String? = null,
    @ColumnInfo(name = "error") val error: String? = null,
    @ColumnInfo(name = "completed_at_epoch_ms") val completedAtEpochMs: Long = 0L,
    @ColumnInfo(name = "updated_at_epoch_ms") val updatedAtEpochMs: Long = 0L,
)
