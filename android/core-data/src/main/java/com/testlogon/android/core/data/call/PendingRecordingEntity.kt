package com.testlogon.android.core.data.call

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * AND-302 — durable queue row for a captured call recording awaiting upload, keyed by recording_id.
 *
 * The recording flow persists a row at PendingUpload (after a successful capture, before/while uploading)
 * so an upload survives process death and can be resumed/retried; the row is deleted once the upload
 * completes (Uploaded) or the user cancels. No cookies / signed URLs / payment data are ever stored here —
 * only the local [filePath] of the artifact + enough metadata to re-presign + complete.
 *
 * [phase] is the durable sub-state token (PendingUpload | Uploading | Failed) the controller reconciles on
 * resume. [durationMs] feeds the complete body's duration_seconds (ms -> Float seconds).
 *
 * Backed by the shared [com.testlogon.android.core.data.db.TestLogonDatabase] (additive table, DB v6).
 */
@Entity(tableName = "pending_recording", primaryKeys = ["recording_id"])
data class PendingRecordingEntity(
    @ColumnInfo(name = "recording_id") val recordingId: String,
    @ColumnInfo(name = "call_id") val callId: String,
    @ColumnInfo(name = "file_path") val filePath: String,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Long = 0L,
    @ColumnInfo(name = "duration_ms") val durationMs: Long = 0L,
    /** PendingUpload | Uploading | Failed */
    @ColumnInfo(name = "phase") val phase: String,
    @ColumnInfo(name = "attempts") val attempts: Int = 0,
    @ColumnInfo(name = "created_at") val createdAtEpochMs: Long = 0L,
)
