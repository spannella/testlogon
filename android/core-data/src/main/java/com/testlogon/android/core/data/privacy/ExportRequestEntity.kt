package com.testlogon.android.core.data.privacy

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * AND-385 - durable cache of the user's data-export requests (FR-6 offline/stale).
 *
 * Keyed by the server `request_id`. The cache is non-authoritative: rows mirror the last-known status fetched
 * from GET /ui/privacy/requests (+ single-request status polls) so the screen can render last-known requests
 * while the unreliable dev host is slow/offline, surviving process death. No export FILE CONTENTS are stored
 * here - only metadata (status / timestamps / size / the download reference).
 *
 * Backed by the shared [com.testlogon.android.core.data.db.TestLogonDatabase] (DB v9).
 */
@Entity(tableName = "export_requests")
data class ExportRequestEntity(
    @PrimaryKey @ColumnInfo(name = "id") val id: String,
    @ColumnInfo(name = "status") val status: String,
    @ColumnInfo(name = "requested_at") val requestedAt: Long,
    @ColumnInfo(name = "expires_at") val expiresAt: Long?,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Long?,
    @ColumnInfo(name = "download_url") val downloadUrl: String?,
    @ColumnInfo(name = "synced_at") val syncedAt: Long,
)
