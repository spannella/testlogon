package com.testlogon.android.data.privacy

/**
 * AND-385 - the data-export status vocabulary. The wire `status` is a free-form string; known values map to a
 * variant and ANY unknown value maps to [UNKNOWN] (forward-compatible - never throw on an unexpected value).
 * Observed strings: pending, processing, completed, cancelled, failed, rejected, held.
 */
enum class ExportStatus {
    PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED, REJECTED, HELD, UNKNOWN;

    /** Terminal states do not re-poll and re-enable the request CTA. */
    val isTerminal: Boolean
        get() = this == COMPLETED || this == FAILED || this == CANCELLED || this == REJECTED

    companion object {
        /** Normalizes any wire value to a known state, falling back to [UNKNOWN]. */
        fun fromWire(value: String?): ExportStatus = when (value?.trim()?.lowercase()) {
            "pending" -> PENDING
            "processing" -> PROCESSING
            "completed" -> COMPLETED
            "failed" -> FAILED
            "cancelled", "canceled" -> CANCELLED
            "rejected" -> REJECTED
            "held" -> HELD
            else -> UNKNOWN
        }
    }
}

/**
 * AND-385 - the domain view of one export request. [createdAt] / [downloadExpiresAt] are epoch MILLISECONDS
 * (built from the wire epoch SECONDS * 1000). [isDownloadable] is true only for a COMPLETED request whose
 * download is referenceable and not past its expiry.
 */
data class ExportRequest(
    val id: String,
    val status: ExportStatus,
    val createdAtEpochMs: Long,
    val downloadExpiresAtEpochMs: Long?,
    val sizeBytes: Long?,
    val downloadUrl: String?,
) {
    val isTerminal: Boolean get() = status.isTerminal

    /** True once the expiry timestamp (if any) has passed [nowEpochMs]. */
    fun isExpired(nowEpochMs: Long): Boolean {
        val exp = downloadExpiresAtEpochMs ?: return false
        return exp <= nowEpochMs
    }

    /** A COMPLETED request that has not expired can be downloaded (via the stable {id}/download sub-path). */
    fun isDownloadable(nowEpochMs: Long): Boolean =
        status == ExportStatus.COMPLETED && !isExpired(nowEpochMs)

    /** A FAILED / CANCELLED / REJECTED request can be re-requested. */
    val isRetryable: Boolean
        get() = status == ExportStatus.FAILED || status == ExportStatus.CANCELLED ||
            status == ExportStatus.REJECTED
}

/**
 * AND-385 - the data categories offered for export. Keys mirror the web client (AccountDeletionPage.tsx
 * EXPORT_CATEGORIES); every category defaults to true (the user can deselect). The POST body is a map of
 * key -> include-flag.
 */
object ExportCategories {
    val ALL: List<String> = listOf(
        "profile",
        "messages",
        "posts",
        "billing",
        "files",
        "contacts",
        "calendar",
        "subscriptions",
        "push_devices",
        "tickets",
        "sessions",
    )

    /** The default selection: every known category included. */
    fun allSelected(): Map<String, Boolean> = ALL.associateWith { true }
}

/** AND-385 - DTO -> domain mappers (kept in :app per the module contract). */

/** Epoch SECONDS -> epoch MILLISECONDS (null-tolerant). */
private fun Long?.secondsToMillis(): Long? = this?.let { it * 1000L }

fun ExportStatusDto.toDomain(): ExportRequest = ExportRequest(
    id = requestId,
    status = ExportStatus.fromWire(status),
    createdAtEpochMs = (createdAt * 1000L),
    downloadExpiresAtEpochMs = downloadExpiresAt.secondsToMillis(),
    sizeBytes = fileSizeBytes,
    downloadUrl = downloadUrl,
)

fun DataRequestDto.toDomain(): ExportRequest = ExportRequest(
    id = requestId,
    status = ExportStatus.fromWire(status),
    createdAtEpochMs = (createdAt * 1000L),
    // The list row carries no explicit expiry; expiry is only known from the single-request status object.
    downloadExpiresAtEpochMs = null,
    sizeBytes = exportSizeBytes,
    downloadUrl = exportDownloadUrl,
)

/** Keeps only EXPORT rows, mapped + sorted newest-first by created_at. */
fun DataRequestListDto.toExportDomain(): List<ExportRequest> =
    requests.asSequence()
        .filter { it.requestType.equals("export", ignoreCase = true) }
        .map { it.toDomain() }
        .sortedByDescending { it.createdAtEpochMs }
        .toList()
