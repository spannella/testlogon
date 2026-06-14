package com.testlogon.android.core.model.files

import java.time.Instant

/**
 * AND-331 - domain models for the path-addressed file-manager surface (the typed, mapper-produced
 * counterparts to the wire DTOs in FilesDtos.kt).
 *
 * The wire `type` String is normalized to [FileNodeType] (file or folder, else UNKNOWN). The nullable
 * ISO-8601 timestamp Strings are parsed to [Instant] by the core-network FileDtoMappers (a malformed or
 * absent value becomes null). These domain types are pure data and carry NO Moshi annotations.
 */

/** Kind of a file-system node. Unknown / unrecognized wire `type` tokens map to [UNKNOWN]. */
enum class FileNodeType { FILE, FOLDER, UNKNOWN }

/** A typed file-system entry (file or folder). */
data class FileNode(
    val path: String,
    val name: String,
    val type: FileNodeType,
    val sizeBytes: Long? = null,
    val contentType: String? = null,
    val updatedAt: Instant? = null,
    val createdAt: Instant? = null,
    val isEncrypted: Boolean = false,
    val previewKind: String? = null,
    val posterUrl: String? = null,
)

/** A page of a directory listing: the listed [path], its [items], and an optional [cursor]. */
data class FilePage(
    val path: String,
    val items: List<FileNode>,
    val cursor: String? = null,
)

/**
 * Results of a search. [query] holds the search term regardless of whether it came from the prefix /
 * name search or the full-text search surface.
 */
data class FileSearchResults(
    val query: String,
    val results: List<FileNode>,
)
