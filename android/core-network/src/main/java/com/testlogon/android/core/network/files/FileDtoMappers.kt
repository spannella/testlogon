package com.testlogon.android.core.network.files

import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.model.files.FilePage
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileSearchResults
import com.testlogon.android.core.model.files.FileTextSearchDto
import java.time.Instant

/**
 * AND-331 - DTO to domain mappers for the file-manager surface.
 *
 * The wire `type` String is normalized case-insensitively to [FileNodeType]; any token other than file
 * or folder becomes [FileNodeType.UNKNOWN]. The nullable ISO-8601 timestamp Strings are parsed with
 * [Instant.parse] wrapped in [runCatching], so a malformed (or absent) value maps to null and NEVER
 * crashes the decode. These mappers live in core-network (not core-model) because Instant parsing is the
 * transport layer's concern and core-model holds no parsing logic.
 */

/** Maps a wire `type` token to a typed [FileNodeType] (unrecognized -> [FileNodeType.UNKNOWN]). */
private fun fileNodeTypeFromWire(value: String): FileNodeType = when (value.lowercase()) {
    "file" -> FileNodeType.FILE
    "folder" -> FileNodeType.FOLDER
    else -> FileNodeType.UNKNOWN
}

/** Parses a nullable ISO-8601 timestamp; absent or malformed values yield null (never throws). */
private fun parseInstantOrNull(value: String?): Instant? =
    value?.let { runCatching { Instant.parse(it) }.getOrNull() }

/** Maps a single [FileEntryDto] to its typed [FileNode] domain model. */
fun FileEntryDto.toDomain(): FileNode = FileNode(
    path = path,
    name = name,
    type = fileNodeTypeFromWire(type),
    sizeBytes = size,
    contentType = content_type,
    updatedAt = parseInstantOrNull(updated_at),
    createdAt = parseInstantOrNull(created_at),
    isEncrypted = is_encrypted,
    previewKind = preview_kind,
    posterUrl = poster_url,
)

/** Maps a directory listing DTO to a typed [FilePage] (cursor passed through). */
fun FileListDto.toDomain(): FilePage = FilePage(
    path = path,
    items = items.map { it.toDomain() },
    cursor = cursor,
)

/** Maps a prefix/name search DTO to typed [FileSearchResults] (prefix carried as the query). */
fun FileSearchDto.toDomain(): FileSearchResults = FileSearchResults(
    query = prefix,
    results = results.map { it.toDomain() },
)

/** Maps a full-text search DTO to typed [FileSearchResults]. */
fun FileTextSearchDto.toDomain(): FileSearchResults = FileSearchResults(
    query = query,
    results = results.map { it.toDomain() },
)
