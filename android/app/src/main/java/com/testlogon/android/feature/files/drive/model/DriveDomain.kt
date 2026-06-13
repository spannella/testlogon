package com.testlogon.android.feature.files.drive.model

import com.testlogon.android.core.model.files.DriveFileDto
import com.testlogon.android.core.model.files.DriveFilesRespDto
import com.testlogon.android.core.model.files.DriveImportRespDto
import com.testlogon.android.core.model.files.DriveStatusRespDto

/**
 * AND-336 - domain models for the BACKEND-MEDIATED Google Drive import surface (the typed,
 * mapper-produced counterparts to the wire DTOs in core-model GoogleDriveDtos.kt).
 *
 * Folder detection is LENIENT and happens here in the mapper: a Drive entry is a folder when the wire
 * is_folder flag is true OR its mime_type is the Google folder mime. These domain types are pure data.
 */

/** The connection state of the user's Drive integration. */
data class DriveStatus(
    val connected: Boolean,
    val email: String? = null,
)

/** A typed Drive entry. [isFolder] is DERIVED (is_folder OR the folder mime); unknown maps to a file. */
data class DriveFile(
    val id: String,
    val name: String,
    val mimeType: String? = null,
    val isFolder: Boolean = false,
    val sizeBytes: Long? = null,
)

/** A page of Drive entries plus the optional continuation token. */
data class DriveFilesPage(
    val files: List<DriveFile>,
    val nextPageToken: String? = null,
)

/** Result of a server-side Drive to TestLogon import. [path] is the resulting TestLogon path when known. */
data class DriveImportResult(
    val ok: Boolean,
    val path: String? = null,
)

/** The Google Drive mime that identifies a folder. */
const val DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"

/** Maps a status DTO to its domain model. */
fun DriveStatusRespDto.toDomain(): DriveStatus = DriveStatus(
    connected = connected,
    email = email,
)

/** Maps a single Drive entry DTO to domain, deriving the folder flag leniently. */
fun DriveFileDto.toDomain(): DriveFile = DriveFile(
    id = id,
    name = name,
    mimeType = mime_type,
    isFolder = (is_folder == true) || (mime_type == DRIVE_FOLDER_MIME),
    sizeBytes = size,
)

/** Maps a Drive listing DTO to a typed page (continuation token passed through). */
fun DriveFilesRespDto.toDomain(): DriveFilesPage = DriveFilesPage(
    files = files.map { it.toDomain() },
    nextPageToken = next_page_token,
)

/** Maps an import DTO to domain. */
fun DriveImportRespDto.toDomain(): DriveImportResult = DriveImportResult(
    ok = ok,
    path = path,
)
