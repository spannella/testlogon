package com.testlogon.android.core.network.files

import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileTextSearchDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.time.Instant

/**
 * AND-331 - pure (no MockWebServer) unit tests for the file DTO to domain mappers: the `type` token
 * mapping (file / folder / unknown), Instant.parse of a valid + a malformed + an absent timestamp (the
 * latter two yield null and never throw), and the list -> page cursor passthrough.
 */
class FileDtoMappersTest {

    private fun entry(
        name: String = "a.txt",
        path: String = "/docs/a.txt",
        type: String = "file",
        updatedAt: String? = null,
        createdAt: String? = null,
    ) = FileEntryDto(
        name = name,
        path = path,
        type = type,
        updated_at = updatedAt,
        created_at = createdAt,
    )

    @Test
    fun type_file_mapsToFile() {
        assertEquals(FileNodeType.FILE, entry(type = "file").toDomain().type)
    }

    @Test
    fun type_folder_mapsToFolder() {
        assertEquals(FileNodeType.FOLDER, entry(type = "folder").toDomain().type)
    }

    @Test
    fun type_isCaseInsensitive() {
        assertEquals(FileNodeType.FILE, entry(type = "FILE").toDomain().type)
        assertEquals(FileNodeType.FOLDER, entry(type = "Folder").toDomain().type)
    }

    @Test
    fun type_unknownToken_mapsToUnknown() {
        assertEquals(FileNodeType.UNKNOWN, entry(type = "symlink").toDomain().type)
        assertEquals(FileNodeType.UNKNOWN, entry(type = "").toDomain().type)
    }

    @Test
    fun timestamp_validIso_parsesToInstant() {
        val node = entry(updatedAt = "2026-01-02T03:04:05Z").toDomain()
        assertEquals(Instant.parse("2026-01-02T03:04:05Z"), node.updatedAt)
    }

    @Test
    fun timestamp_malformed_mapsToNull() {
        val node = entry(updatedAt = "not-a-timestamp", createdAt = "2026-13-99").toDomain()
        assertNull(node.updatedAt)
        assertNull(node.createdAt)
    }

    @Test
    fun timestamp_absent_mapsToNull() {
        val node = entry(updatedAt = null, createdAt = null).toDomain()
        assertNull(node.updatedAt)
        assertNull(node.createdAt)
    }

    @Test
    fun entryFields_passThrough() {
        val dto = FileEntryDto(
            name = "a.txt",
            path = "/docs/a.txt",
            type = "file",
            size = 99L,
            content_type = "text/plain",
            is_encrypted = true,
            preview_kind = "image",
            poster_url = "https://cdn.example/p.png",
        )
        val node = dto.toDomain()
        assertEquals(99L, node.sizeBytes)
        assertEquals("text/plain", node.contentType)
        assertEquals(true, node.isEncrypted)
        assertEquals("image", node.previewKind)
        assertEquals("https://cdn.example/p.png", node.posterUrl)
    }

    @Test
    fun list_toPage_passesCursorAndMapsItems() {
        val dto = FileListDto(
            path = "/docs",
            items = listOf(entry(type = "file"), entry(name = "sub", path = "/docs/sub", type = "folder")),
            cursor = "next_page",
        )
        val page = dto.toDomain()
        assertEquals("/docs", page.path)
        assertEquals("next_page", page.cursor)
        assertEquals(2, page.items.size)
        assertEquals(FileNodeType.FILE, page.items[0].type)
        assertEquals(FileNodeType.FOLDER, page.items[1].type)
    }

    @Test
    fun list_nullCursor_passesThrough() {
        val page = FileListDto(path = "/", items = emptyList(), cursor = null).toDomain()
        assertNull(page.cursor)
        assertEquals(0, page.items.size)
    }

    @Test
    fun prefixSearch_toResults_usesPrefixAsQuery() {
        val dto = FileSearchDto(prefix = "rep", results = listOf(entry(name = "report.pdf")))
        val results = dto.toDomain()
        assertEquals("rep", results.query)
        assertEquals(1, results.results.size)
    }

    @Test
    fun textSearch_toResults_usesQuery() {
        val dto = FileTextSearchDto(query = "invoice", results = listOf(entry(name = "invoice.pdf")))
        val results = dto.toDomain()
        assertEquals("invoice", results.query)
        assertEquals(1, results.results.size)
    }
}
