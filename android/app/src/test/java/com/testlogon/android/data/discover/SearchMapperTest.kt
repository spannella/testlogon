package com.testlogon.android.data.discover

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-185 — pure unit tests for [SearchMapper]: bucketing, ordering, OTHER fallback, snippet suppression. */
class SearchMapperTest {

    private fun section(vararg items: SearchItemDto, total: Int = items.size, more: Boolean = false) =
        SearchSectionDto(items = items.toList(), totalEstimate = total, hasMore = more)

    private fun item(type: String, id: String, title: String, snippet: String? = null, url: String = "/x/$id") =
        SearchItemDto(type = type, id = id, title = title, snippet = snippet, url = url)

    @Test
    fun mapsEachType_toItsCategory_inFixedOrder() {
        val dto = SearchResponseDto(
            query = "q",
            results = SearchResultsDto(
                posts = section(item("post", "p1", "P")),
                users = section(item("user", "u1", "U")),
                videos = section(item("video", "v1", "V")),
            ),
        )
        val result = SearchMapper.toDomain(dto)
        // SECTION_ORDER puts USER, then POST, then VIDEO.
        assertEquals(
            listOf(SearchEntityType.USER, SearchEntityType.POST, SearchEntityType.VIDEO),
            result.categories.map { it.type },
        )
        assertEquals(3, result.totalCount)
    }

    @Test
    fun emptySections_areDropped() {
        val dto = SearchResponseDto(
            results = SearchResultsDto(
                users = section(item("user", "u1", "U")),
                posts = section(total = 0), // empty -> dropped
            ),
        )
        val result = SearchMapper.toDomain(dto)
        assertEquals(listOf(SearchEntityType.USER), result.categories.map { it.type })
    }

    @Test
    fun unknownType_mapsToOther() {
        val dto = SearchResponseDto(
            results = SearchResultsDto(
                users = section(SearchItemDto(type = "widget", id = "w1", title = "Widget", url = "/w/w1")),
            ),
        )
        val result = SearchMapper.toDomain(dto)
        assertEquals(SearchEntityType.OTHER, result.categories.single().items.single().type)
    }

    @Test
    fun snippetEqualToTitle_isSuppressed() {
        val dto = SearchResponseDto(
            results = SearchResultsDto(
                users = section(item("user", "u1", "Jane", snippet = "Jane")),
            ),
        )
        assertNull(SearchMapper.toDomain(dto).categories.single().items.single().snippet)
    }

    @Test
    fun blankIdItems_dropped_emptySectionRemoved() {
        val dto = SearchResponseDto(
            results = SearchResultsDto(users = section(item("user", "", "no id"))),
        )
        assertTrue(SearchMapper.toDomain(dto).categories.isEmpty())
    }

    @Test
    fun totalEstimate_neverBelowRenderedCount() {
        val dto = SearchResponseDto(
            results = SearchResultsDto(
                users = section(item("user", "u1", "U"), item("user", "u2", "U2"), total = 0, more = true),
            ),
        )
        val cat = SearchMapper.toDomain(dto).categories.single()
        assertEquals(2, cat.totalEstimate) // coerced up to items.size
        assertTrue(cat.hasMore)
    }

    @Test
    fun fromWire_caseInsensitive_andDefaults() {
        assertEquals(SearchEntityType.USER, SearchEntityType.fromWire("USER"))
        assertEquals(SearchEntityType.OTHER, SearchEntityType.fromWire(null))
        assertEquals(SearchEntityType.OTHER, SearchEntityType.fromWire("nope"))
    }
}
