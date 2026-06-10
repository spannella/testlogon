package com.testlogon.android.data.discover

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-186 / TC-AND-186-01 — pure mapping of [SearchFilters] to the single supported server query
 * param (`types`). ALL omits the param; non-ALL emits the PLURAL section key; there is never a `sort`
 * (or any other) key, because GET /ui/search exposes only `q`, `types`, `limit`.
 */
class SearchFiltersTest {

    @Test
    fun default_isAll_omitsTypes() {
        val f = SearchFilters()
        assertTrue(f.isDefault)
        assertNull(f.toTypesParam())
        assertEquals(mapOf<String, String?>("types" to null), f.toQueryParams())
    }

    @Test
    fun users_mapsToPluralSectionKey() {
        val f = SearchFilters(SearchEntityType.USER)
        assertFalse(f.isDefault)
        assertEquals("users", f.toTypesParam())
        assertEquals(mapOf<String, String?>("types" to "users"), f.toQueryParams())
    }

    @Test
    fun posts_videos_catalog_useExpectedKeys() {
        assertEquals("posts", SearchFilters(SearchEntityType.POST).toTypesParam())
        assertEquals("videos", SearchFilters(SearchEntityType.VIDEO).toTypesParam())
        assertEquals("catalog", SearchFilters(SearchEntityType.CATALOG).toTypesParam())
        assertEquals("files", SearchFilters(SearchEntityType.FILE).toTypesParam())
        assertEquals("messages", SearchFilters(SearchEntityType.MESSAGE).toTypesParam())
        assertEquals("tickets", SearchFilters(SearchEntityType.TICKET).toTypesParam())
        assertEquals("contacts", SearchFilters(SearchEntityType.CONTACT).toTypesParam())
        assertEquals("calendar", SearchFilters(SearchEntityType.CALENDAR).toTypesParam())
    }

    @Test
    fun queryParams_neverContainSortOrDate() {
        val keys = SearchFilters(SearchEntityType.USER).toQueryParams().keys
        assertEquals(setOf("types"), keys)
    }

    @Test
    fun other_hasNoServerKey() {
        // OTHER is a forward-compat fallback for an unknown item type; it never scopes a request.
        assertNull(SearchFilters(SearchEntityType.OTHER).toTypesParam())
    }
}
