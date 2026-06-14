package com.testlogon.android.feature.seo

import com.squareup.moshi.Moshi
import com.testlogon.android.feature.seo.data.SeoMetadataDto
import com.testlogon.android.feature.seo.data.SeoMetadataMapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-400 - unit tests for [SeoMetadataMapper]: blank->null, tag-map cleanup, json_ld pretty-print, isEmpty. */
class SeoMetadataMapperTest {

    private val mapper = SeoMetadataMapper(Moshi.Builder().build())

    @Test
    fun blankScalarsNormalizeToNull() {
        val domain = mapper.toDomain(
            SeoMetadataDto(available = true, title = "  ", description = "Real", locale = ""),
        )
        assertNull(domain.title)
        assertEquals("Real", domain.description)
        assertNull(domain.locale)
    }

    @Test
    fun blankTagEntriesAreDropped() {
        val domain = mapper.toDomain(
            SeoMetadataDto(
                available = true,
                og = mapOf("og:title" to "T", "og:locale" to "  ", "og:url" to null),
                twitter = mapOf("twitter:card" to "summary", "twitter:title" to ""),
            ),
        )
        assertEquals(mapOf("og:title" to "T"), domain.og)
        assertEquals(mapOf("twitter:card" to "summary"), domain.twitter)
    }

    @Test
    fun jsonLdObjectRendersToIndentedString() {
        val domain = mapper.toDomain(
            SeoMetadataDto(
                available = true,
                title = "T",
                jsonLd = mapOf("@context" to "https://schema.org", "@type" to "ProfilePage"),
            ),
        )
        val json = domain.jsonLd!!
        assertTrue(json.contains("schema.org"))
        assertTrue(json.contains("ProfilePage"))
        // Indented (pretty) output contains a newline.
        assertTrue(json.contains("\n"))
    }

    @Test
    fun emptyJsonLdMapMapsToNull() {
        val domain = mapper.toDomain(SeoMetadataDto(available = true, title = "T", jsonLd = emptyMap()))
        assertNull(domain.jsonLd)
    }

    @Test
    fun isEmptyTrueWhenAvailableFalse() {
        val domain = mapper.toDomain(SeoMetadataDto(available = false, title = "Generic"))
        assertTrue(domain.isEmpty)
    }

    @Test
    fun isEmptyTrueWhenNoRenderableFields() {
        val domain = mapper.toDomain(
            SeoMetadataDto(available = true, title = "", og = emptyMap(), twitter = emptyMap()),
        )
        assertTrue(domain.isEmpty)
    }

    @Test
    fun isEmptyFalseWhenAnyFieldSet() {
        val domain = mapper.toDomain(SeoMetadataDto(available = true, title = "Has title"))
        assertFalse(domain.isEmpty)
    }
}
