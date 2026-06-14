package com.testlogon.android.data.vod

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-191 — DTO -> domain mapping for both catalog envelopes (public VideoListOut + gallery). */
class VodMapperTest {

    @Test
    fun publicCatalog_mapsItemsAndCursor() {
        val resp = VideoListResponseDto(
            items = listOf(
                VideoListItemDto(videoId = "v1", title = "A", thumbnailUrl = "u", durationSeconds = 5400.0),
                VideoListItemDto(videoId = "", title = "skip"),
            ),
            cursor = "c2",
        )
        val page = resp.toDomain()
        assertEquals(listOf("v1"), page.items.map { it.id })
        assertEquals(5400, page.items.single().durationSec)
        assertEquals("c2", page.cursor)
    }

    @Test
    fun gallery_mapsVideosAndCursor() {
        val resp = GalleryListResponseDto(
            videos = listOf(GalleryVideoItemDto(videoId = "v2", title = "B", durationSeconds = 60.4)),
            categories = listOf(GalleryCategoryDto(slug = "comedy", label = "Comedy")),
            cursor = null,
        )
        val page = resp.toDomain()
        assertEquals("v2", page.items.single().id)
        assertEquals(60, page.items.single().durationSec)
        assertNull(page.cursor)
        assertEquals(VodCategory("comedy", "Comedy"), resp.categories.single().toDomain())
    }

    @Test
    fun gallerySearch_mapsVideos() {
        val page = GallerySearchResponseDto(
            videos = listOf(GalleryVideoItemDto(videoId = "v3", title = "C")),
            cursor = "next",
        ).toDomain()
        assertEquals("v3", page.items.single().id)
        assertEquals("next", page.cursor)
    }
}
