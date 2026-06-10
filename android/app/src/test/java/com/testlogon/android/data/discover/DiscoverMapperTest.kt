package com.testlogon.android.data.discover

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-182 / AND-184 — pure mapper unit tests for discover creators/tags and recommendations. */
class DiscoverMapperTest {

    @Test
    fun discoveryUser_mapsToCreator_blankFieldsNulled() {
        val dto = DiscoveryUserDto(
            userId = "u1",
            displayName = "Ava",
            profilePhotoUrl = "",
            description = "  ",
            followerCount = 10,
            isFollowing = true,
        )
        val c = dto.toCreator()
        assertEquals("u1", c.userId)
        assertEquals("Ava", c.displayName)
        assertNull(c.profilePhotoUrl) // blank -> null
        assertNull(c.description) // blank -> null
        assertTrue(c.isFollowing)
    }

    @Test
    fun creators_dropBlankUserId() {
        val list = listOf(
            DiscoveryUserDto(userId = "", displayName = "x"),
            DiscoveryUserDto(userId = "u1", displayName = "y"),
        )
        assertEquals(listOf("u1"), list.toCreators().map { it.userId })
    }

    @Test
    fun tags_dropBlank() {
        val list = listOf(TrendingTagDto(tag = ""), TrendingTagDto(tag = "art", count = 5))
        assertEquals(listOf("art"), list.toTags().map { it.tag })
    }

    @Test
    fun forYou_mapsRealFieldNames_andDropsBlankId() {
        val dto = ForYouResponseDto(
            videos = listOf(
                RecommendedVideoDto(videoId = "", title = "bad"),
                RecommendedVideoDto(
                    videoId = "v1",
                    title = "Good",
                    thumbnailUrl = "http://h/t.jpg",
                    recommendationReason = "Because",
                ),
            ),
            source = "trending_fallback",
        )
        val recs = dto.toDomain()
        assertEquals(1, recs.items.size)
        val item = recs.items.single()
        assertEquals("v1", item.id)
        assertEquals("http://h/t.jpg", item.posterUrl)
        assertEquals("Because", item.reason)
        assertTrue(recs.isTrendingFallback)
    }

    @Test
    fun discoverContent_isEmpty_whenAllSectionsEmpty() {
        assertTrue(DiscoverContent(emptyList(), emptyList(), emptyList()).isEmpty)
        assertTrue(!DiscoverContent(listOf(DiscoverCreator("u", "n", null, null, 0, false)), emptyList(), emptyList()).isEmpty)
    }
}
