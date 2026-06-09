package com.testlogon.android.data.feed

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-097 / AND-101 — pure mapper unit tests (no network). Covers paywall derivation, media synthesis,
 * locked-content redaction, timestamp parsing, and fail-safe fallbacks.
 */
class FeedMapperTest {

    private fun post(
        locked: Boolean = false,
        unlocked: Boolean = false,
        lockType: String? = null,
        priceCents: Int? = null,
        unlockLimit: Int? = null,
        unlockCount: Int? = null,
        unlockLimitReached: Boolean? = null,
        lockExpired: Boolean? = null,
        body: String? = "Full body",
        bodyPlain: String? = null,
        imageUrls: List<String>? = null,
        video: VideoDto? = null,
        createdAt: String = "2026-06-04T18:22:10Z",
    ) = PostDto(
        postId = "post_1",
        authorId = "u_42",
        createdAt = createdAt,
        body = body,
        bodyPlain = bodyPlain,
        imageUrls = imageUrls,
        video = video,
        locked = locked,
        unlocked = unlocked,
        lockType = lockType,
        unlockPriceCents = priceCents,
        unlockLimit = unlockLimit,
        unlockCount = unlockCount,
        unlockLimitReached = unlockLimitReached,
        lockExpired = lockExpired,
    )

    @Test
    fun unlockedPost_mapsToUnlocked_withAccessibleMedia() {
        val domain = post(imageUrls = listOf("http://h/m1.jpg")).toDomain()
        assertTrue(domain.paywall is Paywall.Unlocked)
        assertEquals("post_1", domain.id)
        assertEquals("u_42", domain.authorId)
        assertEquals("Full body", domain.body)
        assertEquals(1, domain.media.size)
        assertEquals("http://h/m1.jpg", domain.media[0].url)
        assertEquals(MediaType.IMAGE, domain.media[0].type)
    }

    @Test
    fun lockedNotUnlocked_mapsToLocked_andRedactsContent() {
        val domain = post(
            locked = true, unlocked = false, lockType = "fixed_price", priceCents = 499,
            unlockLimit = 500, unlockCount = 230, unlockLimitReached = false, lockExpired = false,
            imageUrls = listOf("http://h/paid.jpg"),
            video = VideoDto(videoId = "v_2", thumbnailUrl = "http://h/thumb.jpg", durationSeconds = 45),
        ).toDomain()

        val pw = domain.paywall as Paywall.Locked
        assertEquals(LockType.FIXED_PRICE, pw.lockType)
        assertEquals(499, pw.priceCents)
        assertEquals(230, pw.unlockCount)
        assertEquals(500, pw.unlockLimit)
        assertEquals(false, pw.unlockLimitReached)
        assertEquals(false, pw.lockExpired)
        // Redaction: body dropped, media emptied -> no paid URL can leak.
        assertNull(domain.body)
        assertTrue(domain.media.isEmpty())
        assertTrue(domain.isLocked)
    }

    @Test
    fun lockedButUnlocked_mapsToUnlocked_preservesContent() {
        val domain = post(locked = true, unlocked = true, imageUrls = listOf("http://h/m.jpg")).toDomain()
        assertTrue(domain.paywall is Paywall.Unlocked)
        assertEquals("Full body", domain.body)
        assertEquals(1, domain.media.size)
    }

    @Test
    fun tipLottery_mapsToTipLottery() {
        val domain = post(locked = true, unlocked = false, lockType = "tip_lottery").toDomain()
        assertEquals(LockType.TIP_LOTTERY, (domain.paywall as Paywall.Locked).lockType)
    }

    @Test
    fun unknownLockType_withPrice_fallsBackToFixedPrice() {
        val domain = post(locked = true, unlocked = false, lockType = "weird", priceCents = 100).toDomain()
        assertEquals(LockType.FIXED_PRICE, (domain.paywall as Paywall.Locked).lockType)
    }

    @Test
    fun unknownLockType_noPrice_isUnknown() {
        val domain = post(locked = true, unlocked = false, lockType = "weird", priceCents = null).toDomain()
        assertEquals(LockType.UNKNOWN, (domain.paywall as Paywall.Locked).lockType)
    }

    @Test
    fun soldOut_andExpired_carriedThrough() {
        val domain = post(
            locked = true, unlocked = false, lockType = "fixed_price",
            unlockLimitReached = true, lockExpired = true,
        ).toDomain()
        val pw = domain.paywall as Paywall.Locked
        assertTrue(pw.unlockLimitReached)
        assertTrue(pw.lockExpired)
    }

    @Test
    fun bodyPlain_preferredOverBody() {
        val domain = post(body = "raw", bodyPlain = "plain projection").toDomain()
        assertEquals("plain projection", domain.body)
    }

    @Test
    fun blankBody_mapsToNull() {
        val domain = post(body = "   ", bodyPlain = null).toDomain()
        assertNull(domain.body)
    }

    @Test
    fun videoOnly_mapsToVideoMedia_keyedOnVideoId() {
        val domain = post(
            video = VideoDto(videoId = "v_9", thumbnailUrl = "http://h/t.jpg", durationSeconds = 30),
        ).toDomain()
        assertEquals(1, domain.media.size)
        val m = domain.media[0]
        assertEquals("v_9", m.id)
        assertEquals(MediaType.VIDEO, m.type)
        assertEquals("http://h/t.jpg", m.thumbnailUrl)
        assertEquals(30L, m.durationSeconds)
    }

    @Test
    fun imagesThenVideo_orderPreserved() {
        val domain = post(
            imageUrls = listOf("http://h/a.jpg", "http://h/b.jpg"),
            video = VideoDto(videoId = "v_1", thumbnailUrl = "http://h/t.jpg"),
        ).toDomain()
        assertEquals(3, domain.media.size)
        assertEquals(MediaType.IMAGE, domain.media[0].type)
        assertEquals(MediaType.VIDEO, domain.media[2].type)
    }

    @Test
    fun blankImageUrls_filteredOut() {
        val domain = post(imageUrls = listOf("", "  ", "http://h/ok.jpg")).toDomain()
        assertEquals(1, domain.media.size)
    }

    @Test
    fun malformedTimestamp_fallsBackToEpoch() {
        assertEquals(0L, post(createdAt = "not-a-date").toDomain().createdAtEpochSeconds)
        assertEquals(0L, post(createdAt = "").toDomain().createdAtEpochSeconds)
    }

    @Test
    fun isoTimestamp_parsedToEpochSeconds() {
        // 2026-06-04T18:22:10Z == 1780597330 (Unix seconds, UTC).
        val expected = 1780597330L
        assertEquals(expected, post(createdAt = "2026-06-04T18:22:10Z").toDomain().createdAtEpochSeconds)
    }

    @Test
    fun isoTimestamp_withMillisAndOffset_parsed() {
        val z = post(createdAt = "2026-06-04T18:22:10.123Z").toDomain().createdAtEpochSeconds
        assertEquals(1780597330L, z)
        // +00:00 offset equals the Z value.
        val off = post(createdAt = "2026-06-04T18:22:10+00:00").toDomain().createdAtEpochSeconds
        assertEquals(1780597330L, off)
    }

    @Test
    fun pageEnvelope_propagatesCursor_andNullEnd() {
        val withCursor = FeedPageDto(items = listOf(post()), nextCursor = "c2").toDomain()
        assertEquals("c2", withCursor.nextCursor)
        assertEquals(1, withCursor.posts.size)
        val end = FeedPageDto(items = emptyList(), nextCursor = null).toDomain()
        assertNull(end.nextCursor)
    }
}
