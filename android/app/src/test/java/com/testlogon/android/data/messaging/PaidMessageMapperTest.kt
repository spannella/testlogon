package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-137/138/139 — DTO -> domain mapping for countdown, calendar, paid, and lottery messages. */
class PaidMessageMapperTest {

    private fun dto(kind: String, build: MessageDto.() -> MessageDto): MessageDto =
        MessageDto(messageId = "m1", conversationId = "c1", senderId = "u1", createdAt = 100, kind = kind).build()

    // ---- AND-137 countdown ----

    @Test
    fun countdown_mapsTitleTargetAndEventType() {
        val msg = dto("countdown") {
            copy(countdownTitle = "Launch", targetDatetime = 1780000000, associatedEventType = "custom")
        }.toDomain()
        val media = msg.media as MessageMedia.Countdown
        assertEquals("Launch", media.title)
        assertEquals(1780000000L, media.targetEpochSeconds)
        assertEquals(AssociatedEventType.CUSTOM, media.associatedEventType)
    }

    @Test
    fun associatedEventType_unknownMapsToUnknown_nullToCustom() {
        assertEquals(AssociatedEventType.CUSTOM, (null as String?).toAssociatedEventType())
        assertEquals(AssociatedEventType.BROADCAST, "broadcast".toAssociatedEventType())
        assertEquals(AssociatedEventType.UNKNOWN, "hologram".toAssociatedEventType())
    }

    // ---- AND-138 calendar ----

    @Test
    fun calendarEvent_mapsName_startEnd_notTitle() {
        val msg = dto("calendar_event") {
            copy(
                calendarEvent = CalendarEventAttachmentDto(
                    eventId = "evt_1", calendarId = "cal_1", name = "Sprint review",
                    startUtc = "2026-06-10T17:00:00Z", endUtc = "2026-06-10T18:00:00Z",
                    allDay = false, timezone = "America/New_York", description = "Demo", owner = "u1",
                ),
            )
        }.toDomain()
        val media = msg.media as MessageMedia.CalendarEvent
        assertEquals("Sprint review", media.name)
        assertEquals("2026-06-10T17:00:00Z", media.startUtc)
        assertFalse(media.allDay)
        assertEquals("Demo", media.description)
    }

    @Test
    fun calendarEvent_allDay_hasDateAndNoClock() {
        val msg = dto("calendar_event") {
            copy(
                calendarEvent = CalendarEventAttachmentDto(
                    eventId = "evt_2", calendarId = "cal_1", name = "Holiday",
                    startUtc = null, endUtc = null, allDay = true, allDayDate = "2026-12-25",
                    timezone = "UTC", owner = "u1",
                ),
            )
        }.toDomain()
        val media = msg.media as MessageMedia.CalendarEvent
        assertTrue(media.allDay)
        assertEquals("2026-12-25", media.allDayDate)
        assertNull(media.endUtc)
    }

    @Test
    fun calendarShare_mapsPermission_readWrite_unknown() {
        fun share(p: String) = dto("calendar_share") {
            copy(calendarShare = CalendarShareAttachmentDto(calendarId = "cal_1", name = "Team", owner = "Dana", permission = p))
        }.toDomain().media as MessageMedia.CalendarShare
        assertEquals(SharePermission.READ, share("read").permission)
        assertEquals(SharePermission.WRITE, share("write").permission)
        assertEquals(SharePermission.UNKNOWN, share("owner").permission)
    }

    // ---- AND-139 paid / lottery ----

    @Test
    fun fixedPriceLocked_mapsPriceAndTeaser_noRevealedText() {
        val msg = dto("text") {
            copy(locked = true, isUnlocked = false, lockPriceCents = 500, lockDescription = "preview", text = "GATED")
        }.toDomain()
        val media = msg.media as MessageMedia.Paid
        assertEquals(UnlockType.FIXED, media.monetization.type)
        assertFalse(media.monetization.unlocked)
        assertEquals(500L, media.monetization.priceMinorUnits)
        assertEquals("preview", media.monetization.teaser)
        // Gated body is NOT carried into the monetization model while locked.
        assertNull(media.monetization.revealedText)
    }

    @Test
    fun unlockedFixed_isNotARenderedLockedTeaser() {
        // locked but already unlocked -> falls through to a non-Paid media (normal message).
        val msg = dto("text") {
            copy(locked = true, isUnlocked = true, lockPriceCents = 500, text = "revealed body")
        }.toDomain()
        assertFalse(msg.media is MessageMedia.Paid)
    }

    @Test
    fun lottery_lockedMapsToLotteryPaid_noRevealedText() {
        val msg = dto("lottery_dm") {
            copy(lottery = LotteryAttachmentDto(messageType = "lottery_dm", lockState = "locked"))
        }.toDomain()
        val media = msg.media as MessageMedia.Paid
        assertEquals(UnlockType.LOTTERY, media.monetization.type)
        assertFalse(media.monetization.unlocked)
        assertNull(media.monetization.priceMinorUnits)
        assertNull(media.monetization.revealedText)
    }

    @Test
    fun lottery_unlockedRevealsSelectedOutcomeText() {
        val msg = dto("lottery_dm") {
            copy(
                lottery = LotteryAttachmentDto(
                    messageType = "lottery_dm", lockState = "unlocked",
                    selectedOutcome = LotterySelectedOutcomeDto(outcomeId = "o1", payloadType = "text", textContent = "You win"),
                ),
            )
        }.toDomain()
        val media = msg.media as MessageMedia.Paid
        assertTrue(media.monetization.unlocked)
        assertEquals("You win", media.monetization.revealedText)
    }
}
