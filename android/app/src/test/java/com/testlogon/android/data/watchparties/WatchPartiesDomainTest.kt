package com.testlogon.android.data.watchparties

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM mapper tests for the watch-parties DTO -> domain layer. */
class WatchPartiesDomainTest {

    private fun partyDto(
        status: String = "waiting",
        position: Double = 0.0,
    ) = WatchPartyDto(
        partyId = "wp_1",
        hostUserSub = "host_sub",
        videoId = "vid_1",
        videoTitle = "The Video",
        videoDurationSeconds = 3600,
        title = "My Party",
        inviteCode = "INV123",
        status = status,
        maxParticipants = 50,
        participantCount = 7,
        position = position,
        createdAt = 1000,
        updatedAt = 2000,
        endedAt = null,
    )

    @Test
    fun partyDto_toDomain_mapsAllFields() {
        val domain = partyDto(status = "playing", position = 42.9).toDomain()

        assertEquals("wp_1", domain.id)
        assertEquals("host_sub", domain.hostUserSub)
        assertEquals("vid_1", domain.videoId)
        assertEquals("The Video", domain.videoTitle)
        assertEquals(3600L, domain.videoDurationSeconds)
        assertEquals("My Party", domain.title)
        assertEquals("INV123", domain.inviteCode)
        assertEquals(WatchPartyStatus.PLAYING, domain.status)
        assertEquals(50, domain.maxParticipants)
        assertEquals(7, domain.participantCount)
        assertEquals(1000L, domain.createdAtSeconds)
        assertNull(domain.endedAtSeconds)
    }

    @Test
    fun partyDto_position_doubleTruncatesToLong() {
        assertEquals(42L, partyDto(position = 42.9).toDomain().positionSeconds)
        assertEquals(0L, partyDto(position = 0.0).toDomain().positionSeconds)
    }

    @Test
    fun statusOf_mapsKnownStrings() {
        assertEquals(WatchPartyStatus.WAITING, statusOf("waiting"))
        assertEquals(WatchPartyStatus.PLAYING, statusOf("playing"))
        assertEquals(WatchPartyStatus.PAUSED, statusOf("paused"))
        assertEquals(WatchPartyStatus.ENDED, statusOf("ended"))
    }

    @Test
    fun statusOf_isCaseInsensitive() {
        assertEquals(WatchPartyStatus.PLAYING, statusOf("PLAYING"))
        assertEquals(WatchPartyStatus.ENDED, statusOf("Ended"))
    }

    @Test
    fun statusOf_unknownString_mapsToUnknown() {
        assertEquals(WatchPartyStatus.UNKNOWN, statusOf("bogus"))
        assertEquals(WatchPartyStatus.UNKNOWN, statusOf(""))
    }

    @Test
    fun partyDto_endedStatus_setsIsEnded() {
        val domain = partyDto(status = "ended").toDomain()
        assertEquals(WatchPartyStatus.ENDED, domain.status)
        assertTrue(domain.isEnded)
    }

    @Test
    fun partyDto_nonEnded_isNotEnded() {
        assertFalse(partyDto(status = "waiting").toDomain().isEnded)
    }

    @Test
    fun participantDto_toDomain_mapsRoleAndStatus() {
        val host = WatchPartyParticipantDto(
            userSub = "u_host", role = "host", status = "active", joinedAt = 5,
        ).toDomain()
        assertEquals("u_host", host.userSub)
        assertEquals(ParticipantRole.HOST, host.role)
        assertEquals(ParticipantStatus.ACTIVE, host.status)
        assertEquals(5L, host.joinedAtSeconds)
        assertTrue(host.isActive)
    }

    @Test
    fun participantDto_coHostAliases_mapToCoHost() {
        assertEquals(
            ParticipantRole.CO_HOST,
            WatchPartyParticipantDto(userSub = "a", role = "co-host", status = "active").toDomain().role,
        )
        assertEquals(
            ParticipantRole.CO_HOST,
            WatchPartyParticipantDto(userSub = "b", role = "cohost", status = "active").toDomain().role,
        )
    }

    @Test
    fun participantDto_unknownRole_mapsToMember() {
        assertEquals(
            ParticipantRole.MEMBER,
            WatchPartyParticipantDto(userSub = "c", role = "whatever", status = "active").toDomain().role,
        )
    }

    @Test
    fun participantDto_statusVariants() {
        fun statusOf(raw: String) =
            WatchPartyParticipantDto(userSub = "x", role = "member", status = raw).toDomain().status
        assertEquals(ParticipantStatus.ACTIVE, statusOf("active"))
        assertEquals(ParticipantStatus.LEFT, statusOf("left"))
        assertEquals(ParticipantStatus.KICKED, statusOf("kicked"))
        assertEquals(ParticipantStatus.UNKNOWN, statusOf("???"))
        assertFalse(WatchPartyParticipantDto(userSub = "x", role = "member", status = "left").toDomain().isActive)
    }

    @Test
    fun listOfPartyDtos_bareArray_mapsEachToDomain() {
        // The list endpoint returns a BARE JSON array of WatchPartyDto; mapping is List.map { toDomain() }.
        val dtos = listOf(
            partyDto(status = "waiting").copy(partyId = "wp_a"),
            partyDto(status = "playing").copy(partyId = "wp_b"),
        )
        val domain = dtos.map { it.toDomain() }
        assertEquals(2, domain.size)
        assertEquals("wp_a", domain[0].id)
        assertEquals(WatchPartyStatus.WAITING, domain[0].status)
        assertEquals("wp_b", domain[1].id)
        assertEquals(WatchPartyStatus.PLAYING, domain[1].status)
    }

    @Test
    fun emptyList_mapsToEmpty() {
        assertTrue(emptyList<WatchPartyDto>().map { it.toDomain() }.isEmpty())
    }

    @Test
    fun listOfParticipants_participantCountReflectsSize() {
        val participants = listOf(
            WatchPartyParticipantDto(userSub = "a", role = "host", status = "active"),
            WatchPartyParticipantDto(userSub = "b", role = "member", status = "active"),
            WatchPartyParticipantDto(userSub = "c", role = "member", status = "left"),
        ).map { it.toDomain() }
        assertEquals(3, participants.size)
        assertEquals(2, participants.count { it.isActive })
    }

    @Test
    fun inviteResolveDto_toDomain_mapsFields() {
        val domain = InviteResolveRespDto(
            partyId = "wp_inv",
            title = "Invite Party",
            hostUserSub = "h",
            videoTitle = "Vid",
            status = "paused",
            participantCount = 3,
            maxParticipants = 20,
        ).toDomain()

        assertEquals("wp_inv", domain.partyId)
        assertEquals("Invite Party", domain.title)
        assertEquals("Vid", domain.videoTitle)
        assertEquals(WatchPartyStatus.PAUSED, domain.status)
        assertEquals(3, domain.participantCount)
        assertEquals(20, domain.maxParticipants)
    }

    @Test
    fun party_displayTitle_fallsBackToVideoTitleThenId() {
        assertEquals("My Party", partyDto().copy(title = "My Party").toDomain().displayTitle)
        assertEquals("The Video", partyDto().copy(title = "", videoTitle = "The Video").toDomain().displayTitle)
        assertEquals("wp_1", partyDto().copy(title = "", videoTitle = "").toDomain().displayTitle)
    }

    @Test
    fun party_formattedCreated_emptyForNonPositiveTimestamp() {
        assertEquals("", partyDto().copy(createdAt = 0).toDomain().formattedCreated())
        assertTrue(partyDto().copy(createdAt = 1000).toDomain().formattedCreated().isNotEmpty())
    }
}
