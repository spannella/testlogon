package com.testlogon.android.feature.signing.model

import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.testing.SigningFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-345 - focused GAP test for the AND-340 [SigningDomain] mappers (toDomain).
 *
 * SignatureRepositoryTest already covers getPacket DTO->domain for enums / signers / fields / Instant /
 * isAssignedToViewer, so this does NOT duplicate that. It fills the remaining mapper gaps that no
 * existing test asserts directly: the legal-notice mapping, a field's value + filledAt mapping, the
 * capabilities passthrough, and the event mapper. It consumes the shared [SigningFixtures] builders.
 *
 * Packet-LIST mapping is intentionally absent: there is no backend list endpoint and no list domain
 * (see SigningDomain.kt), so no list mapper exists to test. KDoc avoids the comment-terminator pair.
 */
class SigningDomainMapperTest {

    @Test
    fun legalNotice_mapsAllFields() {
        val dto = SigningFixtures.legalNoticeDto(
            required = true,
            accepted = false,
            version = "v9",
            text = "Sign electronically",
        )

        val domain = dto.toDomain()

        assertEquals(true, domain.required)
        assertEquals(false, domain.accepted)
        assertEquals("v9", domain.version)
        assertEquals("Sign electronically", domain.text)
    }

    @Test
    fun field_mapsValueAndFilledAtInstant() {
        val dto = SigningFixtures.fieldDto(
            fieldId = "fld_sig",
            fieldType = SignatureFieldType.SIGNATURE,
        ).copy(
            value = "John Doe",
            filledAt = "2026-05-02T11:00:00Z",
        )

        val domain = dto.toDomain()

        assertEquals("John Doe", domain.value)
        assertEquals(Instant.parse("2026-05-02T11:00:00Z"), domain.filledAt)
    }

    @Test
    fun field_badFilledAt_degradesToNull() {
        val dto = SigningFixtures.fieldDto().copy(filledAt = "not-a-date")
        assertNull(dto.toDomain().filledAt)
    }

    @Test
    fun packet_mapsCapabilitiesAndLegalNotice_andRoleStatus() {
        val dto = SigningFixtures.packetDetailDto(
            status = PacketStatus.SENT,
            role = PacketRole.SIGNER,
            capabilities = mapOf("can_fill_fields" to true, "can_send" to false),
        )

        val domain = dto.toDomain()

        assertEquals(PacketStatus.SENT, domain.status)
        assertEquals(PacketRole.SIGNER, domain.role)
        assertEquals(true, domain.capabilities["can_fill_fields"])
        assertEquals(false, domain.capabilities["can_send"])
        assertEquals("v2", domain.legalNotice?.version)
        assertTrue(domain.legalNotice?.required == true)
        // The five-type field fixture round-trips through the field mapper.
        assertEquals(3, domain.fields.size)
    }

    @Test
    fun event_mapsTypeActorAndInstant() {
        val dto = SigningFixtures.eventDto(
            eventId = "evt_1",
            eventType = "packet.sent",
            actorUserId = "usr_owner",
            createdAt = "2026-05-02T10:00:00Z",
        )

        val domain = dto.toDomain()

        assertEquals("evt_1", domain.eventId)
        assertEquals("packet.sent", domain.eventType)
        assertEquals("usr_owner", domain.actorUserId)
        assertEquals(Instant.parse("2026-05-02T10:00:00Z"), domain.createdAt)
    }
}
