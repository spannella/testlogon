package com.testlogon.android.data.gcal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-273 — pure mapper + derived-phase tests. */
class GoogleCalendarMapperTest {

    @Test
    fun status_connectionActive_isConnected_emailCachedFromCallback() {
        val dto = IntegrationStatusDto(connectionActive = true, syncEnabled = true)
        val domain = dto.toDomain(cachedAccountEmail = "user@example.com")
        assertEquals(ConnectPhase.CONNECTED, domain.phase)
        assertEquals("user@example.com", domain.accountEmail)
    }

    @Test
    fun status_inactive_isDisconnected() {
        assertEquals(ConnectPhase.DISCONNECTED, IntegrationStatusDto(connectionActive = false).toDomain().phase)
    }

    @Test
    fun status_reauthRequired_takesPrecedence() {
        val dto = IntegrationStatusDto(connectionActive = true, reauthRequired = true)
        assertEquals(ConnectPhase.REAUTH_REQUIRED, dto.toDomain().phase)
    }

    @Test
    fun status_defaults_noThrow() {
        // All optionals absent -> defaults; no email cached.
        val domain = IntegrationStatusDto().toDomain()
        assertFalse(domain.connectionActive)
        assertNull(domain.accountEmail)
        assertEquals("unknown", domain.syncHealth)
    }

    @Test
    fun providerCalendar_mapsFlatFields() {
        val dto = ProviderCalendarDto(
            googleCalendarId = "gcal_team",
            summary = "Team",
            accessRole = "reader",
            primary = false,
            mappedInternalCalendarId = null,
        )
        val domain = dto.toDomain()
        assertEquals("gcal_team", domain.googleCalendarId)
        assertEquals("Team", domain.summary)
        assertNull(domain.mappedInternalCalendarId)
    }

    @Test
    fun mapping_toProviderCalendar_carriesMappedId_whenActive() {
        val dto = MappingDto(
            mappingId = "map_1",
            internalCalendarId = "cal_1",
            googleCalendarId = "gcal_team",
            active = true,
        )
        assertEquals("cal_1", dto.toProviderCalendar().mappedInternalCalendarId)
        assertTrue(dto.toProviderCalendar().googleCalendarId == "gcal_team")
    }
}
