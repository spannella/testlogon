package com.testlogon.android.data.messaging.presence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-145 — DTO -> domain mapping: status derives purely from `online`; no AWAY ever produced. */
class PresenceMapperTest {

    @Test
    fun onlineTrueMapsToOnline() {
        val p = PresenceDto(userId = "u1", online = true, lastSeenAt = 1749126655).toPresence()
        assertEquals(PresenceStatus.ONLINE, p.status)
        assertEquals(1749126655L, p.lastSeenAtEpochSeconds)
    }

    @Test
    fun onlineFalseMapsToOffline() {
        val p = PresenceDto(userId = "u2", online = false, lastSeenAt = 1749066131).toPresence()
        assertEquals(PresenceStatus.OFFLINE, p.status)
    }

    @Test
    fun missingLastSeenMapsToNull() {
        val p = PresenceDto(userId = "u3", online = true, lastSeenAt = null).toPresence()
        assertNull(p.lastSeenAtEpochSeconds)
    }

    @Test
    fun offlineFactoryDefault() {
        val p = Presence.offline("u9")
        assertEquals(PresenceStatus.OFFLINE, p.status)
        assertNull(p.lastSeenAtEpochSeconds)
        assertEquals(false, p.stale)
    }
}
