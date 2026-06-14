package com.testlogon.android.feature.webhooks

import com.testlogon.android.core.network.webhooks.WebhookEndpointDto
import com.testlogon.android.core.network.webhooks.WebhookEventTypeDto
import com.testlogon.android.feature.webhooks.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-398 - tests for the DTO -> domain mappers: the corrected field names (endpoint_id -> id, event_types ->
 * events, enabled -> enabled), the DERIVED secretSet (secret != null), the passed-through one-time secret, the
 * epoch-seconds createdAt, and the defaulted description / event-type description.
 */
class WebhookMappersTest {

    @Test
    fun endpoint_mapsCorrectedFields_andDerivesSecretSet() {
        val dto = WebhookEndpointDto(
            endpointId = "wh_1",
            url = "https://a.test/h",
            description = "hook",
            eventTypes = listOf("session.finalized", "mfa.verified"),
            enabled = false,
            secret = "whsec_abc",
            createdAt = 1_747_072_651L,
            updatedAt = 1_747_072_651L,
        )
        val domain = dto.toDomain()

        assertEquals("wh_1", domain.id)
        assertEquals("https://a.test/h", domain.url)
        assertEquals("hook", domain.description)
        assertEquals(listOf("session.finalized", "mfa.verified"), domain.events)
        assertFalse(domain.enabled)
        assertTrue(domain.secretSet) // derived from secret != null
        assertEquals("whsec_abc", domain.secret)
        assertEquals(1_747_072_651L, domain.createdAt)
    }

    @Test
    fun endpoint_nullSecret_secretSetFalse_descriptionDefaultsBlank() {
        val dto = WebhookEndpointDto(
            endpointId = "wh_2",
            url = "https://b.test/h",
            description = null,
            secret = null,
        )
        val domain = dto.toDomain()
        assertFalse(domain.secretSet)
        assertNull(domain.secret)
        assertEquals("", domain.description)
    }

    @Test
    fun eventType_mapsType_andDefaultsDescription() {
        assertEquals("", WebhookEventTypeDto(type = "x", description = null).toDomain().description)
        assertEquals("d", WebhookEventTypeDto(type = "x", description = "d").toDomain().description)
        assertEquals("x", WebhookEventTypeDto(type = "x").toDomain().type)
    }
}
