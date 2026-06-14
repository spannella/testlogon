package com.testlogon.android.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class ErrorDetailMapperTest {

    @Test
    fun `string detail passes through`() {
        assertEquals("Invalid challenge", ErrorDetailMapper.normalize("Invalid challenge"))
    }

    @Test
    fun `blank string falls back`() {
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize("   "))
    }

    @Test
    fun `validation array joins all msgs with comma space`() {
        val detail = listOf(
            mapOf("msg" to "field required", "loc" to listOf("body", "x")),
            mapOf("msg" to "value too short"),
        )
        assertEquals("field required, value too short", ErrorDetailMapper.normalize(detail))
    }

    @Test
    fun `empty validation array falls back`() {
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize(emptyList<Any?>()))
    }

    @Test
    fun `coded role_required maps to curated copy and ignores backend message`() {
        val detail = mapOf("code" to "role_required", "message" to "ignored")
        assertEquals(
            ErrorDetailMapper.codeMessages.getValue("role_required"),
            ErrorDetailMapper.normalize(detail),
        )
    }

    @Test
    fun `geo_blocked prefers backend message`() {
        val detail = mapOf("code" to "geo_blocked", "message" to "Blocked in XX")
        assertEquals("Blocked in XX", ErrorDetailMapper.normalize(detail))
    }

    @Test
    fun `geo_blocked falls back to curated copy when no message`() {
        val detail = mapOf("code" to "geo_blocked")
        assertEquals(
            ErrorDetailMapper.codeMessages.getValue("geo_blocked"),
            ErrorDetailMapper.normalize(detail),
        )
    }

    @Test
    fun `helpdesk codes map`() {
        assertEquals(
            ErrorDetailMapper.codeMessages.getValue("helpdesk_claim_required"),
            ErrorDetailMapper.normalize(mapOf("code" to "helpdesk_claim_required")),
        )
    }

    // AND-165 — gap-fill: the other two real helpdesk codes (only helpdesk_claim_required was covered).
    @Test
    fun `helpdesk assignee_required and claim_not_available map to distinct curated copy`() {
        assertEquals(
            ErrorDetailMapper.codeMessages.getValue("helpdesk_assignee_required"),
            ErrorDetailMapper.normalize(mapOf("code" to "helpdesk_assignee_required")),
        )
        assertEquals(
            ErrorDetailMapper.codeMessages.getValue("helpdesk_claim_not_available"),
            ErrorDetailMapper.normalize(mapOf("code" to "helpdesk_claim_not_available")),
        )
        // Distinct messages (would fail if two codes collapsed to the same copy).
        assertNotEquals(
            ErrorDetailMapper.normalize(mapOf("code" to "helpdesk_assignee_required")),
            ErrorDetailMapper.normalize(mapOf("code" to "helpdesk_claim_not_available")),
        )
    }

    // AND-165 — gap-fill: malformed/atypical `detail` shapes degrade to fallback without throwing.
    @Test
    fun `malformed numeric detail falls back without crashing`() {
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize(123))
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize(true))
    }

    @Test
    fun `validation array with no msg falls back`() {
        assertEquals(
            ErrorDetailMapper.GENERIC,
            ErrorDetailMapper.normalize(listOf(mapOf("loc" to listOf("body")))),
        )
    }

    @Test
    fun `unknown code degrades to fallback and does not surface backend message`() {
        val detail = mapOf("code" to "widget_exploded", "message" to "boom")
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize(detail))
    }

    @Test
    fun `null detail falls back`() {
        assertEquals(ErrorDetailMapper.GENERIC, ErrorDetailMapper.normalize(null))
    }

    @Test
    fun `extractCode returns code for coded object`() {
        assertEquals("role_required", ErrorDetailMapper.extractCode(mapOf("code" to "role_required")))
        assertEquals(null, ErrorDetailMapper.extractCode("a string"))
    }
}
