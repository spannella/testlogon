package com.testlogon.android.notifications

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-110 (FR-6/FR-9) — JVM unit tests for the FCM data-payload parser. Pure logic, no Android,
 * no live Firebase. Covers each valid kind, missing-required, unknown-kind, deep_link optional, and
 * the real backend key names (notification_type/notification_id).
 */
class PushPayloadParserTest {

    private val parser = PushPayloadParser()

    @Test
    fun parses_message_payload_with_android_keys() {
        val result = parser.parse(
            mapOf(
                "kind" to "message",
                "entity_id" to "msg_42",
                "title" to "New message",
                "body" to "hi",
                "deep_link" to "testlogon://message/msg_42",
            ),
        )
        assertEquals(
            PushPayload(
                NotificationKind.MESSAGE,
                "msg_42",
                "New message",
                "hi",
                "testlogon://message/msg_42",
            ),
            result,
        )
    }

    @Test
    fun parses_broadcast_and_alert_kinds() {
        assertEquals(
            NotificationKind.BROADCAST,
            parser.parse(base(kind = "broadcast"))?.kind,
        )
        assertEquals(
            NotificationKind.ALERT,
            parser.parse(base(kind = "alert"))?.kind,
        )
    }

    @Test
    fun unknown_kind_maps_to_UNKNOWN() {
        assertEquals(NotificationKind.UNKNOWN, parser.parse(base(kind = "weird"))?.kind)
    }

    @Test
    fun missing_kind_maps_to_UNKNOWN_but_still_parses() {
        val data = mapOf("entity_id" to "e1", "title" to "t", "body" to "b")
        assertEquals(NotificationKind.UNKNOWN, parser.parse(data)?.kind)
    }

    @Test
    fun missing_required_fields_return_null() {
        assertNull(parser.parse(emptyMap()))
        assertNull(parser.parse(mapOf("kind" to "message", "title" to "t", "body" to "b"))) // no id
        assertNull(parser.parse(mapOf("kind" to "message", "entity_id" to "e", "body" to "b"))) // no title
        assertNull(parser.parse(mapOf("kind" to "message", "entity_id" to "e", "title" to "t"))) // no body
    }

    @Test
    fun blank_required_fields_return_null() {
        assertNull(parser.parse(base(entityId = " ")))
        assertNull(parser.parse(base(title = "")))
    }

    @Test
    fun deep_link_optional_is_null_when_absent() {
        assertNull(parser.parse(base())?.deepLink)
    }

    @Test
    fun tolerates_real_backend_key_names() {
        val result = parser.parse(
            mapOf(
                "notification_type" to "MESSAGE", // case-insensitive
                "notification_id" to "ntf_7",
                "title" to "t",
                "body" to "b",
            ),
        )
        assertEquals(NotificationKind.MESSAGE, result?.kind)
        assertEquals("ntf_7", result?.entityId)
    }

    private fun base(
        kind: String = "message",
        entityId: String = "e1",
        title: String = "t",
        body: String = "b",
    ) = mapOf("kind" to kind, "entity_id" to entityId, "title" to title, "body" to body)
}

/** AND-110 — channel routing is total and deterministic for every kind. */
class TlChannelsTest {

    @Test
    fun channel_id_for_each_kind() {
        assertEquals(TlChannels.MESSAGES, TlChannels.channelIdFor(NotificationKind.MESSAGE))
        assertEquals(TlChannels.ALERTS, TlChannels.channelIdFor(NotificationKind.ALERT))
        assertEquals(TlChannels.BROADCASTS, TlChannels.channelIdFor(NotificationKind.BROADCAST))
        assertEquals(TlChannels.BROADCASTS, TlChannels.channelIdFor(NotificationKind.UNKNOWN))
    }
}
