package com.testlogon.android.navigation.deeplink

import com.testlogon.android.feature.notifications.NotificationTarget
import com.testlogon.android.notifications.NotificationKind
import com.testlogon.android.notifications.PushPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-110 (FR-6/FR-7) — JVM unit tests for the deep-link contract + push-tap routing. Pure logic; no
 * Android Intent (the Intent factory/parser are covered instrumented). Verifies the payload->link
 * mapping is total, the type/id round-trips, and push taps reuse the notification target routing.
 */
class DeepLinkContractTest {

    @Test
    fun fromPayload_maps_every_kind() {
        assertEquals(
            NotificationDeepLink.Message("m1"),
            DeepLinkContract.fromPayload(payload(NotificationKind.MESSAGE, "m1")),
        )
        assertEquals(
            NotificationDeepLink.Broadcast("b1"),
            DeepLinkContract.fromPayload(payload(NotificationKind.BROADCAST, "b1")),
        )
        assertEquals(
            NotificationDeepLink.Alert("a1"),
            DeepLinkContract.fromPayload(payload(NotificationKind.ALERT, "a1")),
        )
        assertEquals(
            NotificationDeepLink.Generic("g1"),
            DeepLinkContract.fromPayload(payload(NotificationKind.UNKNOWN, "g1")),
        )
    }

    @Test
    fun typeString_and_id_round_trip() {
        for (link in listOf(
            NotificationDeepLink.Message("m1"),
            NotificationDeepLink.Broadcast("b1"),
            NotificationDeepLink.Alert("a1"),
            NotificationDeepLink.Generic("g1"),
        )) {
            val type = DeepLinkContract.typeString(link)
            val id = DeepLinkContract.idOf(link)
            assertEquals(link, DeepLinkContract.fromTypeAndId(type, id))
        }
    }

    @Test
    fun fromTypeAndId_rejects_unknown_type_and_blank_id() {
        assertNull(DeepLinkContract.fromTypeAndId("nope", "x"))
        assertNull(DeepLinkContract.fromTypeAndId(DeepLinkContract.TYPE_MESSAGE, " "))
        assertNull(DeepLinkContract.fromTypeAndId(DeepLinkContract.TYPE_MESSAGE, null))
        assertNull(DeepLinkContract.fromTypeAndId(null, "x"))
    }

    @Test
    fun pushTapRouting_message_routes_to_notification_center_via_resolver() {
        // The message kind has no first-party detail route yet -> resolver fails safe to Unknown,
        // which navigateToNotificationTarget lands on the Notification Center (never a dead end).
        val target = PushTapRouting.targetFor(NotificationDeepLink.Message("m1"))
        assertTrue(target is NotificationTarget.Unknown)
    }

    @Test
    fun pushTapRouting_broadcast_and_alert_resolve_to_unknown_target() {
        assertTrue(PushTapRouting.targetFor(NotificationDeepLink.Broadcast("b1")) is NotificationTarget.Unknown)
        assertTrue(PushTapRouting.targetFor(NotificationDeepLink.Alert("a1")) is NotificationTarget.Unknown)
        assertTrue(PushTapRouting.targetFor(NotificationDeepLink.Generic("g1")) is NotificationTarget.Unknown)
    }

    private fun payload(kind: NotificationKind, id: String) =
        PushPayload(kind, id, "title", "body", null)
}
