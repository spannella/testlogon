package com.testlogon.android.feature.notifications

import com.testlogon.android.data.notifications.NotificationType
import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-090 — pure unit tests for [NotificationTargetResolver] (AND-085 deep-link routing). */
class NotificationTargetResolverTest {

    @Test
    fun follow_withIdentifier_resolvesProfile() {
        val target = NotificationTargetResolver.resolve(
            NotificationType.FOLLOW, mapOf("u_identifier" to "alice"),
        )
        assertEquals(NotificationTarget.Profile("alice"), target)
    }

    @Test
    fun mention_withIdentifier_resolvesProfile() {
        assertEquals(
            NotificationTarget.Profile("bob"),
            NotificationTargetResolver.resolve(NotificationType.MENTION, mapOf("u_identifier" to "bob")),
        )
    }

    @Test
    fun follow_missingIdentifier_failsSafeToUnknown() {
        assertEquals(
            NotificationTarget.Unknown,
            NotificationTargetResolver.resolve(NotificationType.FOLLOW, emptyMap()),
        )
    }

    @Test
    fun follow_blankIdentifier_failsSafeToUnknown() {
        assertEquals(
            NotificationTarget.Unknown,
            NotificationTargetResolver.resolve(NotificationType.FOLLOW, mapOf("u_identifier" to "  ")),
        )
    }

    @Test
    fun system_resolvesSettings() {
        assertEquals(
            NotificationTarget.Settings,
            NotificationTargetResolver.resolve(NotificationType.SYSTEM, emptyMap()),
        )
    }

    @Test
    fun otherTypes_failSafeToUnknown() {
        for (type in listOf(
            NotificationType.LIKE, NotificationType.COMMENT, NotificationType.TIP,
            NotificationType.MESSAGE, NotificationType.UNKNOWN,
        )) {
            assertEquals(
                NotificationTarget.Unknown,
                NotificationTargetResolver.resolve(type, mapOf("item_id" to "x")),
            )
        }
    }

    @Test
    fun fromToken_normalizesMixedCase_andUnknown() {
        assertEquals(NotificationType.FOLLOW, NotificationType.fromToken("follow"))
        assertEquals(NotificationType.SYSTEM, NotificationType.fromToken("SYSTEM"))
        assertEquals(NotificationType.UNKNOWN, NotificationType.fromToken("weird"))
        assertEquals(NotificationType.UNKNOWN, NotificationType.fromToken(null))
    }
}
