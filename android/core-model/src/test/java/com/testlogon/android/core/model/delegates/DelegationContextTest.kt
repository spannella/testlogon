package com.testlogon.android.core.model.delegates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-360 - pure domain tests for the typed delegation overlay: [DelegatePermission.from] (including the
 * forward-compat UNKNOWN sink), the [ManagingCreator.toDelegationContext] projection, and the null-safe
 * can* capability helpers. No Android / Moshi dependency.
 */
class DelegationContextTest {

    @Test
    fun from_resolvesKnownTokens_andUnknownToUnknown() {
        assertEquals(DelegatePermission.CHAT_READ, DelegatePermission.from("chat_read"))
        assertEquals(DelegatePermission.FEED_POST, DelegatePermission.from("feed_post"))
        assertEquals(DelegatePermission.BROADCAST_CONTROL, DelegatePermission.from("broadcast_control"))
        // unrecognized / future token -> UNKNOWN (forward compat, never throws)
        assertEquals(DelegatePermission.UNKNOWN, DelegatePermission.from("teleport"))
        // a blank token also resolves to UNKNOWN (it never positively matches UNKNOWN's empty wire)
        assertEquals(DelegatePermission.UNKNOWN, DelegatePermission.from(""))
    }

    @Test
    fun toDelegationContext_mapsPermissionSet_andCarriesNameAndId() {
        val managing = ManagingCreator(
            creatorId = "cr_1",
            label = "Acme",
            permissions = listOf("chat_read", "chat_respond", "feed_post", "teleport"),
        )

        val context = managing.toDelegationContext()

        assertEquals("cr_1", context.creatorId)
        assertEquals("Acme", context.creatorName)
        assertTrue(DelegatePermission.CHAT_READ in context.permissions)
        assertTrue(DelegatePermission.CHAT_RESPOND in context.permissions)
        assertTrue(DelegatePermission.FEED_POST in context.permissions)
        // the unknown token is retained as UNKNOWN but is inert for gating
        assertTrue(DelegatePermission.UNKNOWN in context.permissions)
    }

    @Test
    fun canHelpers_trueWhenPermissionPresent() {
        val context = DelegationContext(
            creatorId = "cr_1",
            creatorName = "Acme",
            permissions = setOf(
                DelegatePermission.FEED_POST,
                DelegatePermission.FEED_READ,
                DelegatePermission.CHAT_READ,
                DelegatePermission.CHAT_RESPOND,
                DelegatePermission.BROADCAST_CONTROL,
                DelegatePermission.BROADCAST_MODERATE,
                DelegatePermission.FEED_MODERATE,
            ),
        )
        assertTrue(context.canPostFeed())
        assertTrue(context.canReadFeed())
        assertTrue(context.canModerateFeed())
        assertTrue(context.canReadChat())
        assertTrue(context.canRespondMessages())
        assertTrue(context.canControlBroadcast())
        assertTrue(context.canModerateBroadcast())
    }

    @Test
    fun canHelpers_falseWhenPermissionAbsent_orContextNull() {
        val readOnly = DelegationContext(
            creatorId = "cr_1",
            creatorName = null,
            permissions = setOf(DelegatePermission.FEED_READ),
        )
        assertTrue(readOnly.canReadFeed())
        assertFalse(readOnly.canPostFeed())
        assertFalse(readOnly.canRespondMessages())
        assertFalse(readOnly.canControlBroadcast())

        // null context (acting as oneself) -> every helper is false
        val none: DelegationContext? = null
        assertFalse(none.canPostFeed())
        assertFalse(none.canReadChat())
        assertFalse(none.canControlBroadcast())
        assertFalse(none.canModerateBroadcast())
    }
}
