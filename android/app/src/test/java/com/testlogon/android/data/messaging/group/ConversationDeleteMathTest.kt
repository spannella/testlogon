package com.testlogon.android.data.messaging.group

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-160 — pure unit tests for the delete-conversation degrade rule. */
class ConversationDeleteMathTest {

    @Test
    fun notFound_isBenign() {
        assertTrue(ConversationDeleteMath.isBenignDeleteFailure(404))
    }

    @Test
    fun gone_isBenign() {
        assertTrue(ConversationDeleteMath.isBenignDeleteFailure(410))
    }

    @Test
    fun forbidden_isNotBenign() {
        assertFalse(ConversationDeleteMath.isBenignDeleteFailure(403))
    }

    @Test
    fun serverError_isNotBenign() {
        assertFalse(ConversationDeleteMath.isBenignDeleteFailure(500))
    }

    @Test
    fun nullStatus_transportError_isNotBenign() {
        assertFalse(ConversationDeleteMath.isBenignDeleteFailure(null))
    }
}
