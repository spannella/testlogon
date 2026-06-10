package com.testlogon.android.data.billing

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-225/226 — the FLAGGED [StubCardTokenizer] MUST always return NotConfigured and never tokenize a
 * card or hit the network. It takes no network dependency, so calling [addCard] proves no charge /
 * setup-intent confirm occurs (there is nothing to call).
 */
class StubCardTokenizerTest {

    @Test
    fun addCard_alwaysReturnsNotConfigured() = runTest {
        val tokenizer = StubCardTokenizer()
        repeat(3) {
            assertTrue(tokenizer.addCard() is CardEntryResult.NotConfigured)
        }
    }

    @Test
    fun stub_hasNoNetworkOrChargeCollaborators() {
        // The stub's only constructor is @Inject() with no args: it cannot tokenize or charge.
        assertEquals(0, StubCardTokenizer::class.java.declaredConstructors.first().parameterCount)
    }
}
