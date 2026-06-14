package com.testlogon.android.feature.billing

import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.billing.CardEntryResult
import com.testlogon.android.data.billing.CardTokenizer
import com.testlogon.android.data.billing.StubCardTokenizer
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-226 — [AddCardViewModel] wired to the FLAGGED card-entry seam.
 *
 * With the [StubCardTokenizer], onAddCard surfaces NotConfigured (unavailable state + event) and NEVER
 * tokenizes a card. The Saved/Failed branches are exercised with a fake tokenizer to prove the seam is
 * future-proof, but the production binding is the stub.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AddCardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun onAddCard_withStub_isNotConfigured_andNeverTokenizes() = runTest {
        val model = AddCardViewModel(StubCardTokenizer())
        val events = mutableListOf<AddCardEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onAddCard()
        advanceUntilIdle()

        assertTrue(model.uiState.value.unavailable)
        assertFalse(model.uiState.value.isPreparing)
        assertTrue(events.single() is AddCardEvent.NotConfigured)
        ejob.cancel()
    }

    @Test
    fun onAddCard_savedResult_emitsSaved() = runTest {
        val fake = FakeCardTokenizer(CardEntryResult.Saved("pm_new"))
        val model = AddCardViewModel(fake)
        val events = mutableListOf<AddCardEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onAddCard()
        advanceUntilIdle()

        assertTrue(events.single() is AddCardEvent.Saved)
        assertEquals(1, fake.calls)
        ejob.cancel()
    }

    @Test
    fun onAddCard_failed_emitsFailure() = runTest {
        val model = AddCardViewModel(FakeCardTokenizer(CardEntryResult.Failed("declined")))
        val events = mutableListOf<AddCardEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onAddCard()
        advanceUntilIdle()

        assertEquals("declined", (events.single() as AddCardEvent.Failure).message)
        ejob.cancel()
    }
}

private class FakeCardTokenizer(private val result: CardEntryResult) : CardTokenizer {
    var calls = 0
    override suspend fun addCard(): CardEntryResult {
        calls++
        return result
    }
}
