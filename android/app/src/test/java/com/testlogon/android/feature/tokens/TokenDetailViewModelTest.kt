package com.testlogon.android.feature.tokens

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.feature.trading.FakeTokensRepository
import com.testlogon.android.feature.trading.FakeWatchlistStore
import com.testlogon.android.feature.trading.sampleTokenFake
import com.testlogon.android.navigation.TokenDetailDest
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel coverage for [TokenDetailViewModel] using the [com.testlogon.android.data.exchange.watchlist.WatchlistStore]
 * interface seam: degrade-to-empty Content when the repo returns nulls (404 folded), a happy path with
 * a token, and the watch-star toggle calling through to the fake store.
 */
class TokenDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun handle(id: String) = SavedStateHandle(mapOf(TokenDetailDest.ARG_TOKEN_ID to id))

    @Test
    fun degrade_nullReads_toContentWithNullToken() = runTest(mainRule.dispatcher) {
        val vm = TokenDetailViewModel(FakeTokensRepository(), FakeWatchlistStore(), handle("tok-1"))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokenDetailUiState.Phase.Content, s.phase)
        assertNull(s.token)
        assertNull(s.errorMessage)
    }

    @Test
    fun happy_tokenSurfaced() = runTest(mainRule.dispatcher) {
        val repo = FakeTokensRepository(tokenResult = ApiResult.Success(sampleTokenFake("tok-1", "AAA")))
        val vm = TokenDetailViewModel(repo, FakeWatchlistStore(), handle("tok-1"))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokenDetailUiState.Phase.Content, s.phase)
        assertEquals("AAA", s.token?.ticker)
    }

    @Test
    fun toggleWatch_callsStore() = runTest(mainRule.dispatcher) {
        val store = FakeWatchlistStore()
        val vm = TokenDetailViewModel(FakeTokensRepository(), store, handle("tok-1"))
        advanceUntilIdle()
        assertFalse(vm.isWatched.value)
        vm.toggleWatch()
        advanceUntilIdle()
        assertEquals(1, store.toggleCalls.size)
        assertEquals(WatchKind.TOKEN to "tok-1", store.toggleCalls.first())
        assertTrue(store.isWatched(WatchKind.TOKEN, "tok-1"))
    }
}
