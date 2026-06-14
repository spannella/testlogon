package com.testlogon.android.feature.purchases

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-219 / AND-222 — pure [purchaseHistoryUiState] derivation: loading/error gates, and the
 * empty-history vs empty-search distinction keyed on the trimmed query.
 */
class PurchaseHistoryUiStateTest {

    private fun state(
        query: String = "",
        loading: Boolean = false,
        error: Boolean = false,
        message: String? = null,
        retryable: Boolean = true,
        count: Int = 0,
    ) = purchaseHistoryUiState(query, loading, error, message, retryable, count)

    @Test
    fun error_whenRefreshErrorAndEmpty() {
        val s = state(error = true, message = "boom", count = 0)
        assertTrue(s is PurchaseHistoryUiState.Error)
        assertEquals("boom", (s as PurchaseHistoryUiState.Error).message)
    }

    @Test
    fun loading_whenRefreshLoadingAndEmpty() {
        assertEquals(PurchaseHistoryUiState.Loading, state(loading = true, count = 0))
    }

    @Test
    fun emptyHistory_whenBlankQueryAndNoItems() {
        assertEquals(PurchaseHistoryUiState.EmptyHistory, state(query = "  ", count = 0))
    }

    @Test
    fun emptySearch_whenNonBlankQueryAndNoItems() {
        val s = state(query = "tee", count = 0)
        assertTrue(s is PurchaseHistoryUiState.EmptySearch)
        assertEquals("tee", (s as PurchaseHistoryUiState.EmptySearch).query)
    }

    @Test
    fun content_whenItemsPresent() {
        val s = state(query = "tee", count = 3)
        assertTrue(s is PurchaseHistoryUiState.Content)
    }

    @Test
    fun error_doesNotMaskExistingContent() {
        // An append-style error with items present is still Content (refresh-error gate requires empty).
        assertTrue(state(error = true, count = 2) is PurchaseHistoryUiState.Content)
    }
}
