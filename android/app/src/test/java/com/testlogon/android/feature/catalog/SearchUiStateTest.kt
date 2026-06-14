package com.testlogon.android.feature.catalog

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-207 / AND-209 — pure unit tests for [searchUiState], the screen's load-state derivation: Idle
 * below the min length, Loading on refresh-loading with no items, Empty when a settled query yields zero
 * items, Content for >=1 item, and Error from a refresh error with no items.
 */
class SearchUiStateTest {

    private fun derive(
        query: String,
        loading: Boolean = false,
        error: Boolean = false,
        message: String? = null,
        retryable: Boolean = true,
        itemCount: Int = 0,
    ) = searchUiState(query, loading, error, message, retryable, itemCount)

    @Test
    fun blankOrShortQuery_isIdle() {
        assertEquals(CatalogSearchUiState.Idle, derive(""))
        assertEquals(CatalogSearchUiState.Idle, derive("a"))
        assertEquals(CatalogSearchUiState.Idle, derive("   "))
    }

    @Test
    fun refreshLoading_noItems_isLoading() {
        assertEquals(CatalogSearchUiState.Loading, derive("hood", loading = true, itemCount = 0))
    }

    @Test
    fun settledQuery_zeroItems_isEmpty_withQueryEchoed() {
        val state = derive("hood", loading = false, itemCount = 0)
        assertTrue(state is CatalogSearchUiState.Empty)
        assertEquals("hood", (state as CatalogSearchUiState.Empty).query)
    }

    @Test
    fun items_isContent() {
        val state = derive("hood", itemCount = 3)
        assertTrue(state is CatalogSearchUiState.Content)
        assertEquals("hood", (state as CatalogSearchUiState.Content).query)
    }

    @Test
    fun refreshError_noItems_isError() {
        val state = derive("hood", error = true, message = "boom", retryable = true, itemCount = 0)
        assertTrue(state is CatalogSearchUiState.Error)
        assertEquals("boom", (state as CatalogSearchUiState.Error).message)
        assertTrue(state.retryable)
    }

    @Test
    fun error_butItemsPresent_staysContent() {
        // An append error with loaded items keeps Content (the inline footer handles append retry).
        val state = derive("hood", error = true, itemCount = 5)
        assertTrue(state is CatalogSearchUiState.Content)
    }
}
