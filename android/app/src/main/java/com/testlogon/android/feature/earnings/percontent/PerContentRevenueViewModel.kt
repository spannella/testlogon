package com.testlogon.android.feature.earnings.percontent

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.earnings.ContentRevenue
import com.testlogon.android.data.earnings.ContentRevenuePage
import com.testlogon.android.data.earnings.ContentRevenueQuery
import com.testlogon.android.data.earnings.ContentRevenueRepository
import com.testlogon.android.data.earnings.RevenueSortKey
import com.testlogon.android.data.earnings.SortOrder
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.update
import javax.inject.Inject

/**
 * AND-253 — per-content revenue presentation logic.
 *
 * Drives a Paging 3 `Flow<PagingData<ContentRevenue>>` keyed on the active [ContentRevenueQuery]: any
 * sort/filter change emits a new query, which invalidates the pager (re-loads from cursor=null) and
 * resets the header summary. The header (totalItems/totalRevenueCents/currency) is captured from the
 * first page via the repository's onHeader callback and pushed into [uiState].
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class PerContentRevenueViewModel @Inject constructor(
    private val repository: ContentRevenueRepository,
) : ViewModel() {

    data class UiState(
        val query: ContentRevenueQuery = ContentRevenueQuery(),
        val totalItems: Int = 0,
        val totalRevenueCents: Long = 0,
        val currency: String = "USD",
    )

    private val queryFlow = MutableStateFlow(ContentRevenueQuery())

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    val items: Flow<PagingData<ContentRevenue>> =
        queryFlow
            .flatMapLatest { query ->
                repository.pager(query, onHeader = ::onHeader).flow
            }
            .cachedIn(viewModelScope)

    fun onSortChange(key: RevenueSortKey, order: SortOrder) {
        updateQuery { it.copy(sortBy = key, sortOrder = order) }
    }

    fun onContentTypeChange(type: String?) {
        updateQuery { it.copy(contentType = type?.takeIf { t -> t.isNotBlank() }) }
    }

    fun onDateRangeChange(from: String?, to: String?) {
        updateQuery {
            it.copy(
                fromDate = from?.takeIf { d -> d.isNotBlank() },
                toDate = to?.takeIf { d -> d.isNotBlank() },
            )
        }
    }

    /** Re-anchor the list at the head with the current query (pull-to-refresh / retry). */
    fun refresh() {
        // Re-emit the same query instance reference change to invalidate the pager.
        queryFlow.update { it.copy() }
    }

    private fun updateQuery(transform: (ContentRevenueQuery) -> ContentRevenueQuery) {
        val next = transform(queryFlow.value)
        if (next == queryFlow.value) return
        // Reset the header summary; it is repopulated from the new first page.
        _uiState.update { it.copy(query = next, totalItems = 0, totalRevenueCents = 0) }
        queryFlow.value = next
    }

    private fun onHeader(page: ContentRevenuePage) {
        _uiState.update {
            it.copy(
                totalItems = page.totalItems,
                totalRevenueCents = page.totalRevenueCents,
                currency = page.currency,
            )
        }
    }
}
