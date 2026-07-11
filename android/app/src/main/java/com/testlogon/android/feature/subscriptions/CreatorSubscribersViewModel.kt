package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.subscriptions.CreatorSubscriberPage
import com.testlogon.android.data.subscriptions.CreatorSubscriberRow
import com.testlogon.android.data.subscriptions.SubscriptionAnalytics
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * SUB-E4-3 — the status filter chips for the creator subscriber list. Each maps to the backend
 * `status` query token (null = all). "canceled" folds canceled/expired/canceling server-side.
 */
enum class SubscriberFilter(val wire: String?) {
    ALL(null),
    ACTIVE("active"),
    TRIALING("trialing"),
    PAST_DUE("past_due"),
    CANCELED("canceled"),
}

/** SUB-E4-3 — a creator management action awaiting confirmation. */
enum class SubscriberActionKind { STOP_RENEWAL, REMOVE }

/** SUB-E4-3 — the pending confirm-dialog target. */
data class PendingSubscriberAction(
    val row: CreatorSubscriberRow,
    val kind: SubscriberActionKind,
)

/**
 * SUB-E4-3 — creator "Subscribers" + MRR dashboard screen state. A single screen: the analytics
 * cards sit above the (status-filtered, paginated) subscriber list.
 */
sealed interface CreatorSubscribersUiState {
    data object Loading : CreatorSubscribersUiState

    data class Content(
        /** SUB-E4-2 MRR/analytics; null when the analytics read failed (list can still render). */
        val analytics: SubscriptionAnalytics? = null,
        val filter: SubscriberFilter = SubscriberFilter.ALL,
        val subscribers: List<CreatorSubscriberRow> = emptyList(),
        val total: Int = 0,
        val nextCursor: String? = null,
        val loadingList: Boolean = false,
        val loadingMore: Boolean = false,
        /** In-flight remove/stop-renewal subscription id (row spinner + disabled actions). */
        val actioningId: String? = null,
        /** Confirm dialog target (null = no dialog). */
        val pendingAction: PendingSubscriberAction? = null,
        /** Transient action failure to surface as a snackbar (cleared on consume). */
        val actionError: UiText? = null,
    ) : CreatorSubscribersUiState {
        val canLoadMore: Boolean get() = nextCursor != null && !loadingMore && !loadingList
    }

    data class Error(val message: UiText, val retryable: Boolean) : CreatorSubscribersUiState
}

/**
 * SUB-E4-3 — presentation logic for the creator subscriber management + MRR/analytics screen.
 *
 * Owner-scoped by construction: [SubscriptionsRepository.getMySubscribers] /
 * [SubscriptionsRepository.getMyAnalytics] pass the signed-in principal as BOTH the X-User-Id header
 * and the creator id path, so a creator only ever sees their own subscribers. Reuses the SUB-E4
 * backend endpoints and the shared [BillingErrorMapper].
 */
@HiltViewModel
class CreatorSubscribersViewModel @Inject constructor(
    private val repository: SubscriptionsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow<CreatorSubscribersUiState>(CreatorSubscribersUiState.Loading)
    val uiState: StateFlow<CreatorSubscribersUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** Full (re)load: analytics + the first page of subscribers for the current filter. */
    fun load(filter: SubscriberFilter = currentFilter()) {
        _uiState.value = CreatorSubscribersUiState.Loading
        viewModelScope.launch {
            val analyticsDeferred = async { repository.getMyAnalytics() }
            val listDeferred = async { repository.getMySubscribers(status = filter.wire) }
            val analyticsResult = analyticsDeferred.await()
            val listResult = listDeferred.await()

            when (listResult) {
                is ApiResult.Success -> {
                    _uiState.value = CreatorSubscribersUiState.Content(
                        analytics = (analyticsResult as? ApiResult.Success)?.data,
                        filter = filter,
                        subscribers = listResult.data.subscribers,
                        total = listResult.data.total,
                        nextCursor = listResult.data.nextCursor,
                    )
                }
                else -> {
                    val error = errorMapper.map(listResult)
                    _uiState.value = CreatorSubscribersUiState.Error(
                        message = error.message,
                        retryable = error.recoverability == Recoverability.RETRYABLE,
                    )
                }
            }
        }
    }

    fun onRetry() = load()

    /** Switch the status filter and reload the list (analytics is unchanged). */
    fun onFilterSelected(filter: SubscriberFilter) {
        val content = currentContent()
        if (content == null) {
            load(filter)
            return
        }
        if (content.filter == filter && !content.loadingList) return
        _uiState.value = content.copy(filter = filter, loadingList = true, subscribers = emptyList(), nextCursor = null)
        viewModelScope.launch {
            when (val result = repository.getMySubscribers(status = filter.wire)) {
                is ApiResult.Success -> updateContent {
                    it.copy(
                        loadingList = false,
                        subscribers = result.data.subscribers,
                        total = result.data.total,
                        nextCursor = result.data.nextCursor,
                    )
                }
                else -> updateContent {
                    it.copy(loadingList = false, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    /** Append the next page (SUB-E4-1 opaque cursor). No-op when already loading / no cursor. */
    fun onLoadMore() {
        val content = currentContent() ?: return
        val cursor = content.nextCursor ?: return
        if (content.loadingMore || content.loadingList) return
        _uiState.value = content.copy(loadingMore = true)
        viewModelScope.launch {
            when (val result = repository.getMySubscribers(status = content.filter.wire, cursor = cursor)) {
                is ApiResult.Success -> updateContent {
                    it.copy(
                        loadingMore = false,
                        subscribers = it.subscribers + result.data.subscribers,
                        total = result.data.total,
                        nextCursor = result.data.nextCursor,
                    )
                }
                else -> updateContent {
                    it.copy(loadingMore = false, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    // ---- Per-row management actions ----

    fun onStopRenewalClicked(row: CreatorSubscriberRow) = requestAction(row, SubscriberActionKind.STOP_RENEWAL)

    fun onRemoveClicked(row: CreatorSubscriberRow) = requestAction(row, SubscriberActionKind.REMOVE)

    private fun requestAction(row: CreatorSubscriberRow, kind: SubscriberActionKind) {
        val content = currentContent() ?: return
        if (content.actioningId != null) return
        _uiState.value = content.copy(pendingAction = PendingSubscriberAction(row, kind))
    }

    fun onActionDismissed() {
        updateContent { it.copy(pendingAction = null) }
    }

    fun onActionConfirmed() {
        val content = currentContent() ?: return
        val pending = content.pendingAction ?: return
        val subId = pending.row.subscriptionId
        _uiState.value = content.copy(pendingAction = null, actioningId = subId)
        viewModelScope.launch {
            val result = when (pending.kind) {
                SubscriberActionKind.STOP_RENEWAL ->
                    repository.stopSubscriberRenewal(subId, reason = "creator_stop_renewal")
                SubscriberActionKind.REMOVE ->
                    repository.removeSubscriber(subId, reason = "creator_removed")
            }
            when (result) {
                is ApiResult.Success -> reloadAfterAction(subId)
                else -> updateContent {
                    it.copy(actioningId = null, actionError = errorMapper.map(result).message)
                }
            }
        }
    }

    fun onActionErrorConsumed() {
        updateContent { it.copy(actionError = null) }
    }

    /** After a successful remove/stop-renewal, re-pull analytics + the current filter page. */
    private suspend fun reloadAfterAction(subId: String) {
        val filter = currentFilter()
        val analyticsResult = repository.getMyAnalytics()
        val listResult = repository.getMySubscribers(status = filter.wire)
        updateContent { c ->
            val subs = (listResult as? ApiResult.Success)?.data?.subscribers ?: c.subscribers.filterNot { it.subscriptionId == subId }
            c.copy(
                actioningId = null,
                analytics = (analyticsResult as? ApiResult.Success)?.data ?: c.analytics,
                subscribers = subs,
                total = (listResult as? ApiResult.Success)?.data?.total ?: c.total,
                nextCursor = (listResult as? ApiResult.Success)?.data?.nextCursor,
            )
        }
    }

    private fun currentContent(): CreatorSubscribersUiState.Content? =
        _uiState.value as? CreatorSubscribersUiState.Content

    private fun currentFilter(): SubscriberFilter = currentContent()?.filter ?: SubscriberFilter.ALL

    private inline fun updateContent(block: (CreatorSubscribersUiState.Content) -> CreatorSubscribersUiState.Content) {
        val content = currentContent() ?: return
        _uiState.value = block(content)
    }

    companion object {
        const val ROUTE = "subscriptions/subscribers"
    }
}
