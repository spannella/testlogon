package com.testlogon.android.feature.notifications

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.map
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.notifications.NotificationRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Non-paged overlay state for the badge + top-bar action enablement. */
data class UnreadBadgeUiState(
    val count: Int = 0,
    val isLoading: Boolean = true,
    val isStale: Boolean = false,
) {
    /** Capped display string: "" at 0, "n" up to 99, "99+" beyond. */
    val display: String = when {
        count <= 0 -> ""
        count > 99 -> "99+"
        else -> count.toString()
    }

    /** Mark-all-read is enabled only when there is something unread. */
    val markAllEnabled: Boolean = count > 0
}

/** One-shot effects consumed by the screen. */
sealed interface NotificationsEvent {
    data class Navigate(val target: NotificationTarget) : NotificationsEvent
    data class Error(val message: String) : NotificationsEvent
}

/**
 * AND-089 — Notifications presentation logic: a Paging 3 feed of [NotificationUi] plus an unread
 * badge [UnreadBadgeUiState] (AND-085 consumes both).
 *
 * Optimistic read state is held as a local id set + an all-read flag merged into the paged data via
 * PagingData.map, so a tap reflects immediately without a server round-trip. Mutating intents flow
 * through a Channel so badge math is race-free; one-shot navigation / error effects use a
 * Channel + receiveAsFlow.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
@HiltViewModel
class NotificationsViewModel @Inject constructor(
    private val repository: NotificationRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)
    private val locallyRead = MutableStateFlow<Set<String>>(emptySet())
    private val allReadFlag = MutableStateFlow(false)

    val pagedNotifications: Flow<PagingData<NotificationUi>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = INITIAL_LOAD_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { NotificationsPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)
            .combine(combine(locallyRead, allReadFlag) { read, all -> read to all }) { paging, overlay ->
                val (readIds, all) = overlay
                paging.map { it.toUi(forcedRead = all || it.id in readIds) }
            }

    private val _badge = MutableStateFlow(UnreadBadgeUiState())
    val badge: StateFlow<UnreadBadgeUiState> = _badge.asStateFlow()

    private val _events = Channel<NotificationsEvent>(Channel.BUFFERED)
    val events: Flow<NotificationsEvent> = _events.receiveAsFlow()

    private val intents = Channel<Intent>(Channel.UNLIMITED)

    init {
        viewModelScope.launch { processIntents() }
        refreshUnreadCount()
    }

    /** Optimistically mark a row read, fire the server mark-read, and navigate when routable. */
    fun onItemClick(item: NotificationUi) {
        if (!item.isRead) {
            locallyRead.update { it + item.id }
            intents.trySend(Intent.MarkRead(item.id))
        }
        if (item.target != NotificationTarget.Unknown) {
            _events.trySend(NotificationsEvent.Navigate(item.target))
        }
    }

    fun onMarkAllRead() {
        if (!_badge.value.markAllEnabled) return
        intents.trySend(Intent.MarkAllRead)
    }

    /** Invalidate the page feed and re-fetch the unread count. */
    fun refresh() {
        refreshTrigger.value = System.currentTimeMillis()
        refreshUnreadCount()
    }

    private fun refreshUnreadCount() = viewModelScope.launch {
        when (val r = repository.refreshUnreadCount()) {
            is ApiResult.Success -> _badge.value = UnreadBadgeUiState(count = r.data, isLoading = false)
            is ApiResult.Failure, is ApiResult.NetworkError ->
                _badge.value = _badge.value.copy(isLoading = false, isStale = true)
        }
    }

    private suspend fun processIntents() {
        for (intent in intents) {
            when (intent) {
                is Intent.MarkRead -> handleMarkRead(intent.id)
                Intent.MarkAllRead -> handleMarkAllRead()
            }
        }
    }

    private suspend fun handleMarkRead(id: String) {
        // Optimistic badge decrement; reconcile on failure.
        _badge.value = _badge.value.copy(count = (_badge.value.count - 1).coerceAtLeast(0))
        when (repository.markRead(id)) {
            is ApiResult.Success -> Unit
            else -> {
                locallyRead.update { it - id }
                reconcileBadge()
            }
        }
    }

    private suspend fun handleMarkAllRead() {
        val prior = _badge.value.count
        allReadFlag.value = true
        _badge.value = _badge.value.copy(count = 0)
        when (repository.markAllRead()) {
            is ApiResult.Success -> refreshTrigger.value = System.currentTimeMillis()
            is ApiResult.Failure -> {
                allReadFlag.value = false
                _badge.value = _badge.value.copy(count = prior)
                _events.trySend(NotificationsEvent.Error(MARK_ALL_FAILED))
            }
            is ApiResult.NetworkError -> {
                allReadFlag.value = false
                _badge.value = _badge.value.copy(count = prior)
                _events.trySend(NotificationsEvent.Error(MARK_ALL_FAILED))
            }
        }
    }

    private suspend fun reconcileBadge() {
        when (val r = repository.refreshUnreadCount()) {
            is ApiResult.Success -> _badge.value = UnreadBadgeUiState(count = r.data, isLoading = false)
            else -> Unit
        }
    }

    private sealed interface Intent {
        data class MarkRead(val id: String) : Intent
        data object MarkAllRead : Intent
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 40
        const val MARK_ALL_FAILED = "Couldn't mark all as read — try again."
    }
}
