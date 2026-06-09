package com.testlogon.android.feature.feed

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import javax.inject.Inject

/**
 * AND-102 — Feed presentation logic: a cached Paging 3 stream of [FeedPost].
 *
 * The list's own CombinedLoadStates (collected on the screen via collectAsLazyPagingItems) drive the
 * loading / empty / error / append-footer branches, so this ViewModel owns the cached pager, a refresh
 * trigger, and a one-shot event channel (M2 unlock CTA is a deferred stub — AND-E24). [refresh]
 * re-anchors the pager at the head via flatMapLatest, and the stream is cachedIn(viewModelScope) so it
 * survives configuration changes / resubscription without re-fetching (state preservation, AC-7).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val repository: FeedRepository,
) : ViewModel() {

    private val refreshTrigger = MutableStateFlow(0L)

    val items: Flow<PagingData<FeedPost>> =
        refreshTrigger
            .flatMapLatest {
                Pager(
                    config = PagingConfig(
                        pageSize = PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        initialLoadSize = INITIAL_LOAD_SIZE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { FeedPagingSource(repository) },
                ).flow
            }
            .cachedIn(viewModelScope)

    private val _events = Channel<FeedEvent>(Channel.BUFFERED)

    /** One-shot UI effects (e.g. the deferred unlock CTA hand-off). Use receiveAsFlow so events fire once. */
    val events: Flow<FeedEvent> = _events.receiveAsFlow()

    /** Invalidate the feed and re-fetch from the head. */
    fun refresh() {
        refreshTrigger.value = refreshTrigger.value + 1L
    }

    /**
     * AND-101 — paywall CTA seam. M2 is display-only: this emits a one-shot intent event and performs
     * NO purchase. TODO(AND-E24): wire to the unlock/purchase flow (POST /posts/unlock).
     */
    fun onUnlockClick(postId: String) {
        _events.trySend(FeedEvent.UnlockRequested(postId))
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 10
        const val INITIAL_LOAD_SIZE = 20
    }
}

/** One-shot feed UI effects. */
sealed interface FeedEvent {
    /** The viewer tapped a locked post's CTA; the unlock transaction itself is deferred to M4/E24. */
    data class UnlockRequested(val postId: String) : FeedEvent
}
