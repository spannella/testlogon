package com.testlogon.android.feature.syndicates.ui

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateMember
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.poll.ArbitraryPollRepository
import com.testlogon.android.data.poll.PollVoter
import com.testlogon.android.core.network.poll.PollInputDto
import com.testlogon.android.feature.common.poll.PollDraft
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-356 - drives the [SyndicateOverviewUiState] for the READ-ONLY 3-tab syndicate overview.
 *
 * syndicateId arrives as a nav arg via [SavedStateHandle] (survives process death). load() reads the
 * overview, the treasury summary and the revenue-split policy concurrently. NotMember (FR-7) is derived when
 * the overview returns is_member == false OR a 403. Each non-paged tab carries its own [TabState] so a
 * single failing tab does not blank the whole screen.
 *
 * STALE (FR-6, in-memory only): refresh() re-reads everything but, on a failure, KEEPS the last-good
 * [SyndicateOverviewUiState.Content] and flips isStale true (the snapshot lives only in this StateFlow - it
 * is NOT persisted to disk; Room persistence across process death is DEFERRED, no migration this wave).
 *
 * The FEED and the treasury LEDGER are network Paging-3 Flows ([feed] / [ledger]), cached in
 * [viewModelScope] so a tab switch / rotation does not re-fetch; pull-to-refresh on the feed is driven by
 * the LazyPagingItems.refresh() at the UI. There is NO poll loop.
 */
@HiltViewModel
class SyndicateOverviewViewModel @Inject constructor(
    private val repository: SyndicateRepository,
    private val imageUploader: CommentImageUploader,
    private val arbitraryPollRepository: ArbitraryPollRepository,
    authStateStore: AuthStateStore,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    /** Shared arbitrary-poll vote/close client for poll posts in the feed. */
    val pollVoter: PollVoter get() = arbitraryPollRepository

    /** The signed-in user id (to gate the owner-only close-poll action). */
    val currentUserId: StateFlow<String?> = authStateStore.userSub

    private val _uiState = MutableStateFlow<SyndicateOverviewUiState>(SyndicateOverviewUiState.Loading)
    val uiState: StateFlow<SyndicateOverviewUiState> = _uiState.asStateFlow()

    /** The reverse-chronological feed (network Paging-3); cached so a tab switch does not re-fetch. */
    val feed: Flow<PagingData<SyndicateFeedItem>> =
        repository.feedPager(syndicateId).cachedIn(viewModelScope)

    /** The treasury ledger (network Paging-3); cached so a tab switch does not re-fetch. */
    val ledger: Flow<PagingData<TreasuryEntry>> =
        repository.treasuryLedgerPager(syndicateId).cachedIn(viewModelScope)

    // ---- Batch-9 (#12): feed composer (group parity) ----

    private val _compose = MutableStateFlow(SyndicateComposeState())
    val compose: StateFlow<SyndicateComposeState> = _compose.asStateFlow()

    private val _feedRefresh = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.BUFFERED)
    val feedRefresh = _feedRefresh.receiveAsFlow()

    // ---- Batch-9 (#12): members tab (group parity) ----

    private val _members = MutableStateFlow(SyndicateMembersState())
    val members: StateFlow<SyndicateMembersState> = _members.asStateFlow()

    fun onComposeTextChange(value: String) = _compose.update { it.copy(text = value, error = null) }

    fun attachImage(uri: Uri) {
        _compose.update { it.copy(uploadingImage = true, error = null) }
        viewModelScope.launch {
            when (val r = imageUploader.uploadImage(uri)) {
                is ApiResult.Success -> _compose.update { it.copy(imageUrl = r.data, uploadingImage = false) }
                is ApiResult.Failure -> _compose.update { it.copy(uploadingImage = false, error = r.error.message) }
                is ApiResult.NetworkError -> _compose.update { it.copy(uploadingImage = false, error = OFFLINE_FALLBACK) }
            }
        }
    }

    fun clearImage() = _compose.update { it.copy(imageUrl = null) }
    fun onPollEnabledChange(enabled: Boolean) = _compose.update { it.copy(pollEnabled = enabled, error = null) }
    fun onPollDraftChange(draft: PollDraft) = _compose.update { it.copy(pollDraft = draft, error = null) }

    fun submitPost() {
        val form = _compose.value
        val poll = form.pollDraft.takeIf { form.pollEnabled && it.isValid }
        val text = form.text.trim().ifEmpty { poll?.question?.trim().orEmpty() }
        if ((text.isEmpty() && poll == null) || form.sending) return
        _compose.update { it.copy(sending = true, error = null) }
        val nowSec = System.currentTimeMillis() / 1000L
        val pollInput: PollInputDto? = poll?.let { d ->
            PollInputDto(
                question = d.question.trim(),
                options = d.trimmedOptions,
                choiceMode = if (d.multiSelect) "multi" else "single",
                maxSelections = if (d.multiSelect) d.trimmedOptions.size else null,
                closesAt = d.closesAtOrNull(nowSec),
            )
        }
        viewModelScope.launch {
            when (val r = repository.createPost(syndicateId, text, imageUrl = form.imageUrl, poll = pollInput)) {
                is ApiResult.Success -> {
                    _compose.value = SyndicateComposeState()
                    _feedRefresh.send(Unit)
                }
                is ApiResult.Failure -> _compose.update { it.copy(sending = false, error = r.error.message) }
                is ApiResult.NetworkError -> _compose.update { it.copy(sending = false, error = OFFLINE_FALLBACK) }
            }
        }
    }

    /** Lazily loads the member roster the first time the Members tab is shown (or on retry). */
    fun loadMembers(force: Boolean = false) {
        if (_members.value.loading) return
        if (_members.value.loaded && !force) return
        _members.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val r = repository.listMembers(syndicateId)) {
                is ApiResult.Success -> _members.update {
                    it.copy(members = r.data, loading = false, loaded = true, error = null)
                }
                is ApiResult.Failure -> _members.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _members.update { it.copy(loading = false, error = OFFLINE_FALLBACK) }
            }
        }
    }

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to NotMember / Error. */
    fun load() {
        _uiState.value = SyndicateOverviewUiState.Loading
        refreshInternal(isRefresh = false)
    }

    fun onRetry() = load()

    /**
     * Pull-to-refresh of the non-paged surfaces. On failure the last-good Content is kept with isStale=true
     * (the paged feed / ledger refresh independently at the UI via LazyPagingItems.refresh()).
     */
    fun refresh() = refreshInternal(isRefresh = true)

    private fun refreshInternal(isRefresh: Boolean) {
        viewModelScope.launch {
            val overviewResult = repository.getOverview(syndicateId)

            // FR-7: a 403/404 OR is_member == false -> NotMember empty-state (404 = no/unknown syndicate,
            // e.g. the SAMPLE_SYNDICATE_ID stub when the user has no syndicate -> friendly empty, not Error).
            when (overviewResult) {
                is ApiResult.Success ->
                    if (!overviewResult.data.isMember) {
                        _uiState.value = SyndicateOverviewUiState.NotMember
                        return@launch
                    }
                is ApiResult.Failure ->
                    if (overviewResult.error.status == STATUS_FORBIDDEN ||
                        overviewResult.error.status == STATUS_NOT_FOUND) {
                        _uiState.value = SyndicateOverviewUiState.NotMember
                        return@launch
                    }
                is ApiResult.NetworkError -> Unit
            }

            val overview: SyndicateOverview? = (overviewResult as? ApiResult.Success)?.data
            if (overview == null) {
                // Overview itself failed (non-403). Keep stale content on refresh, else surface Error.
                val prior = _uiState.value as? SyndicateOverviewUiState.Content
                _uiState.value = if (isRefresh && prior != null) {
                    prior.copy(isStale = true)
                } else {
                    SyndicateOverviewUiState.Error(overviewResult.toError())
                }
                return@launch
            }

            // Header is good; load the two non-paged tab snapshots.
            val treasury = repository.getTreasury(syndicateId).toTabState()
            val split = repository.getRevenueSplit(syndicateId).toTabState()
            _uiState.value = SyndicateOverviewUiState.Content(
                overview = overview,
                treasury = treasury,
                split = split,
                isStale = false,
            )
        }
    }

    private fun <T> ApiResult<T>.toTabState(): TabState<T> = when (this) {
        is ApiResult.Success -> TabState.Content(data)
        else -> TabState.Error(toError())
    }

    private fun ApiResult<*>.toError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        is ApiResult.NetworkError -> ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)
        is ApiResult.Success -> ApiError(status = ApiError.STATUS_PARSE, message = OFFLINE_FALLBACK)
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"

        private const val STATUS_FORBIDDEN = 403
        private const val STATUS_NOT_FOUND = 404
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}

/** Batch-9 (#12) - the syndicate feed composer state (text + optional single image). */
data class SyndicateComposeState(
    val text: String = "",
    val imageUrl: String? = null,
    val uploadingImage: Boolean = false,
    val sending: Boolean = false,
    val error: String? = null,
    val pollEnabled: Boolean = false,
    val pollDraft: PollDraft = PollDraft(),
)

/** Batch-9 (#12) - the syndicate members tab state. */
data class SyndicateMembersState(
    val members: List<SyndicateMember> = emptyList(),
    val loading: Boolean = false,
    val loaded: Boolean = false,
    val error: String? = null,
)
