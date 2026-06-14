package com.testlogon.android.feature.collaborations.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.collaborations.data.CollaborationsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-358 - drives the [CollaborationDetailUiState] for the READ-ONLY collaboration detail.
 *
 * collabId arrives as a nav arg via [SavedStateHandle] (survives process death). [load] reads the
 * collaboration and (best-effort) its split history; a split-history failure is TOLERATED (folds to an empty
 * distributions list) since the section is optional. An unrecoverable 401 (after the shared client's one auth
 * refresh) -> [CollaborationDetailUiState.SessionExpired] SIGNAL (AND-358 does NOT own the routing).
 *
 * STALE (in-memory only): [refresh] re-reads but, on a failure, KEEPS the last-good
 * [CollaborationDetailUiState.Content] and flips isStale true (the snapshot lives only in this StateFlow - it
 * is NOT persisted to disk; Room persistence across process death is DEFERRED, no migration this wave). There
 * is NO poll loop.
 *
 * [viewerId] is the viewer's own user id (from [AuthStateStore]) so the split section can highlight the
 * viewer's own row.
 */
@HiltViewModel
class CollaborationDetailViewModel @Inject constructor(
    private val repository: CollaborationsRepository,
    savedState: SavedStateHandle,
    authStateStore: AuthStateStore,
) : ViewModel() {

    val collabId: String =
        checkNotNull(savedState[ARG_COLLAB_ID]) { "missing $ARG_COLLAB_ID nav arg" }

    /** The viewer's own user id (may be null); used to highlight the viewer's own split row. */
    val viewerId: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<CollaborationDetailUiState>(CollaborationDetailUiState.Loading)
    val uiState: StateFlow<CollaborationDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to SessionExpired / Error. */
    fun load() {
        _uiState.value = CollaborationDetailUiState.Loading
        refreshInternal(isRefresh = false)
    }

    fun retry() = load()

    /**
     * Pull-to-refresh. On failure with prior content the last-good Content is kept with isStale=true; a 401
     * always wins (-> SessionExpired) even with prior content.
     */
    fun refresh() = refreshInternal(isRefresh = true)

    private fun refreshInternal(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val result = repository.getCollaboration(collabId)) {
                is ApiResult.Success -> {
                    // The split history is OPTIONAL: a failure folds to an empty distributions list.
                    val distributions =
                        (repository.getSplits(collabId) as? ApiResult.Success)?.data ?: emptyList()
                    _uiState.value = CollaborationDetailUiState.Content(
                        collab = result.data,
                        distributions = distributions,
                        isStale = false,
                    )
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.value = CollaborationDetailUiState.SessionExpired
                    } else {
                        emitFailure(isRefresh, result.error)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(
                        isRefresh,
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? CollaborationDetailUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isStale = true)
        } else {
            CollaborationDetailUiState.Error(error)
        }
    }

    companion object {
        const val ARG_COLLAB_ID = "collabId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
