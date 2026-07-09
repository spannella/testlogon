package com.testlogon.android.feature.syndicates.ads.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.syndicates.ads.data.SyndicateAdsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-710 (F7) — presentation logic for the SYNDICATE ad-placement SPLIT editor. Loads the per-syndicate
 * member_share_bps config, edits the member's share (bps of the 70% content-owner cut) via a slider, and
 * PUTs it. A 403 (non-admin) surfaces [SyndicateAdSplitUiState.Forbidden]. The write is NON-idempotent
 * (last-writer-wins) so it is ignored while saving and never auto-retried. On success the saved config
 * replaces the draft baseline so `dirty` resets.
 */
@HiltViewModel
class SyndicateAdSplitViewModel @Inject constructor(
    private val repository: SyndicateAdsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    private val _uiState = MutableStateFlow<SyndicateAdSplitUiState>(SyndicateAdSplitUiState.Loading)
    val uiState: StateFlow<SyndicateAdSplitUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = SyndicateAdSplitUiState.Loading
        viewModelScope.launch {
            when (val r = repository.getPlacementConfig(syndicateId)) {
                is ApiResult.Success -> _uiState.value = SyndicateAdSplitUiState.Content(
                    config = r.data,
                    draftMemberShareBps = r.data.memberShareBps,
                )
                is ApiResult.Failure -> _uiState.value =
                    if (r.error.status == HTTP_FORBIDDEN) SyndicateAdSplitUiState.Forbidden
                    else SyndicateAdSplitUiState.Error(r.error.message)
                is ApiResult.NetworkError -> _uiState.value = SyndicateAdSplitUiState.Error(OFFLINE)
            }
        }
    }

    /** The slider moved: update the draft (clamped 0..10000), clearing any prior save flags. */
    fun onDraftChange(bps: Int) {
        _uiState.update { s ->
            (s as? SyndicateAdSplitUiState.Content)?.copy(
                draftMemberShareBps = bps.coerceIn(0, MAX_BPS),
                saved = false,
                error = null,
            ) ?: s
        }
    }

    /** Snaps the draft back to the server default (does not save until Save is tapped). */
    fun resetToDefault() {
        _uiState.update { s ->
            (s as? SyndicateAdSplitUiState.Content)?.let {
                it.copy(draftMemberShareBps = it.config.defaultMemberShareBps, saved = false, error = null)
            } ?: s
        }
    }

    fun save() {
        val current = _uiState.value as? SyndicateAdSplitUiState.Content ?: return
        if (current.saving) return
        val bps = current.draftMemberShareBps
        _uiState.value = current.copy(saving = true, saved = false, error = null)
        viewModelScope.launch {
            when (val r = repository.setMemberShareBps(syndicateId, bps)) {
                is ApiResult.Success -> _uiState.value = SyndicateAdSplitUiState.Content(
                    config = r.data,
                    draftMemberShareBps = r.data.memberShareBps,
                    saved = true,
                )
                is ApiResult.Failure -> _uiState.value = current.copy(
                    saving = false,
                    error = if (r.error.status == HTTP_FORBIDDEN)
                        "Only a syndicate admin can change the split." else r.error.message,
                )
                is ApiResult.NetworkError ->
                    _uiState.value = current.copy(saving = false, error = OFFLINE)
            }
        }
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"
        const val MAX_BPS = 10000
        private const val HTTP_FORBIDDEN = 403
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
