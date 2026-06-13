package com.testlogon.android.feature.syndicates.ui

import androidx.lifecycle.ViewModel
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

/**
 * AND-361 - drives the single [SyndicateListUiState] for the "syndicates the caller belongs to" LIST
 * screen (FR-6).
 *
 * NO LIST ENDPOINT (do NOT invent one): the existing [SyndicateRepository] (AND-356 / AND-357) and its
 * [com.testlogon.android.core.network.syndicates.SyndicateApi] expose ONLY by-id reads
 * (getOverview/getTreasury/getRevenueSplit/feed/ledger/open-licensing). There is NO "list my syndicates"
 * method and the OpenAPI surface for this wave does not define one; the overview is reached by id via a
 * stub. Per AND-361 this ViewModel therefore surfaces [SyndicateListUiState.NotAvailable] instead of
 * fabricating a network call. The repository is still injected (so this seam is real and the wiring is
 * ready) but is intentionally NOT called.
 *
 * FLAG / TODO: when a real list endpoint ships (e.g. GET ui/syndicates), add listMySyndicates() to
 * [SyndicateRepository] (and update ALL of its fakes), then switch load()/refresh()/retry() here to that
 * call and reduce to Content/Empty/Error - the contract already carries those variants. AND-362 will
 * consolidate.
 *
 * One StateFlow only; no one-shot effects. There is NO poll loop and NO networking of its own.
 */
@HiltViewModel
class SyndicateListViewModel @Inject constructor(
    @Suppress("unused") private val repository: SyndicateRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<SyndicateListUiState>(SyndicateListUiState.Loading)
    val uiState: StateFlow<SyndicateListUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /**
     * Resolves the list surface. With no list endpoint this is [SyndicateListUiState.NotAvailable]; when a
     * real endpoint is added (see class KDoc) this becomes the listMySyndicates() read reducing to
     * Content/Empty/Error.
     */
    fun load() {
        _uiState.value = SyndicateListUiState.NotAvailable
    }

    /** Pull-to-refresh. No-op beyond re-resolving the surface while no list endpoint exists. */
    fun refresh() = load()

    /** Re-attempt. No-op beyond re-resolving the surface while no list endpoint exists. */
    fun retry() = load()
}
