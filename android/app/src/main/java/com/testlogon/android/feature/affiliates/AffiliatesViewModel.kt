package com.testlogon.android.feature.affiliates

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.affiliates.AffiliateDashboard
import com.testlogon.android.data.affiliates.AffiliatesRepository
import com.testlogon.android.data.referrals.GrowthLinks
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-265 — drives [AffiliatesUiState] from [AffiliatesRepository].
 *
 * Loads on first composition + pull-to-refresh. Empty links[] -> Empty; failed refresh with cache ->
 * stale Content (banner), else Error/Offline. Copy/share are one-shot [Channel] effects so the screen
 * performs the clipboard/intent side effect (VM stays Android-free); the full URL (webOrigin + short_url)
 * is built here.
 */
@HiltViewModel
class AffiliatesViewModel @Inject constructor(
    private val repository: AffiliatesRepository,
) : ViewModel() {

    private val webOrigin: String = GrowthLinks.WEB_ORIGIN

    private val _uiState = MutableStateFlow(AffiliatesUiState(webOrigin = webOrigin))
    val uiState: StateFlow<AffiliatesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AffiliatesEffect>(Channel.BUFFERED)
    val effects: Flow<AffiliatesEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    fun onChartPointSelected(index: Int?) {
        _uiState.update { it.copy(selectedChartIndex = index) }
    }

    fun onCopyLink(linkId: String) {
        urlFor(linkId)?.let { url ->
            viewModelScope.launch {
                _effects.send(AffiliatesEffect.CopyUrl(url))
                _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_link_copied))
            }
        }
    }

    fun onShareLink(linkId: String) {
        urlFor(linkId)?.let { url ->
            viewModelScope.launch { _effects.send(AffiliatesEffect.ShareUrl(url)) }
        }
    }

    private fun urlFor(linkId: String): String? =
        _uiState.value.dashboard?.links?.firstOrNull { it.id == linkId }?.shareUrl(webOrigin)

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.dashboard != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else AffiliatesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadDashboard()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> reduceFailure(result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: AffiliateDashboard) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) AffiliatesUiState.Phase.Empty else AffiliatesUiState.Phase.Content,
                dashboard = data,
                isRefreshing = false,
                isStale = false,
                selectedChartIndex = null,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cached()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) {
                        AffiliatesUiState.Phase.Empty
                    } else {
                        AffiliatesUiState.Phase.Content
                    },
                    dashboard = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) AffiliatesUiState.Phase.Offline else AffiliatesUiState.Phase.Error,
                    dashboard = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    companion object {
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
