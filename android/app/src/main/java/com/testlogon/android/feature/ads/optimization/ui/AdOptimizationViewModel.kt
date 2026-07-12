package com.testlogon.android.feature.ads.optimization.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.ads.optimization.data.AdOptimizationRepository
import com.testlogon.android.feature.ads.studio.data.AdsStudioCampaignResolver
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Presentation logic for the ad OPTIMIZATION panel (web parity: AdOptimizationPanel.tsx).
 *
 * On init, resolves the caller's first campaign, lists existing recommendations, and (best effort) loads the
 * suggested-bid + budget-recommendation summary. The user can generate a fresh pass, apply / dismiss a
 * recommendation, and toggle auto-optimize. READ+WRITE; no polling loop.
 *
 * Dispatcher seam: ioDispatcher defaults to IO; read inside coroutines so a test can swap it.
 */
@HiltViewModel
class AdOptimizationViewModel @Inject constructor(
    private val resolver: AdsStudioCampaignResolver,
    private val repository: AdOptimizationRepository,
) : ViewModel() {

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdOptimizationUiState>(AdOptimizationUiState.Loading)
    val uiState: StateFlow<AdOptimizationUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = AdOptimizationUiState.Loading
        viewModelScope.launch {
            when (val res = withContext(ioDispatcher) { resolver.resolveFirstCampaign() }) {
                is AdsStudioCampaignResolver.Resolution.NoCampaign ->
                    _uiState.value = AdOptimizationUiState.NoCampaign
                is AdsStudioCampaignResolver.Resolution.Failed ->
                    _uiState.value = AdOptimizationUiState.Error(res.result.toApiError())
                is AdsStudioCampaignResolver.Resolution.Found -> {
                    val campaign = res.campaign
                    val name = campaign.name ?: campaign.campaignId
                    when (val rr = withContext(ioDispatcher) { repository.listRecommendations(campaign.campaignId) }) {
                        is ApiResult.Success -> {
                            _uiState.value = AdOptimizationUiState.Content(
                                campaignId = campaign.campaignId,
                                campaignName = name,
                                recommendations = rr.data,
                            )
                            loadSummary(campaign.campaignId)
                        }
                        is ApiResult.Failure -> _uiState.value = AdOptimizationUiState.Error(rr.error)
                        is ApiResult.NetworkError ->
                            _uiState.value = AdOptimizationUiState.Error(networkError())
                    }
                }
            }
        }
    }

    private fun loadSummary(campaignId: String) {
        viewModelScope.launch {
            (withContext(ioDispatcher) { repository.getSuggestedBid(campaignId) } as? ApiResult.Success)?.let { r ->
                updateContent { it.copy(suggestedBid = r.data) }
            }
            (withContext(ioDispatcher) {
                repository.getBudgetRecommendation(campaignId, DEFAULT_DESIRED_REACH)
            } as? ApiResult.Success)?.let { r ->
                updateContent { it.copy(budgetRecommendation = r.data) }
            }
        }
    }

    fun onRetry() = load()

    /** Runs a fresh deterministic optimization pass, then reloads the list. */
    fun generate() {
        val content = _uiState.value as? AdOptimizationUiState.Content ?: return
        if (content.generating) return
        _uiState.value = content.copy(generating = true, actionError = null)
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.generate(content.campaignId) }) {
                is ApiResult.Success -> updateContent {
                    it.copy(generating = false, recommendations = r.data)
                }
                is ApiResult.Failure -> updateContent {
                    it.copy(generating = false, actionError = r.error.message)
                }
                is ApiResult.NetworkError -> updateContent {
                    it.copy(generating = false, actionError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    fun applyRecommendation(recId: String) = mutateRecommendation(recId, apply = true)

    fun dismissRecommendation(recId: String) = mutateRecommendation(recId, apply = false)

    private fun mutateRecommendation(recId: String, apply: Boolean) {
        val content = _uiState.value as? AdOptimizationUiState.Content ?: return
        if (recId in content.busyRecIds) return
        _uiState.value = content.copy(busyRecIds = content.busyRecIds + recId, actionError = null)
        viewModelScope.launch {
            val result = withContext(ioDispatcher) {
                if (apply) repository.applyRecommendation(content.campaignId, recId)
                else repository.dismissRecommendation(content.campaignId, recId)
            }
            when (result) {
                is ApiResult.Success -> {
                    // Re-list so the row reflects its new applied/dismissed status.
                    val refreshed = withContext(ioDispatcher) {
                        repository.listRecommendations(content.campaignId)
                    }
                    val recs = (refreshed as? ApiResult.Success)?.data
                    updateContent {
                        it.copy(
                            busyRecIds = it.busyRecIds - recId,
                            recommendations = recs ?: it.recommendations,
                        )
                    }
                }
                is ApiResult.Failure -> updateContent {
                    it.copy(busyRecIds = it.busyRecIds - recId, actionError = result.error.message)
                }
                is ApiResult.NetworkError -> updateContent {
                    it.copy(busyRecIds = it.busyRecIds - recId, actionError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    fun setAutoOptimize(enabled: Boolean) {
        val content = _uiState.value as? AdOptimizationUiState.Content ?: return
        if (content.togglingAuto) return
        _uiState.value = content.copy(togglingAuto = true, actionError = null)
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.setAutoOptimize(content.campaignId, enabled) }) {
                is ApiResult.Success -> updateContent {
                    it.copy(togglingAuto = false, autoOptimizeEnabled = r.data.autoOptimizeEnabled)
                }
                is ApiResult.Failure -> updateContent {
                    it.copy(togglingAuto = false, actionError = r.error.message)
                }
                is ApiResult.NetworkError -> updateContent {
                    it.copy(togglingAuto = false, actionError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private inline fun updateContent(
        transform: (AdOptimizationUiState.Content) -> AdOptimizationUiState.Content,
    ) {
        (_uiState.value as? AdOptimizationUiState.Content)?.let { _uiState.value = transform(it) }
    }

    private fun ApiResult<*>.toApiError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        else -> networkError()
    }

    private fun networkError() = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        private const val DEFAULT_DESIRED_REACH = 1000
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
