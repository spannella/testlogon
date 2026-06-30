package com.testlogon.android.feature.syndicates.campaign

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the [CampaignDetailUiState] for the syndicate-advertising campaign DETAIL screen (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId).
 *
 * load() fetches the campaign + analytics; in parallel it reads the syndicate overview to derive whether the
 * viewer is the syndicate admin (the web gates status / add-budget on admin_user_id == userId, and the
 * server enforces it too). updateStatus() / addBudget() are admin mutations that re-fetch on success. No
 * poll loop. Reuses the existing [SyndicateRepository] for the admin signal (no new endpoint).
 */
@HiltViewModel
class CampaignDetailViewModel @Inject constructor(
    private val repo: CampaignRepository,
    private val syndicateRepository: SyndicateRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val syndicateId: String = savedStateHandle.get<String>(ARG_SYNDICATE_ID).orEmpty()
    private val campaignId: String = savedStateHandle.get<String>(ARG_CAMPAIGN_ID).orEmpty()

    private val _uiState = MutableStateFlow<CampaignDetailUiState>(CampaignDetailUiState.Loading)
    val uiState: StateFlow<CampaignDetailUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        if (_uiState.value !is CampaignDetailUiState.Content) _uiState.value = CampaignDetailUiState.Loading
        loadJob = viewModelScope.launch {
            when (val campaignResult = repo.getCampaign(syndicateId, campaignId)) {
                is ApiResult.Success -> {
                    val analytics = (repo.getAnalytics(syndicateId, campaignId) as? ApiResult.Success)?.data
                    val isAdmin =
                        (syndicateRepository.getOverview(syndicateId) as? ApiResult.Success)?.data?.isAdmin ?: false
                    _uiState.value = CampaignDetailUiState.Content(
                        campaign = campaignResult.data,
                        analytics = analytics,
                        isAdmin = isAdmin,
                    )
                }
                is ApiResult.Failure -> _uiState.value = CampaignDetailUiState.Error(campaignResult.error.message)
                is ApiResult.NetworkError -> _uiState.value = CampaignDetailUiState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    fun retry() = load()

    fun pause() = updateStatus(CampaignStatus.PAUSED)
    fun resume() = updateStatus(CampaignStatus.ACTIVE)
    fun cancel() = updateStatus(CampaignStatus.CANCELLED)

    private fun updateStatus(status: String) {
        val current = _uiState.value as? CampaignDetailUiState.Content ?: return
        if (current.mutating || !current.isAdmin) return
        _uiState.value = current.copy(mutating = true, actionError = null)
        viewModelScope.launch {
            applyMutation(repo.updateStatus(syndicateId, campaignId, status))
        }
    }

    fun addBudget(additionalCents: Int) {
        val current = _uiState.value as? CampaignDetailUiState.Content ?: return
        if (current.mutating || !current.isAdmin || additionalCents < MIN_BUDGET_CENTS) return
        _uiState.value = current.copy(mutating = true, actionError = null)
        viewModelScope.launch {
            applyMutation(repo.addBudget(syndicateId, campaignId, additionalCents))
        }
    }

    private suspend fun applyMutation(result: ApiResult<SyndicateCampaign>) {
        val now = _uiState.value as? CampaignDetailUiState.Content ?: return
        when (result) {
            is ApiResult.Success -> {
                // Refresh analytics too (spend moved), but the campaign comes straight from the mutation.
                val analytics = (repo.getAnalytics(syndicateId, campaignId) as? ApiResult.Success)?.data
                    ?: now.analytics
                _uiState.value = now.copy(campaign = result.data, analytics = analytics, mutating = false)
            }
            is ApiResult.Failure -> _uiState.value = now.copy(mutating = false, actionError = result.error.message)
            is ApiResult.NetworkError -> _uiState.value = now.copy(mutating = false, actionError = OFFLINE_FALLBACK)
        }
    }

    fun clearActionError() {
        val current = _uiState.value as? CampaignDetailUiState.Content ?: return
        _uiState.value = current.copy(actionError = null)
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"
        const val ARG_CAMPAIGN_ID = "campaignId"
        const val MIN_BUDGET_CENTS = 100
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
