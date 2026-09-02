package com.testlogon.android.feature.crm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CrmAbResults
import com.testlogon.android.data.crm.CrmCampaign
import com.testlogon.android.data.crm.CrmCampaignAttribution
import com.testlogon.android.data.crm.CrmCampaignsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

// ─── Campaigns list ───────────────────────────────────────────────────────────

data class CrmCampaignsUiState(
    val phase: Phase = Phase.Loading,
    val campaigns: List<CrmCampaign> = emptyList(),
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-PEC — CRM marketing campaigns list (read-mostly; the web editor is rich). Pulls
 * GET /ui/crm-marketing/campaigns; a 404 (module disabled) degrades to an empty, non-error state.
 */
@HiltViewModel
class CrmCampaignsViewModel @Inject constructor(
    private val repository: CrmCampaignsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CrmCampaignsUiState())
    val uiState: StateFlow<CrmCampaignsUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.campaigns.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CrmCampaignsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.list()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmCampaignsUiState.Phase.Content,
                        campaigns = r.data.campaigns,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.campaigns.isNotEmpty()) CrmCampaignsUiState.Phase.Content else CrmCampaignsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.campaigns.isNotEmpty()) CrmCampaignsUiState.Phase.Content else CrmCampaignsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }
}

// ─── Campaign detail ──────────────────────────────────────────────────────────

data class CrmCampaignDetailUiState(
    val phase: Phase = Phase.Loading,
    val campaign: CrmCampaign? = null,
    val attribution: CrmCampaignAttribution? = null,
    val abResults: CrmAbResults? = null,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

@HiltViewModel
class CrmCampaignDetailViewModel @Inject constructor(
    private val repository: CrmCampaignsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val campaignId: String = checkNotNull(savedStateHandle[ARG_CAMPAIGN_ID]) {
        "CrmCampaignDetailViewModel requires a $ARG_CAMPAIGN_ID nav arg"
    }

    private val _uiState = MutableStateFlow(CrmCampaignDetailUiState())
    val uiState: StateFlow<CrmCampaignDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update {
            it.copy(phase = if (it.campaign == null) CrmCampaignDetailUiState.Phase.Loading else it.phase)
        }
        viewModelScope.launch {
            when (val r = repository.detail(campaignId)) {
                is ApiResult.Success -> {
                    // A/B results are best-effort (only present for multi-variant campaigns; 404 → null).
                    val ab = (repository.abResults(campaignId) as? ApiResult.Success)?.data
                        ?.takeIf { it.variants.isNotEmpty() }
                    _uiState.update {
                        it.copy(
                            phase = CrmCampaignDetailUiState.Phase.Content,
                            campaign = r.data.campaign,
                            attribution = r.data.attribution,
                            abResults = ab,
                            isOffline = false,
                            errorMessage = null,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.campaign != null) CrmCampaignDetailUiState.Phase.Content else CrmCampaignDetailUiState.Phase.Error,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.campaign != null) CrmCampaignDetailUiState.Phase.Content else CrmCampaignDetailUiState.Phase.Error,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    companion object {
        const val ARG_CAMPAIGN_ID: String = "campaignId"
    }
}
