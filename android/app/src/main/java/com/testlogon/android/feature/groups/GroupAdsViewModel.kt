package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupCampaignStats
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 (sub-pages) - drives the group ADS (advertising campaigns) screen. groupId arrives as a nav arg
 * via [SavedStateHandle]. load() lists the campaigns, then best-effort fetches each campaign's stats (a
 * stats failure does NOT fail the screen). create() POSTs a new campaign (admin-gated -> a 403 surfaces a
 * friendly snackbar). No poll loop.
 */
@HiltViewModel
class GroupAdsViewModel @Inject constructor(
    private val repository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupAdsUiState>(GroupAdsUiState.Loading)
    val uiState: StateFlow<GroupAdsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.value = GroupAdsUiState.Loading
        viewModelScope.launch {
            when (val result = repository.listCampaigns(groupId)) {
                is ApiResult.Success -> {
                    val stats = mutableMapOf<String, GroupCampaignStats>()
                    for (c in result.data) {
                        val s = repository.getCampaignStats(groupId, c.campaignId)
                        if (s is ApiResult.Success) stats[c.campaignId] = s.data
                    }
                    _uiState.value = GroupAdsUiState.Content(campaigns = result.data, stats = stats)
                }
                is ApiResult.Failure -> _uiState.value = GroupAdsUiState.Error(result.error)
                is ApiResult.NetworkError -> _uiState.value = GroupAdsUiState.Error(networkError())
            }
        }
    }

    /** Creates a campaign (admin-gated; a 403 surfaces a friendly snackbar). Budgets are in cents. */
    fun create(name: String, dailyBudgetCents: Long, lifetimeBudgetCents: Long, creativeText: String) {
        val content = _uiState.value as? GroupAdsUiState.Content ?: return
        if (content.isCreating || name.isBlank()) return
        _uiState.value = content.copy(isCreating = true, notice = null)
        viewModelScope.launch {
            val result = repository.createCampaign(
                groupId, name, dailyBudgetCents, lifetimeBudgetCents, creativeText,
            )
            when (result) {
                is ApiResult.Success -> load()
                is ApiResult.Failure -> {
                    val now = _uiState.value as? GroupAdsUiState.Content ?: return@launch
                    _uiState.value = now.copy(isCreating = false, notice = noticeFor(result.error))
                }
                is ApiResult.NetworkError -> {
                    val now = _uiState.value as? GroupAdsUiState.Content ?: return@launch
                    _uiState.value = now.copy(isCreating = false, notice = CREATE_FAILED)
                }
            }
        }
    }

    fun consumeNotice() {
        val content = _uiState.value as? GroupAdsUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    private fun noticeFor(error: ApiError): String = when {
        error.status == 403 -> NO_PERMISSION
        else -> CREATE_FAILED
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        private const val NO_PERMISSION = "Only group admins can create campaigns."
        private const val CREATE_FAILED = "Couldn't create the campaign. Please try again."
    }
}
