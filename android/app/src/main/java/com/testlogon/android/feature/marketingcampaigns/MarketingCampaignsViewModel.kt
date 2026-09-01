package com.testlogon.android.feature.marketingcampaigns

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.marketing.campaigns.MarketingCampaign
import com.testlogon.android.data.marketing.campaigns.MarketingCampaignsRepository
import com.testlogon.android.data.marketing.campaigns.MarketingMath
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
 * Drives [MarketingCampaignsUiState] from [MarketingCampaignsRepository]. Loads all three collections
 * (campaigns / lists / segments) on first composition + pull-to-refresh. Campaigns support create +
 * lifecycle transition + send; contact-lists support create; segments are read-only on mobile
 * (create/edit deferred to web). Degrade-on-404: reads honest-empty, mutations surface errors.
 */
@HiltViewModel
class MarketingCampaignsViewModel @Inject constructor(
    private val repository: MarketingCampaignsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketingCampaignsUiState())
    val uiState: StateFlow<MarketingCampaignsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MarketingCampaignsEffect>(Channel.BUFFERED)
    val effects: Flow<MarketingCampaignsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onResumed() = load(fromUser = false, force = true)
    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: MarketingCampaignsTab) {
        if (_uiState.value.tab == tab) return
        _uiState.update { it.copy(tab = tab) }
    }

    // ---- create campaign ----
    fun onOpenCreateCampaign() = _uiState.update { it.copy(createCampaign = CreateCampaignFormState(isOpen = true)) }
    fun onDismissCreateCampaign() {
        if (_uiState.value.createCampaign.isSubmitting) return
        _uiState.update { it.copy(createCampaign = CreateCampaignFormState(isOpen = false)) }
    }
    fun onCampaignNameChange(v: String) =
        _uiState.update { it.copy(createCampaign = it.createCampaign.copy(name = v)) }
    fun onCampaignObjectiveChange(v: MarketingMath.CampaignObjective) =
        _uiState.update { it.copy(createCampaign = it.createCampaign.copy(objective = v)) }
    fun onCampaignBudgetChange(v: String) =
        _uiState.update { it.copy(createCampaign = it.createCampaign.copy(budget = v)) }

    fun onSubmitCreateCampaign() {
        val form = _uiState.value.createCampaign
        val cents = form.budgetCents
        if (!form.canSubmit || cents == null) return
        _uiState.update { it.copy(createCampaign = it.createCampaign.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createCampaign(form.name, form.objective, cents)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createCampaign = CreateCampaignFormState(isOpen = false)) }
                    _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_campaign_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> failCreateCampaign(r.error.status, r.error.message)
                is ApiResult.NetworkError -> failCreateCampaign(null, null)
            }
        }
    }

    private suspend fun failCreateCampaign(status: Int?, message: String?) {
        _uiState.update { it.copy(createCampaign = it.createCampaign.copy(isSubmitting = false)) }
        if (status == HTTP_UNAUTHORIZED) {
            _uiState.update { it.copy(phase = MarketingCampaignsUiState.Phase.SessionExpired) }
        } else if (message != null) {
            _effects.send(MarketingCampaignsEffect.ShowText(message))
        } else {
            _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_action_failed))
        }
    }

    // ---- campaign lifecycle ----
    fun onTransition(c: MarketingCampaign, target: MarketingMath.CampaignStatus) {
        if (_uiState.value.busyCampaignId != null) return
        if (!MarketingMath.canTransition(c.status, target)) return
        _uiState.update { it.copy(busyCampaignId = c.id) }
        viewModelScope.launch {
            val r = repository.transition(c.id, target)
            _uiState.update { it.copy(busyCampaignId = null) }
            when (r) {
                is ApiResult.Success -> {
                    _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_action_done))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> handleMutationFailure(r.error.status, r.error.message)
                is ApiResult.NetworkError -> _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_action_failed))
            }
        }
    }

    fun onSend(c: MarketingCampaign) {
        if (_uiState.value.busyCampaignId != null || !c.canSend) return
        _uiState.update { it.copy(busyCampaignId = c.id) }
        viewModelScope.launch {
            val r = repository.send(c.id)
            _uiState.update { it.copy(busyCampaignId = null) }
            when (r) {
                is ApiResult.Success ->
                    _effects.send(MarketingCampaignsEffect.ShowText("Sent ${r.data.sentCount} · skipped ${r.data.skippedCount}"))
                is ApiResult.Failure -> handleMutationFailure(r.error.status, r.error.message)
                is ApiResult.NetworkError -> _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_action_failed))
            }
        }
    }

    private suspend fun handleMutationFailure(status: Int, message: String) {
        if (status == HTTP_UNAUTHORIZED) {
            _uiState.update { it.copy(phase = MarketingCampaignsUiState.Phase.SessionExpired) }
        } else {
            _effects.send(MarketingCampaignsEffect.ShowText(message))
        }
    }

    // ---- create contact list ----
    fun onOpenCreateList() = _uiState.update { it.copy(createList = CreateListFormState(isOpen = true)) }
    fun onDismissCreateList() {
        if (_uiState.value.createList.isSubmitting) return
        _uiState.update { it.copy(createList = CreateListFormState(isOpen = false)) }
    }
    fun onListNameChange(v: String) =
        _uiState.update { it.copy(createList = it.createList.copy(name = v)) }
    fun onListDescriptionChange(v: String) =
        _uiState.update { it.copy(createList = it.createList.copy(description = v)) }

    fun onSubmitCreateList() {
        val form = _uiState.value.createList
        if (!form.canSubmit) return
        _uiState.update { it.copy(createList = it.createList.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createList(form.name, form.description)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createList = CreateListFormState(isOpen = false)) }
                    _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_list_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(createList = it.createList.copy(isSubmitting = false)) }
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingCampaignsUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(MarketingCampaignsEffect.ShowText(r.error.message))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(createList = it.createList.copy(isSubmitting = false)) }
                    _effects.send(MarketingCampaignsEffect.ShowMessage(R.string.mktc_action_failed))
                }
            }
        }
    }

    // ---- load ----
    private fun load(fromUser: Boolean, force: Boolean = false) {
        val hasContent = _uiState.value.phase == MarketingCampaignsUiState.Phase.Content
        if (_uiState.value.isRefreshing && !force) return
        _uiState.update {
            it.copy(
                phase = if (hasContent && !force) it.phase else MarketingCampaignsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            val campaignsR = repository.loadCampaigns()
            val listsR = repository.loadLists()
            val segmentsR = repository.loadSegments()

            // Session-expiry short-circuits regardless of tab.
            val unauthorized = listOf(campaignsR, listsR, segmentsR).any {
                it is ApiResult.Failure && it.error.status == HTTP_UNAUTHORIZED
            }
            if (unauthorized) {
                _uiState.update { it.copy(phase = MarketingCampaignsUiState.Phase.SessionExpired, isRefreshing = false) }
                return@launch
            }

            val anyNetworkError = listOf(campaignsR, listsR, segmentsR).any { it is ApiResult.NetworkError }
            val firstFailure = listOf(campaignsR, listsR, segmentsR).firstNotNullOfOrNull {
                (it as? ApiResult.Failure)?.error
            }

            val campaigns = (campaignsR as? ApiResult.Success)?.data?.campaigns.orEmpty()
            val lists = (listsR as? ApiResult.Success)?.data.orEmpty()
            val segments = (segmentsR as? ApiResult.Success)?.data.orEmpty()

            // If everything failed with no partial data, surface an error/offline screen.
            val allFailed = campaignsR !is ApiResult.Success &&
                listsR !is ApiResult.Success &&
                segmentsR !is ApiResult.Success
            val phase = when {
                allFailed && anyNetworkError -> MarketingCampaignsUiState.Phase.Offline
                allFailed -> MarketingCampaignsUiState.Phase.Error
                else -> MarketingCampaignsUiState.Phase.Content
            }

            _uiState.update {
                it.copy(
                    phase = phase,
                    campaigns = campaigns,
                    lists = lists,
                    segments = segments,
                    isRefreshing = false,
                    errorMessage = firstFailure?.message,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
    }
}
