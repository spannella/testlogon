package com.testlogon.android.feature.ads.targeting.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.AdTargetingCreateIn
import com.testlogon.android.core.network.ads.AdTargetingDto
import com.testlogon.android.feature.ads.studio.data.AdsStudioCampaignResolver
import com.testlogon.android.feature.ads.studio.data.StudioCampaignSelector
import com.testlogon.android.feature.ads.targeting.data.AdTargetingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Presentation logic for the ad TARGETING editor (web parity: TargetingEditor.tsx).
 *
 * On init, resolves the caller's first campaign (via AdsStudioCampaignResolver) and loads its first
 * targeting set into an editable TargetingForm. Edits update the in-memory form and (debounced) request a
 * fresh audience estimate. Save PUTs the existing set or POSTs a new one. READ+WRITE; no polling loop (the
 * estimate is a one-shot debounced request, cancelled on each edit).
 *
 * Dispatcher seam: ioDispatcher defaults to IO and is read inside coroutines so a test can swap it.
 */
@HiltViewModel
class AdTargetingViewModel @Inject constructor(
    private val resolver: AdsStudioCampaignResolver,
    val campaignSelector: StudioCampaignSelector,
    private val repository: AdTargetingRepository,
) : ViewModel() {

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdTargetingUiState>(AdTargetingUiState.Loading)
    val uiState: StateFlow<AdTargetingUiState> = _uiState.asStateFlow()

    private var estimateJob: Job? = null

    init {
        load()
        campaignSelector.start(viewModelScope)
    }

    /** PAR-23 - user picked a different ad account in the studio picker; reload against its campaign. */
    fun onAccountSelected(accountId: String) {
        campaignSelector.onAccountSelected(viewModelScope, accountId) { load() }
    }

    /** PAR-23 - user picked a different campaign in the studio picker; reload against it. */
    fun onCampaignSelected(campaignId: String) {
        campaignSelector.onCampaignSelected(campaignId) { load() }
    }

    fun load() {
        _uiState.value = AdTargetingUiState.Loading
        viewModelScope.launch {
            when (val res = withContext(ioDispatcher) { resolver.resolveFirstCampaign() }) {
                is AdsStudioCampaignResolver.Resolution.NoCampaign ->
                    _uiState.value = AdTargetingUiState.NoCampaign
                is AdsStudioCampaignResolver.Resolution.Failed ->
                    _uiState.value = AdTargetingUiState.Error(res.result.toApiError())
                is AdsStudioCampaignResolver.Resolution.Found -> {
                    val campaign = res.campaign
                    val name = campaign.name ?: campaign.campaignId
                    when (val tr = withContext(ioDispatcher) { repository.listTargeting(campaign.campaignId) }) {
                        is ApiResult.Success -> {
                            val existing = tr.data.firstOrNull()
                            _uiState.value = AdTargetingUiState.Content(
                                campaignId = campaign.campaignId,
                                campaignName = name,
                                targetSetId = existing?.targetSetId,
                                form = existing.toForm(),
                            )
                            requestEstimate()
                        }
                        is ApiResult.Failure -> _uiState.value = AdTargetingUiState.Error(tr.error)
                        is ApiResult.NetworkError ->
                            _uiState.value = AdTargetingUiState.Error(networkError())
                    }
                }
            }
        }
    }

    fun onRetry() = load()

    /** Applies a form mutation, clears the saved flag, and schedules a debounced estimate. */
    fun updateForm(transform: (TargetingForm) -> TargetingForm) {
        val content = _uiState.value as? AdTargetingUiState.Content ?: return
        _uiState.value = content.copy(form = transform(content.form), saved = false, actionError = null)
        requestEstimate()
    }

    private fun requestEstimate() {
        val content = _uiState.value as? AdTargetingUiState.Content ?: return
        estimateJob?.cancel()
        estimateJob = viewModelScope.launch {
            delay(ESTIMATE_DEBOUNCE_MS)
            (_uiState.value as? AdTargetingUiState.Content)?.let {
                _uiState.value = it.copy(estimating = true)
            }
            val cur = _uiState.value as? AdTargetingUiState.Content ?: return@launch
            when (val r = withContext(ioDispatcher) {
                repository.estimateAudience(content.campaignId, cur.form.toCreateIn())
            }) {
                is ApiResult.Success -> updateContent { it.copy(estimatedReach = r.data, estimating = false) }
                is ApiResult.Failure -> updateContent { it.copy(estimating = false) }
                is ApiResult.NetworkError -> updateContent { it.copy(estimating = false) }
            }
        }
    }

    fun save() {
        val content = _uiState.value as? AdTargetingUiState.Content ?: return
        if (content.saving) return
        _uiState.value = content.copy(saving = true, saved = false, actionError = null)
        viewModelScope.launch {
            val body = content.form.toCreateIn()
            val result = withContext(ioDispatcher) {
                if (content.targetSetId != null) {
                    repository.updateTargeting(content.campaignId, content.targetSetId, body)
                } else {
                    repository.createTargeting(content.campaignId, body)
                }
            }
            when (result) {
                is ApiResult.Success -> updateContent {
                    it.copy(saving = false, saved = true, targetSetId = result.data.targetSetId)
                }
                is ApiResult.Failure -> updateContent {
                    it.copy(saving = false, actionError = result.error.message)
                }
                is ApiResult.NetworkError -> updateContent {
                    it.copy(saving = false, actionError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private inline fun updateContent(transform: (AdTargetingUiState.Content) -> AdTargetingUiState.Content) {
        (_uiState.value as? AdTargetingUiState.Content)?.let { _uiState.value = transform(it) }
    }

    private fun ApiResult<*>.toApiError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        else -> networkError()
    }

    private fun networkError() = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        private const val ESTIMATE_DEBOUNCE_MS = 500L
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}

private fun AdTargetingDto?.toForm(): TargetingForm = TargetingForm(
    name = this?.name ?: "Default",
    ageRanges = this?.ageRanges.orEmpty().toSet(),
    genders = this?.genders.orEmpty().toSet(),
    countryCodes = this?.countryCodes.orEmpty(),
    contentCategories = this?.contentCategories.orEmpty().toSet(),
    deviceTypes = this?.deviceTypes.orEmpty().toSet(),
    activeHours = this?.activeHours.orEmpty().toSet(),
    newUserOnly = this?.newUserOnly ?: false,
)

private fun TargetingForm.toCreateIn(): AdTargetingCreateIn = AdTargetingCreateIn(
    name = name.ifBlank { "Default" },
    ageRanges = ageRanges.toList().ifEmpty { null },
    genders = genders.toList().ifEmpty { null },
    countryCodes = countryCodes.ifEmpty { null },
    contentCategories = contentCategories.toList().ifEmpty { null },
    deviceTypes = deviceTypes.toList().ifEmpty { null },
    activeHours = activeHours.sorted().ifEmpty { null },
    newUserOnly = newUserOnly,
)
