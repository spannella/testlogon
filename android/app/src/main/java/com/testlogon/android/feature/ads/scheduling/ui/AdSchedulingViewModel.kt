package com.testlogon.android.feature.ads.scheduling.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.DaypartingDto
import com.testlogon.android.feature.ads.scheduling.data.AdSchedulingRepository
import com.testlogon.android.feature.ads.studio.data.AdsStudioCampaignResolver
import com.testlogon.android.feature.ads.studio.data.StudioCampaignSelector
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
 * Presentation logic for the ad SCHEDULING editor (web parity: AdSchedulePage.tsx).
 *
 * On init, resolves the caller's first campaign, loads its schedule + the dayparting templates, and (best
 * effort) the eligibility + pacing summary. Edits toggle hour cells / apply a template in-memory; save PATCHes
 * the dayparting + timezone. READ+WRITE; no polling loop.
 *
 * Dispatcher seam: ioDispatcher defaults to IO; read inside coroutines so a test can swap it.
 */
@HiltViewModel
class AdSchedulingViewModel @Inject constructor(
    private val resolver: AdsStudioCampaignResolver,
    val campaignSelector: StudioCampaignSelector,
    private val repository: AdSchedulingRepository,
) : ViewModel() {

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdSchedulingUiState>(AdSchedulingUiState.Loading)
    val uiState: StateFlow<AdSchedulingUiState> = _uiState.asStateFlow()

    /** Templates keyed by name -> {day -> [hours]}; cached so applyTemplate is local. */
    private var templates: Map<String, Map<String, List<Int>>> = emptyMap()

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
        _uiState.value = AdSchedulingUiState.Loading
        viewModelScope.launch {
            when (val res = withContext(ioDispatcher) { resolver.resolveFirstCampaign() }) {
                is AdsStudioCampaignResolver.Resolution.NoCampaign ->
                    _uiState.value = AdSchedulingUiState.NoCampaign
                is AdsStudioCampaignResolver.Resolution.Failed ->
                    _uiState.value = AdSchedulingUiState.Error(res.result.toApiError())
                is AdsStudioCampaignResolver.Resolution.Found -> {
                    val campaign = res.campaign
                    val name = campaign.name ?: campaign.campaignId
                    val scheduleRes = withContext(ioDispatcher) { repository.getSchedule(campaign.campaignId) }
                    val schedule = when (scheduleRes) {
                        is ApiResult.Success -> scheduleRes.data
                        is ApiResult.Failure -> {
                            _uiState.value = AdSchedulingUiState.Error(scheduleRes.error); return@launch
                        }
                        is ApiResult.NetworkError -> {
                            _uiState.value = AdSchedulingUiState.Error(networkError()); return@launch
                        }
                    }
                    templates = (withContext(ioDispatcher) { repository.getTemplates() } as? ApiResult.Success)
                        ?.data.orEmpty()

                    val grid = schedule.dayparting?.schedule.orEmpty()
                        .mapValues { (_, hours) -> hours.toSet() }
                    _uiState.value = AdSchedulingUiState.Content(
                        campaignId = campaign.campaignId,
                        campaignName = name,
                        timezone = schedule.dayparting?.timezone ?: schedule.campaignTimezone,
                        schedule = grid,
                        templateNames = templates.keys.sorted(),
                        flights = schedule.flights.orEmpty(),
                    )
                    loadSummary(campaign.campaignId)
                }
            }
        }
    }

    private fun loadSummary(campaignId: String) {
        viewModelScope.launch {
            val elig = withContext(ioDispatcher) { repository.getEligibility(campaignId) }
            (elig as? ApiResult.Success)?.let { e ->
                updateContent { it.copy(eligibleNow = e.data.eligible) }
            }
            val pacing = withContext(ioDispatcher) { repository.getPacing(campaignId) }
            (pacing as? ApiResult.Success)?.let { p ->
                updateContent { it.copy(hourlyBudgetCents = p.data.hourlyBudgetCents) }
            }
        }
    }

    fun onRetry() = load()

    /** Toggles a single hour cell for a day. */
    fun toggleHour(day: String, hour: Int) {
        updateContent { content ->
            val current = content.schedule[day].orEmpty()
            val next = if (hour in current) current - hour else current + hour
            content.copy(schedule = content.schedule + (day to next), saved = false, actionError = null)
        }
    }

    /** Toggles a whole day on (all 24 hours) / off (none). */
    fun toggleDay(day: String) {
        updateContent { content ->
            val current = content.schedule[day].orEmpty()
            val next = if (current.size >= 24) emptySet() else (0..23).toSet()
            content.copy(schedule = content.schedule + (day to next), saved = false, actionError = null)
        }
    }

    /** Applies a named template to the grid. */
    fun applyTemplate(name: String) {
        val tmpl = templates[name] ?: return
        updateContent { content ->
            content.copy(
                schedule = tmpl.mapValues { (_, hours) -> hours.toSet() },
                saved = false,
                actionError = null,
            )
        }
    }

    fun setTimezone(tz: String) {
        updateContent { it.copy(timezone = tz, saved = false, actionError = null) }
    }

    fun save() {
        val content = _uiState.value as? AdSchedulingUiState.Content ?: return
        if (content.saving) return
        _uiState.value = content.copy(saving = true, saved = false, actionError = null)
        viewModelScope.launch {
            val dayparting = DaypartingDto(
                timezone = content.timezone,
                schedule = content.schedule.mapValues { (_, hours) -> hours.sorted() },
            )
            val result = withContext(ioDispatcher) {
                repository.updateSchedule(content.campaignId, dayparting, content.timezone)
            }
            when (result) {
                is ApiResult.Success -> updateContent { it.copy(saving = false, saved = true) }
                is ApiResult.Failure -> updateContent {
                    it.copy(saving = false, actionError = result.error.message)
                }
                is ApiResult.NetworkError -> updateContent {
                    it.copy(saving = false, actionError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private inline fun updateContent(
        transform: (AdSchedulingUiState.Content) -> AdSchedulingUiState.Content,
    ) {
        (_uiState.value as? AdSchedulingUiState.Content)?.let { _uiState.value = transform(it) }
    }

    private fun ApiResult<*>.toApiError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        else -> networkError()
    }

    private fun networkError() = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
