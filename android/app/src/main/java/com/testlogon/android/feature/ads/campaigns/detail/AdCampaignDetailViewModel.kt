package com.testlogon.android.feature.ads.campaigns.detail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import javax.inject.Inject

/**
 * ADV3-4 (B2) - presentation logic for the campaign MANAGEMENT (detail) screen. accountId + campaignId
 * arrive as nav args via [SavedStateHandle]. Reads one campaign and drives pause/resume/archive + budget/bid
 * edits through the existing PATCH endpoint ([AdsBillingRepository.updateCampaign]); every mutation re-reads
 * the campaign on success so the rendered status/budget/bid is always server-authoritative.
 *
 * The mutation runs in a SEPARATE [ActionState] off the read state (a failed pause never drops the screen to
 * a fatal error). Every mutation is NON-idempotent (the server validates the status transition) -> NO retry.
 */
@HiltViewModel
class AdCampaignDetailViewModel @Inject constructor(
    private val repository: AdsBillingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val accountId: String =
        checkNotNull(savedState[ARG_ACCOUNT_ID]) { "missing $ARG_ACCOUNT_ID nav arg" }
    val campaignId: String =
        checkNotNull(savedState[ARG_CAMPAIGN_ID]) { "missing $ARG_CAMPAIGN_ID nav arg" }

    /** Dispatcher seam: defaults to IO; a test swaps it via apply after construction. */
    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdCampaignDetailUiState>(AdCampaignDetailUiState.Loading)
    val uiState: StateFlow<AdCampaignDetailUiState> = _uiState.asStateFlow()

    init { load() }

    fun load() {
        if (_uiState.value !is AdCampaignDetailUiState.Content) {
            _uiState.value = AdCampaignDetailUiState.Loading
        }
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.getCampaign(accountId, campaignId) }) {
                is ApiResult.Success ->
                    _uiState.value = AdCampaignDetailUiState.Content(r.data)
                is ApiResult.Failure -> setLoadError(r.error)
                is ApiResult.NetworkError ->
                    setLoadError(ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE))
            }
        }
    }

    fun onRetry() = load()

    /** Pause an active campaign (active -> paused). */
    fun pause() = mutate(status = "paused")

    /** Resume a paused campaign (paused -> active). */
    fun resume() = mutate(status = "active")

    /** Archive the campaign (draft/active/paused -> archived). */
    fun archive() = mutate(status = "archived")

    /** Edit the lifetime/daily budget (USD entry -> integer cents; >= $1). Ignored when unparseable. */
    fun editBudget(usd: String) {
        val cents = parseCents(usd)?.takeIf { it >= MIN_BUDGET_CENTS } ?: return
        mutate(budgetCents = cents)
    }

    /** Edit the CPM bid (USD entry -> integer cents; $0.50..$200). Ignored when out of range. */
    fun editBid(usd: String) {
        val cents = parseCents(usd)?.takeIf { it in MIN_BID_CENTS..MAX_BID_CENTS }?.toInt() ?: return
        mutate(bidCpmCents = cents)
    }

    // ---- internals ----

    private fun mutate(
        status: String? = null,
        budgetCents: Long? = null,
        bidCpmCents: Int? = null,
    ) {
        val content = _uiState.value as? AdCampaignDetailUiState.Content ?: return
        if (content.action is ActionState.Submitting) return
        _uiState.value = content.copy(action = ActionState.Submitting)
        viewModelScope.launch {
            val r = withContext(ioDispatcher) {
                repository.updateCampaign(
                    accountId = accountId,
                    campaignId = campaignId,
                    status = status,
                    budgetCents = budgetCents,
                    bidCpmCents = bidCpmCents,
                )
            }
            when (r) {
                is ApiResult.Success -> reloadAfterMutation()
                is ApiResult.Failure -> setActionError(r.error.message)
                is ApiResult.NetworkError -> setActionError(OFFLINE)
            }
        }
    }

    /** Re-reads the campaign after a successful mutation and clears the action to Idle. */
    private suspend fun reloadAfterMutation() {
        when (val r = withContext(ioDispatcher) { repository.getCampaign(accountId, campaignId) }) {
            is ApiResult.Success ->
                _uiState.value = AdCampaignDetailUiState.Content(r.data, ActionState.Idle)
            else -> {
                // The mutation succeeded but the re-read failed: keep the prior content, clear Submitting.
                (_uiState.value as? AdCampaignDetailUiState.Content)?.let {
                    _uiState.value = it.copy(action = ActionState.Idle)
                }
            }
        }
    }

    private fun setActionError(message: String) {
        (_uiState.value as? AdCampaignDetailUiState.Content)?.let {
            _uiState.value = it.copy(action = ActionState.Error(message))
        }
    }

    private fun setLoadError(error: ApiError) {
        if (_uiState.value !is AdCampaignDetailUiState.Content) {
            _uiState.value = AdCampaignDetailUiState.Error(error)
        }
    }

    companion object {
        const val ARG_ACCOUNT_ID = "accountId"
        const val ARG_CAMPAIGN_ID = "campaignId"

        const val MIN_BUDGET_CENTS = 100L
        const val MIN_BID_CENTS = 50L
        const val MAX_BID_CENTS = 20_000L
        private const val OFFLINE = "Couldn't reach the server. Try again."

        /** True when this status can be paused (active only). */
        fun canPause(status: AdCampaignStatusDomain?): Boolean = status == AdCampaignStatusDomain.ACTIVE
        /** True when this status can be resumed (paused only). */
        fun canResume(status: AdCampaignStatusDomain?): Boolean = status == AdCampaignStatusDomain.PAUSED
        /** True when this status can be archived (anything but completed/archived). */
        fun canArchive(status: AdCampaignStatusDomain?): Boolean = when (status) {
            AdCampaignStatusDomain.DRAFT,
            AdCampaignStatusDomain.ACTIVE,
            AdCampaignStatusDomain.PAUSED,
            -> true
            else -> false
        }

        internal fun parseCents(text: String): Long? {
            val cleaned = text.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return null
            val dollars = cleaned.toBigDecimalOrNull() ?: return null
            if (dollars.signum() < 0) return null
            return dollars.movePointRight(2).setScale(0, BigDecimal.ROUND_HALF_UP).toLong()
        }
    }
}
