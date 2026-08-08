package com.testlogon.android.feature.ads.studio.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * PAR-23 - shared account + campaign picker logic for the ads STUDIO editors (targeting / scheduling /
 * optimization), factored out to avoid triplicating the dropdown wiring across the three ViewModels.
 *
 * It loads the caller's ad accounts + the selected account's campaigns (REUSING the AND-367
 * [AdsBillingRepository] over the AND-363 accounts API - NO new network code), and persists every explicit
 * pick to [AdsStudioSelection] so the [AdsStudioCampaignResolver] (which each editor already uses to resolve
 * its target campaign) honours it. This is a per-VM instance (@Inject, NOT a singleton) so each editor's
 * dropdown state is scoped to that screen; the persisted selection is the shared source of truth.
 *
 * FLOW: [start] loads accounts, preselects (the persisted account, else the first "active", else the first),
 * and loads that account's campaigns, preselecting the persisted campaign (else the first). Selecting a NEW
 * account clears any stale campaign (via [AdsStudioSelection.selectAccount]) and reloads campaigns. Each
 * account/campaign change invokes [onSelectionChanged] so the host VM can re-resolve + reload its editor.
 *
 * NOTE (called out in the PAR-23 report): [AdsStudioSelection] is ALSO read by the sponsored-post / mass-DM
 * compose flows, so a studio picker change also changes THEIR prefill. That is acceptable - those flows keep
 * an editable picker of their own.
 */
class StudioCampaignSelector @Inject constructor(
    private val billing: AdsBillingRepository,
    private val selection: AdsStudioSelection,
) {

    sealed interface AccountsState {
        data object Loading : AccountsState
        data class Content(val accounts: List<AdAccountSummary>) : AccountsState
        data object Empty : AccountsState
        data class Error(val message: String) : AccountsState
    }

    sealed interface CampaignsState {
        data object Idle : CampaignsState
        data object Loading : CampaignsState
        data class Content(val campaigns: List<AdCampaign>) : CampaignsState
        data object Empty : CampaignsState
        data class Error(val message: String) : CampaignsState
    }

    private val _accountsState = MutableStateFlow<AccountsState>(AccountsState.Loading)
    val accountsState: StateFlow<AccountsState> = _accountsState.asStateFlow()

    private val _campaignsState = MutableStateFlow<CampaignsState>(CampaignsState.Idle)
    val campaignsState: StateFlow<CampaignsState> = _campaignsState.asStateFlow()

    private val _selectedAccountId = MutableStateFlow<String?>(null)
    val selectedAccountId: StateFlow<String?> = _selectedAccountId.asStateFlow()

    private val _selectedCampaignId = MutableStateFlow<String?>(selection.selectedCampaignId)
    val selectedCampaignId: StateFlow<String?> = _selectedCampaignId.asStateFlow()

    /**
     * Loads accounts (+ the preselected account's campaigns) in [scope]. Does NOT itself trigger the host's
     * reload - the host has already resolved on its own init; the picker only drives reloads on an explicit
     * user selection thereafter.
     */
    fun start(scope: CoroutineScope) {
        _accountsState.value = AccountsState.Loading
        scope.launch {
            when (val r = billing.listAccounts()) {
                is ApiResult.Success -> {
                    _accountsState.value =
                        if (r.data.isEmpty()) AccountsState.Empty else AccountsState.Content(r.data)
                    val pre = selection.current.accountId
                        ?.let { id -> r.data.firstOrNull { it.accountId == id } }
                        ?: r.data.firstOrNull { it.status == "active" }
                        ?: r.data.firstOrNull()
                    val accId = pre?.accountId
                    if (accId != null) {
                        _selectedAccountId.value = accId
                        selection.selectAccount(accId)
                        loadCampaigns(scope, accId, notify = null)
                    }
                }
                is ApiResult.Failure -> _accountsState.value = AccountsState.Error(r.error.message)
                is ApiResult.NetworkError -> _accountsState.value = AccountsState.Error(OFFLINE)
            }
        }
    }

    /**
     * Handles an account pick: persists it (clearing a stale campaign), reloads that account's campaigns and
     * invokes [onSelectionChanged] once the campaign has been (re)selected.
     */
    fun onAccountSelected(scope: CoroutineScope, accountId: String, onSelectionChanged: () -> Unit) {
        if (_selectedAccountId.value == accountId) return
        _selectedAccountId.value = accountId
        // selectAccount clears any campaign that belonged to a different account.
        selection.selectAccount(accountId)
        _selectedCampaignId.value = selection.current.campaignId
        loadCampaigns(scope, accountId, notify = onSelectionChanged)
    }

    /** Handles a campaign pick: persists it and invokes [onSelectionChanged] so the host re-resolves. */
    fun onCampaignSelected(campaignId: String, onSelectionChanged: () -> Unit) {
        if (_selectedCampaignId.value == campaignId) return
        _selectedCampaignId.value = campaignId
        selection.selectCampaign(campaignId, _selectedAccountId.value)
        onSelectionChanged()
    }

    private fun loadCampaigns(scope: CoroutineScope, accountId: String, notify: (() -> Unit)?) {
        _campaignsState.value = CampaignsState.Loading
        scope.launch {
            when (val r = billing.getCampaigns(accountId)) {
                is ApiResult.Success -> {
                    _campaignsState.value =
                        if (r.data.isEmpty()) CampaignsState.Empty else CampaignsState.Content(r.data)
                    // Preserve a valid prior/selected campaign, else preselect the first; persist the pick so
                    // the resolver honours it. A zero-campaign account leaves the selection null (NoCampaign).
                    val valid = r.data.any { it.campaignId == _selectedCampaignId.value }
                    val next = if (valid) _selectedCampaignId.value else r.data.firstOrNull()?.campaignId
                    _selectedCampaignId.value = next
                    if (next != null) selection.selectCampaign(next, accountId)
                    notify?.invoke()
                }
                is ApiResult.Failure -> {
                    _campaignsState.value = CampaignsState.Error(r.error.message)
                    notify?.invoke()
                }
                is ApiResult.NetworkError -> {
                    _campaignsState.value = CampaignsState.Error(OFFLINE)
                    notify?.invoke()
                }
            }
        }
    }

    private companion object {
        const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
