package com.testlogon.android.feature.ads.create.campaign

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.feature.ads.create.data.AdsCreateRepository
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.math.BigDecimal
import javax.inject.Inject

/**
 * ADV-108 - presentation logic for the CREATE-CAMPAIGN screen (name, objective, budget + type, bid_cpm) ->
 * POST ui/ads/accounts/{id}/campaigns, then optional submit-for-review. Replaces the legacy first-of-first
 * auto-resolve: a REAL account PICKER chooses which account the campaign lives under, and the created
 * campaign is recorded as the studio [AdsStudioSelection] so targeting/scheduling/optimization open against it.
 *
 * The account list is loaded on init ([accountsState]); the form pre-selects the studio-selected account (or
 * the first active one). Create is NON-idempotent (in-flight guard, no auto-retry). Budget/bid are entered in
 * USD and parsed to integer cents (budget >= $1; bid $0.50..$200, default $5.00).
 */
@HiltViewModel
class CreateCampaignViewModel @Inject constructor(
    private val repository: AdsCreateRepository,
    private val selection: AdsStudioSelection,
) : ViewModel() {

    sealed interface AccountsState {
        data object Loading : AccountsState
        data class Content(val accounts: List<AdAccountSummary>) : AccountsState
        data object Empty : AccountsState
        data class Error(val message: String) : AccountsState
    }

    sealed interface SubmitState {
        data object Idle : SubmitState
        data object Submitting : SubmitState
        data class Success(val campaign: AdCampaign) : SubmitState
        data class Error(val message: String) : SubmitState
    }

    sealed interface ReviewState {
        data object Idle : ReviewState
        data object Submitting : ReviewState
        data class Done(val status: String) : ReviewState
        data class Error(val message: String) : ReviewState
    }

    private val _accountsState = MutableStateFlow<AccountsState>(AccountsState.Loading)
    val accountsState: StateFlow<AccountsState> = _accountsState.asStateFlow()

    private val _selectedAccountId = MutableStateFlow<String?>(null)
    val selectedAccountId: StateFlow<String?> = _selectedAccountId.asStateFlow()

    private val _name = MutableStateFlow("")
    val name: StateFlow<String> = _name.asStateFlow()

    private val _objective = MutableStateFlow(OBJECTIVES.first())
    val objective: StateFlow<String> = _objective.asStateFlow()

    private val _budgetType = MutableStateFlow(BUDGET_TYPES.first())
    val budgetType: StateFlow<String> = _budgetType.asStateFlow()

    private val _budgetUsd = MutableStateFlow("")
    val budgetUsd: StateFlow<String> = _budgetUsd.asStateFlow()

    private val _bidCpmUsd = MutableStateFlow(DEFAULT_BID_USD)
    val bidCpmUsd: StateFlow<String> = _bidCpmUsd.asStateFlow()

    // ADV-301 - advertiser-set CPC / CPA bids (USD entry -> integer cents; server defaults 50c / 500c).
    private val _bidCpcUsd = MutableStateFlow(DEFAULT_CPC_USD)
    val bidCpcUsd: StateFlow<String> = _bidCpcUsd.asStateFlow()

    private val _bidCpaUsd = MutableStateFlow(DEFAULT_CPA_USD)
    val bidCpaUsd: StateFlow<String> = _bidCpaUsd.asStateFlow()

    // ADV2-306 (F3) — free "promote my content" self-advertising. When on, budget/bids are hidden + not
    // required (the campaign is free, needs no funding, and the server zeroes all bids), and the fill mode
    // (fill_only vs always_win) governs whether it only backfills empty own-content slots or always wins them.
    private val _isSelfPromo = MutableStateFlow(false)
    val isSelfPromo: StateFlow<Boolean> = _isSelfPromo.asStateFlow()

    private val _selfPromoMode = MutableStateFlow(SELF_PROMO_MODES.first())
    val selfPromoMode: StateFlow<String> = _selfPromoMode.asStateFlow()

    private val _submitState = MutableStateFlow<SubmitState>(SubmitState.Idle)
    val submitState: StateFlow<SubmitState> = _submitState.asStateFlow()

    private val _reviewState = MutableStateFlow<ReviewState>(ReviewState.Idle)
    val reviewState: StateFlow<ReviewState> = _reviewState.asStateFlow()

    init {
        loadAccounts()
    }

    fun loadAccounts() {
        _accountsState.value = AccountsState.Loading
        viewModelScope.launch {
            when (val r = repository.listAccounts()) {
                is ApiResult.Success -> {
                    _accountsState.value =
                        if (r.data.isEmpty()) AccountsState.Empty else AccountsState.Content(r.data)
                    preselect(r.data)
                }
                is ApiResult.Failure -> _accountsState.value = AccountsState.Error(r.error.message)
                is ApiResult.NetworkError -> _accountsState.value = AccountsState.Error(OFFLINE)
            }
        }
    }

    fun onAccountSelected(accountId: String) {
        _selectedAccountId.value = accountId
        selection.selectAccount(accountId)
    }

    fun onName(text: String) { _name.value = text; clearError() }
    fun onObjective(value: String) { _objective.value = value }
    fun onBudgetType(value: String) { _budgetType.value = value }
    fun onBudgetUsd(text: String) { _budgetUsd.value = text; clearError() }
    fun onBidCpmUsd(text: String) { _bidCpmUsd.value = text; clearError() }
    fun onBidCpcUsd(text: String) { _bidCpcUsd.value = text; clearError() }
    fun onBidCpaUsd(text: String) { _bidCpaUsd.value = text; clearError() }
    fun onSelfPromo(on: Boolean) { _isSelfPromo.value = on; clearError() }
    fun onSelfPromoMode(mode: String) { _selfPromoMode.value = mode }

    /** True when an account is selected, a name is present, and budget/bid parse into their valid ranges. */
    val canSubmit: Boolean
        get() = _selectedAccountId.value != null &&
            _name.value.isNotBlank() &&
            // A self-promo is free: no budget/bid entry is required (server zeroes bids, needs no funding).
            (_isSelfPromo.value || (
                (parseCents(_budgetUsd.value)?.let { it >= MIN_BUDGET_CENTS } == true) &&
                    (parseCents(_bidCpmUsd.value)?.let { it in MIN_BID_CENTS..MAX_BID_CENTS } == true) &&
                    (parseCents(_bidCpcUsd.value)?.let { it in MIN_CPC_CENTS..MAX_CPC_CENTS } == true) &&
                    (parseCents(_bidCpaUsd.value)?.let { it in MIN_CPA_CENTS..MAX_CPA_CENTS } == true)
                ))

    fun submit() {
        if (_submitState.value is SubmitState.Submitting) return
        val accountId = _selectedAccountId.value ?: return
        if (_name.value.isBlank()) return
        val selfPromo = _isSelfPromo.value

        // A self-promo is free: send budget 0 and OMIT all bids (null) so the server floors are not tripped
        // and the server zeroes the bids itself. A paid campaign parses + range-validates budget/bids.
        val budget: Long
        val bid: Int?
        val cpc: Int?
        val cpa: Int?
        if (selfPromo) {
            budget = 0L; bid = null; cpc = null; cpa = null
        } else {
            budget = parseCents(_budgetUsd.value)?.takeIf { it >= MIN_BUDGET_CENTS } ?: return
            bid = parseCents(_bidCpmUsd.value)?.takeIf { it in MIN_BID_CENTS..MAX_BID_CENTS }?.toInt() ?: return
            cpc = parseCents(_bidCpcUsd.value)?.takeIf { it in MIN_CPC_CENTS..MAX_CPC_CENTS }?.toInt() ?: return
            cpa = parseCents(_bidCpaUsd.value)?.takeIf { it in MIN_CPA_CENTS..MAX_CPA_CENTS }?.toInt() ?: return
        }

        _submitState.value = SubmitState.Submitting
        viewModelScope.launch {
            val result = repository.createCampaign(
                accountId = accountId,
                name = _name.value.trim(),
                objective = _objective.value,
                budgetCents = budget,
                budgetType = _budgetType.value,
                bidCpmCents = bid,
                bidCpcCents = cpc,
                bidCpaCents = cpa,
                category = null,
                startDate = null,
                endDate = null,
                isSelfPromo = selfPromo,
                selfPromoMode = if (selfPromo) _selfPromoMode.value else null,
            )
            when (result) {
                is ApiResult.Success -> {
                    selection.selectCampaign(result.data.campaignId, accountId)
                    _submitState.value = SubmitState.Success(result.data)
                }
                is ApiResult.Failure -> _submitState.value = SubmitState.Error(result.error.friendly())
                is ApiResult.NetworkError -> _submitState.value = SubmitState.Error(OFFLINE)
            }
        }
    }

    /** ADV-108 - submit the just-created draft campaign for admin review. */
    fun submitForReview() {
        val created = _submitState.value as? SubmitState.Success ?: return
        val accountId = _selectedAccountId.value ?: created.campaign.accountId ?: return
        if (_reviewState.value is ReviewState.Submitting) return

        _reviewState.value = ReviewState.Submitting
        viewModelScope.launch {
            when (val r = repository.submitCampaign(accountId, created.campaign.campaignId)) {
                is ApiResult.Success ->
                    _reviewState.value = ReviewState.Done(r.data)
                is ApiResult.Failure -> _reviewState.value = ReviewState.Error(r.error.friendly())
                is ApiResult.NetworkError -> _reviewState.value = ReviewState.Error(OFFLINE)
            }
        }
    }

    private fun preselect(accounts: List<AdAccountSummary>) {
        if (_selectedAccountId.value != null) return
        val fromStudio = selection.current.accountId
            ?.let { id -> accounts.firstOrNull { it.accountId == id } }
        val active = accounts.firstOrNull { it.status == "active" }
        (fromStudio ?: active ?: accounts.firstOrNull())?.accountId?.let { _selectedAccountId.value = it }
    }

    private fun clearError() {
        if (_submitState.value is SubmitState.Error) _submitState.value = SubmitState.Idle
    }

    private fun ApiError.friendly(): String = when (status) {
        HTTP_FORBIDDEN -> "This account isn't approved yet. An admin must approve it before you can create campaigns."
        else -> message
    }

    companion object {
        val OBJECTIVES = listOf("awareness", "traffic", "conversions")
        val BUDGET_TYPES = listOf("lifetime", "daily")
        // ADV2-306 (F3) — self-promo fill modes; fill_only is the safe default (only backfills empty slots).
        val SELF_PROMO_MODES = listOf("fill_only", "always_win")

        const val MIN_BUDGET_CENTS = 100L
        const val MIN_BID_CENTS = 50L
        const val MAX_BID_CENTS = 20_000L
        const val DEFAULT_BID_USD = "5.00"

        // ADV-301 - CPC/CPA bounds mirror the server (bid_cpc_cents 1..10000, bid_cpa_cents 1..100000).
        const val MIN_CPC_CENTS = 1L
        const val MAX_CPC_CENTS = 10_000L
        const val MIN_CPA_CENTS = 1L
        const val MAX_CPA_CENTS = 100_000L
        const val DEFAULT_CPC_USD = "0.50"
        const val DEFAULT_CPA_USD = "5.00"

        private const val HTTP_FORBIDDEN = 403
        private const val OFFLINE = "Couldn't reach the server. Try again."

        /** Parses a USD entry into integer cents, or null when unparseable/negative. */
        internal fun parseCents(text: String): Long? {
            val cleaned = text.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return null
            val dollars = cleaned.toBigDecimalOrNull() ?: return null
            if (dollars.signum() < 0) return null
            return dollars.movePointRight(2).setScale(0, BigDecimal.ROUND_HALF_UP).toLong()
        }
    }
}
