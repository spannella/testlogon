package com.testlogon.android.feature.custody

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyAsset
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyBalance
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.BridgeAction
import com.testlogon.android.data.custody.CustodyBridgeResult
import com.testlogon.android.data.custody.CustodySubAccount
import com.testlogon.android.data.custody.CustodySubAccounts
import com.testlogon.android.data.custody.SubAccountTransferResult
import com.testlogon.android.data.custody.CustodyDepositAddress
import com.testlogon.android.data.custody.CustodyDeposits
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.custody.StakingDashboard
import com.testlogon.android.data.custody.StakeResult
import com.testlogon.android.data.custody.CustodyWithdrawResult
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.SpotBalance
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.core.model.ApiResult.Success
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * The seven in-screen custody tabs. Activity + Approvals have no backing endpoint on this backend and
 * render a static "not available" state; they are always shown (no role gating).
 */
enum class CustodyTab { BALANCES, STAKING, SUBACCOUNTS, TRANSFER, DEPOSIT, WITHDRAW, ACTIVITY, APPROVALS }

/** A generic async slice: loading / error(message) / data. */
data class Async<out T>(
    val loading: Boolean = false,
    val error: String? = null,
    val data: T? = null,
)

/** Deposit-tab state: the selected asset symbol + resolved per-chain address. */
data class DepositUiState(
    val selectedKey: String? = null,
    val address: Async<CustodyDepositAddress> = Async(),
    /** Recent scanned incoming transfers (soft-unavailable when the backend lacks the endpoint). */
    val deposits: Async<CustodyDeposits> = Async(),
)

/** Withdraw form + submit result. */
data class WithdrawUiState(
    val selectedKey: String? = null,
    val amount: String = "",
    val destination: String = "",
    val tokenOverride: String = "",
    val submitting: Boolean = false,
    val result: CustodyWithdrawResult? = null,
    val submitError: String? = null,
)

/** Sub-accounts tab: the vault list + the create-form field / in-flight flag. */
data class SubAccountsUiState(
    val list: Async<CustodySubAccounts> = Async(loading = true),
    val newLabel: String = "",
    val creating: Boolean = false,
    val createError: String? = null,
)

/**
 * Transfer tab. Two independent forms: the custody<->trading bridge (action = fund/settle x
 * spot/margin + a token symbol + a decimal amount) and the between-sub-accounts move (from/to labels +
 * asset symbol + amount). Each holds its own in-flight flag, error, and last (real) result.
 */
data class TransferUiState(
    // Bridge (custody <-> trading)
    val bridgeAction: BridgeAction = BridgeAction.FUND_SPOT,
    val bridgeToken: String = CustodyAssets.BRIDGE_TOKENS.firstOrNull() ?: "ETH",
    val bridgeAmountText: String = "",
    val bridgeSubmitting: Boolean = false,
    val bridgeError: String? = null,
    val bridgeResult: CustodyBridgeResult? = null,
    // Between sub-accounts
    val fromLabel: String = "",
    val toLabel: String = "",
    val subAsset: String = "",
    val subAmountText: String = "",
    val subSubmitting: Boolean = false,
    val subError: String? = null,
    val subResult: SubAccountTransferResult? = null,
) {
    val bridgeAmountDouble: Double? get() = bridgeAmountText.trim().toDoubleOrNull()
    val canBridge: Boolean get() = !bridgeSubmitting &&
        bridgeToken.trim().isNotEmpty() &&
        (bridgeAmountDouble ?: 0.0) > 0.0
    val subAmountDouble: Double? get() = subAmountText.trim().toDoubleOrNull()
    val canSubTransfer: Boolean get() = !subSubmitting &&
        subAsset.trim().isNotEmpty() &&
        (subAmountDouble ?: 0.0) > 0.0 &&
        fromLabel.trim() != toLabel.trim()
}

/**
 * Staking tab: the providers + positions read (soft-unavailable when the backend lacks the endpoint)
 * plus the stake form (selected provider id + amount + in-flight/result).
 */
data class StakingUiState(
    val dashboard: Async<StakingDashboard> = Async(loading = true),
    val selectedProvider: String = "",
    val amountText: String = "",
    val submitting: Boolean = false,
    val submitError: String? = null,
    val result: StakeResult? = null,
) {
    val amountDouble: Double? get() = amountText.trim().toDoubleOrNull()
    val canStake: Boolean get() = !submitting &&
        selectedProvider.trim().isNotEmpty() &&
        (amountDouble ?: 0.0) > 0.0
}

data class CustodyUiState(
    val tab: CustodyTab = CustodyTab.BALANCES,
    val balances: Async<CustodyBalances> = Async(loading = true),
    val deposit: DepositUiState = DepositUiState(),
    val withdraw: WithdrawUiState = WithdrawUiState(),
    val subAccounts: SubAccountsUiState = SubAccountsUiState(),
    val staking: StakingUiState = StakingUiState(),
    val transfer: TransferUiState = TransferUiState(),
    /** Best-effort exchange-side balances for the bridge settle path (source-balance guidance only). */
    val spot: Async<SpotBalance> = Async(),
    val margin: Async<MarginAccount> = Async(),
) {
    val rows: List<CustodyBalance> get() = balances.data?.rows.orEmpty()
    val fundedRows: List<CustodyBalance> get() = balances.data?.funded().orEmpty()
    fun rowFor(key: String?): CustodyBalance? = rows.firstOrNull { it.key == key }

    /** Custody-side available for a bridge/transfer token symbol (EXACT). Null when not in the balance map. */
    fun custodyAvailableFor(symbol: String?): Double? {
        val s = symbol?.trim()?.uppercase()?.takeIf { it.isNotBlank() } ?: return null
        return rows.firstOrNull { it.symbol.equals(s, ignoreCase = true) }?.amount
    }

    /** Best-effort spot available for a token symbol (guidance only; null when unknown/unavailable). */
    fun spotAvailableFor(symbol: String?): Double? {
        val s = symbol?.trim()?.uppercase()?.takeIf { it.isNotBlank() } ?: return null
        val a = spot.data?.assets?.firstOrNull { it.symbol.equals(s, ignoreCase = true) } ?: return null
        return a.available.toDouble()
    }

    /** Best-effort margin available (single collateral pool; symbol-agnostic guidance). */
    val marginAvailable: Double? get() = margin.data?.availableBalance?.toDouble()
}

@HiltViewModel
class CustodyViewModel @Inject constructor(
    private val repo: CustodyRepository,
    private val trading: TradingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CustodyUiState())
    val uiState: StateFlow<CustodyUiState> = _uiState.asStateFlow()

    init {
        loadBalance()
        loadDeposits()
        loadSubAccounts()
        loadStaking()
        loadExchangeBalances()
    }

    /**
     * Best-effort read of the exchange-side spot/margin balances used for source-balance guidance on the
     * settle path. Any failure leaves the slice empty (the UI degrades to "unavailable" guidance).
     */
    fun loadExchangeBalances() {
        viewModelScope.launch {
            when (val r = trading.spotBalance()) {
                is Success -> _uiState.update { it.copy(spot = Async(data = r.data)) }
                else -> _uiState.update { it.copy(spot = Async(error = "unavailable")) }
            }
        }
        viewModelScope.launch {
            when (val r = trading.marginAccount()) {
                is Success -> _uiState.update { it.copy(margin = Async(data = r.data)) }
                else -> _uiState.update { it.copy(margin = Async(error = "unavailable")) }
            }
        }
    }

    // ---- staking (custody-gated; 404/403 -> soft unavailable) ----

    fun loadStaking() {
        _uiState.update { it.copy(staking = it.staking.copy(dashboard = it.staking.dashboard.copy(loading = true, error = null))) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(staking = st.staking.copy(dashboard = repo.getStaking().toAsync())) }
        }
    }

    fun onStakeProviderSelected(providerId: String) {
        _uiState.update { it.copy(staking = it.staking.copy(selectedProvider = providerId, submitError = null)) }
    }

    fun onStakeAmountChanged(v: String) {
        _uiState.update { it.copy(staking = it.staking.copy(amountText = sanitizeDecimal(v), submitError = null)) }
    }

    fun clearStakeResult() {
        _uiState.update { it.copy(staking = it.staking.copy(result = null, submitError = null)) }
    }

    fun submitStake() {
        val f = _uiState.value.staking
        if (!f.canStake) return
        _uiState.update { it.copy(staking = it.staking.copy(submitting = true, submitError = null, result = null)) }
        viewModelScope.launch {
            when (val r = repo.stake(f.selectedProvider.trim(), f.amountText.trim())) {
                is Success -> {
                    _uiState.update { it.copy(staking = it.staking.copy(submitting = false, result = r.data)) }
                    // Refresh positions so a newly-created stake shows up.
                    loadStaking()
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(staking = it.staking.copy(submitting = false, submitError = r.error.messageFor())) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(staking = it.staking.copy(submitting = false, submitError = "Network error. Check your connection and try again.")) }
            }
        }
    }

    // ---- tab + selection ----

    fun onTabSelected(tab: CustodyTab) {
        _uiState.update { it.copy(tab = tab) }
    }

    fun loadBalance() {
        _uiState.update { it.copy(balances = it.balances.copy(loading = true, error = null)) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(balances = repo.getBalance().toAsync()) }
        }
    }

    /** Fetch recent incoming transfers for the deposit tab (404 -> a soft "unavailable" data state). */
    fun loadDeposits() {
        _uiState.update { it.copy(deposit = it.deposit.copy(deposits = it.deposit.deposits.copy(loading = true, error = null))) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(deposit = st.deposit.copy(deposits = repo.getDeposits().toAsync())) }
        }
    }

    // ---- deposit ----

    fun onDepositAssetSelected(key: String) {
        val asset = CustodyAssets.findAsset(key) ?: return
        _uiState.update { it.copy(deposit = it.deposit.copy(selectedKey = key, address = Async(loading = true))) }
        viewModelScope.launch {
            val res = repo.getDepositAddress(asset.chainId)
            _uiState.update { it.copy(deposit = it.deposit.copy(address = res.toAsync())) }
        }
    }

    // ---- withdraw ----

    fun onWithdrawAssetSelected(key: String) {
        _uiState.update {
            it.copy(withdraw = it.withdraw.copy(selectedKey = key, tokenOverride = "", submitError = null, result = null))
        }
    }

    fun onAmountChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(amount = v, submitError = null)) }
    }

    fun onDestinationChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(destination = v, submitError = null)) }
    }

    fun onTokenOverrideChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(tokenOverride = v, submitError = null)) }
    }

    fun onMax() {
        val w = _uiState.value.withdraw
        val row = _uiState.value.rowFor(w.selectedKey) ?: return
        _uiState.update { it.copy(withdraw = it.withdraw.copy(amount = row.amountText, submitError = null)) }
    }

    /** The token that will be sent for the selected asset (registry value, or an advanced override). */
    fun effectiveToken(): String {
        val w = _uiState.value.withdraw
        val override = w.tokenOverride.trim()
        if (override.isNotEmpty()) return override
        return CustodyAssets.findAsset(w.selectedKey)?.token ?: CustodyAssets.NATIVE
    }

    /** Validates the current form; returns an error string, or null if OK to submit. */
    fun validateWithdraw(): String? {
        val w = _uiState.value.withdraw
        val row = _uiState.value.rowFor(w.selectedKey) ?: return "Select an asset."
        if (!row.known) return "This asset is not withdrawable from this app."
        val amt = w.amount.trim().toDoubleOrNull()
        if (amt == null || amt <= 0.0) return "Enter an amount greater than 0."
        if (amt > row.amount) return "Amount exceeds your ${row.symbol} balance."
        if (w.destination.trim().isEmpty()) return "Enter a destination address."
        return null
    }

    fun submitWithdraw() {
        val err = validateWithdraw()
        if (err != null) {
            _uiState.update { it.copy(withdraw = it.withdraw.copy(submitError = err)) }
            return
        }
        val w = _uiState.value.withdraw
        val asset: CustodyAsset = CustodyAssets.findAsset(w.selectedKey) ?: return
        val token = effectiveToken()
        _uiState.update { it.copy(withdraw = it.withdraw.copy(submitting = true, submitError = null, result = null)) }
        viewModelScope.launch {
            when (val r = repo.withdraw(
                chain = asset.chainId.toString(),
                to = w.destination.trim(),
                amount = w.amount.trim(),
                token = token,
            )) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(withdraw = it.withdraw.copy(submitting = false, result = r.data)) }
                    // Refresh balances so the debit (on a signed outcome) shows.
                    loadBalance()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(withdraw = it.withdraw.copy(submitting = false, submitError = r.error.message))
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(withdraw = it.withdraw.copy(submitting = false, submitError = "Network error. Check your connection and try again."))
                }
            }
        }
    }

    // ---- sub-accounts ----

    fun loadSubAccounts() {
        _uiState.update { it.copy(subAccounts = it.subAccounts.copy(list = it.subAccounts.list.copy(loading = true, error = null))) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(subAccounts = st.subAccounts.copy(list = repo.getSubAccounts().toAsync())) }
        }
    }

    fun onNewSubAccountLabelChanged(v: String) {
        // Mirror the server sanitizer client-side: [A-Za-z0-9_-], capped 48.
        val sanitized = v.filter { it.isLetterOrDigit() || it == '_' || it == '-' }.take(48)
        _uiState.update { it.copy(subAccounts = it.subAccounts.copy(newLabel = sanitized, createError = null)) }
    }

    fun createSubAccount() {
        val label = _uiState.value.subAccounts.newLabel.trim()
        if (label.isEmpty()) {
            _uiState.update { it.copy(subAccounts = it.subAccounts.copy(createError = "Enter a label.")) }
            return
        }
        _uiState.update { it.copy(subAccounts = it.subAccounts.copy(creating = true, createError = null)) }
        viewModelScope.launch {
            when (val r = repo.createSubAccount(label)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(subAccounts = it.subAccounts.copy(creating = false, newLabel = "")) }
                    loadSubAccounts()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(subAccounts = it.subAccounts.copy(creating = false, createError = r.error.messageFor()))
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(subAccounts = it.subAccounts.copy(creating = false, createError = "Network error. Check your connection and try again."))
                }
            }
        }
    }

    /** Sub-account labels available as transfer endpoints (base vault + named), for the picker chips. */
    fun subAccountLabels(): List<String> {
        val subs = _uiState.value.subAccounts.list.data?.subAccounts.orEmpty().map { it.label }.filter { it.isNotBlank() }
        return listOf("") + subs   // "" == base vault
    }

    // ---- transfer: custody <-> trading bridge ----

    fun onBridgeActionSelected(action: BridgeAction) =
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeAction = action, bridgeError = null, bridgeResult = null)) }

    fun onBridgeTokenSelected(token: String) =
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeToken = token.trim().uppercase(), bridgeError = null)) }

    fun onBridgeAmountChanged(v: String) =
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeAmountText = sanitizeDecimal(v), bridgeError = null)) }

    /**
     * The source available for the current bridge action + token, and whether it is an EXACT figure.
     * fund-spot / fund-margin draw from custody (EXACT). settle-spot / settle-margin draw from the
     * exchange-side balance (best-effort guidance). Returns null when the source balance is unknown.
     */
    data class SourceBalance(val amount: Double?, val exact: Boolean, val label: String)

    private fun SourceBalance.toSafety(): MoneySafety.Source = MoneySafety.Source(amount, exact)

    fun bridgeSource(): SourceBalance {
        val st = _uiState.value
        val t = st.transfer
        return when (t.bridgeAction) {
            BridgeAction.FUND_SPOT, BridgeAction.FUND_MARGIN ->
                SourceBalance(st.custodyAvailableFor(t.bridgeToken), exact = true, label = "Custody")
            BridgeAction.SETTLE_SPOT ->
                SourceBalance(st.spotAvailableFor(t.bridgeToken), exact = false, label = "Spot")
            BridgeAction.SETTLE_MARGIN ->
                SourceBalance(st.marginAvailable, exact = false, label = "Margin")
        }
    }

    /** Whether a Max action is meaningful for the current action (only when the source is EXACT + known). */
    fun bridgeCanMax(): Boolean = MoneySafety.canMax(bridgeSource().toSafety())

    fun onBridgeMax() {
        val v = MoneySafety.maxValue(bridgeSource().toSafety()) ?: return
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeAmountText = v, bridgeError = null)) }
    }

    /** Returns a validation error string, or null if the bridge form is OK to review. */
    fun validateBridge(): String? {
        val t = _uiState.value.transfer
        if (t.bridgeToken.trim().isEmpty()) return "Choose a token."
        if (MoneySafety.positiveAmount(t.bridgeAmountText) == null) return "Enter an amount greater than 0."
        // Only block over-spend when the source figure is EXACT (fund path). Settle guidance never blocks.
        if (MoneySafety.overspends(t.bridgeAmountText, bridgeSource().toSafety())) {
            return "Amount exceeds your ${t.bridgeToken} custody balance."
        }
        return null
    }

    fun submitBridgeTransfer() {
        val err = validateBridge()
        if (err != null) {
            _uiState.update { it.copy(transfer = it.transfer.copy(bridgeError = err)) }
            return
        }
        val t = _uiState.value.transfer
        val action = t.bridgeAction
        val token = t.bridgeToken
        val amount = t.bridgeAmountText.trim()
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeSubmitting = true, bridgeError = null, bridgeResult = null)) }
        viewModelScope.launch {
            when (val r = repo.bridge(action, token, amount)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(transfer = it.transfer.copy(bridgeSubmitting = false, bridgeResult = r.data)) }
                    loadBalance()
                    loadExchangeBalances()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(transfer = it.transfer.copy(bridgeSubmitting = false, bridgeError = r.error.messageFor())) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(transfer = it.transfer.copy(bridgeSubmitting = false, bridgeError = "Network error. Check your connection and try again.")) }
            }
        }
    }

    fun clearBridgeResult() =
        _uiState.update { it.copy(transfer = it.transfer.copy(bridgeResult = null, bridgeAmountText = "")) }

    // ---- transfer: between sub-accounts ----

    fun onFromLabelChanged(v: String) = _uiState.update { it.copy(transfer = it.transfer.copy(fromLabel = v, subError = null)) }
    fun onToLabelChanged(v: String) = _uiState.update { it.copy(transfer = it.transfer.copy(toLabel = v, subError = null)) }
    fun onSubAssetChanged(v: String) = _uiState.update { it.copy(transfer = it.transfer.copy(subAsset = v.trim().uppercase().take(12), subError = null)) }
    fun onSubAmountChanged(v: String) = _uiState.update { it.copy(transfer = it.transfer.copy(subAmountText = sanitizeDecimal(v), subError = null)) }

    /**
     * Source available for the between-sub-accounts move. Only the BASE vault (blank from-label) exposes
     * an EXACT custody balance for the entered asset; a named sub-account has no per-asset balance
     * endpoint here, so its source is unknown (Max hidden, over-spend not blocked). Requires amount > 0.
     */
    fun subSource(): SourceBalance {
        val st = _uiState.value
        val t = st.transfer
        val fromBase = t.fromLabel.trim().isEmpty()
        return if (fromBase) {
            SourceBalance(st.custodyAvailableFor(t.subAsset), exact = true, label = "Base vault")
        } else {
            SourceBalance(amount = null, exact = false, label = t.fromLabel.trim())
        }
    }

    fun subCanMax(): Boolean = MoneySafety.canMax(subSource().toSafety())

    fun onSubMax() {
        val v = MoneySafety.maxValue(subSource().toSafety()) ?: return
        _uiState.update { it.copy(transfer = it.transfer.copy(subAmountText = v, subError = null)) }
    }

    /** Returns a validation error string, or null if the sub-account form is OK to review. */
    fun validateSubTransfer(): String? {
        val t = _uiState.value.transfer
        if (t.fromLabel.trim() == t.toLabel.trim()) return "Choose two different vaults."
        if (t.subAsset.trim().isEmpty()) return "Enter an asset."
        if (MoneySafety.positiveAmount(t.subAmountText) == null) return "Enter an amount greater than 0."
        if (MoneySafety.overspends(t.subAmountText, subSource().toSafety())) {
            return "Amount exceeds your ${t.subAsset} base-vault balance."
        }
        return null
    }

    fun submitSubAccountTransfer() {
        val err = validateSubTransfer()
        if (err != null) {
            _uiState.update { it.copy(transfer = it.transfer.copy(subError = err)) }
            return
        }
        val t = _uiState.value.transfer
        val from = t.fromLabel.trim()
        val to = t.toLabel.trim()
        val asset = t.subAsset.trim()
        val amount = t.subAmountText.trim()
        _uiState.update { it.copy(transfer = it.transfer.copy(subSubmitting = true, subError = null, subResult = null)) }
        viewModelScope.launch {
            when (val r = repo.subAccountTransfer(from.ifBlank { null }, to.ifBlank { null }, asset, amount)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(transfer = it.transfer.copy(subSubmitting = false, subResult = r.data)) }
                    loadSubAccounts()
                    loadBalance()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(transfer = it.transfer.copy(subSubmitting = false, subError = r.error.messageFor())) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(transfer = it.transfer.copy(subSubmitting = false, subError = "Network error. Check your connection and try again.")) }
            }
        }
    }

    fun clearSubTransferResult() =
        _uiState.update { it.copy(transfer = it.transfer.copy(subResult = null, subAmountText = "")) }

    /** Clears the withdraw result/form after the user acknowledges the outcome. */
    fun clearWithdrawResult() {
        _uiState.update {
            it.copy(withdraw = it.withdraw.copy(result = null, amount = "", destination = "", tokenOverride = "", submitError = null))
        }
    }
}

/** Trim a Double to a compact decimal string (drops a trailing .0 for whole numbers). */
private fun trimDecimal(v: Double): String = MoneySafety.trimDecimal(v)

/** Keep digits + a single decimal point, capped to a sane length. */
private fun sanitizeDecimal(v: String): String = MoneySafety.sanitizeDecimal(v)

// ---- ApiResult -> Async projection ----

private fun <T> ApiResult<T>.toAsync(): Async<T> = when (this) {
    is ApiResult.Success -> Async(loading = false, error = null, data = data)
    is ApiResult.Failure -> Async(loading = false, error = error.messageFor())
    is ApiResult.NetworkError -> Async(loading = false, error = "Network error. Check your connection and try again.")
}

private fun ApiError.messageFor(): String = when (status) {
    403 -> "You do not have access to this."
    else -> message
}
