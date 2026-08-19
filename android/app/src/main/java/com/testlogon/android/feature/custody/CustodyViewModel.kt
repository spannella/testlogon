package com.testlogon.android.feature.custody

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyAsset
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyBalance
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.CustodyDepositAddress
import com.testlogon.android.data.custody.CustodyDeposits
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.custody.CustodyWithdrawResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * The five in-screen custody tabs. Activity + Approvals have no backing endpoint on this backend and
 * render a static "not available" state; they are always shown (no role gating).
 */
enum class CustodyTab { BALANCES, DEPOSIT, WITHDRAW, ACTIVITY, APPROVALS }

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

data class CustodyUiState(
    val tab: CustodyTab = CustodyTab.BALANCES,
    val balances: Async<CustodyBalances> = Async(loading = true),
    val deposit: DepositUiState = DepositUiState(),
    val withdraw: WithdrawUiState = WithdrawUiState(),
) {
    val rows: List<CustodyBalance> get() = balances.data?.rows.orEmpty()
    val fundedRows: List<CustodyBalance> get() = balances.data?.funded().orEmpty()
    fun rowFor(key: String?): CustodyBalance? = rows.firstOrNull { it.key == key }
}

@HiltViewModel
class CustodyViewModel @Inject constructor(
    private val repo: CustodyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CustodyUiState())
    val uiState: StateFlow<CustodyUiState> = _uiState.asStateFlow()

    init {
        loadBalance()
        loadDeposits()
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

    /** Clears the withdraw result/form after the user acknowledges the outcome. */
    fun clearWithdrawResult() {
        _uiState.update {
            it.copy(withdraw = it.withdraw.copy(result = null, amount = "", destination = "", tokenOverride = "", submitError = null))
        }
    }
}

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
