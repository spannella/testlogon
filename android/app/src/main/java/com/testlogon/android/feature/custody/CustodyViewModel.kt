package com.testlogon.android.feature.custody

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyAsset
import com.testlogon.android.data.custody.CustodyAudit
import com.testlogon.android.data.custody.CustodyDeposit
import com.testlogon.android.data.custody.CustodyDepositAddress
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.custody.CustodyWithdrawal
import com.testlogon.android.data.custody.CustodyWithdrawalResult
import com.testlogon.android.data.custody.WithdrawalStatus
import com.testlogon.android.data.feed.CurrentUserRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** The five in-screen custody tabs. Approvals is only present for an officer/admin caller. */
enum class CustodyTab { BALANCES, DEPOSIT, WITHDRAW, ACTIVITY, APPROVALS }

/** A generic async slice: loading / error(message) / data. */
data class Async<out T>(
    val loading: Boolean = false,
    val error: String? = null,
    val data: T? = null,
)

/** Deposit-tab state: the selected asset + resolved address + recent deposits. */
data class DepositUiState(
    val selectedKey: String? = null,
    val address: Async<CustodyDepositAddress> = Async(),
    val deposits: Async<List<CustodyDeposit>> = Async(),
)

/** Withdraw form + submit result. */
data class WithdrawUiState(
    val selectedKey: String? = null,
    val amount: String = "",
    val destination: String = "",
    val memo: String = "",
    val submitting: Boolean = false,
    val result: CustodyWithdrawalResult? = null,
    val submitError: String? = null,
)

/** Officer approvals queue + audit trail. */
data class ApprovalsUiState(
    val isOfficer: Boolean = false,
    val checkedOfficer: Boolean = false,
    val queue: Async<List<CustodyWithdrawal>> = Async(),
    val audit: Async<CustodyAudit> = Async(),
    /** Per-withdrawal action feedback keyed by id (approve/release outcome). */
    val actionMessages: Map<String, String> = emptyMap(),
    val actioning: Set<String> = emptySet(),
)

data class CustodyUiState(
    val tab: CustodyTab = CustodyTab.BALANCES,
    val assets: Async<List<CustodyAsset>> = Async(loading = true),
    val deposit: DepositUiState = DepositUiState(),
    val withdraw: WithdrawUiState = WithdrawUiState(),
    val activity: Async<List<CustodyWithdrawal>> = Async(),
    val approvals: ApprovalsUiState = ApprovalsUiState(),
) {
    val fundedAssets: List<CustodyAsset> get() = assets.data.orEmpty().filter { it.balance > 0.0 }
    fun assetFor(key: String?): CustodyAsset? = assets.data.orEmpty().firstOrNull { it.key == key }
}

@HiltViewModel
class CustodyViewModel @Inject constructor(
    private val repo: CustodyRepository,
    private val currentUser: CurrentUserRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CustodyUiState())
    val uiState: StateFlow<CustodyUiState> = _uiState.asStateFlow()

    init {
        loadAssets()
        checkOfficer()
    }

    // ---- tab + selection ----

    fun onTabSelected(tab: CustodyTab) {
        _uiState.update { it.copy(tab = tab) }
        when (tab) {
            CustodyTab.ACTIVITY -> if (_uiState.value.activity.data == null) loadActivity()
            CustodyTab.APPROVALS -> {
                loadApprovals()
                loadAudit()
            }
            else -> Unit
        }
    }

    fun loadAssets() {
        _uiState.update { it.copy(assets = it.assets.copy(loading = true, error = null)) }
        viewModelScope.launch {
            _uiState.update { st ->
                st.copy(assets = repo.loadAssets().toAsync())
            }
        }
    }

    // ---- deposit ----

    fun onDepositAssetSelected(key: String) {
        _uiState.update { it.copy(deposit = it.deposit.copy(selectedKey = key, address = Async(loading = true))) }
        val asset = _uiState.value.assetFor(key) ?: return
        viewModelScope.launch {
            val res = repo.depositAddress(asset.asset, asset.chain)
            _uiState.update { it.copy(deposit = it.deposit.copy(address = res.toAsync())) }
        }
        loadDeposits()
    }

    fun loadDeposits() {
        _uiState.update { it.copy(deposit = it.deposit.copy(deposits = it.deposit.deposits.copy(loading = true))) }
        viewModelScope.launch {
            _uiState.update { it.copy(deposit = it.deposit.copy(deposits = repo.loadDeposits().toAsync())) }
        }
    }

    // ---- withdraw ----

    fun onWithdrawAssetSelected(key: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(selectedKey = key, submitError = null, result = null)) }
    }

    fun onAmountChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(amount = v, submitError = null)) }
    }

    fun onDestinationChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(destination = v, submitError = null)) }
    }

    fun onMemoChanged(v: String) {
        _uiState.update { it.copy(withdraw = it.withdraw.copy(memo = v)) }
    }

    fun onMax() {
        val w = _uiState.value.withdraw
        val asset = _uiState.value.assetFor(w.selectedKey) ?: return
        _uiState.update { it.copy(withdraw = it.withdraw.copy(amount = asset.balanceText.trim(), submitError = null)) }
    }

    /** Validates the current form; returns an error string, or null if OK to submit. */
    fun validateWithdraw(): String? {
        val w = _uiState.value.withdraw
        val asset = _uiState.value.assetFor(w.selectedKey) ?: return "Select an asset."
        val amt = w.amount.trim().toDoubleOrNull()
        if (amt == null || amt <= 0.0) return "Enter an amount greater than 0."
        if (amt > asset.balance) return "Amount exceeds your ${asset.symbol} balance."
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
        val asset = _uiState.value.assetFor(w.selectedKey) ?: return
        _uiState.update { it.copy(withdraw = it.withdraw.copy(submitting = true, submitError = null, result = null)) }
        viewModelScope.launch {
            when (val r = repo.submitWithdrawal(asset.asset, asset.chain, w.amount.trim(), w.destination.trim(), w.memo)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(withdraw = it.withdraw.copy(submitting = false, result = r.data))
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(withdraw = it.withdraw.copy(submitting = false, submitError = r.error.message))
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(withdraw = it.withdraw.copy(submitting = false, submitError = "Network error. Check your connection and try again."))
                }
            }
            // Refresh balances + activity so the new withdrawal shows and the balance reflects the debit.
            loadAssets()
            loadActivity()
        }
    }

    /** Clears the withdraw result/form after the user acknowledges the outcome. */
    fun clearWithdrawResult() {
        _uiState.update {
            it.copy(withdraw = it.withdraw.copy(result = null, amount = "", destination = "", memo = "", submitError = null))
        }
    }

    // ---- activity ----

    fun loadActivity() {
        _uiState.update { it.copy(activity = it.activity.copy(loading = it.activity.data == null, error = null)) }
        viewModelScope.launch {
            _uiState.update { it.copy(activity = repo.loadWithdrawals().toAsync()) }
        }
    }

    /**
     * One polling pass: silently re-fetch withdrawals so non-terminal rows advance. Driven from the
     * screen via a LaunchedEffect loop (NOT an unbounded loop in init), so it stops when the screen
     * leaves composition. No-ops (returns false) once every row is terminal, letting the screen stop.
     */
    suspend fun pollActivityOnce(): Boolean {
        val current = _uiState.value.activity.data.orEmpty()
        val hasNonTerminal = current.isEmpty() || current.any { !it.status.isTerminal }
        val res = repo.loadWithdrawals()
        if (res is ApiResult.Success) {
            _uiState.update { it.copy(activity = it.activity.copy(loading = false, error = null, data = res.data)) }
        }
        val after = (_uiState.value.activity.data).orEmpty()
        return hasNonTerminal && (after.isEmpty() || after.any { !it.status.isTerminal })
    }

    // ---- officer approvals + audit ----

    private fun checkOfficer() {
        viewModelScope.launch {
            val res = currentUser.isAdmin()
            val officer = (res as? ApiResult.Success)?.data ?: false
            _uiState.update { it.copy(approvals = it.approvals.copy(isOfficer = officer, checkedOfficer = true)) }
        }
    }

    fun loadApprovals() {
        _uiState.update { it.copy(approvals = it.approvals.copy(queue = it.approvals.queue.copy(loading = true, error = null))) }
        viewModelScope.launch {
            val res = repo.loadApprovals()
            // A 403 here means the caller is not actually an officer; reflect that + do not show an error.
            if (res is ApiResult.Failure && res.error.status == 403) {
                _uiState.update {
                    it.copy(approvals = it.approvals.copy(isOfficer = false, checkedOfficer = true, queue = Async(data = emptyList())))
                }
                return@launch
            }
            _uiState.update { it.copy(approvals = it.approvals.copy(queue = res.toAsync())) }
        }
    }

    fun loadAudit() {
        _uiState.update { it.copy(approvals = it.approvals.copy(audit = it.approvals.audit.copy(loading = true, error = null))) }
        viewModelScope.launch {
            _uiState.update { it.copy(approvals = it.approvals.copy(audit = repo.loadAudit().toAsync())) }
        }
    }

    fun verifyAudit() {
        viewModelScope.launch {
            when (val r = repo.verifyAudit()) {
                is ApiResult.Success -> _uiState.update { st ->
                    val existing = st.approvals.audit.data
                    val merged = existing?.copy(verifiedOk = r.data.ok, verifiedCount = r.data.entries)
                    st.copy(approvals = st.approvals.copy(audit = st.approvals.audit.copy(data = merged)))
                }
                else -> Unit
            }
        }
    }

    fun approve(id: String) {
        setActioning(id, true)
        viewModelScope.launch {
            val msg = when (val r = repo.approve(id, approver = null)) {
                is ApiResult.Success -> "Approved (${r.data.approvals.size} of ${r.data.approvalsRequired})"
                is ApiResult.Failure -> r.error.message
                is ApiResult.NetworkError -> "Network error."
            }
            postAction(id, msg)
            loadApprovals()
        }
    }

    fun release(id: String) {
        setActioning(id, true)
        viewModelScope.launch {
            val msg = when (val r = repo.release(id)) {
                is ApiResult.Success -> "Released — signed ✓"
                is ApiResult.Failure -> when (r.error.status) {
                    425 -> "Timelock not yet elapsed."
                    409 -> "Not enough approvals yet."
                    else -> r.error.message
                }
                is ApiResult.NetworkError -> "Network error."
            }
            postAction(id, msg)
            loadApprovals()
        }
    }

    private fun setActioning(id: String, on: Boolean) {
        _uiState.update {
            val s = it.approvals.actioning.toMutableSet()
            if (on) s.add(id) else s.remove(id)
            it.copy(approvals = it.approvals.copy(actioning = s))
        }
    }

    private fun postAction(id: String, message: String) {
        _uiState.update {
            val s = it.approvals.actioning.toMutableSet().apply { remove(id) }
            it.copy(approvals = it.approvals.copy(actioning = s, actionMessages = it.approvals.actionMessages + (id to message)))
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
