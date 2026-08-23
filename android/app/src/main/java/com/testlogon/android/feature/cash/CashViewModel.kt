package com.testlogon.android.feature.cash

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cash.CashPaymentMethod
import com.testlogon.android.data.cash.CashRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** UI state for the FIAT (USD) Cash screen. */
data class CashUiState(
    val loading: Boolean = true,
    val walletUnavailable: Boolean = false,
    val balanceCents: Long = 0L,
    val currency: String = "USD",
    val paymentMethods: List<CashPaymentMethod> = emptyList(),
    val selectedPaymentMethodId: String? = null,
    val depositText: String = "",
    val withdrawText: String = "",
    val submitting: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
) {
    val hasPaymentMethod: Boolean get() = paymentMethods.isNotEmpty()

    /** Deposit requires a valid >=$1 amount AND a chosen payment method (funds the charge). */
    val canDeposit: Boolean
        get() = !submitting && CashMath.isDepositValid(depositText) && selectedPaymentMethodId != null

    /** Withdraw requires a valid amount in [$1, balance]. Only meaningful when the wallet is available. */
    val canWithdraw: Boolean
        get() = !submitting && !walletUnavailable && CashMath.isWithdrawValid(withdrawText, balanceCents)
}

/**
 * Drives the FIAT (USD) Cash screen against the SAME real /ui/billing/wallet endpoints the web app uses.
 * Balance + payment-methods reads DEGRADE on 404 to an honest empty/unavailable state; deposit/withdraw
 * are money mutations gated behind a confirm dialog in the UI (the VM exposes confirmDeposit /
 * confirmWithdraw, called only after the user accepts). A rejection surfaces as a clear error, never a
 * silent success. Balance is refreshed after every mutation.
 */
@HiltViewModel
class CashViewModel @Inject constructor(
    private val repository: CashRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CashUiState())
    val uiState: StateFlow<CashUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.update { it.copy(loading = true, errorMessage = null) }
        viewModelScope.launch {
            when (val w = repository.wallet()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        loading = false,
                        walletUnavailable = !w.data.available,
                        balanceCents = w.data.balanceCents,
                        currency = w.data.currency,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(loading = false, errorMessage = w.error.message.ifBlank { "Couldn't load your cash balance." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, errorMessage = "No connection. Pull to retry.")
                }
            }
            when (val pm = repository.paymentMethods()) {
                is ApiResult.Success -> _uiState.update { s ->
                    val selected = s.selectedPaymentMethodId
                        ?: pm.data.firstOrNull { it.isDefault }?.id
                        ?: pm.data.firstOrNull()?.id
                    s.copy(paymentMethods = pm.data, selectedPaymentMethodId = selected)
                }
                else -> Unit // payment methods are optional; a failure just leaves the picker empty.
            }
        }
    }

    fun onDepositText(v: String) =
        _uiState.update { it.copy(depositText = CashMath.sanitizeAmountInput(v), errorMessage = null, successMessage = null) }

    fun onWithdrawText(v: String) =
        _uiState.update { it.copy(withdrawText = CashMath.sanitizeAmountInput(v), errorMessage = null, successMessage = null) }

    fun onSelectPaymentMethod(id: String) = _uiState.update { it.copy(selectedPaymentMethodId = id) }

    fun onWithdrawMax() = _uiState.update { it.copy(withdrawText = CashMath.formatCents(it.balanceCents), errorMessage = null) }

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null, successMessage = null) }

    /** Called AFTER the deposit confirm is accepted. */
    fun confirmDeposit() {
        val s = _uiState.value
        val cents = CashMath.parseDollarsToCents(s.depositText)
        val pmId = s.selectedPaymentMethodId
        if (cents == null || cents < CashMath.MIN_CENTS || pmId == null) {
            _uiState.update { it.copy(errorMessage = "Enter at least ${CashMath.formatCentsUsd(CashMath.MIN_CENTS)} and pick a payment method.") }
            return
        }
        _uiState.update { it.copy(submitting = true, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = repository.deposit(cents, pmId)) {
                is ApiResult.Success -> {
                    if (r.data.ok) {
                        _uiState.update {
                            it.copy(submitting = false, depositText = "", successMessage = "Deposited ${CashMath.formatCentsUsd(cents)} to your cash balance.")
                        }
                        refresh()
                    } else {
                        _uiState.update {
                            it.copy(submitting = false, errorMessage = r.data.reason?.ifBlank { null } ?: "Deposit was declined.")
                        }
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, errorMessage = r.error.message.ifBlank { "Deposit isn't available right now. No funds were moved." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, errorMessage = "No connection. No funds were moved.")
                }
            }
        }
    }

    /** Called AFTER the withdraw confirm is accepted. */
    fun confirmWithdraw() {
        val s = _uiState.value
        val cents = CashMath.parseDollarsToCents(s.withdrawText)
        if (cents == null || !CashMath.isWithdrawValid(s.withdrawText, s.balanceCents)) {
            _uiState.update { it.copy(errorMessage = "Enter an amount between ${CashMath.formatCentsUsd(CashMath.MIN_CENTS)} and ${CashMath.formatCentsUsd(it.balanceCents)}.") }
            return
        }
        _uiState.update { it.copy(submitting = true, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = repository.withdraw(cents)) {
                is ApiResult.Success -> {
                    if (r.data.ok) {
                        _uiState.update {
                            it.copy(submitting = false, withdrawText = "", successMessage = "Withdrew ${CashMath.formatCentsUsd(cents)} from your cash balance.")
                        }
                        refresh()
                    } else {
                        _uiState.update {
                            it.copy(submitting = false, errorMessage = r.data.reason?.ifBlank { null } ?: "Withdrawal was declined.")
                        }
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, errorMessage = r.error.message.ifBlank { "Withdrawal isn't available right now. No funds were moved." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, errorMessage = "No connection. No funds were moved.")
                }
            }
        }
    }
}
