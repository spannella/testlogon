package com.testlogon.android.feature.billing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.billing.AddBankReqDto
import com.testlogon.android.data.billing.AddCardReqDto
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.feature.billing.error.BillingError
import com.testlogon.android.feature.billing.error.BillingErrorMapper
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

/** Which add-payment-method tab the user is on (mirrors the web client's Card / Bank choice). */
enum class AddMethodTab { CARD, BANK }

/**
 * Manual add-payment-method form state. Mirrors the WEB client's dev-friendly entry: the user TYPES a
 * fake test card (number/exp/cvc) OR a fake US bank checking/savings account (routing + account
 * number) and submits directly to the BK-C backend endpoints (no Stripe.js / on-device tokenization).
 *
 * Per-field error strings are populated by client-side validation on submit; [formError] holds a
 * mapped backend [BillingError] message; [isSubmitting] guards a duplicate submit.
 */
data class AddCardUiState(
    val tab: AddMethodTab = AddMethodTab.CARD,
    // Card fields
    val cardNumber: String = "",
    val expMonth: String = "",
    val expYear: String = "",
    val cvc: String = "",
    val cardholderName: String = "",
    val cardNumberError: UiText? = null,
    val expMonthError: UiText? = null,
    val expYearError: UiText? = null,
    val cvcError: UiText? = null,
    // Bank fields
    val routingNumber: String = "",
    val accountNumber: String = "",
    val accountType: String = "checking",
    val accountHolderName: String = "",
    val routingNumberError: UiText? = null,
    val accountNumberError: UiText? = null,
    // Shared
    val isSubmitting: Boolean = false,
    val formError: UiText? = null,
)

/** One-shot effects from the add-payment-method flow. */
sealed interface AddCardEvent {
    /** A card or bank method was saved; triggers a list refresh on the caller (pop back). */
    data object Saved : AddCardEvent

    data class Failure(val message: UiText) : AddCardEvent
}

/**
 * Manual add-payment-method presentation logic, wired to the BK-C dev/test backend endpoints via
 * [BillingRepository.addCard] / [BillingRepository.addBank] — mirroring the web client's manual entry
 * so a fake test card (e.g. 4242 4242 4242 4242) or fake bank account is easy to add for testing.
 *
 * NOTE: this is the dev/test path. In real production the bank endpoint 400s (use the hosted bank
 * flow) — that surfaces as a normal form error. Card entry works in both modes.
 */
@HiltViewModel
class AddCardViewModel @Inject constructor(
    private val repository: BillingRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow(AddCardUiState())
    val uiState: StateFlow<AddCardUiState> = _state.asStateFlow()

    private val _events = Channel<AddCardEvent>(Channel.BUFFERED)
    val events: Flow<AddCardEvent> = _events.receiveAsFlow()

    fun selectTab(tab: AddMethodTab) = _state.update { it.copy(tab = tab, formError = null) }

    fun onCardNumberChange(v: String) =
        _state.update { it.copy(cardNumber = v.filter(Char::isDigit).take(19), cardNumberError = null, formError = null) }

    fun onExpMonthChange(v: String) =
        _state.update { it.copy(expMonth = v.filter(Char::isDigit).take(2), expMonthError = null, formError = null) }

    fun onExpYearChange(v: String) =
        _state.update { it.copy(expYear = v.filter(Char::isDigit).take(4), expYearError = null, formError = null) }

    fun onCvcChange(v: String) =
        _state.update { it.copy(cvc = v.filter(Char::isDigit).take(4), cvcError = null, formError = null) }

    fun onCardholderNameChange(v: String) = _state.update { it.copy(cardholderName = v.take(200)) }

    fun onRoutingNumberChange(v: String) =
        _state.update { it.copy(routingNumber = v.filter(Char::isDigit).take(9), routingNumberError = null, formError = null) }

    fun onAccountNumberChange(v: String) =
        _state.update { it.copy(accountNumber = v.filter(Char::isDigit).take(17), accountNumberError = null, formError = null) }

    fun onAccountTypeChange(v: String) = _state.update { it.copy(accountType = v) }

    fun onAccountHolderNameChange(v: String) = _state.update { it.copy(accountHolderName = v.take(200)) }

    /** Validates + submits the currently-selected tab's form. */
    fun submit() {
        if (_state.value.isSubmitting) return
        when (_state.value.tab) {
            AddMethodTab.CARD -> submitCard()
            AddMethodTab.BANK -> submitBank()
        }
    }

    private fun submitCard() {
        val s = _state.value
        val numberErr = if (s.cardNumber.length < 12) errCardNumber else null
        val month = s.expMonth.toIntOrNull()
        val monthErr = if (month == null || month !in 1..12) errExpMonth else null
        val year = s.expYear.toIntOrNull()
        val yearErr = if (year == null || year !in 2000..2100) errExpYear else null
        val cvcErr = if (s.cvc.length < 3) errCvc else null
        if (numberErr != null || monthErr != null || yearErr != null || cvcErr != null) {
            _state.update {
                it.copy(
                    cardNumberError = numberErr,
                    expMonthError = monthErr,
                    expYearError = yearErr,
                    cvcError = cvcErr,
                )
            }
            return
        }
        val req = AddCardReqDto(
            cardNumber = s.cardNumber,
            expMonth = month!!,
            expYear = year!!,
            cvc = s.cvc,
            cardholderName = s.cardholderName.trim().ifBlank { null },
        )
        runSubmit { repository.addCard(req) }
    }

    private fun submitBank() {
        val s = _state.value
        val routingErr = if (s.routingNumber.length != 9) errRouting else null
        val accountErr = if (s.accountNumber.length < 4) errAccount else null
        if (routingErr != null || accountErr != null) {
            _state.update { it.copy(routingNumberError = routingErr, accountNumberError = accountErr) }
            return
        }
        val req = AddBankReqDto(
            routingNumber = s.routingNumber,
            accountNumber = s.accountNumber,
            accountType = s.accountType,
            accountHolderName = s.accountHolderName.trim().ifBlank { null },
        )
        runSubmit { repository.addBank(req) }
    }

    private fun runSubmit(block: suspend () -> ApiResult<*>) {
        _state.update { it.copy(isSubmitting = true, formError = null) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _state.update { it.copy(isSubmitting = false) }
                    _events.send(AddCardEvent.Saved)
                }
                else -> {
                    val err: BillingError = errorMapper.map(r)
                    _state.update { it.copy(isSubmitting = false, formError = err.message) }
                    _events.send(AddCardEvent.Failure(err.message))
                }
            }
        }
    }

    private companion object {
        val errCardNumber = UiText.Res(com.testlogon.android.R.string.add_card_err_number)
        val errExpMonth = UiText.Res(com.testlogon.android.R.string.add_card_err_exp_month)
        val errExpYear = UiText.Res(com.testlogon.android.R.string.add_card_err_exp_year)
        val errCvc = UiText.Res(com.testlogon.android.R.string.add_card_err_cvc)
        val errRouting = UiText.Res(com.testlogon.android.R.string.add_card_err_routing)
        val errAccount = UiText.Res(com.testlogon.android.R.string.add_card_err_account)
    }
}
