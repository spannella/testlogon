package com.testlogon.android.feature.adsbilling.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.PaymentMethod
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.navigation.AdsBillingDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.YearMonth
import java.time.format.DateTimeFormatter
import javax.inject.Inject

/**
 * AND-367 - presentation logic for the ads-account BILLING surface (the first MUTATING ads feature).
 *
 * accountId arrives as a nav arg via [SavedStateHandle] (survives process death). [load] reads the account
 * summary + the billing ledger + the current-month invoice; an invoice failure is TOLERATED (-> null, NOT an
 * Error) and a refresh failure when content already exists keeps the content + flags it stale (in-memory
 * only - NO Room cache this wave; persistent staleness is DEFERRED).
 *
 * DEPOSIT (add funds): a SEPARATE [DepositState] so a deposit in flight / success / error NEVER clobbers the
 * read state. The amount is entered in USD and parsed to integer cents (valid = 5000..10000000). [deposit]
 * is NON-idempotent: while [DepositState.Submitting] a second call is IGNORED (in-flight / debounce duplicate
 * guard, NO double-submit) and there is NO auto-retry. On success the displayed balance is updated from the
 * server's new_balance_cents and the ledger is refreshed. A 400 "Minimum deposit" maps to a friendly message.
 */
@HiltViewModel
class AdsBillingViewModel @Inject constructor(
    private val repository: AdsBillingRepository,
    private val billingRepository: BillingRepository,
    private val errorParser: ApiErrorParser,
    savedState: SavedStateHandle,
) : ViewModel() {

    var accountId: String =
        checkNotNull(savedState[ARG_ACCOUNT_ID]) { "missing $ARG_ACCOUNT_ID nav arg" }
        private set

    private val _uiState = MutableStateFlow<AdsBillingUiState>(AdsBillingUiState.Loading)
    val uiState: StateFlow<AdsBillingUiState> = _uiState.asStateFlow()

    private val _depositState = MutableStateFlow<DepositState>(DepositState.Idle)
    val depositState: StateFlow<DepositState> = _depositState.asStateFlow()

    /** Whether the deposit (add-funds) sheet is currently shown. */
    private val _depositSheetVisible = MutableStateFlow(false)
    val depositSheetVisible: StateFlow<Boolean> = _depositSheetVisible.asStateFlow()

    /** Raw USD amount text the user typed in the deposit sheet. */
    private val _amountText = MutableStateFlow("")
    val amountText: StateFlow<String> = _amountText.asStateFlow()

    /** ADV-306 - the caller saved payment methods for the deposit card picker (empty -> wallet fallback). */
    private val _paymentMethods = MutableStateFlow<List<PaymentMethod>>(emptyList())
    val paymentMethods: StateFlow<List<PaymentMethod>> = _paymentMethods.asStateFlow()

    /** ADV-306 - the card selected to fund the deposit (null until methods load / when the wallet is empty). */
    private val _selectedPaymentMethodId = MutableStateFlow<String?>(null)
    val selectedPaymentMethodId: StateFlow<String?> = _selectedPaymentMethodId.asStateFlow()

    init {
        load()
    }

    /**
     * First load / retry: reads the account summary + ledger; the current-month invoice is best-effort
     * (failure -> null). A refresh failure that has prior content keeps the content + marks it stale; a first
     * load with no content surfaces an Error.
     */
    fun load() {
        val hadContent = _uiState.value as? AdsBillingUiState.Content
        if (hadContent == null) {
            _uiState.value = AdsBillingUiState.Loading
        }
        viewModelScope.launch {
            // The More-hub stub opens a placeholder sample id; resolve it to the caller's first real
            // ad account so the entry shows real balance/ledger/deposit instead of "Account not found".
            if (accountId == AdsBillingDest.SAMPLE_ACCOUNT_ID) {
                (repository.listAccounts() as? ApiResult.Success)?.data
                    ?.firstOrNull()?.accountId?.let { accountId = it }
            }
            when (val accountResult = repository.getAccount(accountId)) {
                is ApiResult.Success -> {
                    val ledger = (repository.getBillingHistory(accountId) as? ApiResult.Success)?.data
                    if (ledger == null) {
                        // The ledger read failed: keep stale content if any, else surface a generic error.
                        keepStaleOrError(hadContent, genericError())
                        return@launch
                    }
                    val invoice = (repository.getInvoice(accountId, currentMonth()) as? ApiResult.Success)?.data
                    _uiState.value = AdsBillingUiState.Content(
                        account = accountResult.data,
                        ledger = ledger,
                        invoice = invoice,
                        isStale = false,
                    )
                }
                is ApiResult.Failure -> keepStaleOrError(hadContent, accountResult.error)
                is ApiResult.NetworkError ->
                    keepStaleOrError(
                        hadContent,
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    fun onRetry() = load()

    // ---- Deposit (add funds) ----

    /** Updates the deposit amount text (USD). Clears a prior deposit error so the sheet is re-armable. */
    fun onAmountChanged(text: String) {
        _amountText.value = text
        if (_depositState.value is DepositState.Error) _depositState.value = DepositState.Idle
    }

    /** Opens the deposit sheet from Idle: resets the amount + clears any prior outcome. */
    fun openDeposit() {
        _amountText.value = ""
        _depositState.value = DepositState.Idle
        _depositSheetVisible.value = true
        loadPaymentMethods()
    }

    /** ADV-306 - the user picked a card in the deposit sheet. */
    fun onPaymentMethodSelected(id: String) {
        _selectedPaymentMethodId.value = id
    }

    /**
     * ADV-306 - loads the caller saved payment methods when the deposit sheet opens so the deposit charges a
     * CARD (payment_method_id) instead of the wallet fallback. Pre-selects via the PM chain (keep the current
     * pick when still valid -> the wallet default -> the first saved method). A read failure is non-fatal:
     * the picker stays empty and the deposit falls back to the wallet (server-authoritative).
     */
    private fun loadPaymentMethods() {
        viewModelScope.launch {
            val r = billingRepository.getPaymentMethods()
            if (r is ApiResult.Success) {
                _paymentMethods.value = r.data
                val current = _selectedPaymentMethodId.value
                if (current == null || r.data.none { it.id == current }) {
                    _selectedPaymentMethodId.value =
                        r.data.firstOrNull { it.isDefault }?.id ?: r.data.firstOrNull()?.id
                }
            }
        }
    }

    /**
     * ADV-306 - resolves the payment_method_id to charge: the explicit pick when still valid -> the wallet
     * default (is_default) -> the first saved method -> null (no saved card -> server wallet fallback).
     */
    private fun resolvePaymentMethodId(): String? {
        val methods = _paymentMethods.value
        val selected = _selectedPaymentMethodId.value
        if (selected != null && methods.any { it.id == selected }) return selected
        return methods.firstOrNull { it.isDefault }?.id ?: methods.firstOrNull()?.id
    }

    /** Dismisses the deposit sheet (only when not submitting) -> Idle. */
    fun dismissDeposit() {
        if (_depositState.value is DepositState.Submitting) return
        _amountText.value = ""
        _depositState.value = DepositState.Idle
        _depositSheetVisible.value = false
    }

    /** True only when the current amount text parses to a valid in-range cents amount (5000..10000000). */
    val canSubmitDeposit: Boolean
        get() = parsedAmountCents()?.let { it in MIN_DEPOSIT_CENTS..MAX_DEPOSIT_CENTS } == true

    /**
     * Submits the deposit. Ignored when the amount is invalid / out of range OR a deposit is already in
     * flight (NO double-submit). On success: [DepositState.Success] + the displayed balance is updated from
     * new_balance_cents + the ledger is refreshed. On a 400 "Minimum deposit" / other failure:
     * [DepositState.Error] with a friendly message (the read state stays intact). NON-idempotent -> NO retry.
     */
    fun deposit() {
        if (_depositState.value is DepositState.Submitting) return
        val cents = parsedAmountCents() ?: return
        if (cents !in MIN_DEPOSIT_CENTS..MAX_DEPOSIT_CENTS) return
        val paymentMethodId = resolvePaymentMethodId()

        _depositState.value = DepositState.Submitting
        viewModelScope.launch {
            when (val result = repository.deposit(accountId, cents, paymentMethodId)) {
                is ApiResult.Success -> {
                    applyNewBalance(result.data.newBalanceCents)
                    refreshLedger()
                    // ADV3-3 (B8): clear the amount on success so the Confirm button (guarded by
                    // canSubmitDeposit, which requires a valid in-range amount) can no longer re-fire the
                    // SAME deposit from the still-open sheet. The sheet now shows the success + a Done action.
                    _amountText.value = ""
                    _depositState.value = DepositState.Success(result.data.newBalanceCents)
                }
                is ApiResult.Failure ->
                    _depositState.value = DepositState.Error(friendlyDepositError(result.error))
                is ApiResult.NetworkError ->
                    _depositState.value = DepositState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    // ---- internals ----

    /** Keeps prior content (flagged stale) on a refresh failure, else surfaces a fatal [Error]. */
    private fun keepStaleOrError(prior: AdsBillingUiState.Content?, error: ApiError) {
        _uiState.value = prior?.copy(isStale = true) ?: AdsBillingUiState.Error(error)
    }

    /** Updates the displayed balance in-place from a successful deposit's new_balance_cents (when present). */
    private fun applyNewBalance(newBalanceCents: Long?) {
        if (newBalanceCents == null) return
        val content = _uiState.value as? AdsBillingUiState.Content ?: return
        _uiState.value = content.copy(
            account = content.account.copyBalance(newBalanceCents),
        )
    }

    /** Re-reads the ledger after a deposit; a failure leaves the existing ledger untouched. */
    private suspend fun refreshLedger() {
        val content = _uiState.value as? AdsBillingUiState.Content ?: return
        val ledger = (repository.getBillingHistory(accountId) as? ApiResult.Success)?.data ?: return
        val latest = _uiState.value as? AdsBillingUiState.Content ?: return
        _uiState.value = latest.copy(ledger = ledger)
    }

    private fun parsedAmountCents(): Long? = parseUsdToCents(_amountText.value)

    /** Maps a deposit failure to a friendly message (a 400 referencing the minimum gets a tailored line). */
    private fun friendlyDepositError(error: ApiError): String {
        if (error.status == HTTP_BAD_REQUEST) {
            val detail = errorParser.parseDetail(error.raw as? String)
            val text = (detail as? String ?: error.message).lowercase()
            if (text.contains("minimum") || text.contains("min ")) return MIN_DEPOSIT_MESSAGE
        }
        return error.message
    }

    companion object {
        /** Nav arg carrying the ad account id. */
        const val ARG_ACCOUNT_ID = "accountId"

        /** Deposit bounds (integer cents): $50 min .. $100k max (server-authoritative; mirrored client-side). */
        const val MIN_DEPOSIT_CENTS = 5_000L
        const val MAX_DEPOSIT_CENTS = 10_000_000L

        private const val HTTP_BAD_REQUEST = 400
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
        private const val GENERIC_ERROR = "Couldn't load billing. Try again."
        private const val MIN_DEPOSIT_MESSAGE = "The minimum deposit is \$50.00."

        /** A generic fatal-load [ApiError] used when the ledger read fails with no prior content. */
        private fun genericError(): ApiError =
            ApiError(status = ApiError.STATUS_PARSE, message = GENERIC_ERROR)

        /** The current-month invoice period label, assumed "YYYY-MM" (the wire format is UNVERIFIED). */
        internal fun currentMonth(): String =
            YearMonth.now().format(DateTimeFormatter.ofPattern("yyyy-MM"))

        /**
         * Parses a USD entry ("50", "50.00", "$50.00", "1,000.00") into integer cents, or null when
         * unparseable / negative. Caps at two decimal places. Mirrors the AND-364 / AND-366 helpers.
         */
        internal fun parseUsdToCents(text: String): Long? {
            val cleaned = text.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return null
            val dollars = cleaned.toBigDecimalOrNull() ?: return null
            if (dollars.signum() < 0) return null
            return dollars.movePointRight(2).toLong()
        }
    }
}

/** AND-367 - returns a copy of the summary with only [balanceCents] changed (deposit balance update). */
private fun AdAccountSummary.copyBalance(balanceCents: Long): AdAccountSummary =
    copy(balanceCents = balanceCents)
