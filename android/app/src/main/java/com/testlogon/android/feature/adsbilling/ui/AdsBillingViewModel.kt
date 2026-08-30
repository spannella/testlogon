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
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyReader
import com.testlogon.android.data.fees.FeeQuote
import com.testlogon.android.data.fees.FeesRepository
import com.testlogon.android.feature.checkout.CheckoutCryptoMath
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlin.math.roundToLong
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
    private val feesRepository: FeesRepository,
    private val custodyReader: CustodyReader,
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

    /** FE-160 - the "Fund with crypto balance" sub-state (asset picker + rate-locked quote + countdown). */
    private val _crypto = MutableStateFlow(CryptoFundUiState())
    val crypto: StateFlow<CryptoFundUiState> = _crypto.asStateFlow()

    /** FE-160 - true when the user has switched the deposit sheet to the crypto-funding tab. */
    private val _cryptoFundingMode = MutableStateFlow(false)
    val cryptoFundingMode: StateFlow<Boolean> = _cryptoFundingMode.asStateFlow()

    /** Drives the 1s rate-lock countdown; cancelled on re-quote / clear / onCleared. */
    private var countdownJob: Job? = null

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
        _cryptoFundingMode.value = false
        _crypto.value = CryptoFundUiState()
        loadPaymentMethods()
        loadCryptoBalances()
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
        countdownJob?.cancel()
        _amountText.value = ""
        _depositState.value = DepositState.Idle
        _depositSheetVisible.value = false
        _cryptoFundingMode.value = false
        _crypto.value = CryptoFundUiState()
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

    // ---- FE-160: fund with crypto balance ----

    /** Switches the deposit sheet between the card/wallet path and the crypto-funding path. */
    fun setCryptoFundingMode(enabled: Boolean) {
        if (enabled == _cryptoFundingMode.value) return
        _cryptoFundingMode.value = enabled
        if (!enabled) {
            countdownJob?.cancel()
            _crypto.update {
                it.copy(selectedSymbol = null, quote = null, error = null, insufficient = false, secondsRemaining = 0L)
            }
        } else {
            _crypto.value.selectedSymbol?.let { requestQuote(it) }
        }
    }

    /** Applies a preset top-up (integer cents) into the amount field (validated by [AdDepositMath]). */
    fun onPresetSelected(cents: Long) {
        onAmountChanged(AdDepositMath.formatCents(cents))
        if (_cryptoFundingMode.value) _crypto.value.selectedSymbol?.let { requestQuote(it) }
    }

    /** Loads the fundable custody balances (known assets with a positive balance) for the picker. */
    private fun loadCryptoBalances() {
        viewModelScope.launch {
            val balances = (custodyReader.getBalance() as? ApiResult.Success)?.data ?: return@launch
            val options = balances.rows
                .filter { it.known && it.amount > 0.0 }
                .mapNotNull { row ->
                    val asset = CustodyAssets.findAsset(row.symbol) ?: return@mapNotNull null
                    AdCryptoAssetOption(
                        symbol = asset.symbol,
                        name = asset.name,
                        decimals = asset.decimals,
                        balanceWhole = row.amount,
                        balanceBaseUnits = wholeToBaseUnits(row.amount, asset.decimals),
                    )
                }
            _crypto.update { it.copy(assets = options) }
        }
    }

    /** The user picked a coin: reset the prior quote and request a fresh rate-locked quote. */
    fun onCryptoAssetSelected(symbol: String) {
        if (symbol == _crypto.value.selectedSymbol && _crypto.value.quote != null) return
        _crypto.update { it.copy(selectedSymbol = symbol, quote = null, error = null, insufficient = false) }
        requestQuote(symbol)
    }

    /**
     * Requests a rate-locked fee quote for the CURRENT top-up amount + [symbol]. Ignored when the amount
     * is not yet a valid top-up. A 404 -> Success(null) flips the crypto path off (degrade-on-404).
     */
    private fun requestQuote(symbol: String) {
        countdownJob?.cancel()
        val cents = parsedAmountCents()
        if (cents == null || !AdDepositMath.isValidTopUpCents(cents)) {
            _crypto.update { it.copy(quoting = false, quote = null, secondsRemaining = 0L) }
            return
        }
        _crypto.update { it.copy(quoting = true, error = null) }
        viewModelScope.launch {
            when (val r = feesRepository.quoteFee(amountCents = cents, payWith = symbol)) {
                is ApiResult.Success -> {
                    val q = r.data
                    if (q == null) {
                        _crypto.update { it.copy(quoting = false, enabled = false, quote = null) }
                    } else {
                        applyQuote(symbol, q)
                    }
                }
                is ApiResult.Failure ->
                    _crypto.update { it.copy(quoting = false, quote = null, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _crypto.update { it.copy(quoting = false, quote = null, error = OFFLINE_FALLBACK) }
            }
        }
    }

    private fun applyQuote(symbol: String, quote: FeeQuote) {
        val bal = _crypto.value.assets.firstOrNull { it.symbol == symbol }?.balanceBaseUnits ?: 0L
        val insufficient = CheckoutCryptoMath.insufficientForQuote(bal, quote.totalNative)
        _crypto.update {
            it.copy(
                quoting = false,
                enabled = true,
                quote = quote,
                insufficient = insufficient,
                secondsRemaining = CheckoutCryptoMath.quoteExpirySeconds(quote.expiresAt, nowMs()),
                error = null,
            )
        }
        startCountdown(symbol, quote)
    }

    private fun startCountdown(symbol: String, quote: FeeQuote) {
        countdownJob?.cancel()
        countdownJob = viewModelScope.launch {
            while (isActive) {
                val remaining = CheckoutCryptoMath.quoteExpirySeconds(quote.expiresAt, nowMs())
                _crypto.update { it.copy(secondsRemaining = remaining) }
                if (remaining <= 0L) {
                    requestQuote(symbol)
                    return@launch
                }
                delay(1000L)
            }
        }
    }

    /**
     * Funds the ad account from the selected crypto balance at the LOCKED rate. Ignored unless a live,
     * affordable quote is ready. On success: reflect the new balance + refresh the ledger (same as the
     * card path). A 409 quote_expired re-quotes; other failures surface a friendly deposit error.
     */
    fun fundWithCrypto() {
        if (_depositState.value is DepositState.Submitting) return
        val cState = _crypto.value
        val quote = cState.quote ?: return
        if (!cState.canFund) return
        val cents = parsedAmountCents() ?: return
        _depositState.value = DepositState.Submitting
        viewModelScope.launch {
            when (
                val r = repository.deposit(
                    accountId = accountId,
                    amountCents = cents,
                    paymentMethodId = null,
                    payWith = quote.payWith,
                    quoteToken = quote.quoteToken,
                )
            ) {
                is ApiResult.Success -> {
                    applyNewBalance(r.data.newBalanceCents)
                    refreshLedger()
                    countdownJob?.cancel()
                    _amountText.value = ""
                    _crypto.update { it.copy(quote = null, secondsRemaining = 0L) }
                    _depositState.value = DepositState.Success(r.data.newBalanceCents)
                }
                is ApiResult.Failure -> {
                    if (r.error.status == 409 || r.error.code == "quote_expired") {
                        _depositState.value = DepositState.Idle
                        requestQuote(quote.payWith)
                    } else {
                        _depositState.value = DepositState.Error(friendlyDepositError(r.error))
                    }
                }
                is ApiResult.NetworkError ->
                    _depositState.value = DepositState.Error(OFFLINE_FALLBACK)
            }
        }
    }

    override fun onCleared() {
        countdownJob?.cancel()
        super.onCleared()
    }

    private fun nowMs(): Long = System.currentTimeMillis()

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
        /** whole-coin Double -> integer native base units (half-up, clamped >= 0). Mirrors FE-152. */
        internal fun wholeToBaseUnits(whole: Double, decimals: Int): Long {
            if (whole <= 0.0) return 0L
            var scale = 1.0
            repeat(if (decimals < 0) 0 else decimals) { scale *= 10.0 }
            val v = (whole * scale).roundToLong()
            return if (v < 0L) 0L else v
        }

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
