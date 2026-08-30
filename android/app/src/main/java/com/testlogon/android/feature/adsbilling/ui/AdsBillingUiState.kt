package com.testlogon.android.feature.adsbilling.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.data.fees.FeeQuote

/**
 * AND-367 - hoisted UI state for the ads-account billing screen (the READ view).
 *
 *  - [Loading] - the initial read is in flight.
 *  - [Content] - the summary + ledger + (best-effort) invoice. [isStale] marks cached data shown after a
 *    refresh failure.
 *  - [Error]   - a fatal load problem (the account / ledger read failed with no cache); retryable.
 *
 * The DEPOSIT (add-funds) flow lives in a SEPARATE [DepositState] so a deposit in flight / success / error
 * NEVER clobbers the read state (the summary + ledger stay rendered behind the deposit sheet).
 */
sealed interface AdsBillingUiState {

    data object Loading : AdsBillingUiState

    /**
     * The loaded billing view. [invoice] is null when the (best-effort) monthly-invoice read failed -
     * a missing invoice is tolerated, NOT a fatal error. [isStale] is true when a refresh failed and the
     * previously-loaded content is being kept.
     */
    data class Content(
        val account: AdAccountSummary,
        val ledger: List<AdBillingEntry>,
        val invoice: AdInvoice? = null,
        val isStale: Boolean = false,
    ) : AdsBillingUiState

    /** A fatal, retryable load error. */
    data class Error(val error: ApiError) : AdsBillingUiState
}

/**
 * AND-367 - the SEPARATE deposit sub-state (kept off the read state). [Idle] is the resting state;
 * [Submitting] disables the confirm + guards against a double-submit; [Success] carries the new balance for
 * the confirmation; [Error] carries a friendly message (a 400 "Minimum deposit" is mapped to a friendly
 * string upstream). The deposit is NON-idempotent -> there is NO auto-retry from any of these.
 */
sealed interface DepositState {

    data object Idle : DepositState

    data object Submitting : DepositState

    data class Success(val newBalanceCents: Long?) : DepositState

    data class Error(val message: String) : DepositState
}


/**
 * FE-160 - one selectable crypto asset row in the "Fund with crypto balance" picker: symbol, human name
 * and the custody balance in BOTH whole units (display) and integer base units (the insufficient compare
 * against a quote total_native). Mirrors the FE-152 checkout CryptoAssetOption.
 */
data class AdCryptoAssetOption(
    val symbol: String,
    val name: String,
    val decimals: Int,
    val balanceWhole: Double,
    val balanceBaseUnits: Long,
) {
    val balanceText: String
        get() = if (balanceWhole == balanceWhole.toLong().toDouble()) balanceWhole.toLong().toString()
        else balanceWhole.toString()
}

/**
 * FE-160 - the "Fund with crypto balance" sub-state layered onto the ads deposit sheet. Additive: the
 * existing card/wallet deposit path is untouched. [enabled] flips false once the fee-quote endpoint 404s
 * (degrade-on-404 -> "Crypto funding unavailable"). [assets] is the fundable custody balance set; [quote]
 * is the live rate-locked quote for [selectedSymbol]; [secondsRemaining] drives the countdown chip;
 * [insufficient] disables funding with a message; [error] carries a quote/pay error. [enabledForFunding]
 * mirrors the checkout canPay gate.
 */
data class CryptoFundUiState(
    val enabled: Boolean = true,
    val assets: List<AdCryptoAssetOption> = emptyList(),
    val selectedSymbol: String? = null,
    val quoting: Boolean = false,
    val quote: FeeQuote? = null,
    val secondsRemaining: Long = 0L,
    val insufficient: Boolean = false,
    val error: String? = null,
) {
    val selectedAsset: AdCryptoAssetOption?
        get() = assets.firstOrNull { it.symbol == selectedSymbol }

    /** True only when a live, non-expired, affordable quote is ready to fund with. */
    val canFund: Boolean
        get() = enabled && quote != null && secondsRemaining > 0L && !insufficient && !quoting
}
