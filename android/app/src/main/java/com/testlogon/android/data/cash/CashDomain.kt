package com.testlogon.android.data.cash

/**
 * Null-safe domain models for the FIAT (USD) cash wallet. The wire DTOs are coerced here so the
 * ViewModel/UI never see nullable wire fields. Money stays integer cents end-to-end (parsed/formatted
 * in feature/cash/CashMath).
 */

/** The USD wallet balance. [available] is false when the read degraded (404 / undeployed). */
data class CashWallet(
    val balanceCents: Long,
    val currency: String,
    val available: Boolean,
) {
    companion object {
        /** Honest "unavailable" wallet for the degrade-on-404 empty state. */
        fun unavailable(): CashWallet = CashWallet(balanceCents = 0L, currency = "USD", available = false)
    }
}

/** A saved payment method usable to fund a deposit. */
data class CashPaymentMethod(
    val id: String,
    val label: String,
    val isDefault: Boolean,
)

/** Result of a wallet deposit (mutation). ok=true when the server accepted the charge. */
data class CashDepositResult(
    val ok: Boolean,
    val status: String?,
    val paymentIntentId: String?,
    val newBalanceCents: Long?,
    val reason: String?,
)

/** Result of a wallet withdrawal (mutation). */
data class CashWithdrawResult(
    val ok: Boolean,
    val newBalanceCents: Long?,
    val reason: String?,
)
