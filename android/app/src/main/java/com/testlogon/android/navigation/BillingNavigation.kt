package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.billing.AddCardRoute
import com.testlogon.android.feature.billing.PaymentMethodsRoute
import com.testlogon.android.feature.billing.config.BillingConfigRoute
import com.testlogon.android.feature.billing.wallet.WalletTransactionsRoute

/** AND-224 — the saved payment-methods management screen (list / set-default / remove). */
data object PaymentMethodsDest {
    const val ROUTE = "billing/payment-methods"

    /**
     * PW14 — the SavedStateHandle result key the add-card flow sets on this destination's back-stack
     * entry when a method is added, so the list refreshes IMMEDIATELY on return (not only on the next
     * ON_RESUME). Read-and-cleared by [PaymentMethodsRoute].
     */
    const val RESULT_ADDED = "payment_method_added"
}

/** AND-226 — the add-card screen (FLAGGED: routed through the stub card-entry seam). */
data object AddCardDest {
    const val ROUTE = "billing/payment-methods/add"
}

/**
 * AND-224 / AND-226 — registers the payment-methods management screen and the add-card screen. The
 * "Add payment method" CTA navigates to [AddCardDest]; a successful add sets the [PaymentMethodsDest.
 * RESULT_ADDED] result on the payment-methods back-stack entry, then pops back so the list force-
 * refreshes immediately (PW14) rather than waiting for the next ON_RESUME.
 */
fun NavGraphBuilder.billingDestinations(navController: NavHostController) {
    composable(PaymentMethodsDest.ROUTE) { backStackEntry ->
        // PW14 — observe the add-card result set on THIS entry's SavedStateHandle. When present we
        // force an immediate refresh and clear the flag so a later return doesn't re-trigger it.
        val savedStateHandle = backStackEntry.savedStateHandle
        val addedResult = savedStateHandle
            .getStateFlow(PaymentMethodsDest.RESULT_ADDED, false)
        PaymentMethodsRoute(
            onBack = { navController.popBackStack() },
            onAddCard = {
                navController.navigate(AddCardDest.ROUTE) { launchSingleTop = true }
            },
            refreshSignal = addedResult,
            onRefreshSignalConsumed = { savedStateHandle[PaymentMethodsDest.RESULT_ADDED] = false },
        )
    }
    composable(AddCardDest.ROUTE) {
        AddCardRoute(
            onBack = { navController.popBackStack() },
            // PW14 — on a successful add, signal the payment-methods entry to refresh, then pop back so
            // the new card shows up right away.
            onCardSaved = {
                navController.previousBackStackEntry
                    ?.savedStateHandle?.set(PaymentMethodsDest.RESULT_ADDED, true)
                navController.popBackStack()
            },
        )
    }
}

/** PW18 — the Wallet transactions (ledger) history screen. */
data object WalletTransactionsDest {
    const val ROUTE = "billing/wallet/transactions"
}

/** PW18 — registers the Wallet transactions history destination (BK3 ledger + wallet balance). */
fun NavGraphBuilder.walletTransactionsDestination(navController: NavHostController) {
    composable(WalletTransactionsDest.ROUTE) {
        WalletTransactionsRoute(onBack = { navController.popBackStack() })
    }
}

/** AND-248 — the read-only billing-config view (effective platform config; root-gated server-side). */
data object BillingConfigDest {
    const val ROUTE = "billing/config"
}

/** AND-248 — registers the read-only billing-config destination. */
fun NavGraphBuilder.billingConfigDestination(navController: NavHostController) {
    composable(BillingConfigDest.ROUTE) {
        BillingConfigRoute(onBack = { navController.popBackStack() })
    }
}
