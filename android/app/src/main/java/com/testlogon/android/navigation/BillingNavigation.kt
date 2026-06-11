package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.billing.AddCardRoute
import com.testlogon.android.feature.billing.PaymentMethodsRoute
import com.testlogon.android.feature.billing.config.BillingConfigRoute

/** AND-224 — the saved payment-methods management screen (list / set-default / remove). */
data object PaymentMethodsDest {
    const val ROUTE = "billing/payment-methods"
}

/** AND-226 — the add-card screen (FLAGGED: routed through the stub card-entry seam). */
data object AddCardDest {
    const val ROUTE = "billing/payment-methods/add"
}

/**
 * AND-224 / AND-226 — registers the payment-methods management screen and the add-card screen. The
 * "Add payment method" CTA navigates to [AddCardDest]; a successful add (only with a real tokenizer)
 * pops back so the list re-fetches.
 */
fun NavGraphBuilder.billingDestinations(navController: NavHostController) {
    composable(PaymentMethodsDest.ROUTE) {
        PaymentMethodsRoute(
            onBack = { navController.popBackStack() },
            onAddCard = {
                navController.navigate(AddCardDest.ROUTE) { launchSingleTop = true }
            },
        )
    }
    composable(AddCardDest.ROUTE) {
        AddCardRoute(
            onBack = { navController.popBackStack() },
            // A real tokenizer would save the card; popping back triggers the list re-fetch.
            onCardSaved = { navController.popBackStack() },
        )
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
