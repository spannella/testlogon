package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.payments.RedirectCheckoutRoute
import com.testlogon.android.feature.payments.RedirectCheckoutViewModel
import com.testlogon.android.feature.payments.VerifyMicrodepositsRoute
import com.testlogon.android.feature.payments.VerifyMicrodepositsViewModel

/**
 * AND-227/228/229 — the redirect checkout (provider selection -> hosted checkout / PayPal / CCBill via
 * Custom Tabs). Reached with an amount + currency + optional description.
 */
data object RedirectCheckoutDest {
    const val ROUTE = "payments/checkout"
    const val ARG_AMOUNT = RedirectCheckoutViewModel.ARG_AMOUNT_CENTS
    const val ARG_CURRENCY = RedirectCheckoutViewModel.ARG_CURRENCY
    const val ARG_DESCRIPTION = RedirectCheckoutViewModel.ARG_DESCRIPTION

    val ROUTE_PATTERN = "$ROUTE?$ARG_AMOUNT={$ARG_AMOUNT}&$ARG_CURRENCY={$ARG_CURRENCY}" +
        "&$ARG_DESCRIPTION={$ARG_DESCRIPTION}"

    fun route(amountCents: Long, currency: String, description: String? = null): String =
        "$ROUTE?$ARG_AMOUNT=$amountCents&$ARG_CURRENCY=$currency" +
            (description?.let { "&$ARG_DESCRIPTION=$it" } ?: "")
}

/** AND-230 — US bank micro-deposit verification screen, keyed by the Stripe setup_intent_id (sid). */
data object VerifyMicrodepositsDest {
    const val ROUTE = "billing/us-bank/verify"
    const val ARG_SID = VerifyMicrodepositsViewModel.ARG_SETUP_INTENT_ID
    const val ROUTE_PATTERN = "$ROUTE/{$ARG_SID}"

    /** Verification deep link (AND-230 FR-7): com.testlogon.android://billing/us-bank/verify?sid=... */
    const val DEEP_LINK = "com.testlogon.android://billing/us-bank/verify?$ARG_SID={$ARG_SID}"

    fun route(setupIntentId: String): String = "$ROUTE/$setupIntentId"
}

/** AND-227..230 — registers the redirect checkout + micro-deposit verify destinations. */
fun NavGraphBuilder.paymentsDestinations(navController: NavHostController) {
    composable(
        route = RedirectCheckoutDest.ROUTE_PATTERN,
        arguments = listOf(
            navArgument(RedirectCheckoutDest.ARG_AMOUNT) {
                type = NavType.LongType
                defaultValue = 0L
            },
            navArgument(RedirectCheckoutDest.ARG_CURRENCY) {
                type = NavType.StringType
                defaultValue = "USD"
            },
            navArgument(RedirectCheckoutDest.ARG_DESCRIPTION) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        RedirectCheckoutRoute(onBack = { navController.popBackStack() })
    }

    composable(
        route = VerifyMicrodepositsDest.ROUTE_PATTERN,
        arguments = listOf(navArgument(VerifyMicrodepositsDest.ARG_SID) { type = NavType.StringType }),
        deepLinks = listOf(navDeepLink { uriPattern = VerifyMicrodepositsDest.DEEP_LINK }),
    ) {
        VerifyMicrodepositsRoute(
            onBack = { navController.popBackStack() },
            // A successful verify pops back so the payment-methods list re-fetches (default state).
            onVerified = { navController.popBackStack() },
        )
    }
}
