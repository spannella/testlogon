package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.payouts.BulkPayoutDetailRoute
import com.testlogon.android.feature.payouts.BulkPayoutDetailViewModel
import com.testlogon.android.feature.payouts.BulkPayoutsListRoute
import com.testlogon.android.feature.payouts.PayoutDetailRoute
import com.testlogon.android.feature.payouts.PayoutDetailViewModel
import com.testlogon.android.feature.payouts.PayoutHistoryRoute
import com.testlogon.android.feature.payouts.PayoutSetupRoute
import com.testlogon.android.feature.payouts.WalletRoute

/** PAY-52 — the money-OUT Wallet home route (More > Wallet hub). Deep-link base `/wallet/payouts`. */
data object WalletDest {
    const val ROUTE = "wallet"
}

/** AND-260 — the payout history list route (reached from earnings / billing / the More hub). */
data object PayoutHistoryDest {
    const val ROUTE = "payouts"
}

/** AND-260 — the payout detail route; the arg is the STRING payout_id (cache-hydrated, no network). */
data object PayoutDetailDest {
    const val ARG_PAYOUT_ID = PayoutDetailViewModel.ARG_PAYOUT_ID
    const val ROUTE = "payouts/{$ARG_PAYOUT_ID}"

    fun build(payoutId: String): String = "payouts/${Uri.encode(payoutId)}"
}

/** AND-259 — the payout setup + KYC gate route. */
data object PayoutSetupDest {
    const val ROUTE = "payouts/setup"
}

/** AND-261 — the READ-ONLY bulk/batch payout list route. */
data object BulkPayoutsDest {
    const val ROUTE = "payouts/bulk"
}

/** AND-261 — the READ-ONLY bulk/batch payout detail route; arg is the STRING batch_id. */
data object BulkPayoutDetailDest {
    const val ARG_BATCH_ID = BulkPayoutDetailViewModel.ARG_BATCH_ID
    const val ROUTE = "payouts/bulk/{$ARG_BATCH_ID}"

    fun build(batchId: String): String = "payouts/bulk/${Uri.encode(batchId)}"
}

/**
 * AND-258/259/260 — registers the payout setup + history + detail destinations in the authenticated graph.
 *
 * STOP-AND-FLAG: the "Verify identity" action's KYC verification entry route (E42 / AND-321..322) is not
 * available at M6, and the KYC vendor SDK is FLAGGED (StubKycVerifier). [PayoutSetupRoute.onNavigateToKyc]
 * is therefore wired to a no-op here so the gate's button is present and accessible while the screen's
 * gate panel already surfaces the "identity verification unavailable" state. Replace the no-op with a real
 * navigate() to the KYC route once it lands.
 */
fun NavGraphBuilder.payoutsDestinations(navController: NavHostController) {
    // PAY-52 - money-OUT Wallet home: available/held/pending/lifetime + Withdraw CTA + history entry.
    composable(WalletDest.ROUTE) {
        WalletRoute(
            onWithdraw = { navController.navigate(PayoutSetupDest.ROUTE) { launchSingleTop = true } },
            onViewHistory = { navController.navigate(PayoutHistoryDest.ROUTE) { launchSingleTop = true } },
            onBack = { navController.popBackStack() },
        )
    }
    composable(PayoutHistoryDest.ROUTE) {
        PayoutHistoryRoute(
            onPayoutClick = { payoutId ->
                navController.navigate(PayoutDetailDest.build(payoutId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = PayoutDetailDest.ROUTE,
        arguments = listOf(
            navArgument(PayoutDetailDest.ARG_PAYOUT_ID) { type = NavType.StringType },
        ),
    ) {
        PayoutDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(PayoutSetupDest.ROUTE) {
        PayoutSetupRoute(
            // PAY-22 - route the pre-withdrawal gate to the EXISTING KYC case flow (view status /
            // start-or-continue verification). The gate re-resolves on return (LifecycleResumeEffect).
            onNavigateToKyc = { navController.navigate(KycCasesDest.ROUTE) { launchSingleTop = true } },
            onBack = { navController.popBackStack() },
        )
    }
    // AND-261 — READ-ONLY bulk/batch payout list + detail (no mutating affordances).
    composable(BulkPayoutsDest.ROUTE) {
        BulkPayoutsListRoute(
            onBatchClick = { batchId ->
                navController.navigate(BulkPayoutDetailDest.build(batchId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = BulkPayoutDetailDest.ROUTE,
        arguments = listOf(
            navArgument(BulkPayoutDetailDest.ARG_BATCH_ID) { type = NavType.StringType },
        ),
    ) {
        BulkPayoutDetailRoute(onBack = { navController.popBackStack() })
    }
}
