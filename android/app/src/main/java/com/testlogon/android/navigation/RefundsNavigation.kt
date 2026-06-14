package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.refunds.RefundDetailRoute
import com.testlogon.android.feature.refunds.RefundDetailViewModel
import com.testlogon.android.feature.refunds.RefundListRoute
import com.testlogon.android.feature.refunds.RefundSubmitRoute
import com.testlogon.android.feature.refunds.RefundSubmitViewModel

/** AND-244 — the refund-requests list route (reached from billing / the More hub). */
data object RefundsListDest {
    const val ROUTE = "billing/refunds"
}

/** AND-244 — the refund submit route; the arg is the transaction_entry_id the refund targets. */
data object RefundSubmitDest {
    const val ARG_TRANSACTION_ENTRY_ID = RefundSubmitViewModel.ARG_TRANSACTION_ENTRY_ID
    const val ROUTE = "billing/refunds/new/{$ARG_TRANSACTION_ENTRY_ID}"

    fun build(transactionEntryId: String): String = "billing/refunds/new/${Uri.encode(transactionEntryId)}"
}

/** AND-244 — the refund detail route; the arg is the refund_request_id. */
data object RefundDetailDest {
    const val ARG_REFUND_ID = RefundDetailViewModel.ARG_REFUND_ID
    const val ROUTE = "billing/refunds/{$ARG_REFUND_ID}"

    fun build(refundId: String): String = "billing/refunds/${Uri.encode(refundId)}"
}

/** AND-244 — registers the refund list + submit + detail destinations. */
fun NavGraphBuilder.refundsDestinations(navController: NavHostController) {
    composable(RefundsListDest.ROUTE) {
        RefundListRoute(
            onRefundClick = { refundId ->
                navController.navigate(RefundDetailDest.build(refundId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = RefundSubmitDest.ROUTE,
        arguments = listOf(
            navArgument(RefundSubmitDest.ARG_TRANSACTION_ENTRY_ID) { type = NavType.StringType },
        ),
    ) {
        RefundSubmitRoute(
            onSubmitted = { refundId ->
                // Replace the submit form with the new request's detail.
                navController.navigate(RefundDetailDest.build(refundId)) {
                    popUpTo(RefundSubmitDest.ROUTE) { inclusive = true }
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = RefundDetailDest.ROUTE,
        arguments = listOf(navArgument(RefundDetailDest.ARG_REFUND_ID) { type = NavType.StringType }),
    ) {
        RefundDetailRoute(onBack = { navController.popBackStack() })
    }
}
