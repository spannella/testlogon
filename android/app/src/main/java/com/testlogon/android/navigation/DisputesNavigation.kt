package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.disputes.DisputeDetailRoute
import com.testlogon.android.feature.disputes.DisputeDetailViewModel
import com.testlogon.android.feature.disputes.DisputeFileRoute
import com.testlogon.android.feature.disputes.DisputeFileViewModel
import com.testlogon.android.feature.disputes.DisputesListRoute
import com.testlogon.android.feature.disputes.CreatorDisputesRoute

/** AND-245 — the disputes list route (reached from billing / the More hub). */
data object DisputesListDest {
    const val ROUTE = "billing/disputes"
}

/** AND-245 — the file-dispute route; the arg is the transaction_entry_id the dispute targets. */
data object DisputeFileDest {
    const val ARG_TRANSACTION_ENTRY_ID = DisputeFileViewModel.ARG_TRANSACTION_ENTRY_ID
    const val ROUTE = "billing/disputes/new/{$ARG_TRANSACTION_ENTRY_ID}"

    fun build(transactionEntryId: String): String = "billing/disputes/new/${Uri.encode(transactionEntryId)}"
}

/** AND-245 — the dispute detail route; the arg is the dispute_id. */
data object DisputeDetailDest {
    const val ARG_DISPUTE_ID = DisputeDetailViewModel.ARG_DISPUTE_ID
    const val ROUTE = "billing/disputes/{$ARG_DISPUTE_ID}"

    fun build(disputeId: String): String = "billing/disputes/${Uri.encode(disputeId)}"
}

/** DISP-024 — the creator inbound "Respond to dispute" queue route. */
data object CreatorDisputesDest {
    const val ROUTE = "creator/disputes"
}

/** AND-245 — registers the disputes list + file + detail destinations. */
fun NavGraphBuilder.disputesDestinations(navController: NavHostController) {
    composable(DisputesListDest.ROUTE) {
        DisputesListRoute(
            onDisputeClick = { disputeId ->
                navController.navigate(DisputeDetailDest.build(disputeId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = DisputeFileDest.ROUTE,
        arguments = listOf(
            navArgument(DisputeFileDest.ARG_TRANSACTION_ENTRY_ID) { type = NavType.StringType },
        ),
    ) {
        DisputeFileRoute(
            onFiled = { disputeId ->
                navController.navigate(DisputeDetailDest.build(disputeId)) {
                    popUpTo(DisputeFileDest.ROUTE) { inclusive = true }
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = DisputeDetailDest.ROUTE,
        arguments = listOf(navArgument(DisputeDetailDest.ARG_DISPUTE_ID) { type = NavType.StringType }),
    ) {
        DisputeDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(CreatorDisputesDest.ROUTE) {
        CreatorDisputesRoute(onBack = { navController.popBackStack() })
    }
}
