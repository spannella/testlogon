package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.dca.DcaCreateRoute
import com.testlogon.android.feature.dca.DcaDetailRoute
import com.testlogon.android.feature.dca.DcaPlansRoute

/**
 * DCA / RECURRING-BUYS destinations, registered in the AUTHENTICATED nav graph.
 *
 * [DcaPlansDest] is the plans list (the navigable hub entry); [DcaCreateDest] is the create flow;
 * [DcaDetailDest] is the per-plan detail + history + run-now. Plan CRUD + schedule preview live in the
 * client; the periodic EXECUTION is a server-side runner, so every read degrades on 404 to an honest
 * pending state. Back pops the stack.
 */
data object DcaPlansDest {
    const val ROUTE = "dca"
}

data object DcaCreateDest {
    const val ROUTE = "dca/create"
}

data object DcaDetailDest {
    const val ROUTE = "dca/detail/{planId}"
    const val ARG_PLAN_ID = "planId"

    fun build(planId: String): String = "dca/detail/${Uri.encode(planId)}"
}

/** Registers the DCA plans list + create + detail destinations. */
fun NavGraphBuilder.dcaDestinations(navController: NavHostController) {
    composable(DcaPlansDest.ROUTE) {
        DcaPlansRoute(
            onBack = { navController.popBackStack() },
            onCreate = { navController.navigate(DcaCreateDest.ROUTE) { launchSingleTop = true } },
            onOpenPlan = { id -> navController.navigate(DcaDetailDest.build(id)) { launchSingleTop = true } },
        )
    }
    composable(DcaCreateDest.ROUTE) {
        DcaCreateRoute(
            onBack = { navController.popBackStack() },
            onCreated = { id ->
                // Replace the create screen with the new plan's detail so Back returns to the list.
                navController.navigate(DcaDetailDest.build(id)) {
                    launchSingleTop = true
                    popUpTo(DcaCreateDest.ROUTE) { inclusive = true }
                }
            },
            onAddCash = { navController.navigate(CashDest.ROUTE) { launchSingleTop = true } },
        )
    }
    composable(
        route = DcaDetailDest.ROUTE,
        arguments = listOf(navArgument(DcaDetailDest.ARG_PLAN_ID) { type = NavType.StringType }),
    ) {
        DcaDetailRoute(onBack = { navController.popBackStack() })
    }
}
