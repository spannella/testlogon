package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.ordertracking.OrderTrackingRoute
import com.testlogon.android.feature.ordertracking.OrderTrackingViewModel

/**
 * D4 - BUYER order shipment-tracking, keyed by ship-group id. Reached from the buyer shipment alerts
 * (order_shipped / order_out_for_delivery / order_delivered), whose action_url is
 * /orders?order=..&ship_group=..&track=1 -> the ship_group id is passed here.
 */
data object OrderTrackingDest {
    const val ARG_SHIP_GROUP = OrderTrackingViewModel.ARG_SHIP_GROUP
    const val ROUTE = "orders/tracking/{$ARG_SHIP_GROUP}"

    fun build(shipGroupId: String): String = "orders/tracking/" + Uri.encode(shipGroupId)
}

/** Registers the buyer order-tracking destination in the authenticated graph. */
fun NavGraphBuilder.orderTrackingDestination(navController: NavHostController) {
    composable(
        route = OrderTrackingDest.ROUTE,
        arguments = listOf(
            navArgument(OrderTrackingDest.ARG_SHIP_GROUP) { type = NavType.StringType },
        ),
    ) {
        OrderTrackingRoute(onBack = { navController.popBackStack() })
    }
}
