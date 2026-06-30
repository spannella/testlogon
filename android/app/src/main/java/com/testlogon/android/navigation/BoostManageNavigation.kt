package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.boost.manage.BoostDetailRoute
import com.testlogon.android.feature.boost.manage.BoostDetailViewModel
import com.testlogon.android.feature.boost.manage.BoostListRoute

/**
 * Web-parity BOOST MANAGEMENT destinations: the boost LIST (`ads-boost`, web /ads/boost) and the boost
 * DETAIL by boost id (`ads-boost/{boostId}`, web /ads/boost/:boostId). Both reuse the existing AND-364
 * boost network client + [com.testlogon.android.feature.boost.data.BoostRepository] (listBoosts / getBoost /
 * cancelBoost) - NO new network code. The per-post CREATE flow stays in the existing BoostDest route.
 */
data object BoostManageDest {
    const val LIST_ROUTE = "ads-boost"

    const val ARG_BOOST_ID = "boostId"
    const val DETAIL_ROUTE = "ads-boost/{$ARG_BOOST_ID}"

    /** Builds the concrete detail route for [boostId]. */
    fun detail(boostId: String): String = "ads-boost/$boostId"
}

fun NavHostController.navigateToBoostList() {
    navigate(BoostManageDest.LIST_ROUTE) { launchSingleTop = true }
}

fun NavHostController.navigateToBoostDetail(boostId: String) {
    navigate(BoostManageDest.detail(boostId)) { launchSingleTop = true }
}

fun NavGraphBuilder.boostManageDestinations(navController: NavHostController) {
    composable(route = BoostManageDest.LIST_ROUTE) {
        BoostListRoute(
            onBack = { navController.popBackStack() },
            onOpenBoost = { boostId -> navController.navigateToBoostDetail(boostId) },
        )
    }
    composable(
        route = BoostManageDest.DETAIL_ROUTE,
        arguments = listOf(
            navArgument(BoostDetailViewModel.ARG_BOOST_ID) { type = NavType.StringType },
        ),
    ) {
        BoostDetailRoute(onBack = { navController.popBackStack() })
    }
}
