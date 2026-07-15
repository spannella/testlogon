package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.subscriptions.CreatorTierManagerRoute
import com.testlogon.android.feature.subscriptions.CreatorTierManagerViewModel

/**
 * SUBX-40 — creator "Your subscription tiers" authoring destination (arg-less; the VM resolves the
 * signed-in creator as both the X-User-Id and the creator-id path, so authoring is owner-scoped).
 * Reached from the Growth hub ([MoreRoutes.CREATOR_TIERS]).
 */
data object CreatorTierManagerDest {
    const val ROUTE = CreatorTierManagerViewModel.ROUTE
}

/** SUBX-40 — registers the creator tier-authoring destination. */
fun NavGraphBuilder.creatorTierManagerDestination(navController: NavHostController) {
    composable(CreatorTierManagerDest.ROUTE) {
        CreatorTierManagerRoute(onBack = { navController.popBackStack() })
    }
}
