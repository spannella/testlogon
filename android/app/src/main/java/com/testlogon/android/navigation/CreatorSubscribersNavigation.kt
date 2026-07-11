package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.subscriptions.CreatorSubscribersRoute
import com.testlogon.android.feature.subscriptions.CreatorSubscribersViewModel

/**
 * SUB-E4-3 — creator "Subscribers & MRR" destination (arg-less; the VM resolves the signed-in
 * creator as both the X-User-Id and the creator-id path, so the screen is owner-scoped). Reached
 * from the Growth hub ([MoreRoutes.CREATOR_SUBSCRIBERS]).
 */
data object CreatorSubscribersDest {
    const val ROUTE = CreatorSubscribersViewModel.ROUTE
}

/** SUB-E4-3 — registers the creator subscribers + MRR/analytics destination. */
fun NavGraphBuilder.creatorSubscribersDestination(navController: NavHostController) {
    composable(CreatorSubscribersDest.ROUTE) {
        CreatorSubscribersRoute(onBack = { navController.popBackStack() })
    }
}
