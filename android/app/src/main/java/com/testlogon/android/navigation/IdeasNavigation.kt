package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ideas.IdeasRoute

/** The product-ideas route (reached from the More hub). Mirrors the web ideas/submit page. */
data object IdeasDest {
    const val ROUTE = "ideas"
}

/** Registers the ideas destination in the authenticated graph. */
fun NavGraphBuilder.ideasDestination(navController: NavHostController) {
    composable(IdeasDest.ROUTE) {
        IdeasRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
