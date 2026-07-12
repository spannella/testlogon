package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.moderation.MyContentReviewRoute

/**
 * MOD-D2 — the poster-facing "My content under review" destination. Reachable from the More hub
 * (Account) and from a moderation alert deep-link (MOD-D1). Lists the caller's under_review / hold /
 * awaiting_final cases with respond + close actions.
 */
data object ModerationReviewDest {
    const val ROUTE = "moderation/my-content-review"
}

fun NavGraphBuilder.moderationReviewDestination(navController: NavHostController) {
    composable(ModerationReviewDest.ROUTE) {
        MyContentReviewRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
