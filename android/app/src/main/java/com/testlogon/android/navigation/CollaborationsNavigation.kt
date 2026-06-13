package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.collaborations.ui.CollaborationDetailRoute
import com.testlogon.android.feature.collaborations.ui.CollaborationsListRoute

/**
 * AND-358 - the READ-ONLY collaborations destinations: a Paging-3 LIST of the viewer's collaborations and a
 * DETAIL screen (two parties + status + the revenue split). The detail ViewModel reads {collabId} from
 * SavedStateHandle (the nav arg). Write actions (create / edit / propose / payout) are OUT OF SCOPE.
 */
data object CollaborationsListDest {
    const val ROUTE = "collaborations"
}

data object CollaborationDetailDest {
    const val ARG_COLLAB_ID = "collabId"
    const val ROUTE = "collaboration/{$ARG_COLLAB_ID}"

    fun build(collabId: String): String = "collaboration/${Uri.encode(collabId)}"
}

/**
 * AND-358 - registers the collaborations list + detail destinations in the authenticated graph (one shared
 * nav graph; NOT forked). The list row taps through to the detail; the detail pops back.
 */
fun NavGraphBuilder.collaborationsDestinations(navController: NavHostController) {
    composable(route = CollaborationsListDest.ROUTE) {
        CollaborationsListRoute(
            onBack = { navController.popBackStack() },
            onOpenCollaboration = { collabId ->
                navController.navigate(CollaborationDetailDest.build(collabId))
            },
        )
    }
    composable(
        route = CollaborationDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CollaborationDetailDest.ARG_COLLAB_ID) { type = NavType.StringType },
        ),
    ) {
        CollaborationDetailRoute(onBack = { navController.popBackStack() })
    }
}
