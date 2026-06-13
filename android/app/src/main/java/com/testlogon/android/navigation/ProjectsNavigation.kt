package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.projects.ui.ProjectsListRoute
import com.testlogon.android.feature.projects.ui.detail.ProjectDetailRoute

/**
 * AND-374 - the PROJECTS destinations: a paged projects LIST -> a project DETAIL (with the account-scoped
 * Google Drive provider connect flow). The detail ViewModel reads its {projectId} nav arg from SavedStateHandle.
 *
 * The Drive OAuth return deep link (`testlogon://projects/{projectId}/providers/google_drive/callback?...`) is
 * NOT routed as a nav destination; the Activity parses it and emits it through the
 * com.testlogon.android.feature.projects.provider.ProjectDriveReturnDispatcher, which the detail ViewModel (the
 * same instance the user left to enter the Custom Tab, since the task is singleTask) consumes. A registered
 * `navDeepLink` is added to the detail composable so a cold-start return still resolves to the detail screen.
 */
data object ProjectsListDest {
    const val ROUTE = "projects"
}

data object ProjectDetailDest {
    const val ARG_PROJECT_ID = "projectId"
    const val ROUTE = "projects/{$ARG_PROJECT_ID}"

    fun build(projectId: String): String = "projects/${Uri.encode(projectId)}"

    /** The Drive OAuth return deep link, so a cold-start return lands on the detail screen for the project. */
    const val DEEP_LINK =
        "testlogon://projects/{$ARG_PROJECT_ID}/providers/google_drive/callback"
}

/**
 * AND-374 - registers the projects list + detail destinations in the authenticated graph (one shared nav graph;
 * NOT forked). The terminal-401 re-auth handoff routes to the Login destination carrying SESSION_EXPIRED
 * (mirrors the AND-372 tickets handoff).
 */
fun NavGraphBuilder.projectsDestinations(navController: NavHostController) {
    composable(route = ProjectsListDest.ROUTE) {
        ProjectsListRoute(
            onBack = { navController.popBackStack() },
            onOpenProject = { projectId ->
                navController.navigate(ProjectDetailDest.build(projectId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = ProjectDetailDest.ROUTE,
        arguments = listOf(
            navArgument(ProjectDetailDest.ARG_PROJECT_ID) { type = NavType.StringType },
        ),
        deepLinks = listOf(navDeepLink { uriPattern = ProjectDetailDest.DEEP_LINK }),
    ) {
        ProjectDetailRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToProjectsReauth() },
        )
    }
}

/** AND-374 - the terminal-401 re-auth handoff: navigate to Login carrying SESSION_EXPIRED. */
private fun NavHostController.navigateToProjectsReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
