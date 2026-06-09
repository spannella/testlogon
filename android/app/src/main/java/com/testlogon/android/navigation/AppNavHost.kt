package com.testlogon.android.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import com.testlogon.android.core.ui.navigation.TLTransitions
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * Single-Activity NavHost with auth-gated top-level routing (AND-022/023/024/025).
 *
 * Observes [AuthRoutingViewModel.isAuthenticated]; on every distinct change it navigates to the
 * matching top-level graph and pops the opposing graph inclusive so Back never crosses the auth
 * boundary. Idempotent: re-emitting the same state (config change / process death) is a no-op when
 * already on the target graph.
 *
 * The default [AuthStateProvider][com.testlogon.android.auth.AuthStateProvider] reports
 * unauthenticated, so the app currently boots into the unauthenticated graph (Login).
 */
@Composable
fun AppNavHost(
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController(),
    // AND-061: lets the host Activity grab the NavController so onNewIntent can forward warm/foreground
    // magic-link deep links. Defaulted to a no-op so previews / tests don't need to supply it.
    onNavControllerReady: (NavHostController) -> Unit = {},
    viewModel: AuthRoutingViewModel = hiltViewModel(),
) {
    LaunchedEffect(navController) { onNavControllerReady(navController) }

    // The graph swap is driven entirely by the effect below so the start destination stays fixed
    // (avoids rebuilding the NavHost when auth flips). The default provider is unauthenticated.
    LaunchedEffect(navController) {
        viewModel.isAuthenticated
            .map { authed -> if (authed) TlGraphs.AUTHENTICATED else TlGraphs.UNAUTHENTICATED }
            .distinctUntilChanged()
            .collect { targetGraph -> navController.routeToGraph(targetGraph) }
    }

    NavHost(
        navController = navController,
        startDestination = TlGraphs.UNAUTHENTICATED,
        modifier = modifier,
        enterTransition = { TLTransitions.enter() },
        exitTransition = { TLTransitions.exit() },
        popEnterTransition = { TLTransitions.popEnter() },
        popExitTransition = { TLTransitions.popExit() },
    ) {
        unauthenticatedGraph(navController)
        authenticatedGraph(navController)
    }
}

/** Navigates to [targetGraph], clearing the whole back stack across the auth boundary. No-op if already there. */
private fun NavHostController.routeToGraph(targetGraph: String) {
    val alreadyThere = currentDestination?.hierarchy?.any { it.route == targetGraph } == true
    if (alreadyThere) return
    navigate(targetGraph) {
        popUpTo(graph.findStartDestination().id) { inclusive = true }
        launchSingleTop = true
    }
}
