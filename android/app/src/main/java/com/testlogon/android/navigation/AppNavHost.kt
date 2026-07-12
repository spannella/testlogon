package com.testlogon.android.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import com.testlogon.android.core.ui.navigation.TLTransitions
import com.testlogon.android.feature.call.domain.CallPhase
import com.testlogon.android.feature.call.nav.CallRoutes
import com.testlogon.android.feature.report.LocalDmcaLauncher
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
    callRoutingViewModel: CallRoutingViewModel = hiltViewModel(),
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

    // AND-396: drain a buffered HTTP(S) App Link once the NavHost is composed (cold start, FR-4) and
    // whenever a new link buffers (warm onNewIntent). consume() is single-shot + idempotent.
    LaunchedEffect(navController) {
        viewModel.pendingDeepLink.collect { buffered ->
            if (buffered != null) viewModel.consumeDeepLink(navController)
        }
    }

    // AND-396: flush a buffered AUTHED App Link after the session becomes authenticated (FR-6). The
    // StateFlow already conflates equal values; exactly-once because the router clears the buffer.
    LaunchedEffect(navController) {
        viewModel.isAuthenticated.collect { authed ->
            if (authed) viewModel.resumeDeepLinkAfterAuth(navController)
        }
    }

    // Route to the in-call (video) screen the moment a 1:1 call reaches Connecting/Connected. The
    // caller is otherwise stranded on the text-only outgoing screen and the callee returns to home
    // after IncomingCallActivity finishes; this surfaces the connected media view for both sides.
    LaunchedEffect(navController) {
        callRoutingViewModel.callState
            .map { st ->
                st.call?.callId?.takeIf {
                    st.phase is CallPhase.Connecting || st.phase is CallPhase.Connected
                }
            }
            .distinctUntilChanged()
            .collect { callId ->
                if (callId == null) return@collect
                val onIncall = navController.currentDestination?.route
                    ?.startsWith("call/incall/") == true
                if (!onIncall) {
                    runCatching {
                        navController.navigate(CallRoutes.incall(callId)) { launchSingleTop = true }
                    }
                }
            }
    }

    // MOD-C3 - provide the DMCA launcher once so any content Report sheet can route a licensing/IP
    // violation into the pre-filled DMCA claim flow without threading a lambda through every screen.
    CompositionLocalProvider(
        LocalDmcaLauncher provides { contentType, contentId ->
            navController.navigateToDmca(contentType = contentType, contentId = contentId)
        },
    ) {
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
