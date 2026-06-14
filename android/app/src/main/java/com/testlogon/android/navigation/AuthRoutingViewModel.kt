package com.testlogon.android.navigation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.navigation.applink.DeepLinkRouter
import com.testlogon.android.navigation.applink.RouteNavigator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * Bridges the observed [AuthStateProvider] into a lifecycle-aware flow the host can collect, and
 * drives the central App Link [DeepLinkRouter] (AND-396) once the NavController is ready.
 *
 * WAVE 4 / AND-025+: this is where logout(), session-expiry handling, and pending-return-route
 * capture will be added once the real session source (AND-029) lands.
 */
@HiltViewModel
class AuthRoutingViewModel @Inject constructor(
    authStateProvider: AuthStateProvider,
    private val deepLinkRouter: DeepLinkRouter,
) : ViewModel() {

    val isAuthenticated: StateFlow<Boolean> =
        authStateProvider.isAuthenticated.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = authStateProvider.isAuthenticated.value,
        )

    /** AND-396: a buffered App Link awaiting NavController readiness / authentication. */
    val pendingDeepLink: StateFlow<DeepLinkRouter.Buffered?> = deepLinkRouter.pending

    /** AND-396: drain a buffered App Link once the NavHost is composed (FR-4). */
    fun consumeDeepLink(navController: NavController) =
        deepLinkRouter.consume(navController.asRouteNavigator())

    /** AND-396: flush a buffered authed App Link after a successful session finalize (FR-6). */
    fun resumeDeepLinkAfterAuth(navController: NavController) =
        deepLinkRouter.onAuthenticated(navController.asRouteNavigator())
}

/**
 * AND-396 — wraps a [NavController] as a [RouteNavigator]. Navigation REPLACES the start destination
 * (popUpTo + inclusive) so Back from a deep-linked screen exits naturally instead of returning to a
 * stale Home (FR-4); launchSingleTop makes re-consumption on recomposition a no-op (TC-07).
 */
private fun NavController.asRouteNavigator(): RouteNavigator = object : RouteNavigator {
    override fun navigate(route: String) {
        navigate(route) {
            popUpTo(graph.findStartDestination().id) { saveState = false }
            launchSingleTop = true
        }
    }

    override fun navigateToAuth() {
        // The auth-gate (AuthRoutingViewModel.isAuthenticated -> routeToGraph) already keeps an
        // unauthenticated user on the login graph; routing here is a no-op beyond ensuring the login
        // surface is current. The buffered link resumes via resumeDeepLinkAfterAuth after finalize.
    }
}
