package com.testlogon.android.feature.shell

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.testlogon.android.R

/** Bottom-nav tabs for the authenticated shell (AND-024). */
enum class AuthedTab(
    val route: String,
    @StringRes val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
) {
    HOME("authed/home", R.string.tab_home, Icons.Filled.Home, Icons.Outlined.Home),
    ME("authed/me", R.string.tab_me, Icons.Filled.Person, Icons.Outlined.Person);

    companion object {
        val START = HOME
        fun fromRoute(route: String?): AuthedTab =
            entries.firstOrNull { route?.startsWith(it.route) == true } ?: START
    }
}

/**
 * The authenticated app shell: a Material 3 [Scaffold] with a bottom [NavigationBar] and an inner
 * [NavController] that keeps each tab's back stack isolated and preserves per-tab state.
 */
@Composable
fun AuthedShellScreen(
    modifier: Modifier = Modifier,
    onOpenSessions: () -> Unit = {},
) {
    val tabNav = rememberNavController()
    val backStack by tabNav.currentBackStackEntryAsState()
    val current = AuthedTab.fromRoute(backStack?.destination?.route)

    Scaffold(
        modifier = modifier,
        bottomBar = {
            NavigationBar {
                AuthedTab.entries.forEach { tab ->
                    val selected = tab == current
                    NavigationBarItem(
                        selected = selected,
                        onClick = { tabNav.navigateToTab(tab) },
                        icon = {
                            Icon(
                                imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                contentDescription = null,
                            )
                        },
                        label = { Text(stringResource(tab.labelRes)) },
                        modifier = Modifier.testTag("tab_${tab.name.lowercase()}"),
                    )
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = tabNav,
            startDestination = AuthedTab.START.route,
            modifier = Modifier.padding(padding),
        ) {
            composable(AuthedTab.HOME.route) { HomePlaceholderScreen() }
            composable(AuthedTab.ME.route) { MePlaceholderScreen(onOpenSessions = onOpenSessions) }
        }
    }
}

private fun NavController.navigateToTab(tab: AuthedTab) {
    navigate(tab.route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@Composable
private fun HomePlaceholderScreen() {
    Box(Modifier.fillMaxSize().testTag("home_placeholder"), contentAlignment = Alignment.Center) {
        Text("Home", style = MaterialTheme.typography.headlineSmall)
    }
}

@Composable
private fun MePlaceholderScreen(onOpenSessions: () -> Unit) {
    com.testlogon.android.feature.profile.ProfileScreen(onOpenSessions = onOpenSessions)
}
