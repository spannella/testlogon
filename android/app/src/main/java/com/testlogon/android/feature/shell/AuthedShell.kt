package com.testlogon.android.feature.shell

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.DynamicFeed
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.DynamicFeed
import androidx.compose.material.icons.outlined.Explore
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
    FEED("authed/feed", R.string.tab_feed, Icons.Filled.DynamicFeed, Icons.Outlined.DynamicFeed),
    DISCOVER("authed/discover", R.string.tab_discover, Icons.Filled.Explore, Icons.Outlined.Explore),
    ME("authed/me", R.string.tab_me, Icons.Filled.Person, Icons.Outlined.Person),
    MORE("authed/more", R.string.tab_more, Icons.Filled.Apps, Icons.Outlined.Apps);

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
    onOpenMfaDevices: () -> Unit = {},
    onEditProfile: () -> Unit = {},
    // AND-077: opens a full-screen outer-graph route (e.g. the Settings hub) by route constant.
    onOpenRoute: (route: String) -> Unit = {},
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
        // AND-107: request POST_NOTIFICATIONS once now that the user is authenticated (no-op < API 33).
        com.testlogon.android.notifications.NotificationPermissionGate()
        NavHost(
            navController = tabNav,
            startDestination = AuthedTab.START.route,
            modifier = Modifier.padding(padding),
        ) {
            composable(AuthedTab.HOME.route) {
                com.testlogon.android.feature.dashboard.DashboardRoute(
                    onOpenProfile = { tabNav.navigateToTab(AuthedTab.ME) },
                    onOpenSessions = onOpenSessions,
                    onOpenSettings = {
                        onOpenRoute(com.testlogon.android.navigation.MainDest.Settings.route)
                    },
                    onOpenMore = { tabNav.navigateToTab(AuthedTab.MORE) },
                )
            }
            composable(AuthedTab.FEED.route) {
                com.testlogon.android.feature.feed.FeedRoute(
                    onPostClick = { postId ->
                        onOpenRoute(com.testlogon.android.navigation.PostDetailDest.build(postId))
                    },
                    onAuthorClick = { authorId ->
                        onOpenRoute(com.testlogon.android.navigation.PublicProfileDest.build(authorId))
                    },
                )
            }
            // AND-182/AND-184: Discover (curated creators/tags + "for you" recommendations).
            composable(AuthedTab.DISCOVER.route) {
                com.testlogon.android.feature.discover.DiscoverRoute(
                    onOpenProfile = { userId ->
                        onOpenRoute(com.testlogon.android.navigation.PublicProfileDest.build(userId))
                    },
                    onOpenTag = { tag ->
                        onOpenRoute(com.testlogon.android.navigation.TagPageDest.build(tag))
                    },
                    onOpenSearch = {
                        onOpenRoute(com.testlogon.android.navigation.MultiSearchDest.ROUTE)
                    },
                    // AND-184: the web video-detail route (/gallery/{video_id}) has no Android screen
                    // yet (owned by AND-182's scope); video taps are a safe no-op until it lands.
                    onOpenVideo = {},
                )
            }
            composable(AuthedTab.ME.route) {
                com.testlogon.android.feature.profile.own.OwnProfileRoute(
                    onEditProfile = onEditProfile,
                    onOpenSessions = onOpenSessions,
                    onOpenMfaDevices = onOpenMfaDevices,
                    onOpenSettings = {
                        onOpenRoute(com.testlogon.android.navigation.MainDest.Settings.route)
                    },
                )
            }
            composable(AuthedTab.MORE.route) {
                com.testlogon.android.feature.more.MoreRoute(
                    onNavigate = { route ->
                        when (route) {
                            com.testlogon.android.navigation.MoreRoutes.PROFILE ->
                                tabNav.navigateToTab(AuthedTab.ME)
                            com.testlogon.android.navigation.MoreRoutes.SESSIONS -> onOpenSessions()
                            com.testlogon.android.navigation.MoreRoutes.MFA_DEVICES -> onOpenMfaDevices()
                            // AND-077/080: Settings hub + notification prefs are outer-graph routes.
                            // AND-091/092/093: activity / saved / achievements are outer-graph routes.
                            com.testlogon.android.navigation.MoreRoutes.SETTINGS,
                            com.testlogon.android.navigation.MoreRoutes.NOTIFICATIONS,
                            com.testlogon.android.navigation.MoreRoutes.MESSAGES,
                            com.testlogon.android.navigation.MoreRoutes.ACTIVITY,
                            com.testlogon.android.navigation.MoreRoutes.SAVED,
                            com.testlogon.android.navigation.MoreRoutes.ACHIEVEMENTS ->
                                onOpenRoute(route)
                            else -> Unit // coming-soon entries are non-interactive
                        }
                    },
                )
            }
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
