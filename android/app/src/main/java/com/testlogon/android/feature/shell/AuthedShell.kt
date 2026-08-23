package com.testlogon.android.feature.shell

import com.testlogon.android.feature.ads.cta.navigateCta
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.DynamicFeed
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Forum
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.ShowChart
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.DynamicFeed
import androidx.compose.material.icons.outlined.Explore
import androidx.compose.material.icons.outlined.Forum
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.ShowChart
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
    /** Whether this tab is rendered in the bottom [NavigationBar]; some tabs are inner-only. */
    val inNavBar: Boolean = true,
) {
    HOME("authed/home", R.string.tab_home, Icons.Filled.Home, Icons.Outlined.Home),
    FEED("authed/feed", R.string.tab_feed, Icons.Filled.DynamicFeed, Icons.Outlined.DynamicFeed),
    DISCOVER("authed/discover", R.string.tab_discover, Icons.Filled.Explore, Icons.Outlined.Explore),
    INVEST("authed/invest", R.string.tab_invest, Icons.Filled.ShowChart, Icons.Outlined.ShowChart),
    INBOX("authed/inbox", R.string.tab_inbox, Icons.Filled.Forum, Icons.Outlined.Forum),
    ME("authed/me", R.string.tab_me, Icons.Filled.Person, Icons.Outlined.Person, inNavBar = false),
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
                AuthedTab.entries.filter { it.inNavBar }.forEach { tab ->
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
        // One-time biometric-enrollment offer after a fresh login/registration (AND biometric).
        BiometricEnrollGate()
        // AND-067: shared "More" item routing — used by both the More tab's hub tiles' detail screen
        // and (historically) the flat grid. A few routes are in-shell tab jumps / dedicated callbacks;
        // everything else opens as an outer-graph destination (onOpenRoute guards unregistered routes).
        val onMoreNavigate: (String) -> Unit = onMoreNavigate@{ route ->
            when (route) {
                com.testlogon.android.navigation.MoreRoutes.PROFILE ->
                    tabNav.navigateToTab(AuthedTab.ME)
                com.testlogon.android.navigation.MoreRoutes.SESSIONS -> onOpenSessions()
                com.testlogon.android.navigation.MoreRoutes.MFA_DEVICES -> onOpenMfaDevices()
                com.testlogon.android.navigation.MoreRoutes.INVEST ->
                    tabNav.navigateToTab(AuthedTab.INVEST)
                else -> onOpenRoute(route)
            }
        }
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
                    onOpenRoute = onOpenRoute,
                    onOpenInbox = { tabNav.navigateToTab(AuthedTab.INBOX) },
                    // UX-2 launchpad tiles open a More hub. The hub-detail destination is registered in
                    // THIS inner tab NavController (not the outer graph), so drill into it on tabNav
                    // directly — routing it through onOpenRoute hits the outer graph where the route is
                    // unregistered and the runCatching guard silently dropped it (tiles did nothing).
                    onOpenHub = { hub ->
                        tabNav.navigate(com.testlogon.android.navigation.MoreHubDest.build(hub))
                    },
                )
            }
            composable(AuthedTab.FEED.route) {
                com.testlogon.android.feature.feed.FeedRoute(
                    onComposePost = { onOpenRoute(com.testlogon.android.navigation.ComposePostDest.build()) },
                    onOpenDiscover = { tabNav.navigateToTab(AuthedTab.DISCOVER) },
                    // FD11 — a visible 'Your posts' entry straight from the feed top bar.
                    onOpenMyPosts = { onOpenRoute(com.testlogon.android.navigation.MyPostsDest.ROUTE) },
                    // PAR-13 — scheduled-posts management from the feed top bar.
                    onOpenScheduledPosts = { onOpenRoute(com.testlogon.android.navigation.ScheduledPostsDest.ROUTE) },
                    // FD12 — Edit own post from the feed overflow.
                    onEditPost = { postId ->
                        onOpenRoute(com.testlogon.android.navigation.EditPostDest.build(postId))
                    },
                    onPostClick = { postId ->
                        onOpenRoute(com.testlogon.android.navigation.PostDetailDest.build(postId))
                    },
                    onAuthorClick = { authorId ->
                        onOpenRoute(com.testlogon.android.navigation.PublicProfileDest.build(authorId))
                    },
                    // AND-199 — open the full-screen story viewer for the tapped author.
                    onOpenStory = { userId ->
                        onOpenRoute(com.testlogon.android.navigation.StoryViewerDest.build(userId))
                    },
                    // PAR-01 — open the create-story screen from the "Your story" tray tile.
                    onCreateStory = {
                        onOpenRoute(com.testlogon.android.navigation.CreateStoryDest.build())
                    },
                    // ADV2-209 (F2): route a sponsored-unit CTA tap to product/cart/subscribe/profile.
                    onCtaNavigate = { dest -> tabNav.navigateCta(dest) },
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
                    // AND-184 + AND-190: recommendation taps now open the video detail + player
                    // route (previously a no-op awaiting AND-190's detail screen).
                    onOpenVideo = { videoId ->
                        onOpenRoute(com.testlogon.android.navigation.VideoDetailDest.build(videoId))
                    },
                )
            }
            // Unified INVEST hub, promoted to a first-class bottom-nav tab. The hub owns no detail
            // routes; each card / see-all deep-links through onOpenRoute into the outer graph, exactly
            // as when it was reached from the More hub / Dashboard.
            composable(AuthedTab.INVEST.route) {
                com.testlogon.android.feature.invest.InvestRoute(
                    onBack = { tabNav.navigateToTab(AuthedTab.HOME) },
                    onOpenRoute = onOpenRoute,
                )
            }
            // Inbox — the conversation list, promoted to a first-class bottom-nav tab. Its row/search/
            // group-create taps open the same outer-graph messaging destinations the More hub uses.
            composable(AuthedTab.INBOX.route) {
                com.testlogon.android.feature.messaging.list.ConversationListRoute(
                    onOpenConversation = { id ->
                        onOpenRoute(com.testlogon.android.feature.messaging.nav.MessagingRoutes.thread(id))
                    },
                    onOpenSearch = {
                        onOpenRoute(com.testlogon.android.feature.messaging.nav.MessagingRoutes.SEARCH)
                    },
                    onNewGroup = {
                        onOpenRoute(com.testlogon.android.feature.messaging.nav.MessagingRoutes.GROUP_CREATE)
                    },
                    // Inbox is a top-level tab; its back arrow returns to Home (was a no-op {}).
                    onBack = { tabNav.navigateToTab(AuthedTab.HOME) },
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
                    // FD1 -- "Your posts" management surface.
                    onOpenMyPosts = {
                        onOpenRoute(com.testlogon.android.navigation.MyPostsDest.ROUTE)
                    },
                    onOpenHighlights = {
                        onOpenRoute(com.testlogon.android.navigation.HighlightsDest.buildForSelf())
                    },
                )
            }
            composable(AuthedTab.MORE.route) {
                com.testlogon.android.feature.more.MoreRoute(
                    // AND-067 IA: the More tab now shows hub tiles; a tap drills into the hub-detail
                    // screen registered below (in this tab's own back stack).
                    onOpenHub = { hub ->
                        tabNav.navigate(com.testlogon.android.navigation.MoreHubDest.build(hub))
                    },
                    onNavigate = { route -> onMoreNavigate(route) },
                )
            }
            // AND-067 IA: the hub-detail screen. Reads the hubId nav arg and reuses the shared
            // [onMoreNavigate] so every item destination keeps routing exactly as before.
            composable(com.testlogon.android.navigation.MoreHubDest.ROUTE) { backStackEntry ->
                val hubId = backStackEntry.arguments
                    ?.getString(com.testlogon.android.navigation.MoreHubDest.ARG_HUB_ID)
                val hub = com.testlogon.android.navigation.MoreHubDest.hubFromArg(hubId)
                if (hub == null) {
                    tabNav.popBackStack()
                } else {
                    com.testlogon.android.feature.more.MoreHubRoute(
                        hub = hub,
                        onBack = { tabNav.popBackStack() },
                        onNavigate = { route -> onMoreNavigate(route) },
                    )
                }
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
