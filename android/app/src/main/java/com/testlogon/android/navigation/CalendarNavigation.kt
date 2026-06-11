package com.testlogon.android.navigation

import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.calendar.CalendarRoute
import com.testlogon.android.feature.calendar.content.ContentCalendarRoute
import com.testlogon.android.feature.calendar.detail.EventDetailRoute
import com.testlogon.android.feature.calendar.integrations.GoogleCalendarConnectRoute
import com.testlogon.android.feature.calendar.scheduler.SchedulerListRoute
import com.testlogon.android.feature.calendar.scheduler.SchedulerRoute

/**
 * AND-271 — registers the calendar Month/Week/Agenda screen (`calendar`). Tapping an event routes to
 * the AND-272 event detail destination.
 */
fun NavGraphBuilder.calendarDestination(navController: NavHostController) {
    composable(CalendarDest.ROUTE) {
        CalendarRoute(
            onBack = { navController.popBackStack() },
            onEventClick = { calendarId, eventId ->
                navController.navigate(EventDetailDest.build(calendarId, eventId)) {
                    launchSingleTop = true
                }
            },
        )
    }
}

/**
 * AND-274 — registers the read-only content-calendar schedule view (`content_calendar`). A row tap hands
 * off to the AND-275 scheduler edit sheet (the content id is passed as the action id).
 */
fun NavGraphBuilder.contentCalendarDestination(navController: NavHostController) {
    composable(ContentCalendarDest.ROUTE) {
        ContentCalendarRoute(
            onBack = { navController.popBackStack() },
            onItemClick = { contentId ->
                navController.navigate(SchedulerEditDest.edit(contentId)) { launchSingleTop = true }
            },
        )
    }
}

/**
 * AND-275 — registers the scheduler list (`scheduler`) + the create/edit sheet
 * (`scheduler/edit?...`). The list FAB opens create; a pending row opens edit.
 */
fun NavGraphBuilder.schedulerDestinations(navController: NavHostController) {
    composable(SchedulerListDest.ROUTE) {
        SchedulerListRoute(
            onBack = { navController.popBackStack() },
            onCreate = { navController.navigate(SchedulerEditDest.create()) { launchSingleTop = true } },
            onEdit = { actionId ->
                navController.navigate(SchedulerEditDest.edit(actionId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = SchedulerEditDest.ROUTE,
        arguments = listOf(
            navArgument(SchedulerEditDest.ARG_ACTION_ID) {
                type = NavType.StringType; nullable = true; defaultValue = null
            },
            navArgument(SchedulerEditDest.ARG_SCHEDULED_AT) {
                type = NavType.StringType; nullable = true; defaultValue = null
            },
            navArgument(SchedulerEditDest.ARG_ACTION_TYPE) {
                type = NavType.StringType; nullable = true; defaultValue = null
            },
        ),
    ) {
        SchedulerRoute(onDismiss = { navController.popBackStack() })
    }
}

/**
 * AND-273 — registers the Google Calendar Connect screen (`calendar/integrations/google`). The
 * backend-mediated OAuth Custom-Tab return refreshes status on resume; an optional custom-scheme deep
 * link is handled by the return dispatcher (see MainActivity).
 */
fun NavGraphBuilder.googleCalendarDestination(navController: NavHostController) {
    composable(GoogleCalendarDest.ROUTE) {
        GoogleCalendarConnectRoute(onBack = { navController.popBackStack() })
    }
}

/**
 * AND-272 — registers the event detail destination with its in-app route + public App Link / dev-host /
 * custom-scheme deep links. Registered in BOTH graphs (the public read is auth-optional). On a cold
 * deep-link start the back stack may be empty; Back falls back to the graph start.
 */
fun NavGraphBuilder.eventDetailDestination(navController: NavHostController) {
    composable(
        route = EventDetailDest.ROUTE,
        arguments = listOf(
            navArgument(EventDetailDest.ARG_CALENDAR_ID) { type = NavType.StringType },
            navArgument(EventDetailDest.ARG_EVENT_ID) { type = NavType.StringType },
            navArgument(EventDetailDest.ARG_IS_PUBLIC) {
                type = NavType.StringType
                defaultValue = "false"
            },
        ),
        deepLinks = eventDetailDeepLinks(),
    ) {
        EventDetailRoute(
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}

/**
 * Deep links for `/event/{calendarId}/{eventId}`: a verified HTTPS App Link on the production host, a
 * plaintext HTTP tap-through on the dev host, and a custom-scheme fallback for share flows. The public
 * variants set isPublic so the unauthenticated reduced payload is fetched.
 */
private fun eventDetailDeepLinks(): List<NavDeepLink> {
    val path = EventDetailDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{calendarId}/{eventId}?isPublic={isPublic}" },
        navDeepLink { uriPattern = "https://{host}$path/{calendarId}/{eventId}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{calendarId}/{eventId}" },
        navDeepLink { uriPattern = "testlogon://event/{calendarId}/{eventId}" },
    )
}
