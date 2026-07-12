package com.testlogon.android.feature.dashboard

/** AND-066/AND-069 — stable Compose test tags shared by production and tests. */
object DashboardTestTags {
    const val LOADING = "dashboard_loading"
    const val CONTENT = "dashboard_content"
    const val LIST = "dashboard_list"
    const val EMPTY = "dashboard_empty"
    const val ERROR = "dashboard_error"
    const val OFFLINE = "dashboard_offline"
    const val STALE_BANNER = "dashboard_stale_banner"
    const val RETRY_ACTION = "dashboard_retry"
    const val REFRESH_ACTION = "dashboard_refresh"
    const val SUMMARY_WIDGET = "dashboard_summary"
    const val HIGHLIGHTS_WIDGET = "dashboard_highlights"
    const val QUICK_LINKS_WIDGET = "dashboard_quick_links"

    // Launchpad header + quick actions.
    const val PROFILE_ACTION = "dashboard_action_profile"
    const val ACTION_POST = "dashboard_action_post"
    const val ACTION_GO_LIVE = "dashboard_action_golive"
    const val ACTION_MESSAGES = "dashboard_action_messages"
    const val ACTION_WALLET = "dashboard_action_wallet"

    // Launchpad hub shortcuts.
    const val HUB_STUDIO = "dashboard_hub_studio"
    const val HUB_GROWTH = "dashboard_hub_growth"
    const val HUB_COMMUNITY = "dashboard_hub_community"
    const val HUB_SHOP = "dashboard_hub_shop"
    const val HUB_ALL = "dashboard_hub_all"
}
