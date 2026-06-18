package com.testlogon.android.navigation

import com.testlogon.android.feature.more.MoreHub

/**
 * AND-067 — the "More" hub-detail destination (`more/hub/{hubId}`). The hub tab's drill-down: a hub
 * tile on the More tab opens this screen, which lists that hub's items. [hubId] is the [MoreHub] name
 * (enum constant). Registered in the shell's inner tab NavController (the More tab's own back stack).
 */
data object MoreHubDest {
    const val ARG_HUB_ID = "hubId"
    const val ROUTE = "more/hub/{$ARG_HUB_ID}"

    fun build(hub: MoreHub): String = "more/hub/${hub.name}"

    /** Resolves the [ARG_HUB_ID] nav arg back to a [MoreHub]; null if unknown/missing. */
    fun hubFromArg(hubId: String?): MoreHub? =
        MoreHub.entries.firstOrNull { it.name == hubId }
}
