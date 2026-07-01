package com.testlogon.android.feature.more

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.Diversity3
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material.icons.outlined.AdminPanelSettings
import androidx.compose.material.icons.outlined.ManageAccounts
import androidx.compose.material.icons.outlined.MovieCreation
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material.icons.outlined.TrendingUp
import androidx.compose.ui.graphics.vector.ImageVector
import com.testlogon.android.R

/**
 * AND-067 — descriptor model for the "More" feature directory.
 *
 * Each [MoreEntry] is a static descriptor (icon, label, target route, hub, section, availability gate).
 * The hub owns no business data — it is a routing surface. Capability/feature-flag types are not yet
 * available at M2, so gating is by route registration plus an explicit [comingSoon] flag
 * (built-but-unavailable → Disabled).
 */
data class MoreEntry(
    val id: String,
    @StringRes val labelRes: Int,
    val icon: ImageVector,
    val route: String,
    /** Top-level drill-down hub this entry lives under (the More tab's IA grouping). */
    val hub: MoreHub,
    val section: MoreSection,
    /** When true the entry renders Disabled("coming soon") regardless of route registration. */
    val comingSoon: Boolean = false,
    /**
     * When true the entry is operator/admin-only: it resolves to [EntryAvailability.Hidden] for the
     * member app so it is not advertised to non-operators (the backend still 403s as defence in depth).
     * No authoritative client-side role signal exists on this cookie-session client (GET /ui/me carries
     * no role; AdminRoleProvider defaults to UNKNOWN), so these entries are statically hidden in-app.
     */
    val operatorOnly: Boolean = false,
)

/**
 * Top-level drill-down hubs for the "More" tab. The flat ~74-entry grid is reorganised into these
 * eight scannable hubs; each [MoreEntry] declares its [MoreEntry.hub] and the existing [MoreSection]
 * can sub-group within a hub's detail screen.
 */
enum class MoreHub(
    @StringRes val titleRes: Int,
    val icon: ImageVector,
) {
    WALLET(R.string.more_hub_wallet, Icons.Outlined.AccountBalanceWallet),
    STUDIO(R.string.more_hub_studio, Icons.Outlined.MovieCreation),
    GROWTH(R.string.more_hub_growth, Icons.Outlined.TrendingUp),
    COMMUNITY(R.string.more_hub_community, Icons.Outlined.Diversity3),
    SHOP(R.string.more_hub_shop, Icons.Outlined.Storefront),
    INBOX(R.string.more_hub_inbox, Icons.Outlined.Inbox),
    ACCOUNT(R.string.more_hub_account, Icons.Outlined.ManageAccounts),
    SUPPORT(R.string.more_hub_support, Icons.Outlined.SupportAgent),
    ADMIN(R.string.more_hub_admin, Icons.Outlined.AdminPanelSettings),
}

enum class MoreSection(@StringRes val titleRes: Int) {
    ACCOUNT(R.string.more_section_account),
    SECURITY(R.string.more_section_security),
    APP(R.string.more_section_app),
    SUPPORT(R.string.more_section_support),
}

/** Resolved availability of an entry at render time. */
sealed interface EntryAvailability {
    data object Available : EntryAvailability
    data object Hidden : EntryAvailability
    data class Disabled(@StringRes val reasonRes: Int) : EntryAvailability
}

/** UI projection consumed by the screen. */
sealed interface MoreUiState {
    data object Loading : MoreUiState
    data object Empty : MoreUiState

    /**
     * The resolved directory. [hubs] is the top-level drill-down grouping used by the More tab;
     * [sections] is retained as the flat section grouping (used by the legacy projection + tests).
     */
    data class Content(
        val hubs: List<MoreHubUi>,
        val sections: List<MoreSectionUi>,
    ) : MoreUiState
}

data class MoreSectionUi(val section: MoreSection, val items: List<MoreItemUi>)

/** A top-level hub plus its available (non-Hidden) items, for the hub tile + hub-detail screen. */
data class MoreHubUi(val hub: MoreHub, val items: List<MoreItemUi>)

data class MoreItemUi(val entry: MoreEntry, val availability: EntryAvailability)
