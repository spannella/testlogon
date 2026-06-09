package com.testlogon.android.feature.more

import androidx.annotation.StringRes
import androidx.compose.ui.graphics.vector.ImageVector
import com.testlogon.android.R

/**
 * AND-067 — descriptor model for the "More" feature directory.
 *
 * Each [MoreEntry] is a static descriptor (icon, label, target route, section, availability gate).
 * The hub owns no business data — it is a routing surface. Capability/feature-flag types are not yet
 * available at M2, so gating is by route registration plus an explicit [comingSoon] flag
 * (built-but-unavailable → Disabled).
 */
data class MoreEntry(
    val id: String,
    @StringRes val labelRes: Int,
    val icon: ImageVector,
    val route: String,
    val section: MoreSection,
    /** When true the entry renders Disabled("coming soon") regardless of route registration. */
    val comingSoon: Boolean = false,
)

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
    data class Content(val sections: List<MoreSectionUi>) : MoreUiState
}

data class MoreSectionUi(val section: MoreSection, val items: List<MoreItemUi>)
data class MoreItemUi(val entry: MoreEntry, val availability: EntryAvailability)
