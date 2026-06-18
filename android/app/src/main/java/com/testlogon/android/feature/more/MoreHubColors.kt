package com.testlogon.android.feature.more

import androidx.compose.ui.graphics.Color

/**
 * Visual-polish accent palette for the More hubs (and the Home shortcuts that mirror them).
 *
 * Each hub maps to a soft, muted "container" tone (light background for a small icon circle) plus a
 * darker "on" tone used to tint the icon. Colors are defined literally so they are independent of
 * theme regeneration and read well on the app's light surface. They are deliberately subtle, not
 * neon — colored icon chips on otherwise-neutral cards.
 */
data class HubAccent(val container: Color, val onAccent: Color)

/** Per-hub accent: a fixed palette of 8 distinct, pleasant, muted tones. */
fun MoreHub.accent(): HubAccent = when (this) {
    MoreHub.WALLET -> HubAccent(Color(0xFFE3E7FA), Color(0xFF3F4D9A)) // indigo
    MoreHub.STUDIO -> HubAccent(Color(0xFFD9F0EC), Color(0xFF1F6F63)) // teal
    MoreHub.GROWTH -> HubAccent(Color(0xFFFBEAD0), Color(0xFF8A5A12)) // amber
    MoreHub.COMMUNITY -> HubAccent(Color(0xFFF8E0E6), Color(0xFF9B3C54)) // rose
    MoreHub.SHOP -> HubAccent(Color(0xFFDDF0DD), Color(0xFF2E6B36)) // green
    MoreHub.INBOX -> HubAccent(Color(0xFFEBE2F6), Color(0xFF6A4296)) // violet
    MoreHub.ACCOUNT -> HubAccent(Color(0xFFDDEAF7), Color(0xFF2C5E8F)) // blue
    MoreHub.SUPPORT -> HubAccent(Color(0xFFE4E7EA), Color(0xFF4A555F)) // slate
}
