package com.testlogon.android.feature.legal

/**
 * PAR-29 — legal constants mirrored from the iOS `Legal/LegalConstants.swift`. Single source of truth for
 * the current Terms version, the minimum sign-up age, and the support contact address.
 */
object LegalConstants {
    /** The current Terms of Service version. Bump when the Terms text materially changes. */
    const val CURRENT_TERMS_VERSION = "2026-01-01"

    /** Minimum age (whole years) required to use the service. */
    const val MINIMUM_AGE = 18

    /** Support / contact email surfaced on the Contact screen + used as the mailto target. */
    const val SUPPORT_EMAIL = "support@testlogon.com"
}
