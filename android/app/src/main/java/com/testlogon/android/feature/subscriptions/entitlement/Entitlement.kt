package com.testlogon.android.feature.subscriptions.entitlement

/**
 * AND-241 — the deterministic verdict of an entitlement check.
 *
 *  - [Granted]: the viewer is entitled (owns the required plan / is at-or-above the required tier level).
 *  - [Denied]: the viewer is not entitled and an upgrade would not help (e.g. only a lapsed subscription).
 *  - [RequiresUpgrade]: the viewer is below the required fan-club tier [minLevel] and can upgrade.
 *  - [Unknown]: the underlying data was unavailable — gates MUST treat this as not-entitled (fail closed).
 */
sealed interface Entitlement {
    data object Granted : Entitlement
    data class Denied(val reason: String) : Entitlement
    data class RequiresUpgrade(val minLevel: Int) : Entitlement
    data object Unknown : Entitlement
}

/**
 * AND-241 — identifies what is being gated.
 *
 *  - [Plan]: a specific subscription plan (the "tier" the user subscribes to). Owned == active sub at it.
 *  - [Content]: gated content, optionally requiring a minimum fan-club tier level.
 *  - [FanClub]: a creator's fan-club, optionally requiring a minimum tier level.
 *
 * Fan-club tiers carry an explicit numeric `level` rank (verified TierOut.level); plans have no rank, so
 * plan entitlement is exact-match on plan id. Higher [minLevel] = more privileged (see AND-241 §13 R3).
 */
sealed interface EntitlementKey {
    data class Plan(val planId: String) : EntitlementKey
    data class Content(val contentId: String, val minLevel: Int? = null) : EntitlementKey
    data class FanClub(val creatorId: String, val minLevel: Int? = null) : EntitlementKey
}
