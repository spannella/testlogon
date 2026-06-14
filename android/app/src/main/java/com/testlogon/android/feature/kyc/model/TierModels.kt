package com.testlogon.android.feature.kyc.model

import java.time.Instant

// AND-320 — domain model for the KYC Tier Status surface. Tier levels are plain integers 0..4; the
// human tier NAME and the per-requirement LABEL are presentation concerns resolved at the UI via the
// @StringRes maps in TierStrings.kt (the model carries only the integer level and the opaque requirement
// key). Timestamps are java.time.Instant (mapped from epoch seconds in the data layer).

/** The highest verification tier. Promotion beyond this is not possible; the checklist is hidden at it. */
const val MAX_TIER: Int = 4

/** A verification tier identified by its integer [level] (0..[MAX_TIER]). The display name is UI-resolved. */
data class Tier(val level: Int)

/**
 * A single requirement for the target tier. [key] is the opaque wire key (e.g. "email_verified"); [met]
 * is whether it is satisfied. [label] is an optional pre-resolved human label; when null the UI resolves
 * it from [key] (falling back to the key itself for unknown keys).
 */
data class Requirement(
    val key: String,
    val met: Boolean,
    val label: String? = null,
)

/** One tier-change history entry (audit trail shown under the current-tier card). */
data class TierHistory(
    val fromTier: Int,
    val toTier: Int,
    val changedAt: Instant,
    val reason: String,
    val caseId: String? = null,
)

/**
 * The full tier-status snapshot rendered by the screen.
 *
 * [current] is the caller's tier; [target] is the next tier (null at [MAX_TIER]); [requirements] are the
 * target's checklist (met-first); [eligibleForTarget] reflects the server's eligible flag; [asOf] stamps
 * when the snapshot was assembled (used for the cache + stale display).
 */
data class TierStatus(
    val current: Tier,
    val updatedAt: Instant?,
    val history: List<TierHistory>,
    val target: Tier?,
    val requirements: List<Requirement>,
    val eligibleForTarget: Boolean,
    val asOf: Instant,
)

/** Result of an Evaluate action: the refreshed [tierStatus] + whether the tier was [promoted]. */
data class TierEvaluation(
    val tierStatus: TierStatus,
    val promoted: Boolean,
)
