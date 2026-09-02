package com.testlogon.android.data.adminfraud

/**
 * FIN-015 - PURE, framework-free logic for the admin fraud-detection console. No Android / Moshi /
 * java.time types, so every function here is JVM-unit-testable (mirrors the JiraMath / KbMath idiom).
 *
 * Responsibilities:
 *  - bucket the backend composite risk score (0-100, see UserRiskProfile.score) into a closed
 *    [RiskBucket] band (clamp out-of-range, never throw) + a stable user-facing label.
 *  - case-state gating: normalize the RAW case status token into [CaseState] (unknown-safe) and
 *    derive whether a case is still RESOLVABLE (open / not already resolved).
 *  - flag-state gating: whether a flag is still REVIEWABLE (pending only).
 *  - freeze gating: whether the freeze / unfreeze action is applicable given the current frozen flag
 *    (never offer freeze on an already-frozen user, nor unfreeze on a not-frozen one).
 *
 * degrade-on-404: callers treat a missing profile / empty queue as an honest-empty value, NOT an error;
 * this object only reasons over values it is given and never performs I/O.
 */
object FraudMath {

    /** Closed risk band derived from the composite 0-100 score. */
    enum class RiskBucket { LOW, MEDIUM, HIGH, CRITICAL }

    /** Closed case lifecycle state derived from the RAW server status token. */
    enum class CaseState { OPEN, INVESTIGATING, RESOLVED, UNKNOWN }

    /**
     * Score-band thresholds. Mirror the backend semantics where flag_score_threshold defaults to ~50
     * (a score at/above it is flag-worthy). We split the actionable half into HIGH / CRITICAL.
     */
    const val MEDIUM_MIN = 25
    const val HIGH_MIN = 50
    const val CRITICAL_MIN = 80

    /** Clamp any raw score into the valid 0..100 range (defensive; backend already validates). */
    fun clampScore(raw: Int): Int = when {
        raw < 0 -> 0
        raw > 100 -> 100
        else -> raw
    }

    /** Bucket a composite risk score (out-of-range values are clamped first). */
    fun bucket(score: Int): RiskBucket {
        val s = clampScore(score)
        return when {
            s >= CRITICAL_MIN -> RiskBucket.CRITICAL
            s >= HIGH_MIN -> RiskBucket.HIGH
            s >= MEDIUM_MIN -> RiskBucket.MEDIUM
            else -> RiskBucket.LOW
        }
    }

    /** Stable user-facing label for a bucket. */
    fun bucketLabel(bucket: RiskBucket): String = when (bucket) {
        RiskBucket.LOW -> "Low"
        RiskBucket.MEDIUM -> "Medium"
        RiskBucket.HIGH -> "High"
        RiskBucket.CRITICAL -> "Critical"
    }

    /** Convenience: bucket then label a raw score in one call. */
    fun scoreLabel(score: Int): String = bucketLabel(bucket(score))

    /**
     * Normalize the RAW case status token into a closed [CaseState]. Unknown / blank -> UNKNOWN, so the
     * UI never crashes on a server token it does not recognise.
     */
    fun caseState(raw: String?): CaseState = when (raw?.trim()?.lowercase()) {
        "open" -> CaseState.OPEN
        "investigating", "in_progress", "in_review" -> CaseState.INVESTIGATING
        "resolved", "closed" -> CaseState.RESOLVED
        else -> CaseState.UNKNOWN
    }

    /**
     * Whether a case is still resolvable. A case is resolvable while it is not already resolved AND has
     * no resolved_at timestamp. UNKNOWN state is treated as NOT resolvable (fail-closed) unless there is
     * clearly no resolution recorded yet.
     */
    fun isCaseResolvable(rawStatus: String?, resolvedAt: Long?): Boolean {
        if (resolvedAt != null && resolvedAt > 0L) return false
        return when (caseState(rawStatus)) {
            CaseState.OPEN, CaseState.INVESTIGATING -> true
            CaseState.RESOLVED -> false
            CaseState.UNKNOWN -> false
        }
    }

    /** Whether a flag is still reviewable (only PENDING flags accept a review decision). */
    fun isFlagReviewable(rawStatus: String?): Boolean =
        rawStatus?.trim()?.equals("pending", ignoreCase = true) == true

    /** Whether the FREEZE action should be offered (only when the user is not already frozen). */
    fun canFreeze(frozen: Boolean): Boolean = !frozen

    /** Whether the UNFREEZE action should be offered (only when the user is currently frozen). */
    fun canUnfreeze(frozen: Boolean): Boolean = frozen
}
