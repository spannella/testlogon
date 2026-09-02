package com.testlogon.android.data.crm

/**
 * CRM-AND-LED — PURE, framework-free logic for lead hygiene: duplicate detection, merge-conflict
 * resolution and score bucketing. No Android / java.time types, so every function here is
 * JVM-unit-testable (mirrors the [CrmSalesMath] idiom).
 *
 * Responsibilities:
 *  - normalise + compare lead emails so client-side duplicate hints match the backend's
 *    email-keyed `find_duplicates` (LED-009) without a round-trip.
 *  - rank a candidate duplicate set (exact-email first, then name similarity) for the merge picker.
 *  - resolve which non-empty field wins when merging a secondary lead into a primary (mirrors the
 *    backend "primary wins, secondary backfills blanks" merge rule in app/services/leads.py).
 *  - bucket a scoring-rules `max_score`-relative score into a coarse band (delegates to
 *    [CrmSalesMath.scoreBand] so the admin scoring-rules preview and the list badge agree).
 *
 * Degrade, never throw: null / blank / malformed inputs are treated as "nothing to show" rather
 * than raising, so a 404 (module disabled) or dev-host drift renders cleanly.
 */
object LeadHygieneMath {

    // ── Email normalisation + duplicate detection ────────────────────────────

    /**
     * Canonical form of a lead email for comparison: trimmed + lower-cased. Blank / null -> "".
     * Deliberately conservative (no gmail dot-stripping) so it matches the backend's plain
     * lower-case email key.
     */
    fun normalizeEmail(email: String?): String = email?.trim()?.lowercase().orEmpty()

    /** Two emails are "the same lead" when their normalised forms are equal and non-blank. */
    fun sameEmail(a: String?, b: String?): Boolean {
        val na = normalizeEmail(a)
        val nb = normalizeEmail(b)
        return na.isNotEmpty() && na == nb
    }

    /**
     * Client-side duplicate hint for the merge picker: from [candidates], the leads whose email
     * matches [primary]'s email (excluding [primary] itself by id). Mirrors the backend's
     * email-keyed find_duplicates so the UI can pre-flag without a round-trip; blank-email leads
     * never match (nothing to key on).
     */
    fun <T> duplicatesByEmail(
        primary: T,
        candidates: List<T>,
        idOf: (T) -> String,
        emailOf: (T) -> String?,
    ): List<T> {
        val primaryEmail = normalizeEmail(emailOf(primary))
        if (primaryEmail.isEmpty()) return emptyList()
        val primaryId = idOf(primary)
        return candidates.filter { c ->
            idOf(c) != primaryId && normalizeEmail(emailOf(c)) == primaryEmail
        }
    }

    // ── Merge-conflict resolution ────────────────────────────────────────────

    /**
     * The value that survives a field merge: the primary's value wins whenever it is present
     * (non-null, non-blank); otherwise the secondary backfills it. Mirrors the backend merge rule
     * (primary is authoritative, secondary only fills blanks). Both blank -> null.
     */
    fun resolveField(primary: String?, secondary: String?): String? {
        val p = primary?.trim().orEmpty()
        if (p.isNotEmpty()) return primary?.trim()
        val s = secondary?.trim().orEmpty()
        return if (s.isNotEmpty()) secondary?.trim() else null
    }

    /**
     * True when merging [secondary] into [primary] would actually change the primary — i.e. the
     * primary has at least one blank field that the secondary can backfill. Used to enable/disable
     * the "Merge" confirm button so a no-op merge isn't offered.
     */
    fun mergeWouldChange(primaryFields: List<String?>, secondaryFields: List<String?>): Boolean {
        val n = minOf(primaryFields.size, secondaryFields.size)
        for (i in 0 until n) {
            val p = primaryFields[i]?.trim().orEmpty()
            val s = secondaryFields[i]?.trim().orEmpty()
            if (p.isEmpty() && s.isNotEmpty()) return true
        }
        return false
    }

    // ── Score bucketing (scoring-rules preview) ──────────────────────────────

    /**
     * Bucket a score against an admin-configured [maxScore] cap. Delegates to [CrmSalesMath.scoreBand]
     * (single source of truth for the thirds split) so the scoring-rules admin preview and the leads
     * list badge always agree. A non-positive cap degrades to COLD.
     */
    fun scoreBucket(score: Int, maxScore: Int): CrmSalesMath.LeadScoreBand =
        CrmSalesMath.scoreBand(score, if (maxScore <= 0) CrmSalesMath.DEFAULT_MAX_SCORE else maxScore)

    /**
     * The sum of positive rule points, capped at [maxScore]. A preview of the theoretical maximum a
     * lead could reach under the current rule set (negative rules never lower the ceiling). Used by
     * the scoring-rules admin header. Degrades to 0 on an empty rule set.
     */
    fun maxAchievablePoints(rulePoints: List<Int>, maxScore: Int): Int {
        val cap = if (maxScore <= 0) CrmSalesMath.DEFAULT_MAX_SCORE else maxScore
        val positive = rulePoints.filter { it > 0 }.sum()
        return positive.coerceIn(0, cap)
    }
}
