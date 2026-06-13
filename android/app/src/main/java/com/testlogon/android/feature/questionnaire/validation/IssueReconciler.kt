package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.ValidationIssue

/**
 * AND-350 - PURE (Android-free) merge of LOCAL inline issues (ClientValidator) with SERVER errors
 * (FR-5 / FR-7). Two responsibilities:
 *
 *  1. SPLIT the server error keys: a BARE questionId is a per-field issue (shown INLINE under that
 *     field); a key prefixed `group:` or `form:` is a cross-field / form-level issue (shown in a
 *     FORM-LEVEL BANNER). The respondent validate / submit body sends EMPTY form_rules / group_rules -
 *     the server derives those cross-field rules from the published version - so the client only ever
 *     RECEIVES (never sends) these prefixed keys.
 *
 *  2. UNION + DE-DUP per field by issue `code`: for each question the local + server issues are merged,
 *     de-duplicated by code, with the SERVER winning on display (the authoritative message replaces the
 *     local fallback for the same code). The per-field inline string is the FIRST blocking-or-any issue
 *     of that merged set (mirroring the AND-348 flattening).
 *
 * REVIEW CORRECTION (obey): the SERVER is authoritative, so server issues are ALWAYS surfaced (even for
 * rules the client cannot model, e.g. a group rule) and win on display for a shared code.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object IssueReconciler {

    /** Server error-key prefixes that route to the form-level banner instead of an inline field. */
    const val PREFIX_GROUP = "group:"
    const val PREFIX_FORM = "form:"

    /** The reconciled view: inline per-field messages + the ordered form-level banner messages. */
    data class Reconciled(
        val fieldErrors: Map<String, String>,
        val formBannerIssues: List<String>,
    )

    /**
     * Reconciles [localIssues] (questionId -> local issues) with [serverErrors] (raw wire map: bare
     * questionId or `group:` / `form:` prefixed -> issues).
     *
     * Field-keyed entries (bare questionId, present in either source) are merged + de-duped by code
     * (server wins) into a single inline message. Prefixed keys go to the banner. Determinism: field
     * order follows local-then-server first-seen iteration; banner order follows server iteration.
     */
    fun reconcile(
        localIssues: Map<String, List<ClientValidator.LocalIssue>>,
        serverErrors: Map<String, List<ValidationIssue>>,
    ): Reconciled {
        // Partition server errors into field-keyed vs banner-keyed.
        val serverFieldErrors = LinkedHashMap<String, List<ValidationIssue>>()
        val bannerIssues = mutableListOf<String>()
        for ((key, issues) in serverErrors) {
            if (isBannerKey(key)) {
                issues.forEach { bannerIssues.add(it.message) }
            } else {
                serverFieldErrors[key] = issues
            }
        }

        // The union of question ids that have any field-level issue (local first, then server).
        val questionIds = LinkedHashSet<String>().apply {
            addAll(localIssues.keys)
            addAll(serverFieldErrors.keys)
        }

        val fieldErrors = LinkedHashMap<String, String>()
        for (id in questionIds) {
            val merged = mergeByCode(
                local = localIssues[id].orEmpty(),
                server = serverFieldErrors[id].orEmpty(),
            )
            chooseMessage(merged)?.let { fieldErrors[id] = it }
        }

        return Reconciled(fieldErrors = fieldErrors, formBannerIssues = bannerIssues.distinct())
    }

    /** A merged issue for display: [code] + [message] + whether it is server-blocking (display order). */
    private data class MergedIssue(val code: String, val message: String, val blocking: Boolean)

    /**
     * Merges local + server issues for one field, de-duped by code. The SERVER wins on display for a
     * shared code (its message + blocking flag replace the local fallback). First-seen order is
     * preserved (local first, then any server-only codes).
     */
    private fun mergeByCode(
        local: List<ClientValidator.LocalIssue>,
        server: List<ValidationIssue>,
    ): List<MergedIssue> {
        val byCode = LinkedHashMap<String, MergedIssue>()
        for (issue in local) {
            byCode[issue.code] = MergedIssue(issue.code, issue.message, blocking = false)
        }
        for (issue in server) {
            // Server wins on display (overwrites a same-code local entry; keeps its first-seen slot).
            byCode[issue.code] = MergedIssue(
                code = issue.code,
                message = issue.message,
                blocking = issue.blocking == true,
            )
        }
        return byCode.values.toList()
    }

    /** The single inline message for a field: the first blocking issue if any, else the first issue. */
    private fun chooseMessage(merged: List<MergedIssue>): String? {
        if (merged.isEmpty()) return null
        val chosen = merged.firstOrNull { it.blocking } ?: merged.first()
        return chosen.message
    }

    private fun isBannerKey(key: String): Boolean =
        key.startsWith(PREFIX_GROUP) || key.startsWith(PREFIX_FORM)
}
