package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue

/**
 * AND-350 - PURE (Android-free) helper implementing FR-2: a hidden question's captured value is RETAINED
 * (so toggling a controlling field back ON restores the prior answer - no data loss) but EXCLUDED from
 * the answers sent to validate / submit (a hidden question must not contribute an answer the server would
 * reject or persist).
 *
 * The ViewModel keeps the FULL working answer map (every value ever entered, including currently-hidden
 * ones - the "shadow"). When building the validate / submit body it calls [visibleAnswers] to drop the
 * hidden entries. Because the full map is retained, re-showing a field naturally restores its value; the
 * [mergeOnReshow] helper makes that explicit for callers that prune their own state.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object ShadowAnswers {

    /**
     * The answers to SEND: [all] restricted to the [visibleIds] set (hidden questions excluded). Order is
     * not significant for the wire map; this preserves [all]'s iteration order for determinism.
     */
    fun visibleAnswers(
        all: Map<String, AnswerValue>,
        visibleIds: Set<String>,
    ): Map<String, AnswerValue> = all.filterKeys { it in visibleIds }

    /**
     * Restores any previously-captured values for newly re-shown questions. Given the [shadow] (the full
     * retained map) and the [current] working map, returns [current] augmented with [shadow]'s entries
     * for every id in [visibleIds] that is absent from [current]. [current] values WIN (a fresh edit is
     * never clobbered by a stale shadow). This is a no-op when callers retain the full map themselves.
     */
    fun mergeOnReshow(
        shadow: Map<String, AnswerValue>,
        current: Map<String, AnswerValue>,
        visibleIds: Set<String>,
    ): Map<String, AnswerValue> {
        val merged = LinkedHashMap(current)
        for (id in visibleIds) {
            if (!merged.containsKey(id)) {
                shadow[id]?.let { merged[id] = it }
            }
        }
        return merged
    }
}
