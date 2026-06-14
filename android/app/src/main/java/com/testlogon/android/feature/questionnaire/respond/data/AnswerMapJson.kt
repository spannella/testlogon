package com.testlogon.android.feature.questionnaire.respond.data

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.testlogon.android.core.model.questionnaire.AnswerValue

/**
 * AND-348 - serializes the answers map (questionId -> [AnswerValue]) to/from the JSON stored in
 * [com.testlogon.android.core.data.respond.SessionDraftEntity.answersJson].
 *
 * Uses the INJECTED shared [Moshi] (which already has AND-346's custom AnswerValueAdapter registered),
 * so no new dependency and no hand-rolled JSON. Decoding is failure-proof: a malformed / empty blob
 * yields an empty map rather than throwing (mirrors the AnswerValue-never-throws contract). The
 * resulting map preserves insertion order (LinkedHashMap) for stable round-trips.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
class AnswerMapJson(moshi: Moshi) {

    private val adapter = moshi.adapter<Map<String, AnswerValue>>(
        Types.newParameterizedType(
            Map::class.java,
            String::class.java,
            AnswerValue::class.java,
        ),
    )

    /** Serializes [answers] to a JSON object string (empty map -> "{}"). */
    fun encode(answers: Map<String, AnswerValue>): String = adapter.toJson(answers)

    /** Deserializes [json] back to an answers map; null / blank / malformed -> empty map (never throws). */
    fun decode(json: String?): Map<String, AnswerValue> {
        if (json.isNullOrBlank()) return emptyMap()
        return runCatching { adapter.fromJson(json) }.getOrNull() ?: emptyMap()
    }
}
