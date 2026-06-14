package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.Condition
import com.testlogon.android.core.model.questionnaire.Op

/**
 * AND-350 - PURE (Android-free) LENIENT parser that builds a [Condition] from a field's already-decoded
 * `config_json` map (the AND-346 [com.testlogon.android.core.model.questionnaire.QuestionnaireField.configJson]
 * view), reading the optional `visible_when` slice.
 *
 * REVIEW CORRECTION (obey - FAIL OPEN): the web has NO conditional visibility; `visible_when` is an
 * ANDROID-SPECIFIC, UNVERIFIED design. Therefore ANY unknown op / key / shape (or a missing slice, or
 * anything this parser cannot confidently interpret) yields [Condition.Always] - the field stays
 * VISIBLE. The client NEVER hides content because of a rule it cannot parse; the SERVER still enforces
 * correctness on validate / submit. This parser NEVER throws.
 *
 * ASSUMED (UNVERIFIED) `visible_when` SHAPES this parser recognises (all optional; anything else falls
 * back to Always):
 *   - { "all": [ <cond>, ... ] }            -> [Condition.All]
 *   - { "any": [ <cond>, ... ] }            -> [Condition.Any]
 *   - { "not": <cond> }                     -> [Condition.Not]
 *   - { "question_id": "q", "op": "eq", "value": <v> }   -> [Condition.Compare]
 *       (also accepts the keys `questionId` / `field`, and `operator` for `op`)
 *   - op tokens (case-insensitive, "-" and "_" interchangeable): eq, neq|ne, in, not_in|nin,
 *       gt, gte|ge, lt, lte|le, contains, is_answered|answered, is_empty|empty
 *   - a bare presence shorthand: { "question_id": "q" } with no op -> IS_ANSWERED
 *   - value coercion to [AnswerValue]: Boolean -> Bool, Number -> Num, List -> Choices(strings),
 *       String -> Text, null/absent -> Empty
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object VisibilityParser {

    /** The config_json key carrying the (unverified) Android-only visibility predicate. */
    const val KEY_VISIBLE_WHEN = "visible_when"

    /**
     * Parses the `visible_when` predicate from [configJson]. Returns [Condition.Always] (FAIL OPEN) for a
     * null config, an absent / null slice, or any shape this parser cannot interpret. Never throws.
     */
    fun parse(configJson: Map<String, Any?>?): Condition {
        val raw = configJson?.get(KEY_VISIBLE_WHEN) ?: return Condition.Always
        return parseNode(raw)
    }

    /** Parses one predicate node; unknown / malformed -> [Condition.Always] (fail open). */
    private fun parseNode(node: Any?): Condition {
        val map = node as? Map<*, *> ?: return Condition.Always

        // Boolean combinators take precedence when present.
        readChildList(map["all"])?.let { return Condition.All(it) }
        readChildList(map["any"])?.let { return Condition.Any(it) }
        if (map.containsKey("not")) {
            val child = parseNode(map["not"])
            // A "not" that we could not parse degrades to Always (fail open) rather than Not(Always).
            return if (child is Condition.Always) Condition.Always else Condition.Not(child)
        }

        // Otherwise treat it as a single comparison.
        return parseCompare(map)
    }

    /**
     * Reads a list of child predicate nodes; null when [value] is not a list. Unparseable children
     * become [Condition.Always] (so they do not constrain visibility - fail open).
     */
    private fun readChildList(value: Any?): List<Condition>? {
        val list = value as? List<*> ?: return null
        return list.map { parseNode(it) }
    }

    /** Parses a single comparison; any missing question id or unknown op -> [Condition.Always]. */
    private fun parseCompare(map: Map<*, *>): Condition {
        val questionId = firstString(map, "question_id", "questionId", "field", "field_id")
            ?: return Condition.Always
        if (questionId.isBlank()) return Condition.Always

        val opToken = firstString(map, "op", "operator")
        val hasValueKey = map.containsKey("value")
        // Presence shorthand: a bare { question_id } with no op means "is answered".
        val op = if (opToken == null && !hasValueKey) Op.IS_ANSWERED else parseOp(opToken)
            ?: return Condition.Always

        val value = coerceValue(map["value"])
        return Condition.Compare(questionId = questionId, op = op, value = value)
    }

    /** Maps an op token (lenient on case / separators / synonyms) to an [Op]; null when unknown. */
    private fun parseOp(token: String?): Op? {
        val t = token?.trim()?.lowercase()?.replace('-', '_') ?: return null
        return when (t) {
            "eq", "equals", "==" -> Op.EQ
            "neq", "ne", "not_eq", "!=" -> Op.NEQ
            "in" -> Op.IN
            "not_in", "nin" -> Op.NOT_IN
            "gt" -> Op.GT
            "gte", "ge" -> Op.GTE
            "lt" -> Op.LT
            "lte", "le" -> Op.LTE
            "contains" -> Op.CONTAINS
            "is_answered", "answered" -> Op.IS_ANSWERED
            "is_empty", "empty" -> Op.IS_EMPTY
            else -> null
        }
    }

    /** Coerces an opaque operand into an [AnswerValue] (tolerant; null/absent -> [AnswerValue.Empty]). */
    private fun coerceValue(raw: Any?): AnswerValue = when (raw) {
        null -> AnswerValue.Empty
        is Boolean -> AnswerValue.Bool(raw)
        is Number -> AnswerValue.Num(raw.toDouble())
        is List<*> -> AnswerValue.Choices(raw.mapNotNull { it?.toString() })
        is String -> AnswerValue.Text(raw)
        else -> AnswerValue.Text(raw.toString())
    }

    private fun firstString(map: Map<*, *>, vararg keys: String): String? =
        keys.firstNotNullOfOrNull { map[it] as? String }
}
