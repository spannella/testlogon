package com.testlogon.android.core.model.questionnaire

/**
 * AND-350 - the pure, Android-free model for a CONDITIONAL predicate used by the questionnaire
 * branching / visibility logic (the QUESTIONNAIRES domain, epic E45).
 *
 * REVIEW CORRECTION (obey): the web client has NO conditional visibility; the `visible_when` predicate
 * this models is an ANDROID-SPECIFIC, UNVERIFIED design. The client mirrors server rule semantics ONLY
 * for fast inline UX - the SERVER is authoritative. Accordingly the parser that BUILDS a [Condition] is
 * deliberately LENIENT and FAILS OPEN (any unknown shape becomes [Always], i.e. visible); see the app
 * VisibilityParser. This file declares only the immutable predicate value types - no parsing, no
 * evaluation, no Android - so the evaluator can be unit-tested on the JVM.
 *
 * RECONCILIATION NOTE (core-model has no Moshi): like the rest of core-model this carries NO `@Json` /
 * `@JsonClass` annotations. It is never decoded directly from the wire - it is BUILT from the already
 * decoded opaque config_json map (the [QuestionnaireField.configJson] view) by the app-side lenient
 * parser, so no adapter / codegen / dependency is required.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
sealed interface Condition {

    /**
     * A single comparison of the answer for [questionId] against [value] using [op]. The operand
     * semantics are total over [Op] (see the app ConditionEvaluator): scalar EQ/NEQ, list membership
     * (IN/NOT_IN), numeric ordering (GT/GTE/LT/LTE), substring/membership (CONTAINS), and presence
     * (IS_ANSWERED/IS_EMPTY - which ignore [value]). A missing/absent answer is treated as empty; a
     * type mismatch yields false (never throws).
     */
    data class Compare(
        val questionId: String,
        val op: Op,
        val value: AnswerValue,
    ) : Condition

    /** Conjunction: true when EVERY child is true. An empty [of] is vacuously true. */
    data class All(val of: List<Condition>) : Condition

    /** Disjunction: true when ANY child is true. An empty [of] is vacuously false. */
    data class Any(val of: List<Condition>) : Condition

    /** Negation of [of]. */
    data class Not(val of: Condition) : Condition

    /**
     * The always-true predicate. This is the FAIL-OPEN default the lenient parser returns for any
     * unknown / unparseable `visible_when` shape, so the client NEVER hides content it cannot parse.
     */
    data object Always : Condition
}

/**
 * AND-350 - the comparison operators a [Condition.Compare] supports. Total set; the evaluator is
 * exhaustive over every entry. Operand handling is tolerant (a type mismatch is false, not a throw).
 */
enum class Op {
    /** Scalar equality. */
    EQ,

    /** Scalar inequality (the negation of [EQ]; a missing answer is NOT equal to a concrete value). */
    NEQ,

    /** Membership: the answer is one of the operand's choices/values. */
    IN,

    /** Non-membership: the answer is NOT one of the operand's choices/values. */
    NOT_IN,

    /** Numeric strictly-greater-than. */
    GT,

    /** Numeric greater-than-or-equal. */
    GTE,

    /** Numeric strictly-less-than. */
    LT,

    /** Numeric less-than-or-equal. */
    LTE,

    /** The answer (Choices list contains, or Text substring) contains the operand. */
    CONTAINS,

    /** Presence: the answer is non-empty (operand ignored). */
    IS_ANSWERED,

    /** Absence: the answer is empty / missing (operand ignored). */
    IS_EMPTY,
}
