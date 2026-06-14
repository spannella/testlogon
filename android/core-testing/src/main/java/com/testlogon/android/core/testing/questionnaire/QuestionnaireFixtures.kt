package com.testlogon.android.core.testing.questionnaire

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireDto
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.QuestionnaireSection
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus

/**
 * AND-352 - SHARED, dependency-light fixtures for the questionnaire feature (epic E45) test suites.
 *
 * SCOPE (obey core-testing dependency rule): core-testing depends on core-MODEL ONLY, so EVERYTHING here
 * references ONLY core-model types - the AND-346 sealed [QuestionnaireField] hierarchy, [QuestionnaireDto]
 * + [QuestionnaireSection], [AnswerValue] and [RespondentSession]. There are NO core-network DTOs /
 * Moshi adapters here (those are core-network scoped; a fixture needing a :app or core-network type lives
 * in that module's own test source, not here). These are PURE in-memory domain builders, not JSON.
 *
 * WHY (anti-duplication): the per-module suites each hand-roll tiny throwaway schemas. This consolidates a
 * single realistic "one of every type" schema (with realistic config_json - options, slider bounds, date
 * bounds, a visible_when-gated field), a multi-section schema and answer/session sample builders so the
 * AND-352 integration test (and any future suite) shares one fixture instead of re-inventing one. It does
 * NOT replace the existing narrow per-test builders - it is additive.
 *
 * The nine real field types are exactly: text, select, multiselect, radio, slider, date, time, timezone,
 * address (+ Unknown for the forward-compat fallback). config_json keys mirror the opaque wire shape the
 * AND-350 validator / AND-347 renderer read (snake_case where the constraint reader expects it).
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object QuestionnaireFixtures {

    /** Stable section ids used by the multi-type and multi-section schemas. */
    const val SECTION_PRIMARY = "sec_primary"
    const val SECTION_SECONDARY = "sec_secondary"

    /** Stable question ids for the one-of-every-type schema (referenced by integration assertions). */
    const val Q_TEXT = "q_text"
    const val Q_SELECT = "q_select"
    const val Q_MULTISELECT = "q_multiselect"
    const val Q_RADIO = "q_radio"
    const val Q_SLIDER = "q_slider"
    const val Q_DATE = "q_date"
    const val Q_TIME = "q_time"
    const val Q_TIMEZONE = "q_timezone"
    const val Q_ADDRESS = "q_address"

    /**
     * The id of the visible_when-GATED field. It is hidden until [Q_RADIO] equals [GATE_TRIGGER_VALUE]
     * (an "other" radio choice), modelling the canonical "tell us more when you pick Other" flow. It is
     * REQUIRED, so once visible an empty value blocks submit (proving the AND-350 validator runs only over
     * visible fields, AND-351 FR-5).
     */
    const val Q_GATED = "q_gated_detail"

    /** The radio option that reveals [Q_GATED]. */
    const val GATE_TRIGGER_VALUE = "other"

    // ---- option catalogs ----

    private fun optionsConfig(vararg values: String): Map<String, Any?> =
        mapOf("options" to values.map { mapOf("value" to it, "label" to it.replaceFirstChar(Char::uppercase)) })

    // ---- the one-of-every-type schema (single section) ----

    /**
     * A single-section schema containing ONE field of each of the nine real types, with realistic
     * config_json: select/multiselect/radio carry [options], the slider carries min/max/step, the date
     * carries min_date/max_date bounds, and a REQUIRED [Q_GATED] text field carries a visible_when
     * predicate gated on [Q_RADIO] == [GATE_TRIGGER_VALUE]. Field declaration order is preserved (FR-1).
     */
    fun everyTypeSchema(): QuestionnaireDto = QuestionnaireDto(
        questionnaire_id = "qn_every_type",
        title = "Every field type",
        version_id = "v_every_1",
        sections = listOf(
            QuestionnaireSection(
                section_id = SECTION_PRIMARY,
                title = "All field types",
                position = 0,
                questions = everyTypeFields(),
            ),
        ),
    )

    /** The nine typed fields + the gated field, in declaration order (FR-1). */
    fun everyTypeFields(): List<QuestionnaireField> = listOf(
        QuestionnaireField.Text(
            questionId = Q_TEXT,
            sectionId = SECTION_PRIMARY,
            label = "Full name",
            required = true,
            hint = "Your legal name",
            position = 0,
            configJson = mapOf("placeholder" to "Jane Doe", "min_length" to 2, "max_length" to 80),
        ),
        QuestionnaireField.Select(
            questionId = Q_SELECT,
            sectionId = SECTION_PRIMARY,
            label = "Country",
            required = false,
            position = 1,
            configJson = optionsConfig("us", "ca", "uk"),
        ),
        QuestionnaireField.Multiselect(
            questionId = Q_MULTISELECT,
            sectionId = SECTION_PRIMARY,
            label = "Languages",
            required = false,
            position = 2,
            configJson = optionsConfig("en", "fr", "es") +
                mapOf("minSelections" to 1, "maxSelections" to 2),
        ),
        QuestionnaireField.Radio(
            questionId = Q_RADIO,
            sectionId = SECTION_PRIMARY,
            label = "Contact preference",
            required = false,
            position = 3,
            configJson = optionsConfig("email", "phone", GATE_TRIGGER_VALUE),
        ),
        QuestionnaireField.Slider(
            questionId = Q_SLIDER,
            sectionId = SECTION_PRIMARY,
            label = "Satisfaction",
            required = false,
            position = 4,
            configJson = mapOf("min" to 0.0, "max" to 10.0, "step" to 1.0),
        ),
        QuestionnaireField.DateField(
            questionId = Q_DATE,
            sectionId = SECTION_PRIMARY,
            label = "Date of birth",
            required = false,
            position = 5,
            configJson = mapOf("min_date" to "1900-01-01", "max_date" to "2025-12-31"),
        ),
        QuestionnaireField.TimeField(
            questionId = Q_TIME,
            sectionId = SECTION_PRIMARY,
            label = "Preferred time",
            required = false,
            position = 6,
        ),
        QuestionnaireField.Timezone(
            questionId = Q_TIMEZONE,
            sectionId = SECTION_PRIMARY,
            label = "Timezone",
            required = false,
            position = 7,
            configJson = mapOf("allowedTimezones" to listOf("UTC", "America/New_York", "Europe/London")),
        ),
        QuestionnaireField.Address(
            questionId = Q_ADDRESS,
            sectionId = SECTION_PRIMARY,
            label = "Mailing address",
            required = false,
            position = 8,
            configJson = mapOf("requiredFields" to listOf("line1", "city")),
        ),
        // The visible_when-gated, REQUIRED follow-up: shown only when the radio is GATE_TRIGGER_VALUE.
        QuestionnaireField.Text(
            questionId = Q_GATED,
            sectionId = SECTION_PRIMARY,
            label = "Please describe your preference",
            required = true,
            position = 9,
            configJson = mapOf(
                "visible_when" to mapOf(
                    "question_id" to Q_RADIO,
                    "op" to "eq",
                    "value" to GATE_TRIGGER_VALUE,
                ),
            ),
        ),
    )

    /**
     * An [QuestionnaireField.Unknown] forward-compat fallback fixture (FR-5). Carried separately because a
     * real schema never DECLARES an Unknown - the adapter PRODUCES it from an unrecognized wire token - so
     * it would never sit inside [everyTypeSchema]; tests that exercise the fallback opt in explicitly.
     */
    fun unknownField(rawType: String = "future_widget"): QuestionnaireField.Unknown =
        QuestionnaireField.Unknown(
            rawType = rawType,
            questionId = "q_unknown",
            sectionId = SECTION_PRIMARY,
            label = "Mystery field",
            required = false,
            configJson = mapOf("anything" to "preserved"),
        )

    // ---- a multi-section schema (paged navigation, FR-6) ----

    /**
     * A two-section schema: the first section holds a REQUIRED text field (so a Next on an empty first
     * page is BLOCKED, FR-6), the second holds an optional select. Exercises page-per-section layout and
     * the section-index navigation clamp.
     */
    fun multiSectionSchema(): QuestionnaireDto = QuestionnaireDto(
        questionnaire_id = "qn_multi_section",
        title = "Multi-section",
        version_id = "v_multi_1",
        sections = listOf(
            QuestionnaireSection(
                section_id = SECTION_PRIMARY,
                title = "About you",
                position = 0,
                questions = listOf(
                    QuestionnaireField.Text(
                        questionId = Q_TEXT,
                        sectionId = SECTION_PRIMARY,
                        label = "Full name",
                        required = true,
                        position = 0,
                    ),
                ),
            ),
            QuestionnaireSection(
                section_id = SECTION_SECONDARY,
                title = "Preferences",
                position = 1,
                questions = listOf(
                    QuestionnaireField.Select(
                        questionId = Q_SELECT,
                        sectionId = SECTION_SECONDARY,
                        label = "Country",
                        required = false,
                        position = 0,
                        configJson = optionsConfig("us", "ca", "uk"),
                    ),
                ),
            ),
        ),
    )

    // ---- AnswerValue + RespondentSession sample builders ----

    /**
     * A sample answer map for [everyTypeSchema] in which the radio is set to [GATE_TRIGGER_VALUE] (so the
     * gated field is visible) and every constrained field carries a VALID value, including the gated one.
     * A form seeded with these answers validates clean (the integration "valid form submits" path).
     */
    fun validAnswers(): Map<String, AnswerValue> = linkedMapOf(
        Q_TEXT to AnswerValue.Text("Jane Doe"),
        Q_SELECT to AnswerValue.Text("us"),
        Q_MULTISELECT to AnswerValue.Choices(listOf("en", "fr")),
        Q_RADIO to AnswerValue.Text(GATE_TRIGGER_VALUE),
        Q_SLIDER to AnswerValue.Num(7.0),
        Q_DATE to AnswerValue.Text("1990-05-04"),
        Q_TIME to AnswerValue.Text("09:30"),
        Q_TIMEZONE to AnswerValue.Text("UTC"),
        Q_GATED to AnswerValue.Text("Contact me on the weekend."),
    )

    /**
     * A RespondentSession sample over [everyTypeSchema] carrying [answers] (defaults to [validAnswers]).
     * Useful as the AND-348 resume seed for a hydration test.
     */
    fun sampleSession(
        answers: Map<String, AnswerValue> = validAnswers(),
        status: SessionStatus = SessionStatus.IN_PROGRESS,
    ): RespondentSession = RespondentSession(
        sessionId = "rs_fixture_1",
        slug = "every-type",
        questionnaireId = "qn_every_type",
        versionId = "v_every_1",
        answers = answers,
        status = status,
    )
}
