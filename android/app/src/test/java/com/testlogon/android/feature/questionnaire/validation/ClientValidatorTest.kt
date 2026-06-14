package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.FieldOption
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE [ClientValidator] (inline-only fast feedback). Covers required,
 * min/max length, numeric min/max, pattern, choice membership, date range, and skips hidden +
 * unanswered-optional fields. The server remains authoritative; these are local inline issues only.
 */
class ClientValidatorTest {

    private fun text(
        id: String,
        required: Boolean = false,
        config: Map<String, Any?> = emptyMap(),
    ) = QuestionnaireField.Text(
        questionId = id, sectionId = "s", label = id, required = required, configJson = config,
    )

    private fun codes(
        result: Map<String, List<ClientValidator.LocalIssue>>,
        id: String,
    ): List<String> = result[id]?.map { it.code }.orEmpty()

    @Test
    fun required_empty_flags() {
        val result = ClientValidator.validate(listOf(text("q", required = true)), emptyMap())
        assertEquals(listOf(ClientValidator.Codes.REQUIRED), codes(result, "q"))
    }

    @Test
    fun optional_unanswered_skipped() {
        val result = ClientValidator.validate(listOf(text("q", required = false)), emptyMap())
        assertTrue(result.isEmpty())
    }

    @Test
    fun minMaxLength_snakeAndCamel() {
        val snake = text("q", config = mapOf("min_length" to 3, "max_length" to 5))
        val tooShort = ClientValidator.validate(listOf(snake), mapOf("q" to AnswerValue.Text("ab")))
        assertEquals(listOf(ClientValidator.Codes.MIN_LENGTH), codes(tooShort, "q"))
        val tooLong = ClientValidator.validate(listOf(snake), mapOf("q" to AnswerValue.Text("abcdef")))
        assertEquals(listOf(ClientValidator.Codes.MAX_LENGTH), codes(tooLong, "q"))

        val camel = text("q", config = mapOf("minLength" to 3))
        val ok = ClientValidator.validate(listOf(camel), mapOf("q" to AnswerValue.Text("abc")))
        assertTrue(ok.isEmpty())
    }

    @Test
    fun numericMinMax() {
        val slider = QuestionnaireField.Slider(
            questionId = "n", sectionId = "s", label = "n", required = false,
            configJson = mapOf("min" to 1, "max" to 10),
        )
        val low = ClientValidator.validate(listOf(slider), mapOf("n" to AnswerValue.Num(0.0)))
        assertEquals(listOf(ClientValidator.Codes.MIN), codes(low, "n"))
        val high = ClientValidator.validate(listOf(slider), mapOf("n" to AnswerValue.Num(99.0)))
        assertEquals(listOf(ClientValidator.Codes.MAX), codes(high, "n"))
    }

    @Test
    fun pattern() {
        val f = text("q", config = mapOf("pattern" to "[0-9]+"))
        val bad = ClientValidator.validate(listOf(f), mapOf("q" to AnswerValue.Text("abc")))
        assertEquals(listOf(ClientValidator.Codes.PATTERN), codes(bad, "q"))
        val good = ClientValidator.validate(listOf(f), mapOf("q" to AnswerValue.Text("123")))
        assertTrue(good.isEmpty())
    }

    @Test
    fun choiceMembership() {
        val select = QuestionnaireField.Select(
            questionId = "c", sectionId = "s", label = "c", required = false,
            configJson = mapOf("options" to listOf(mapOf("value" to "a"), mapOf("value" to "b"))),
        )
        val invalid = ClientValidator.validate(listOf(select), mapOf("c" to AnswerValue.Text("z")))
        assertEquals(listOf(ClientValidator.Codes.CHOICE), codes(invalid, "c"))
        val valid = ClientValidator.validate(listOf(select), mapOf("c" to AnswerValue.Text("a")))
        assertTrue(valid.isEmpty())
    }

    @Test
    fun dateRange() {
        val f = QuestionnaireField.DateField(
            questionId = "d", sectionId = "s", label = "d", required = false,
            configJson = mapOf("min_date" to "2026-01-01", "max_date" to "2026-12-31"),
        )
        val before = ClientValidator.validate(listOf(f), mapOf("d" to AnswerValue.Text("2025-06-01")))
        assertEquals(listOf(ClientValidator.Codes.MIN_DATE), codes(before, "d"))
        val after = ClientValidator.validate(listOf(f), mapOf("d" to AnswerValue.Text("2027-01-01")))
        assertEquals(listOf(ClientValidator.Codes.MAX_DATE), codes(after, "d"))
        val ok = ClientValidator.validate(listOf(f), mapOf("d" to AnswerValue.Text("2026-06-15")))
        assertTrue(ok.isEmpty())
    }

    @Test
    fun hiddenFieldsAreNeverValidated() {
        // Only the VISIBLE subset is passed in; a required field NOT in the list contributes nothing.
        val visible = listOf(text("shown", required = true))
        val result = ClientValidator.validate(visible, mapOf("shown" to AnswerValue.Text("v")))
        assertTrue(result.isEmpty())
        // Sanity: the option type with a label still resolves membership (no crash on FieldOption).
        assertEquals("opt", FieldOption("opt").value)
    }
}
