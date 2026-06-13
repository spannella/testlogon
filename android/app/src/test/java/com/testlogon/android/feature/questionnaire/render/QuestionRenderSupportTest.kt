package com.testlogon.android.feature.questionnaire.render

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-347 - pure JVM tests for [QuestionRenderSupport] (the android-free renderer helpers): text
 * coercion, single/multi choice mapping, slider value coercion + step derivation, timezone list
 * building, and the address encode/decode round-trip. No Compose rule needed.
 */
class QuestionRenderSupportTest {

    private fun sliderField(
        min: Double? = null,
        max: Double? = null,
        step: Double? = null,
    ): QuestionnaireField.Slider {
        val cfg = buildMap<String, Any?> {
            if (min != null) put("min", min)
            if (max != null) put("max", max)
            if (step != null) put("step", step)
        }
        return QuestionnaireField.Slider(
            questionId = "s1",
            sectionId = "sec",
            label = "Rate",
            required = false,
            configJson = cfg,
        )
    }

    private fun textField(maxLength: Int? = null): QuestionnaireField.Text =
        QuestionnaireField.Text(
            questionId = "t1",
            sectionId = "sec",
            label = "Name",
            required = false,
            configJson = if (maxLength != null) mapOf("maxLength" to maxLength) else emptyMap(),
        )

    // ---- text ----

    @Test
    fun text_blank_emitsEmpty() {
        assertEquals(AnswerValue.Empty, QuestionRenderSupport.textAnswer("   "))
    }

    @Test
    fun text_nonBlank_emitsText() {
        assertEquals(AnswerValue.Text("hi"), QuestionRenderSupport.textAnswer("hi"))
    }

    @Test
    fun text_softTrimsToMaxLength() {
        assertEquals("abc", QuestionRenderSupport.coerceText(textField(maxLength = 3), "abcdef"))
        assertEquals("ab", QuestionRenderSupport.coerceText(textField(maxLength = 5), "ab"))
        assertEquals("abcdef", QuestionRenderSupport.coerceText(textField(maxLength = null), "abcdef"))
    }

    @Test
    fun text_rehydrateReadsValue() {
        assertEquals("foo", QuestionRenderSupport.textOf(AnswerValue.Text("foo")))
        assertEquals("", QuestionRenderSupport.textOf(AnswerValue.Empty))
        assertEquals("", QuestionRenderSupport.textOf(null))
    }

    // ---- single choice ----

    @Test
    fun singleChoice_nullEmitsEmpty_elseText() {
        assertEquals(AnswerValue.Empty, QuestionRenderSupport.singleChoiceAnswer(null))
        assertEquals(AnswerValue.Empty, QuestionRenderSupport.singleChoiceAnswer(""))
        assertEquals(AnswerValue.Text("a"), QuestionRenderSupport.singleChoiceAnswer("a"))
    }

    @Test
    fun selectedOption_readsTextAndFirstOfChoices() {
        assertEquals("a", QuestionRenderSupport.selectedOption(AnswerValue.Text("a")))
        assertEquals("x", QuestionRenderSupport.selectedOption(AnswerValue.Choices(listOf("x", "y"))))
        assertEquals(null, QuestionRenderSupport.selectedOption(AnswerValue.Empty))
    }

    // ---- multiselect ----

    @Test
    fun multiselect_toggleOnPreservesOptionOrder() {
        val order = listOf("a", "b", "c")
        val result = QuestionRenderSupport.toggleMultiselect(
            current = listOf("c"),
            option = "a",
            checked = true,
            optionOrder = order,
        )
        assertEquals(AnswerValue.Choices(listOf("a", "c")), result)
    }

    @Test
    fun multiselect_toggleOffToEmptyEmitsEmpty() {
        val result = QuestionRenderSupport.toggleMultiselect(
            current = listOf("a"),
            option = "a",
            checked = false,
            optionOrder = listOf("a", "b"),
        )
        assertEquals(AnswerValue.Empty, result)
    }

    // ---- slider ----

    @Test
    fun slider_defaultsAndCoercion() {
        val f = sliderField()
        assertEquals(0.0f, QuestionRenderSupport.sliderMin(f), 0.0001f)
        assertEquals(100.0f, QuestionRenderSupport.sliderMax(f), 0.0001f)
        assertEquals(50.0f, QuestionRenderSupport.coerceSliderValue(f, 50.0f), 0.0001f)
        assertEquals(100.0f, QuestionRenderSupport.coerceSliderValue(f, 999.0f), 0.0001f)
        assertEquals(0.0f, QuestionRenderSupport.coerceSliderValue(f, -5.0f), 0.0001f)
    }

    @Test
    fun slider_maxBelowMinClamps() {
        val f = sliderField(min = 10.0, max = 5.0)
        assertEquals(10.0f, QuestionRenderSupport.sliderMin(f), 0.0001f)
        assertEquals(10.0f, QuestionRenderSupport.sliderMax(f), 0.0001f)
    }

    @Test
    fun slider_stepDerivesInternalStops() {
        // 0..10 step 1 -> 10 divisions -> 9 internal stops.
        assertEquals(9, QuestionRenderSupport.sliderSteps(sliderField(min = 0.0, max = 10.0, step = 1.0)))
        // no step -> continuous (0).
        assertEquals(0, QuestionRenderSupport.sliderSteps(sliderField(min = 0.0, max = 10.0)))
        // non-positive step -> continuous.
        assertEquals(0, QuestionRenderSupport.sliderSteps(sliderField(min = 0.0, max = 10.0, step = 0.0)))
    }

    @Test
    fun slider_answerIsNum_andRehydrates() {
        val f = sliderField(min = 0.0, max = 10.0)
        assertEquals(AnswerValue.Num(4.0), QuestionRenderSupport.sliderAnswer(4.0f))
        assertEquals(7.0f, QuestionRenderSupport.sliderValueOf(f, AnswerValue.Num(7.0)), 0.0001f)
        // out-of-range rehydration clamps.
        assertEquals(10.0f, QuestionRenderSupport.sliderValueOf(f, AnswerValue.Num(99.0)), 0.0001f)
    }

    @Test
    fun formatNumber_dropsTrailingZeroForIntegral() {
        assertEquals("4", QuestionRenderSupport.formatNumber(4.0))
        assertEquals("4.5", QuestionRenderSupport.formatNumber(4.5))
    }

    // ---- timezone ----

    @Test
    fun timezone_usesAllowedWhenPresent() {
        val f = QuestionnaireField.Timezone(
            questionId = "tz",
            sectionId = "sec",
            label = "TZ",
            required = false,
            configJson = mapOf("allowedTimezones" to listOf("America/New_York", "UTC")),
        )
        assertEquals(listOf("America/New_York", "UTC"), QuestionRenderSupport.timezoneOptions(f))
    }

    @Test
    fun timezone_fallsBackToAllSorted() {
        val f = QuestionnaireField.Timezone(
            questionId = "tz",
            sectionId = "sec",
            label = "TZ",
            required = false,
        )
        val zones = QuestionRenderSupport.timezoneOptions(f)
        assertTrue(zones.isNotEmpty())
        assertEquals(zones.sorted(), zones)
        assertTrue("UTC" in zones)
    }

    // ---- address round-trip ----

    @Test
    fun address_encodeDecodeRoundTrip() {
        val parts = mapOf(
            "line1" to "1 Main St",
            "city" to "Springfield",
            "country" to "US",
        )
        val encoded = QuestionRenderSupport.encodeAddress(parts)
        assertTrue(encoded is AnswerValue.Text)
        val decoded = QuestionRenderSupport.decodeAddress(encoded)
        assertEquals("1 Main St", decoded["line1"])
        assertEquals("Springfield", decoded["city"])
        assertEquals("US", decoded["country"])
        assertEquals(null, decoded["line2"])
    }

    @Test
    fun address_allBlankEmitsEmpty() {
        val encoded = QuestionRenderSupport.encodeAddress(mapOf("line1" to "", "city" to "  "))
        assertEquals(AnswerValue.Empty, encoded)
        assertEquals(emptyMap<String, String>(), QuestionRenderSupport.decodeAddress(encoded))
    }

    @Test
    fun address_encodingEscapesQuotes() {
        val parts = mapOf("line1" to """He said "hi"""", "city" to "A,B")
        val decoded = QuestionRenderSupport.decodeAddress(QuestionRenderSupport.encodeAddress(parts))
        assertEquals("""He said "hi"""", decoded["line1"])
        assertEquals("A,B", decoded["city"])
    }

    @Test
    fun address_decodeTolerantOfNonJson() {
        assertEquals(emptyMap<String, String>(), QuestionRenderSupport.decodeAddress(AnswerValue.Text("garbage")))
        assertEquals(emptyMap<String, String>(), QuestionRenderSupport.decodeAddress(AnswerValue.Empty))
        assertEquals(emptyMap<String, String>(), QuestionRenderSupport.decodeAddress(null))
    }
}
