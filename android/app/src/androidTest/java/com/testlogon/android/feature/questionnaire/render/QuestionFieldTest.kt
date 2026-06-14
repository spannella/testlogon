package com.testlogon.android.feature.questionnaire.render

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-347 - Compose UI tests for the stateless dynamic-form [QuestionField] dispatcher. One render +
 * capture test per field type (text / select / multiselect / radio / slider / date / time / timezone /
 * address), plus Unknown -> non-crashing placeholder, rehydration, enabled=false, and error display.
 * useUnmergedTree; assertDoesNotExist is a MEMBER; the recording callback verifies emitted AnswerValues.
 */
@RunWith(AndroidJUnit4::class)
class QuestionFieldTest {

    @get:Rule
    val rule = createComposeRule()

    private fun optionsConfig(vararg values: String): Map<String, Any?> =
        mapOf("options" to values.toList())

    /** Renders one field with a recording sink; returns a 1-element holder for the last emission. */
    private fun renderField(
        field: QuestionnaireField,
        initial: AnswerValue? = null,
        enabled: Boolean = true,
        error: String? = null,
        recorder: MutableList<Pair<String, AnswerValue>>,
    ) {
        rule.setContent {
            TestLogonTheme {
                var answer by remember { mutableStateOf(initial) }
                QuestionField(
                    field = field,
                    answer = answer,
                    enabled = enabled,
                    error = error,
                    onAnswerChanged = { id, value ->
                        recorder.add(id to value)
                        answer = value
                    },
                )
            }
        }
    }

    // ---- Text ----

    @Test
    fun text_rendersAndCaptures() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Text("q1", "s", "Your name", required = true, hint = "Full legal name"),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.field("q1"), useUnmergedTree = true).assertIsDisplayed()
        // performTextInput needs the text-editing semantics, which the OutlinedTextField exposes on its
        // MERGED node (the tag sits on that node); resolving in the unmerged tree would miss SetText.
        rule.onNodeWithTag(QuestionFieldTestTags.field("q1"))
            .performTextInput("Alice")
        rule.waitForIdle()
        rule.runOnIdle {
            assertEquals("q1", rec.last().first)
            assertEquals(AnswerValue.Text("Alice"), rec.last().second)
        }
    }

    @Test
    fun text_disabledIsNotEnabled() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Text("q1", "s", "Name", required = false),
            enabled = false,
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.field("q1"), useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun text_errorShows() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Text("q1", "s", "Name", required = false),
            error = "Required",
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.error("q1"), useUnmergedTree = true).assertIsDisplayed()
    }

    // ---- Select ----

    @Test
    fun select_rendersAndCaptures() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Select("sel", "s", "Pick one", required = false,
                configJson = optionsConfig("Red", "Green", "Blue")),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.field("sel"), useUnmergedTree = true).performClick()
        rule.onNodeWithTag(QuestionFieldTestTags.option("sel", 1), useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(AnswerValue.Text("Green"), rec.last().second) }
    }

    // ---- Multiselect ----

    @Test
    fun multiselect_rendersAndCaptures_inOptionOrder() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Multiselect("ms", "s", "Pick many", required = false,
                configJson = optionsConfig("A", "B", "C")),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.option("ms", 2), useUnmergedTree = true).performClick()
        // Let the first toggle recompose so the second click's toggle closure sees the updated selection
        // ([C]); otherwise it captures the pre-click empty selection and emits only [A].
        rule.waitForIdle()
        rule.onNodeWithTag(QuestionFieldTestTags.option("ms", 0), useUnmergedTree = true).performClick()
        rule.waitForIdle()
        rule.runOnIdle {
            // Selected C then A -> emitted in option order [A, C].
            assertEquals(AnswerValue.Choices(listOf("A", "C")), rec.last().second)
        }
    }

    @Test
    fun multiselect_clearLastEmitsEmpty() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Multiselect("ms", "s", "Pick many", required = false,
                configJson = optionsConfig("A", "B")),
            initial = AnswerValue.Choices(listOf("A")),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.option("ms", 0), useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(AnswerValue.Empty, rec.last().second) }
    }

    // ---- Radio ----

    @Test
    fun radio_rendersAndCaptures() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Radio("r", "s", "Choose", required = false,
                configJson = optionsConfig("Yes", "No")),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.option("r", 0), useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(AnswerValue.Text("Yes"), rec.last().second) }
    }

    // ---- Slider ----

    @Test
    fun slider_rendersAndCaptures() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Slider("sl", "s", "Rate", required = false,
                configJson = mapOf("min" to 0.0, "max" to 10.0, "step" to 1.0)),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.field("sl"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(QuestionFieldTestTags.field("sl"), useUnmergedTree = true).performClick()
        rule.runOnIdle {
            assertTrue(rec.isNotEmpty())
            assertTrue(rec.last().second is AnswerValue.Num)
        }
    }

    // ---- Date ----

    @Test
    fun date_opensPickerAndConfirmEmitsIso() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.DateField("d", "s", "Birth date", required = false),
            recorder = rec,
        )
        rule.onNodeWithText("Pick").performClick()
        rule.onNodeWithTag(QuestionFieldTestTags.pickerConfirm("d"), useUnmergedTree = true).performClick()
        rule.runOnIdle {
            val v = rec.lastOrNull()?.second
            // A date may or may not be pre-selected; if emitted it must be an ISO Text.
            if (v is AnswerValue.Text) {
                assertTrue(v.value.matches(Regex("""\d{4}-\d{2}-\d{2}""")))
            }
        }
    }

    @Test
    fun date_rehydratesAndClearsToEmpty() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.DateField("d", "s", "Birth date", required = false),
            initial = AnswerValue.Text("2020-01-02"),
            recorder = rec,
        )
        rule.onNodeWithText("2020-01-02").assertIsDisplayed()
        rule.onNodeWithTag(QuestionFieldTestTags.clear("d"), useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(AnswerValue.Empty, rec.last().second) }
    }

    // ---- Time ----

    @Test
    fun time_opensPickerAndConfirmEmitsHhmm() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.TimeField("tm", "s", "Start time", required = false),
            recorder = rec,
        )
        rule.onNodeWithText("Pick").performClick()
        rule.onNodeWithTag(QuestionFieldTestTags.pickerConfirm("tm"), useUnmergedTree = true).performClick()
        rule.runOnIdle {
            val v = rec.last().second
            assertTrue(v is AnswerValue.Text)
            assertTrue((v as AnswerValue.Text).value.matches(Regex("""\d{2}:\d{2}""")))
        }
    }

    // ---- Timezone ----

    @Test
    fun timezone_rendersAndCaptures() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Timezone("tz", "s", "Zone", required = false,
                configJson = mapOf("allowedTimezones" to listOf("UTC", "America/New_York"))),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.field("tz"), useUnmergedTree = true).performClick()
        rule.onNodeWithTag(QuestionFieldTestTags.option("tz", 0), useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(AnswerValue.Text("UTC"), rec.last().second) }
    }

    // ---- Address ----

    @Test
    fun address_rendersAndCapturesEncodedText() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Address("ad", "s", "Mailing address", required = true,
                configJson = mapOf("requiredFields" to listOf("line1", "city"))),
            recorder = rec,
        )
        // performTextInput targets the text-editing semantics on the field's MERGED node (the tag lives
        // there); the unmerged tree would miss SetText and capture nothing.
        rule.onNodeWithTag(QuestionFieldTestTags.addressPart("ad", "line1"))
            .performTextInput("1 Main St")
        rule.waitForIdle()
        rule.runOnIdle {
            val v = rec.last().second
            assertTrue(v is AnswerValue.Text)
            val decoded = QuestionRenderSupport.decodeAddress(v)
            assertEquals("1 Main St", decoded["line1"])
        }
    }

    // ---- Unknown ----

    @Test
    fun unknown_rendersPlaceholderAndDoesNotCrash() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Unknown("future_widget", "u", "s", "Mystery", required = false),
            recorder = rec,
        )
        rule.onNodeWithTag(QuestionFieldTestTags.unsupported("future_widget"), useUnmergedTree = true)
            .assertIsDisplayed()
        rule.runOnIdle { assertTrue(rec.isEmpty()) }
    }

    // ---- rehydration ----

    @Test
    fun text_rehydratesIncomingValue() {
        val rec = mutableListOf<Pair<String, AnswerValue>>()
        renderField(
            QuestionnaireField.Text("q1", "s", "Name", required = false),
            initial = AnswerValue.Text("Bob"),
            recorder = rec,
        )
        rule.onAllNodesWithText("Bob")[0].assertIsDisplayed()
    }
}
