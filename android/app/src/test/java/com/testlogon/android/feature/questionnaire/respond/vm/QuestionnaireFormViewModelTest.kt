package com.testlogon.android.feature.questionnaire.respond.vm

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireDto
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.QuestionnaireSection
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.feature.questionnaire.respond.state.FieldValidator
import com.testlogon.android.feature.questionnaire.respond.state.FormVisibilityEvaluator
import com.testlogon.android.feature.questionnaire.respond.state.QuestionnaireUiState
import com.testlogon.android.feature.questionnaire.respond.state.RespondentAnswers
import com.testlogon.android.feature.questionnaire.respond.state.SubmitGateway
import com.testlogon.android.feature.questionnaire.respond.state.SubmitPhase
import com.testlogon.android.feature.questionnaire.respond.state.SubmitResult
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-351 - unit tests for [QuestionnaireFormViewModel], the JVM-only form state machine (the SOLE
 * acceptance bar). Pure fakes for the three seams; no Android framework, no network, no Compose.
 * MainDispatcherRule (StandardTestDispatcher) + runCurrent drive the only suspending work (the gateway
 * submit on viewModelScope) on the TEST scheduler - never advanceUntilIdle.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
class QuestionnaireFormViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    // ---- fakes (distinct helper names) ----

    /** A validator whose verdict is a configurable per-field error map (questionId -> messages). */
    private class StubFieldValidator : FieldValidator {
        var errorsByField: Map<String, List<String>> = emptyMap()
        override fun validate(
            field: QuestionnaireField,
            value: AnswerValue,
            answers: Map<String, AnswerValue>,
        ): List<String> = errorsByField[field.questionId] ?: emptyList()
    }

    /** A visibility seam that hides a configurable id set; everything else is visible. */
    private class StubVisibilityEvaluator : FormVisibilityEvaluator {
        var hiddenIds: Set<String> = emptySet()
        override fun visibleFieldIds(
            fields: List<QuestionnaireField>,
            answers: Map<String, AnswerValue>,
        ): Set<String> = fields.map { it.questionId }.filterNot { it in hiddenIds }.toSet()
    }

    /** A recording submit gateway that records the snapshot BEFORE returning (or throwing). */
    private class RecordingSubmitGateway : SubmitGateway {
        var lastSnapshot: RespondentAnswers? = null
        var calls = 0
        var result: SubmitResult = SubmitResult.Success("receipt-1")
        var throwOnSubmit: Boolean = false
        override suspend fun submit(answers: RespondentAnswers): SubmitResult {
            // Record BEFORE the (optional) throw so the test can assert it was called.
            lastSnapshot = answers
            calls++
            if (throwOnSubmit) throw IllegalStateException("boom")
            return result
        }
    }

    private val stubValidator = StubFieldValidator()
    private val stubVisibility = StubVisibilityEvaluator()
    private val recordingGateway = RecordingSubmitGateway()

    private fun newViewModel(): QuestionnaireFormViewModel =
        QuestionnaireFormViewModel(
            validator = stubValidator,
            visibility = stubVisibility,
            submitGateway = recordingGateway,
            savedState = SavedStateHandle(),
        )

    // ---- schema helpers (distinct names) ----

    private fun textField(id: String, sectionId: String, required: Boolean = false) =
        QuestionnaireField.Text(
            questionId = id,
            sectionId = sectionId,
            label = id,
            required = required,
        )

    private fun singleSectionSchema(): QuestionnaireDto = QuestionnaireDto(
        questionnaire_id = "q1",
        sections = listOf(
            QuestionnaireSection(
                section_id = "s1",
                questions = listOf(textField("a", "s1"), textField("b", "s1")),
            ),
        ),
    )

    private fun twoSectionSchema(): QuestionnaireDto = QuestionnaireDto(
        questionnaire_id = "q2",
        sections = listOf(
            QuestionnaireSection(section_id = "s1", questions = listOf(textField("a", "s1"))),
            QuestionnaireSection(section_id = "s2", questions = listOf(textField("b", "s2"))),
        ),
    )

    private fun ready(vm: QuestionnaireFormViewModel): QuestionnaireUiState.Ready =
        vm.uiState.value as QuestionnaireUiState.Ready

    // ---- FR-1 hydrate ----

    @Test
    fun `hydrate builds ordered fields and seeds empty answers`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())

        val state = ready(vm)
        assertEquals(listOf("a", "b"), state.orderedFields.map { it.questionId })
        assertEquals(AnswerValue.Empty, state.answers["a"]!!.value)
        assertFalse(state.answers["a"]!!.dirty)
        assertEquals(1, state.pageCount)
        assertEquals(0, state.currentPageIndex)
    }

    @Test
    fun `hydrate seeds answers from resumed session`() = runTest {
        val vm = newViewModel()
        val resumed = RespondentSession(
            sessionId = "rs1",
            slug = "slug",
            questionnaireId = "q1",
            versionId = "v1",
            answers = mapOf("a" to AnswerValue.Text("hello")),
            status = SessionStatus.IN_PROGRESS,
        )
        vm.hydrate(singleSectionSchema(), resumed)

        assertEquals(AnswerValue.Text("hello"), ready(vm).answers["a"]!!.value)
        assertEquals(AnswerValue.Empty, ready(vm).answers["b"]!!.value)
    }

    // ---- FR-2 field changed ----

    @Test
    fun `field changed updates only that field and marks dirty and revalidates`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        stubValidator.errorsByField = mapOf("a" to listOf("bad"))

        vm.onFieldChanged("a", AnswerValue.Text("x"))

        val state = ready(vm)
        assertEquals(AnswerValue.Text("x"), state.answers["a"]!!.value)
        assertTrue(state.answers["a"]!!.dirty)
        // b unchanged.
        assertEquals(AnswerValue.Empty, state.answers["b"]!!.value)
        assertFalse(state.answers["b"]!!.dirty)
        // a revalidated -> aggregate invalid.
        assertEquals(listOf("bad"), state.validation["a"]!!.errors)
        assertFalse(state.isValid)
    }

    @Test
    fun `aggregate isValid true when no visible field has errors`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("x"))
        assertTrue(ready(vm).isValid)
    }

    // ---- FR-3 blur + touched-gated error display ----

    @Test
    fun `error hidden until touched then shown after blur`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        stubValidator.errorsByField = mapOf("a" to listOf("bad"))
        vm.onFieldChanged("a", AnswerValue.Text("x"))

        // Not touched, no submit attempted -> error not displayed.
        assertNull(ready(vm).displayedErrors["a"])

        vm.onFieldBlurred("a")
        assertTrue(ready(vm).answers["a"]!!.touched)
        assertEquals(listOf("bad"), ready(vm).displayedErrors["a"])
    }

    @Test
    fun `submitAttempted ungates all errors even when untouched`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        stubValidator.errorsByField = mapOf("a" to listOf("bad"))
        vm.onFieldChanged("a", AnswerValue.Text("x"))

        vm.onSubmit() // invalid -> blocked, sets submitAttempted.
        runCurrent()

        assertTrue(ready(vm).submitAttempted)
        assertEquals(listOf("bad"), ready(vm).displayedErrors["a"])
        assertEquals(0, recordingGateway.calls)
    }

    // ---- FR-5 hidden excluded from validity ----

    @Test
    fun `hidden field is excluded from validity aggregation`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        stubValidator.errorsByField = mapOf("b" to listOf("b is bad"))
        stubVisibility.hiddenIds = setOf("b")

        vm.onFieldChanged("a", AnswerValue.Text("x"))

        val state = ready(vm)
        assertFalse(state.visibleFieldIds.contains("b"))
        // b has errors but is hidden -> not validated, aggregate stays valid.
        assertNull(state.validation["b"])
        assertTrue(state.isValid)
    }

    // ---- FR-6 paged navigation ----

    @Test
    fun `next blocked on invalid visible page sets submitAttempted`() = runTest {
        val vm = newViewModel()
        vm.hydrate(twoSectionSchema())
        stubValidator.errorsByField = mapOf("a" to listOf("bad"))
        vm.onFieldChanged("a", AnswerValue.Text("x"))

        vm.onNext()

        val state = ready(vm)
        assertEquals(0, state.currentPageIndex) // blocked.
        assertTrue(state.submitAttempted)
    }

    @Test
    fun `next previous and goToPage navigate when valid`() = runTest {
        val vm = newViewModel()
        vm.hydrate(twoSectionSchema())
        assertEquals(2, ready(vm).pageCount)

        vm.onNext()
        assertEquals(1, ready(vm).currentPageIndex)

        vm.onPrevious()
        assertEquals(0, ready(vm).currentPageIndex)

        vm.onGoToPage(1)
        assertEquals(1, ready(vm).currentPageIndex)

        // Clamped.
        vm.onGoToPage(99)
        assertEquals(1, ready(vm).currentPageIndex)
    }

    // ---- FR-7 submit lifecycle ----

    @Test
    fun `submit succeeds transitions to Submitted with receipt`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("x"))
        recordingGateway.result = SubmitResult.Success("R-9")

        vm.onSubmit()
        // Before the scheduler runs the launched coroutine, phase is Submitting.
        assertEquals(SubmitPhase.Submitting, ready(vm).submit)

        runCurrent()

        assertEquals(SubmitPhase.Submitted("R-9"), ready(vm).submit)
        assertEquals(1, recordingGateway.calls)
        assertEquals(AnswerValue.Text("x"), recordingGateway.lastSnapshot!!.values["a"])
    }

    @Test
    fun `submit failure transitions to Failed with submitError`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("x"))
        recordingGateway.result = SubmitResult.Failure("server said no")

        vm.onSubmit()
        runCurrent()

        val state = ready(vm)
        assertEquals(SubmitPhase.Failed, state.submit)
        assertEquals("server said no", state.submitError)
    }

    @Test
    fun `submit gateway throw is caught as Failed`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("x"))
        recordingGateway.throwOnSubmit = true

        vm.onSubmit()
        runCurrent()

        assertEquals(SubmitPhase.Failed, ready(vm).submit)
        // Recorded BEFORE throwing.
        assertEquals(1, recordingGateway.calls)
    }

    @Test
    fun `submit blocked when invalid never calls gateway`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        stubValidator.errorsByField = mapOf("a" to listOf("bad"))
        vm.onFieldChanged("a", AnswerValue.Text("x"))

        vm.onSubmit()
        runCurrent()

        assertEquals(SubmitPhase.Idle, ready(vm).submit)
        assertEquals(0, recordingGateway.calls)
    }

    // ---- FR-8 snapshot ----

    @Test
    fun `currentAnswersSnapshot reflects entered answers`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("x"))
        vm.onFieldChanged("b", AnswerValue.Num(2.0))

        val snap = vm.currentAnswersSnapshot()
        assertEquals(AnswerValue.Text("x"), snap.values["a"])
        assertEquals(AnswerValue.Num(2.0), snap.values["b"])
    }

    // ---- FR-9 retry preserves answers ----

    @Test
    fun `retry after error preserves entered answers`() = runTest {
        val vm = newViewModel()
        vm.hydrate(singleSectionSchema())
        vm.onFieldChanged("a", AnswerValue.Text("kept"))

        vm.onHydrationError("load failed")
        assertTrue(vm.uiState.value is QuestionnaireUiState.Error)

        vm.retry()

        val state = ready(vm)
        assertEquals(AnswerValue.Text("kept"), state.answers["a"]!!.value)
        assertTrue(state.answers["a"]!!.dirty)
    }

    // ---- dispatch entry (exhaustive when smoke) ----

    @Test
    fun `dispatch routes intents`() = runTest {
        val vm = newViewModel()
        vm.dispatch(QuestionnaireFormIntent.Hydrate(singleSectionSchema()))
        vm.dispatch(QuestionnaireFormIntent.FieldChanged("a", AnswerValue.Text("z")))
        vm.dispatch(QuestionnaireFormIntent.FieldBlurred("a"))

        val state = ready(vm)
        assertEquals(AnswerValue.Text("z"), state.answers["a"]!!.value)
        assertTrue(state.answers["a"]!!.touched)
    }
}
