package com.testlogon.android.feature.questionnaire.respond.state

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.testing.questionnaire.QuestionnaireFixtures
import com.testlogon.android.feature.questionnaire.respond.vm.QuestionnaireFormViewModel
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-352 - END-TO-END integration test that wires the REAL AND-351 form state machine
 * ([QuestionnaireFormViewModel] over [QuestionnaireFormReducer]) with the REAL AND-350 default seams
 * ([DefaultFieldValidator] which delegates to ClientValidator, [DefaultVisibilityEvaluator] which
 * delegates to VisibilityEvaluator) over the shared [QuestionnaireFixtures] schema.
 *
 * WHY THIS IS NOT A DUPLICATE: the existing AND-351 unit tests (QuestionnaireFormViewModelTest /
 * QuestionnaireFormReducerTest) drive the state machine with STUB seams (fakes returning canned
 * verdicts), and the existing AND-350 tests exercise the validator / visibility evaluator IN ISOLATION.
 * Neither proves that the two layers WIRE TOGETHER: that a real visible_when predicate, evaluated by the
 * real VisibilityEvaluator, actually hides a field until its trigger is set, and that the real
 * ClientValidator then blocks submit on the now-visible required field. THIS test uses the production
 * DEFAULTS end to end (only the SubmitGateway is a stub - the form-level gate is the REAL validation, not
 * a fake). It is the AND-350 <-> AND-351 contract test.
 *
 * Hermetic + offline: no network, no Compose, no Hilt - the VM is constructed directly with the default
 * seams. MainDispatcherRule (StandardTestDispatcher) + runCurrent drive the only suspending work (the
 * gateway submit on viewModelScope); never advanceUntilIdle.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
class QuestionnaireFormIntegrationTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    // ---- stub gateway (distinct helper name; records BEFORE returning) ----

    /**
     * A recording [SubmitGateway] stub - the ONLY fake in this test. It records the submitted snapshot
     * (before returning) so the test can assert the form-level validation gate let submit through; it is
     * NOT the gate itself (the gate is the real DefaultFieldValidator inside the reducer).
     */
    private class RecordingGatewayStub : SubmitGateway {
        var lastSnapshot: RespondentAnswers? = null
        var calls = 0
        var result: SubmitResult = SubmitResult.Success("ok-receipt")
        override suspend fun submit(answers: RespondentAnswers): SubmitResult {
            lastSnapshot = answers
            calls++
            return result
        }
    }

    private val gatewayStub = RecordingGatewayStub()

    /** Builds the VM with the REAL AND-350 default seams (not fakes) + the stub gateway. */
    private fun realDefaultsViewModel(): QuestionnaireFormViewModel =
        QuestionnaireFormViewModel(
            validator = DefaultFieldValidator,
            visibility = DefaultVisibilityEvaluator,
            submitGateway = gatewayStub,
            savedState = SavedStateHandle(),
        )

    private fun ready(vm: QuestionnaireFormViewModel): QuestionnaireUiState.Ready =
        vm.uiState.value as QuestionnaireUiState.Ready

    // ---- FR-5 real visible_when gating (the AND-350 evaluator inside the AND-351 machine) ----

    @Test
    fun `gated field is hidden until its trigger answer is set then appears`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())

        // Initially the radio is unanswered -> the real VisibilityEvaluator hides the gated field.
        assertFalse(ready(vm).visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))

        // Set the radio to a NON-trigger value -> still hidden.
        vm.onFieldChanged(QuestionnaireFixtures.Q_RADIO, AnswerValue.Text("email"))
        assertFalse(ready(vm).visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))

        // Set the radio to the trigger value -> the real evaluator reveals the gated field.
        vm.onFieldChanged(
            QuestionnaireFixtures.Q_RADIO,
            AnswerValue.Text(QuestionnaireFixtures.GATE_TRIGGER_VALUE),
        )
        assertTrue(ready(vm).visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))
    }

    @Test
    fun `hidden required gated field does not block submit while hidden`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())

        // Satisfy the only OTHER required field (the text field) but leave the gated one hidden + empty.
        vm.onFieldChanged(QuestionnaireFixtures.Q_TEXT, AnswerValue.Text("Jane Doe"))

        val state = ready(vm)
        // The gated REQUIRED field is hidden -> excluded from validity (FR-5) -> aggregate valid.
        assertFalse(state.visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))
        assertTrue(state.isValid)
    }

    // ---- FR-4 real client validation blocks an invalid required field ----

    @Test
    fun `client validation blocks submit when a visible required field is empty`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())

        // Reveal the gated required field but leave it empty; the text field is also required + empty.
        vm.onFieldChanged(
            QuestionnaireFixtures.Q_RADIO,
            AnswerValue.Text(QuestionnaireFixtures.GATE_TRIGGER_VALUE),
        )

        val before = ready(vm)
        assertFalse(before.isValid)
        // The real ClientValidator produced a required error on both visible required fields.
        assertTrue(before.validation[QuestionnaireFixtures.Q_TEXT]!!.errors.isNotEmpty())
        assertTrue(before.validation[QuestionnaireFixtures.Q_GATED]!!.errors.isNotEmpty())

        vm.onSubmit()
        runCurrent()

        val after = ready(vm)
        assertEquals(SubmitPhase.Idle, after.submit)
        assertTrue(after.submitAttempted)
        assertEquals(0, gatewayStub.calls)
    }

    @Test
    fun `client validation blocks submit when a text length constraint is violated`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())

        // The text field has min_length 2; a single char violates the real ClientValidator length rule.
        vm.onFieldChanged(QuestionnaireFixtures.Q_TEXT, AnswerValue.Text("J"))

        val state = ready(vm)
        assertFalse(state.isValid)
        assertTrue(state.validation[QuestionnaireFixtures.Q_TEXT]!!.errors.isNotEmpty())
    }

    // ---- FR-7 a valid form lets submit proceed through the (stub) gateway ----

    @Test
    fun `valid form submits and reaches the gateway`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())

        // Seed every constrained field with a VALID value (radio = trigger, gated filled).
        for ((id, value) in QuestionnaireFixtures.validAnswers()) {
            vm.onFieldChanged(id, value)
        }

        val ready = ready(vm)
        assertTrue(ready.visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))
        assertTrue(ready.isValid)

        gatewayStub.result = SubmitResult.Success("R-42")
        vm.onSubmit()
        // Synchronously moved to Submitting before the launched coroutine runs.
        assertEquals(SubmitPhase.Submitting, ready(vm).submit)

        runCurrent()

        assertEquals(SubmitPhase.Submitted("R-42"), ready(vm).submit)
        assertEquals(1, gatewayStub.calls)
        // The snapshot the real machine handed the gateway carries the entered text answer.
        assertEquals(
            AnswerValue.Text("Jane Doe"),
            gatewayStub.lastSnapshot!!.values[QuestionnaireFixtures.Q_TEXT],
        )
    }

    @Test
    fun `seeding a valid resumed session hydrates straight to a valid form`() = runTest {
        val vm = realDefaultsViewModel()
        // Resume from a session whose answers are all valid (radio = trigger so the gated field shows).
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema(), QuestionnaireFixtures.sampleSession())

        val state = ready(vm)
        assertTrue(state.visibleFieldIds.contains(QuestionnaireFixtures.Q_GATED))
        assertTrue(state.isValid)
        // Resumed answers are seeded but NOT marked dirty.
        assertFalse(state.answers[QuestionnaireFixtures.Q_TEXT]!!.dirty)
    }

    // ---- genuine gap: hydration error -> retry preserves answers, then re-validates with real defaults ----

    @Test
    fun `hydration error then retry preserves answers and re-validates with real defaults`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.everyTypeSchema())
        vm.onFieldChanged(QuestionnaireFixtures.Q_TEXT, AnswerValue.Text("Kept Name"))

        vm.onHydrationError("load failed")
        assertTrue(vm.uiState.value is QuestionnaireUiState.Error)

        vm.retry()

        val state = ready(vm)
        assertEquals(AnswerValue.Text("Kept Name"), state.answers[QuestionnaireFixtures.Q_TEXT]!!.value)
        assertTrue(state.answers[QuestionnaireFixtures.Q_TEXT]!!.dirty)
        // The real validator ran again on the preserved value (length 9 >= min_length 2) -> text is clean.
        assertTrue(state.validation[QuestionnaireFixtures.Q_TEXT]!!.errors.isEmpty())
    }

    // ---- genuine gap: multi-section Next gate + page-index clamp with real defaults ----

    @Test
    fun `multi section next is blocked on an invalid first page then advances and clamps`() = runTest {
        val vm = realDefaultsViewModel()
        vm.hydrate(QuestionnaireFixtures.multiSectionSchema())
        assertEquals(2, ready(vm).pageCount)

        // First page has a required empty text field -> Next is blocked by the real validator.
        vm.onNext()
        assertEquals(0, ready(vm).currentPageIndex)
        assertTrue(ready(vm).submitAttempted)

        // Satisfy the required field -> Next advances.
        vm.onFieldChanged(QuestionnaireFixtures.Q_TEXT, AnswerValue.Text("Jane"))
        vm.onNext()
        assertEquals(1, ready(vm).currentPageIndex)

        // Next past the last page is clamped (bounds clamp, FR-6).
        vm.onNext()
        assertEquals(1, ready(vm).currentPageIndex)

        // GoToPage out of range is clamped to a valid page.
        vm.onGoToPage(99)
        assertEquals(1, ready(vm).currentPageIndex)
        vm.onGoToPage(-5)
        assertEquals(0, ready(vm).currentPageIndex)
    }
}
