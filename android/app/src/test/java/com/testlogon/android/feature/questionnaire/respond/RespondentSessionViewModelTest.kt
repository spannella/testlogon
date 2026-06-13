package com.testlogon.android.feature.questionnaire.respond

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import com.testlogon.android.feature.questionnaire.respond.data.SessionStartOutcome
import com.testlogon.android.feature.questionnaire.respond.data.SessionValidation
import com.testlogon.android.feature.questionnaire.respond.data.SubmitOutcome
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-348 — unit tests for [RespondentSessionViewModel]. Uses MainDispatcherRule (StandardTestDispatcher)
 * + runCurrent / advanceTimeBy to drive the debounced autosave on the TEST scheduler (never a real
 * delay, never advanceUntilIdle). A fake [RespondentSessionRepository] records calls and returns
 * configurable outcomes. Covers immediate saveLocal + debounced sync, offline SYNC_PENDING/SYNC_ERROR,
 * validate->field errors + canSubmit, SchemaChanged, and startOver.
 */
class RespondentSessionViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : RespondentSessionRepository {
        var startOutcome: SessionStartOutcome = SessionStartOutcome.Ready(session("v1"))
        var startOverOutcome: SessionStartOutcome = SessionStartOutcome.Ready(session("v9"))
        var syncResult: ApiResult<RespondentSession> = ApiResult.Success(session("v1"))
        var validateResult: ApiResult<SessionValidation> =
            ApiResult.Success(SessionValidation(true, true, false, emptyMap()))

        var saveLocalCalls = 0
        var syncCalls = 0
        var validateCalls = 0
        var startOverCalls = 0
        var lastSavedAnswers: Map<String, AnswerValue>? = null

        override suspend fun startOrResume(slug: String): SessionStartOutcome = startOutcome
        override suspend fun resume(slug: String): SessionStartOutcome = startOutcome

        override suspend fun saveLocal(
            base: RespondentSession,
            answers: Map<String, AnswerValue>,
            sectionIndex: Int?,
            questionId: String?,
        ) {
            saveLocalCalls++
            lastSavedAnswers = answers
        }

        override suspend fun syncSave(slug: String): ApiResult<RespondentSession> {
            syncCalls++
            return syncResult
        }

        var lastValidateAnswers: Map<String, AnswerValue>? = null

        override suspend fun validate(
            slug: String,
            finalSubmit: Boolean,
            answersOverride: Map<String, AnswerValue>?,
        ): ApiResult<SessionValidation> {
            validateCalls++
            lastValidateAnswers = answersOverride
            return validateResult
        }

        override suspend fun startOver(slug: String): SessionStartOutcome {
            startOverCalls++
            return startOverOutcome
        }

        // AND-349 additions.
        var submitOutcome: SubmitOutcome = SubmitOutcome.Submitted("rs_1", SessionStatus.SUBMITTED)
        var pdfResult: ApiResult<java.io.File> = ApiResult.Success(java.io.File("response.pdf"))
        var alreadySubmitted = false
        var submitCalls = 0
        var pdfCalls = 0
        var lastFieldOrder: List<String>? = null

        var lastSubmitAnswers: Map<String, AnswerValue>? = null

        override suspend fun submit(
            slug: String,
            fieldOrder: List<String>,
            answersOverride: Map<String, AnswerValue>?,
        ): SubmitOutcome {
            submitCalls++
            lastFieldOrder = fieldOrder
            lastSubmitAnswers = answersOverride
            return submitOutcome
        }

        override suspend fun downloadSubmissionPdf(slug: String): ApiResult<java.io.File> {
            pdfCalls++
            return pdfResult
        }

        override suspend fun isAlreadySubmitted(slug: String): Boolean = alreadySubmitted
    }

    private fun vm(repo: RespondentSessionRepository, slug: String? = SLUG): RespondentSessionViewModel {
        val saved = SavedStateHandle(
            if (slug != null) mapOf(RespondentSessionViewModel.ARG_SLUG to slug) else emptyMap(),
        )
        return RespondentSessionViewModel(saved, repo)
    }

    @Test
    fun init_loadsActive() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is RespondentSessionUiState.Active)
    }

    @Test
    fun onAnswerChanged_savesLocalImmediately_andDebouncesSync() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        vm.debounceMillis = 500
        runCurrent()

        vm.onAnswerChanged("q1", AnswerValue.Text("hi"))
        runCurrent()

        // Local save is immediate; sync has NOT fired yet (debounce pending).
        assertEquals(1, repo.saveLocalCalls)
        assertEquals(0, repo.syncCalls)
        val pending = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals(SyncState.SYNC_PENDING, pending.syncState)
        assertEquals(AnswerValue.Text("hi"), pending.answers["q1"])

        // After the debounce window the sync fires once.
        advanceTimeBy(600)
        runCurrent()
        assertEquals(1, repo.syncCalls)
        assertEquals(SyncState.SYNCED, (vm.uiState.value as RespondentSessionUiState.Active).syncState)
    }

    @Test
    fun onAnswerChanged_rapidEdits_debounceToSingleSync() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        vm.debounceMillis = 500
        runCurrent()

        vm.onAnswerChanged("q1", AnswerValue.Text("a"))
        runCurrent()
        advanceTimeBy(100)
        vm.onAnswerChanged("q1", AnswerValue.Text("ab"))
        runCurrent()
        advanceTimeBy(600)
        runCurrent()

        // Two local saves, but the prior debounce was cancelled -> a single sync.
        assertEquals(2, repo.saveLocalCalls)
        assertEquals(1, repo.syncCalls)
    }

    @Test
    fun syncFailure_showsSyncError() = runTest {
        val repo = FakeRepo()
        repo.syncResult = ApiResult.NetworkError(java.io.IOException("offline"))
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()

        vm.onAnswerChanged("q1", AnswerValue.Text("x"))
        runCurrent()
        // Offline: the buffered edit is SYNC_PENDING before the debounce fires.
        assertEquals(
            SyncState.SYNC_PENDING,
            (vm.uiState.value as RespondentSessionUiState.Active).syncState,
        )

        advanceTimeBy(200)
        runCurrent()
        assertEquals(
            SyncState.SYNC_ERROR,
            (vm.uiState.value as RespondentSessionUiState.Active).syncState,
        )
    }

    @Test
    fun onSaveAndContinue_validates_mapsFieldErrors_andCanSubmit() = runTest {
        val repo = FakeRepo()
        repo.validateResult = ApiResult.Success(
            SessionValidation(
                isValid = false,
                canSubmit = false,
                hasBlockingFormError = true,
                fieldErrors = mapOf("q1" to "Required"),
            ),
        )
        val vm = vm(repo)
        runCurrent()

        vm.onSaveAndContinue()
        runCurrent()

        assertEquals(1, repo.validateCalls)
        val state = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals("Required", state.fieldErrors["q1"])
        assertEquals(false, state.canSubmit)
    }

    @Test
    fun schemaChanged_isSurfaced() = runTest {
        val repo = FakeRepo()
        repo.startOutcome = SessionStartOutcome.SchemaChanged(
            slug = SLUG,
            cachedVersionId = "v1",
            serverVersionId = "v2",
            serverSession = session("v2"),
        )
        val vm = vm(repo)
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is RespondentSessionUiState.SchemaChanged)
        assertEquals(SLUG, (state as RespondentSessionUiState.SchemaChanged).slug)
    }

    @Test
    fun onReloadSchema_startsOver_andReloadsActive() = runTest {
        val repo = FakeRepo()
        repo.startOutcome = SessionStartOutcome.SchemaChanged(SLUG, "v1", "v2", session("v2"))
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is RespondentSessionUiState.SchemaChanged)

        vm.onReloadSchema()
        runCurrent()

        assertEquals(1, repo.startOverCalls)
        assertTrue(vm.uiState.value is RespondentSessionUiState.Active)
        assertEquals("v9", (vm.uiState.value as RespondentSessionUiState.Active).session.versionId)
    }

    @Test
    fun onStartOver_reloadsFreshSession() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()

        vm.onStartOver()
        runCurrent()

        assertEquals(1, repo.startOverCalls)
        assertEquals("v9", (vm.uiState.value as RespondentSessionUiState.Active).session.versionId)
    }

    @Test
    fun blankSlug_isError() = runTest {
        val vm = vm(FakeRepo(), slug = null)
        runCurrent()
        assertTrue(vm.uiState.value is RespondentSessionUiState.Error)
    }

    // ---- AND-349 ----

    @Test
    fun onSubmit_success_becomesSubmitted_terminal() = runTest {
        val repo = FakeRepo()
        repo.validateResult = ApiResult.Success(SessionValidation(true, true, false, emptyMap()))
        repo.submitOutcome = SubmitOutcome.Submitted("rs_1", SessionStatus.SUBMITTED)
        val vm = vm(repo)
        runCurrent()
        // Reach a canSubmit=true Active via validate.
        vm.onSaveAndContinue()
        runCurrent()
        assertTrue((vm.uiState.value as RespondentSessionUiState.Active).canSubmit)

        vm.onSubmit()
        runCurrent()

        assertEquals(1, repo.submitCalls)
        val state = vm.uiState.value
        assertTrue(state is RespondentSessionUiState.Submitted)
        assertEquals("rs_1", (state as RespondentSessionUiState.Submitted).sessionId)
        assertEquals(SessionStatus.SUBMITTED, state.sessionStatus)
    }

    @Test
    fun onSubmit_validationFail_mapsFieldErrors_andFirstError() = runTest {
        val repo = FakeRepo()
        repo.submitOutcome = SubmitOutcome.ValidationFailed(
            SessionValidation(
                isValid = false,
                canSubmit = false,
                hasBlockingFormError = true,
                fieldErrors = mapOf("q1" to "Required"),
                firstErrorQuestionId = "q1",
            ),
        )
        val vm = vm(repo)
        runCurrent()
        makeSubmittable(vm)

        vm.onSubmit()
        runCurrent()

        val state = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals("Required", state.fieldErrors["q1"])
        assertEquals("q1", state.firstErrorQuestionId)
        assertEquals(false, state.submitting)
    }

    @Test
    fun onSubmit_doubleTap_blockedWhileSubmitting() = runTest {
        val repo = FakeRepo()
        repo.submitOutcome = SubmitOutcome.Submitted("rs_1", SessionStatus.SUBMITTED)
        val vm = vm(repo)
        runCurrent()
        makeSubmittable(vm)

        vm.onSubmit()
        vm.onSubmit()
        runCurrent()

        // The in-flight guard collapses the second tap.
        assertEquals(1, repo.submitCalls)
    }

    @Test
    fun onDownloadPdf_emitsOpenPdfEffect() = runTest {
        val repo = FakeRepo()
        repo.alreadySubmitted = true
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.uiState.value is RespondentSessionUiState.Submitted)

        val effects = mutableListOf<RespondEffect>()
        backgroundScope.launch { vm.effects.collect { effects.add(it) } }
        runCurrent()

        vm.onDownloadPdf()
        runCurrent()

        assertEquals(1, repo.pdfCalls)
        assertTrue(effects.any { it is RespondEffect.OpenPdf })
    }

    @Test
    fun alreadySubmitted_opensSubmittedOnLoad() = runTest {
        val repo = FakeRepo()
        repo.alreadySubmitted = true
        repo.startOutcome = SessionStartOutcome.Ready(
            RespondentSession(
                sessionId = "rs_done", slug = SLUG, questionnaireId = "q1", versionId = "v1",
                answers = emptyMap(), status = SessionStatus.SUBMITTED,
            ),
        )
        val vm = vm(repo)
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is RespondentSessionUiState.Submitted)
        assertEquals("rs_done", (state as RespondentSessionUiState.Submitted).sessionId)
    }

    @Test
    fun onFirstErrorConsumed_clearsMarker() = runTest {
        val repo = FakeRepo()
        repo.submitOutcome = SubmitOutcome.ValidationFailed(
            SessionValidation(false, false, true, mapOf("q1" to "Required"), "q1"),
        )
        val vm = vm(repo)
        runCurrent()
        makeSubmittable(vm)
        vm.onSubmit()
        runCurrent()
        assertEquals("q1", (vm.uiState.value as RespondentSessionUiState.Active).firstErrorQuestionId)

        vm.onFirstErrorConsumed()
        runCurrent()
        assertNull((vm.uiState.value as RespondentSessionUiState.Active).firstErrorQuestionId)
    }

    /** Drives the VM to a canSubmit=true Active so onSubmit's FR-1 gate passes. */
    private fun kotlinx.coroutines.test.TestScope.makeSubmittable(vm: RespondentSessionViewModel) {
        vm.onSaveAndContinue()
        runCurrent()
    }

    // ---- AND-350: conditional logic + validation ----

    @Test
    fun answerChange_recomputesVisibility_synchronously() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        // Controller not "yes": the dependent is hidden.
        vm.onAnswerChanged("ctrl", AnswerValue.Text("no"))
        runCurrent()
        var active = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals(listOf("ctrl"), active.visibleQuestionIds)

        // Controller "yes": the dependent becomes visible (cascade re-show).
        vm.onAnswerChanged("ctrl", AnswerValue.Text("yes"))
        runCurrent()
        active = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals(listOf("ctrl", "dep"), active.visibleQuestionIds)
    }

    @Test
    fun validateBody_excludesHiddenAnswers() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        // Answer the hidden dependent first, then leave the controller hiding it.
        vm.onAnswerChanged("dep", AnswerValue.Text("secret"))
        runCurrent()
        vm.onAnswerChanged("ctrl", AnswerValue.Text("no"))
        advanceTimeBy(200)
        runCurrent()

        // The debounced server validate ran with the VISIBLE-only body: 'dep' is excluded.
        val body = repo.lastValidateAnswers
        assertTrue(body != null && !body.containsKey("dep"))
        assertTrue(body!!.containsKey("ctrl"))
    }

    @Test
    fun debouncedServerValidate_firesAfterEdit() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        vm.onAnswerChanged("ctrl", AnswerValue.Text("yes"))
        runCurrent()
        assertEquals(0, repo.validateCalls)
        advanceTimeBy(200)
        runCurrent()
        assertTrue(repo.validateCalls >= 1)
    }

    @Test
    fun submitGate_followsServerCanSubmit_notLocal() = runTest {
        val repo = FakeRepo()
        // The server says can_submit=false even though local validation would pass.
        repo.validateResult =
            ApiResult.Success(SessionValidation(isValid = false, canSubmit = false, hasBlockingFormError = false, fieldErrors = emptyMap()))
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        vm.onAnswerChanged("ctrl", AnswerValue.Text("yes"))
        runCurrent()
        // Immediately after a local edit, canSubmit is conservatively false (no local-only enable).
        assertEquals(false, (vm.uiState.value as RespondentSessionUiState.Active).canSubmit)

        advanceTimeBy(200)
        runCurrent()
        // Even after the server validate, canSubmit stays false (server verdict governs).
        assertEquals(false, (vm.uiState.value as RespondentSessionUiState.Active).canSubmit)
    }

    @Test
    fun validateFailure_keepsSubmitDisabled_andShowsRetryNotice() = runTest {
        val repo = FakeRepo()
        repo.validateResult = ApiResult.NetworkError(java.io.IOException("offline"))
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        vm.onAnswerChanged("ctrl", AnswerValue.Text("yes"))
        advanceTimeBy(200)
        runCurrent()

        val active = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals(false, active.canSubmit)
        assertTrue(active.serverConfirmFailed)

        // Retry: a now-successful validate clears the notice.
        repo.validateResult =
            ApiResult.Success(SessionValidation(true, true, false, emptyMap()))
        vm.onRetryValidate()
        runCurrent()
        val retried = vm.uiState.value as RespondentSessionUiState.Active
        assertEquals(false, retried.serverConfirmFailed)
        assertEquals(true, retried.canSubmit)
    }

    @Test
    fun formBanner_surfacesGroupAndFormKeys() = runTest {
        val repo = FakeRepo()
        repo.validateResult = ApiResult.Success(
            SessionValidation(
                isValid = false,
                canSubmit = false,
                hasBlockingFormError = true,
                fieldErrors = emptyMap(),
                serverErrors = mapOf(
                    "group:g1" to listOf(
                        com.testlogon.android.core.model.questionnaire.ValidationIssue("x", "Group issue"),
                    ),
                ),
            ),
        )
        val vm = vm(repo)
        vm.debounceMillis = 100
        runCurrent()
        vm.setSchemaFields(branchingFields())
        runCurrent()

        vm.onAnswerChanged("ctrl", AnswerValue.Text("yes"))
        advanceTimeBy(200)
        runCurrent()

        val active = vm.uiState.value as RespondentSessionUiState.Active
        assertTrue(active.formBannerIssues.contains("Group issue"))
    }

    private fun branchingFields(): List<QuestionnaireField> = listOf(
        QuestionnaireField.Text("ctrl", "s", "ctrl", required = false),
        QuestionnaireField.Text(
            "dep", "s", "dep", required = false,
            configJson = mapOf(
                "visible_when" to mapOf("question_id" to "ctrl", "op" to "eq", "value" to "yes"),
            ),
        ),
    )

    private companion object {
        const val SLUG = "my-survey"
    }
}

private fun session(versionId: String) = RespondentSession(
    sessionId = "rs_1",
    slug = "my-survey",
    questionnaireId = "q1",
    versionId = versionId,
    answers = emptyMap(),
    status = SessionStatus.IN_PROGRESS,
    currentSectionIndex = 0,
    currentQuestionId = "q1",
)
