package com.testlogon.android.feature.questionnaire.respond

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import com.testlogon.android.feature.questionnaire.respond.data.SessionStartOutcome
import com.testlogon.android.feature.questionnaire.respond.data.SessionValidation
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
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

        override suspend fun validate(slug: String, finalSubmit: Boolean): ApiResult<SessionValidation> {
            validateCalls++
            return validateResult
        }

        override suspend fun startOver(slug: String): SessionStartOutcome {
            startOverCalls++
            return startOverOutcome
        }
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
