package com.testlogon.android.feature.questionnaire.respond.publicentry

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireEnvelope
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.questionnaire.respond.RespondentSessionViewModel
import com.testlogon.android.feature.questionnaire.respond.data.PersistedSession
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import com.testlogon.android.feature.questionnaire.respond.data.SessionStartOutcome
import com.testlogon.android.feature.questionnaire.respond.data.SessionValidation
import com.testlogon.android.feature.questionnaire.respond.data.SubmitOutcome
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-395 - unit tests for [PublicRespondViewModel] (TC-AND-395-01/02/03/06/07). A fake
 * [RespondentSessionRepository] records the load/persisted/start calls and returns configurable
 * outcomes; MainDispatcherRule (StandardTestDispatcher) + runCurrent drive the init bootstrap on the
 * test scheduler (never advanceUntilIdle). Asserts the load + resume-before-start ordering, the
 * 404/422 -> NotFound mapping, transport -> retryable Error -> retry() -> Ready, and the terminal flag.
 */
class PublicRespondViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : RespondentSessionRepository {
        var loadResult: ApiResult<PublishedQuestionnaireEnvelope> =
            ApiResult.Success(PUBLISHED)
        var persisted: PersistedSession? = null
        var startResult: ApiResult<RespondentSession> = ApiResult.Success(session("rs1"))

        var loadCalls = 0
        var persistedCalls = 0
        var startCalls = 0

        override suspend fun loadPublished(slug: String): ApiResult<PublishedQuestionnaireEnvelope> {
            loadCalls++
            return loadResult
        }

        override suspend fun persistedSession(slug: String): PersistedSession? {
            persistedCalls++
            return persisted
        }

        override suspend fun startAnonymousSession(slug: String): ApiResult<RespondentSession> {
            startCalls++
            return startResult
        }

        // ---- unused by this VM; satisfied for the shared interface ----
        override suspend fun startOrResume(slug: String): SessionStartOutcome =
            SessionStartOutcome.Ready(session("x"))
        override suspend fun resume(slug: String): SessionStartOutcome =
            SessionStartOutcome.Ready(session("x"))
        override suspend fun saveLocal(
            base: RespondentSession,
            answers: Map<String, AnswerValue>,
            sectionIndex: Int?,
            questionId: String?,
        ) = Unit
        override suspend fun syncSave(slug: String): ApiResult<RespondentSession> =
            ApiResult.Success(session("x"))
        override suspend fun validate(
            slug: String,
            finalSubmit: Boolean,
            answersOverride: Map<String, AnswerValue>?,
        ): ApiResult<SessionValidation> =
            ApiResult.Success(SessionValidation(true, true, false, emptyMap()))
        override suspend fun startOver(slug: String): SessionStartOutcome =
            SessionStartOutcome.Ready(session("x"))
        override suspend fun submit(
            slug: String,
            fieldOrder: List<String>,
            answersOverride: Map<String, AnswerValue>?,
        ): SubmitOutcome = SubmitOutcome.Submitted("rs1", SessionStatus.SUBMITTED)
        override suspend fun downloadSubmissionPdf(slug: String): ApiResult<java.io.File> =
            ApiResult.Success(java.io.File("x.pdf"))
        override suspend fun isAlreadySubmitted(slug: String): Boolean = false
    }

    private fun vm(repo: RespondentSessionRepository, slug: String? = SLUG): PublicRespondViewModel {
        val saved = SavedStateHandle(
            if (slug != null) mapOf(RespondentSessionViewModel.ARG_SLUG to slug) else emptyMap(),
        )
        return PublicRespondViewModel(saved, repo)
    }

    @Test
    fun bootstrap_happyPath_loadThenStart_ready() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()
        val s = vm.state.value
        assertTrue(s is PublicEntryState.Ready)
        s as PublicEntryState.Ready
        assertEquals("rs1", s.sessionId)
        assertEquals(false, s.terminal)
        assertEquals(1, repo.loadCalls)
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun bootstrap_resumeExistingSession_noSecondStart() = runTest {
        val repo = FakeRepo().apply { persisted = PersistedSession("rs7", isTerminal = false) }
        val vm = vm(repo)
        runCurrent()
        val s = vm.state.value
        assertTrue(s is PublicEntryState.Ready)
        s as PublicEntryState.Ready
        assertEquals("rs7", s.sessionId)
        assertEquals(false, s.terminal)
        // FR-8: resume-before-start -> no session-start POST issued.
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun bootstrap_terminalSession_readyTerminal() = runTest {
        val repo = FakeRepo().apply { persisted = PersistedSession("rs9", isTerminal = true) }
        val vm = vm(repo)
        runCurrent()
        val s = vm.state.value as PublicEntryState.Ready
        assertEquals("rs9", s.sessionId)
        assertEquals(true, s.terminal)
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun bootstrap_404_notFound() = runTest {
        val repo = FakeRepo().apply { loadResult = ApiResult.Failure(ApiError(404, "nope")) }
        val vm = vm(repo)
        runCurrent()
        assertEquals(PublicEntryState.NotFound, vm.state.value)
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun bootstrap_422_notFound() = runTest {
        val repo = FakeRepo().apply { loadResult = ApiResult.Failure(ApiError(422, "bad slug")) }
        val vm = vm(repo)
        runCurrent()
        assertEquals(PublicEntryState.NotFound, vm.state.value)
    }

    @Test
    fun bootstrap_5xx_error() = runTest {
        val repo = FakeRepo().apply { loadResult = ApiResult.Failure(ApiError(503, "down")) }
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.state.value is PublicEntryState.Error)
    }

    @Test
    fun bootstrap_networkError_thenRetrySucceeds() = runTest {
        val repo = FakeRepo().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException("offline"))
        }
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.state.value is PublicEntryState.Error)

        // FR-7: user-driven retry re-runs bootstrap and succeeds.
        repo.loadResult = ApiResult.Success(PUBLISHED)
        vm.retry()
        runCurrent()
        assertTrue(vm.state.value is PublicEntryState.Ready)
    }

    @Test
    fun bootstrap_startPostFails_error() = runTest {
        val repo = FakeRepo().apply {
            startResult = ApiResult.NetworkError(java.io.IOException("offline"))
        }
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.state.value is PublicEntryState.Error)
        // POST start is attempted exactly once (no auto-retry at this layer).
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun blankSlug_notFound() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo, slug = "")
        runCurrent()
        assertEquals(PublicEntryState.NotFound, vm.state.value)
        assertEquals(0, repo.loadCalls)
    }

    private companion object {
        const val SLUG = "onboarding-2026"

        val PUBLISHED: PublishedQuestionnaireEnvelope by lazy {
            PublishedQuestionnaireEnvelope(
                version = com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireVersion(
                    published_slug = SLUG,
                    questionnaire_id = "q1",
                    version_id = "v1",
                    schema_json = com.testlogon.android.core.model.questionnaire.QuestionnaireDto(
                        questionnaire_id = "q1",
                    ),
                ),
            )
        }

        fun session(id: String): RespondentSession = RespondentSession(
            sessionId = id,
            slug = SLUG,
            questionnaireId = "q1",
            versionId = "v1",
            answers = emptyMap(),
            status = SessionStatus.IN_PROGRESS,
        )
    }
}
