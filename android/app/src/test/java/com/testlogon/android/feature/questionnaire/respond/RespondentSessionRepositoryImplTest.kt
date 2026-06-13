package com.testlogon.android.feature.questionnaire.respond

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.respond.SessionDraftDao
import com.testlogon.android.core.data.respond.SessionDraftEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.ResponseSessionEnvelope
import com.testlogon.android.core.model.questionnaire.ResponseSessionStartReq
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.model.questionnaire.SessionState
import com.testlogon.android.core.model.questionnaire.SessionStateEnvelope
import com.testlogon.android.core.model.questionnaire.ValidationIssue
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.questionnaire.AnswerValueAdapter
import com.testlogon.android.core.network.questionnaire.QuestionnaireApi
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepositoryImpl
import com.testlogon.android.feature.questionnaire.respond.data.SessionStartOutcome
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import okhttp3.ResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response

/**
 * AND-348 — JVM unit tests for [RespondentSessionRepositoryImpl]. Uses a recording fake
 * [QuestionnaireApi] (records the call BEFORE throwing a configured error), an in-memory
 * [FakeSessionDraftDao], and a real Moshi (AnswerValueAdapter + reflective factory) so answersJson
 * round-trips exactly as production does. Covers start, resume, saveLocal, syncSave (success + offline),
 * validate, schema-version mismatch, and startOver.
 */
class RespondentSessionRepositoryImplTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(AnswerValueAdapter)
        .build()

    // ---- in-memory DAO ----

    private class FakeSessionDraftDao : SessionDraftDao {
        val rows = MutableStateFlow<Map<String, SessionDraftEntity>>(emptyMap())
        override suspend fun upsert(entity: SessionDraftEntity) {
            rows.value = rows.value + (entity.slug to entity)
        }
        override suspend fun getBySlug(slug: String): SessionDraftEntity? = rows.value[slug]
        override fun observe(slug: String): Flow<SessionDraftEntity?> = rows.map { it[slug] }
        override suspend fun setDirty(slug: String, dirty: Boolean, updatedAt: Long) {
            rows.value[slug]?.let { rows.value = rows.value + (slug to it.copy(dirty = dirty, updatedAt = updatedAt)) }
        }
        override suspend fun deleteBySlug(slug: String) { rows.value = rows.value - slug }
    }

    // ---- recording fake API ----

    private class FakeQuestionnaireApi : QuestionnaireApi {
        var startCalls = 0
        var getCalls = 0
        var saveCalls = 0
        var validateCalls = 0
        var lastSave: SessionSaveReq? = null

        var startEnvelope: ResponseSessionEnvelope = envelope("rs_1", "q1", "v1")
        var stateEnvelope: SessionStateEnvelope = stateEnv("rs_1", "q1", "v1", emptyMap())
        var validateResponse: QuestionnaireValidationResponse =
            QuestionnaireValidationResponse(true, true, false, emptyMap())

        // When set, the matching call records itself THEN throws (offline simulation).
        var saveThrows: Throwable? = null

        override suspend fun getPublished(publishedSlug: String) =
            throw UnsupportedOperationException("not used")

        override suspend fun startSession(
            publishedSlug: String,
            body: ResponseSessionStartReq,
        ): ResponseSessionEnvelope {
            startCalls++
            return startEnvelope
        }

        override suspend fun getSession(
            publishedSlug: String,
            responseSessionId: String,
        ): SessionStateEnvelope {
            getCalls++
            return stateEnvelope
        }

        override suspend fun saveAnswers(
            publishedSlug: String,
            responseSessionId: String,
            body: SessionSaveReq,
        ): SessionStateEnvelope {
            saveCalls++
            lastSave = body
            saveThrows?.let { throw it }
            return stateEnv(responseSessionId, "q1", "v1", body.answers_by_question_id)
        }

        override suspend fun validate(
            publishedSlug: String,
            responseSessionId: String,
            body: QuestionnaireValidationRequest,
        ): QuestionnaireValidationResponse {
            validateCalls++
            return validateResponse
        }

        override suspend fun submit(publishedSlug: String, responseSessionId: String, body: QuestionnaireValidationRequest) =
            throw UnsupportedOperationException("out of scope (AND-349)")
        override suspend fun generatePdf(publishedSlug: String, responseSessionId: String) =
            throw UnsupportedOperationException("out of scope (AND-349)")
        override suspend fun downloadPdf(publishedSlug: String, responseSessionId: String): Response<ResponseBody> =
            throw UnsupportedOperationException("out of scope (AND-349)")
    }

    private val dao = FakeSessionDraftDao()
    private val api = FakeQuestionnaireApi()

    private fun repo() = RespondentSessionRepositoryImpl(
        api = api,
        draftDao = dao,
        moshi = moshi,
        errorParser = ApiErrorParser(moshi),
    ).also {
        it.clock = { 1_000L }
        it.dispatcher = UnconfinedTestDispatcher()
    }

    @Test
    fun startOrResume_noDraft_postsStart_andPersistsCleanDraft() = runTest {
        val outcome = repo().startOrResume(SLUG)

        assertEquals(1, api.startCalls)
        assertEquals(0, api.getCalls)
        assertTrue(outcome is SessionStartOutcome.Ready)
        val row = dao.getBySlug(SLUG)!!
        assertEquals("rs_1", row.sessionId)
        assertEquals("v1", row.versionId)
        assertFalse(row.dirty)
    }

    @Test
    fun resume_draftPresent_getsServerSnapshot_andReconciles() = runTest {
        seedDraft(versionId = "v1")
        api.stateEnvelope = stateEnv("rs_1", "q1", "v1", mapOf("q1" to AnswerValue.Text("server")))

        val outcome = repo().resume(SLUG)

        assertEquals(1, api.getCalls)
        assertEquals(0, api.startCalls)
        assertTrue(outcome is SessionStartOutcome.Ready)
        assertEquals(
            AnswerValue.Text("server"),
            (outcome as SessionStartOutcome.Ready).session.answers["q1"],
        )
    }

    @Test
    fun saveLocal_writesDirtyDraft_withoutNetwork() = runTest {
        seedDraft()
        val base = dao.getBySlug(SLUG)!!.let {
            com.testlogon.android.core.model.questionnaire.RespondentSession(
                sessionId = it.sessionId, slug = it.slug, questionnaireId = it.questionnaireId,
                versionId = it.versionId, answers = emptyMap(),
                status = com.testlogon.android.core.model.questionnaire.SessionStatus.IN_PROGRESS,
            )
        }
        repo().saveLocal(base, mapOf("q1" to AnswerValue.Text("typed")))

        assertEquals(0, api.saveCalls)
        val row = dao.getBySlug(SLUG)!!
        assertTrue(row.dirty)
        assertTrue(row.answersJson.contains("typed"))
    }

    @Test
    fun syncSave_dirty_putsAnswers_thenClearsDirty() = runTest {
        seedDraft(dirty = true, answersJson = """{"q1":"typed"}""")

        val result = repo().syncSave(SLUG)

        assertEquals(1, api.saveCalls)
        assertEquals(AnswerValue.Text("typed"), api.lastSave?.answers_by_question_id?.get("q1"))
        assertTrue(result is ApiResult.Success)
        assertFalse(dao.getBySlug(SLUG)!!.dirty)
    }

    @Test
    fun syncSave_networkFailure_keepsDirty_andReturnsNetworkError() = runTest {
        seedDraft(dirty = true, answersJson = """{"q1":"typed"}""")
        api.saveThrows = java.io.IOException("offline")

        val result = repo().syncSave(SLUG)

        // The fake recorded the call BEFORE throwing.
        assertEquals(1, api.saveCalls)
        assertTrue(result is ApiResult.NetworkError)
        assertTrue(dao.getBySlug(SLUG)!!.dirty)
    }

    @Test
    fun validate_mapsErrors_toFieldMap_andCanSubmit() = runTest {
        seedDraft(answersJson = """{"q1":"x"}""")
        api.validateResponse = QuestionnaireValidationResponse(
            is_valid = false,
            can_submit = false,
            has_blocking_form_error = true,
            errors = mapOf(
                "q1" to listOf(
                    ValidationIssue(code = "soft", message = "soft msg", blocking = false),
                    ValidationIssue(code = "hard", message = "blocking msg", blocking = true),
                ),
            ),
        )

        val result = repo().validate(SLUG)

        assertTrue(result is ApiResult.Success)
        val v = (result as ApiResult.Success).data
        // The blocking issue wins for the field message.
        assertEquals("blocking msg", v.fieldErrors["q1"])
        assertFalse(v.canSubmit)
    }

    @Test
    fun startOrResume_versionMismatch_surfacesSchemaChanged_withoutDiscardingDraft() = runTest {
        seedDraft(versionId = "v1", answersJson = """{"q1":"keep"}""")
        api.stateEnvelope = stateEnv("rs_1", "q1", "v2", mapOf("q1" to AnswerValue.Text("server")))

        val outcome = repo().startOrResume(SLUG)

        assertTrue(outcome is SessionStartOutcome.SchemaChanged)
        val sc = outcome as SessionStartOutcome.SchemaChanged
        assertEquals("v1", sc.cachedVersionId)
        assertEquals("v2", sc.serverVersionId)
        // The cached draft is NOT discarded.
        assertEquals("""{"q1":"keep"}""", dao.getBySlug(SLUG)?.answersJson)
    }

    @Test
    fun startOver_clearsDraft_thenStartsFresh() = runTest {
        seedDraft(versionId = "old", answersJson = """{"q1":"old"}""")
        api.startEnvelope = envelope("rs_new", "q1", "v9")

        val outcome = repo().startOver(SLUG)

        assertEquals(1, api.startCalls)
        assertTrue(outcome is SessionStartOutcome.Ready)
        val row = dao.getBySlug(SLUG)!!
        assertEquals("rs_new", row.sessionId)
        assertEquals("v9", row.versionId)
        // Fresh start has no carried-over answers.
        assertEquals("{}", row.answersJson)
    }

    @Test
    fun reconcile_offlineWithDraft_fallsBackToLocal() = runTest {
        seedDraft(versionId = "v1", answersJson = """{"q1":"cached"}""")
        api.stateEnvelope = stateEnv("rs_1", "q1", "v1", emptyMap())
        // Force getSession to fail as offline by routing through saveThrows-style: emulate via a throwing get.
        val throwingApi = object : QuestionnaireApi by api {
            override suspend fun getSession(publishedSlug: String, responseSessionId: String): SessionStateEnvelope =
                throw java.io.IOException("offline")
        }
        val repo = RespondentSessionRepositoryImpl(
            api = throwingApi,
            draftDao = dao,
            moshi = moshi,
            errorParser = ApiErrorParser(moshi),
        ).also {
            it.clock = { 1_000L }
            it.dispatcher = UnconfinedTestDispatcher()
        }

        val outcome = repo.resume(SLUG)

        assertTrue(outcome is SessionStartOutcome.Ready)
        assertEquals(
            AnswerValue.Text("cached"),
            (outcome as SessionStartOutcome.Ready).session.answers["q1"],
        )
    }

    // ---- helpers ----

    private suspend fun seedDraft(
        versionId: String = "v1",
        dirty: Boolean = false,
        answersJson: String = "{}",
    ) {
        dao.upsert(
            SessionDraftEntity(
                slug = SLUG,
                sessionId = "rs_1",
                questionnaireId = "q1",
                versionId = versionId,
                answersJson = answersJson,
                currentSectionIndex = 0,
                currentQuestionId = "q1",
                dirty = dirty,
                updatedAt = 1L,
            ),
        )
    }

    private companion object {
        const val SLUG = "my-survey"
    }
}

private fun envelope(sessionId: String, qId: String, versionId: String) = ResponseSessionEnvelope(
    session = mapOf(
        "response_session_id" to sessionId,
        "questionnaire_id" to qId,
        "version_id" to versionId,
        "status" to "in_progress",
    ),
)

private fun stateEnv(
    sessionId: String,
    qId: String,
    versionId: String,
    answers: Map<String, AnswerValue>,
) = SessionStateEnvelope(
    session = SessionState(
        response_session_id = sessionId,
        questionnaire_id = qId,
        version_id = versionId,
        status = "in_progress",
        current_section_index = 0,
        current_question_id = qId,
    ),
    answers_by_question_id = answers,
)
