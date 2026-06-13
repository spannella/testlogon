package com.testlogon.android.feature.questionnaire.respond.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.respond.SessionDraftDao
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.ResponseSessionStartReq
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.model.questionnaire.SessionState
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.questionnaire.QuestionnaireApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-348 - data layer for the respondent SESSION LIFECYCLE of the public questionnaire-response flow
 * (epic E45). SUBMIT + PDF are OUT OF SCOPE (AND-349).
 *
 * REUSE: every server call REUSES AND-346's [QuestionnaireApi] (raw DTOs); this repository wraps each
 * in [call] -> [ApiResult] and maps the DTO to the [RespondentSession] domain (mirrors AND-340
 * SignatureRepository). The public respond flow is anonymous BUT save/validate are mutating, so the
 * SHARED OkHttp client (persistent cookie jar + CSRF interceptor) is used via the injected
 * [QuestionnaireApi] (NOT a cookieless client).
 *
 * Local durability: the in-progress draft is persisted in Room ([SessionDraftDao]) keyed by slug
 * (FR-7). Answers are serialized to/from the draft via the INJECTED [Moshi] (AnswerValue has a
 * registered AND-346 adapter); no new dependency. [saveLocal] NEVER blocks on the network (FR-5);
 * [syncSave] flushes the dirty draft and clears dirty only on success. Debounce is the ViewModel's
 * job; this repository performs exactly one sync per call.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
interface RespondentSessionRepository {

    /**
     * FR-1/2 - starts OR resumes the session for [slug]. If a local draft exists it GETs the server
     * snapshot and reconciles (schema-version safety, FR-6); otherwise it POSTs startSession and
     * persists a fresh draft. Returns a [SessionStartOutcome] (Ready / SchemaChanged / Failed).
     */
    suspend fun startOrResume(slug: String): SessionStartOutcome

    /**
     * FR-2 - restores the persisted draft for [slug] (answers + sessionId + versionId) merged with the
     * latest server snapshot. Same outcome shape as [startOrResume]; if no draft exists it falls back to
     * a fresh start.
     */
    suspend fun resume(slug: String): SessionStartOutcome

    /**
     * FR-5 - writes the draft for [slug] to Room IMMEDIATELY with dirty=true. NEVER blocks on the
     * network. Requires an already-known session (sessionId/questionnaireId/versionId), so [base] is the
     * current in-memory session whose cursor/answers are being updated.
     */
    suspend fun saveLocal(
        base: RespondentSession,
        answers: Map<String, AnswerValue>,
        sectionIndex: Int? = base.currentSectionIndex,
        questionId: String? = base.currentQuestionId,
    )

    /**
     * FR-3/5 - flushes the dirty draft for [slug] to the server (PUT saveAnswers). On success clears
     * dirty and returns the server-confirmed session. On a network failure keeps dirty and returns a
     * [ApiResult.NetworkError]. A no-op (Success of the current draft) if there is nothing dirty.
     */
    suspend fun syncSave(slug: String): ApiResult<RespondentSession>

    /**
     * FR-4/8 - POSTs validate for [slug] and maps the wire errors (questionId -> List<ValidationIssue>)
     * to a per-field message map for AND-347's renderer, plus the can_submit verdict (the AND-349
     * hand-off). [finalSubmit] is false for an in-flow validate.
     */
    suspend fun validate(slug: String, finalSubmit: Boolean = false): ApiResult<SessionValidation>

    /** FR-7 - clears the draft + prior sessionId for [slug], then starts fresh. */
    suspend fun startOver(slug: String): SessionStartOutcome
}

@Singleton
class RespondentSessionRepositoryImpl @Inject constructor(
    private val api: QuestionnaireApi,
    private val draftDao: SessionDraftDao,
    moshi: Moshi,
    private val errorParser: ApiErrorParser,
) : RespondentSessionRepository {

    private val answerJson = AnswerMapJson(moshi)

    /**
     * IO dispatcher seam. Not constructor-injected because Hilt cannot provide a bare
     * CoroutineDispatcher (no qualifier in this project); tests overwrite it directly.
     */
    var dispatcher: CoroutineDispatcher = Dispatchers.IO

    /** Clock seam (epoch ms) for the draft updated_at column; overridable in tests. */
    var clock: () -> Long = { System.currentTimeMillis() }

    override suspend fun startOrResume(slug: String): SessionStartOutcome = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)
        if (draft?.sessionId?.isNotBlank() == true) {
            reconcileWithServer(slug, draft.sessionId, draft.versionId)
        } else {
            freshStart(slug)
        }
    }

    override suspend fun resume(slug: String): SessionStartOutcome = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)
            ?: return@withContext freshStart(slug)
        reconcileWithServer(slug, draft.sessionId, draft.versionId)
    }

    override suspend fun saveLocal(
        base: RespondentSession,
        answers: Map<String, AnswerValue>,
        sectionIndex: Int?,
        questionId: String?,
    ) {
        withContext(dispatcher) {
            val updated = base.copy(
                answers = answers,
                currentSectionIndex = sectionIndex,
                currentQuestionId = questionId,
            )
            // FR-5: write dirty immediately, never touching the network.
            draftDao.upsert(
                updated.toDraftEntity(
                    dirty = true,
                    updatedAt = clock(),
                    encodeAnswers = answerJson::encode,
                ),
            )
        }
    }

    override suspend fun syncSave(slug: String): ApiResult<RespondentSession> = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)
            ?: return@withContext ApiResult.Failure(errorParser.fromThrowable(IllegalStateException("no draft")))
        if (!draft.dirty) {
            // Nothing to flush; the local draft is the source of truth.
            return@withContext ApiResult.Success(draft.toDomain(answerJson::decode))
        }
        val answers = answerJson.decode(draft.answersJson)
        val result = call {
            val req = SessionSaveReq(
                answers_by_question_id = answers,
                current_section_index = draft.currentSectionIndex,
                current_question_id = draft.currentQuestionId,
            )
            api.saveAnswers(slug, draft.sessionId, req).toDomain(slug)
        }
        when (result) {
            is ApiResult.Success -> {
                // FR-3: clear dirty only after the server confirmed the save.
                draftDao.setDirty(slug, dirty = false, updatedAt = clock())
            }
            // FR-5: a network (or server) failure keeps the draft dirty for a later retry.
            is ApiResult.Failure, is ApiResult.NetworkError -> Unit
        }
        result
    }

    override suspend fun validate(slug: String, finalSubmit: Boolean): ApiResult<SessionValidation> =
        withContext(dispatcher) {
            val draft = draftDao.getBySlug(slug)
                ?: return@withContext ApiResult.Failure(
                    errorParser.fromThrowable(IllegalStateException("no draft")),
                )
            call {
                val req = QuestionnaireValidationRequest(
                    answers_by_question_id = answerJson.decode(draft.answersJson),
                    final_submit = finalSubmit,
                )
                api.validate(slug, draft.sessionId, req).toValidation()
            }
        }

    override suspend fun startOver(slug: String): SessionStartOutcome = withContext(dispatcher) {
        // FR-7: drop the local draft (and its prior sessionId) before starting a brand-new session.
        draftDao.deleteBySlug(slug)
        freshStart(slug)
    }

    // ---- internals ----

    /** POSTs a new session, persists a fresh (clean) draft, and returns it. */
    private suspend fun freshStart(slug: String): SessionStartOutcome {
        val result = call {
            val envelope = api.startSession(slug, ResponseSessionStartReq())
            val state = envelope.session.toSessionState()
            state.toDomain(slug, emptyMap())
        }
        return when (result) {
            is ApiResult.Success -> {
                persistClean(result.data)
                SessionStartOutcome.Ready(result.data)
            }
            is ApiResult.Failure -> SessionStartOutcome.Failed(result)
            is ApiResult.NetworkError -> SessionStartOutcome.Failed(result)
        }
    }

    /**
     * GETs the server snapshot for an existing [sessionId] and reconciles against the cached
     * [cachedVersionId]. A versionId mismatch surfaces [SessionStartOutcome.SchemaChanged] (FR-6, no
     * silent discard). A match persists the reconciled (clean) server snapshot. A NetworkError falls
     * back to the offline-tolerant local draft so the user can keep working (FR-5).
     */
    private suspend fun reconcileWithServer(
        slug: String,
        sessionId: String,
        cachedVersionId: String,
    ): SessionStartOutcome {
        val result = call { api.getSession(slug, sessionId).toDomain(slug) }
        return when (result) {
            is ApiResult.Success -> {
                val server = result.data
                if (cachedVersionId.isNotBlank() && server.versionId != cachedVersionId) {
                    SessionStartOutcome.SchemaChanged(
                        slug = slug,
                        cachedVersionId = cachedVersionId,
                        serverVersionId = server.versionId,
                        serverSession = server,
                    )
                } else {
                    persistClean(server)
                    SessionStartOutcome.Ready(server)
                }
            }
            is ApiResult.Failure -> SessionStartOutcome.Failed(result)
            is ApiResult.NetworkError -> {
                // FR-5 offline tolerance: serve the cached draft if we have one, else surface the error.
                val draft = draftDao.getBySlug(slug)
                if (draft != null) {
                    SessionStartOutcome.Ready(draft.toDomain(answerJson::decode))
                } else {
                    SessionStartOutcome.Failed(result)
                }
            }
        }
    }

    /** Persists [session] as a clean (dirty=false) draft. */
    private suspend fun persistClean(session: RespondentSession) {
        draftDao.upsert(
            session.toDraftEntity(
                dirty = false,
                updatedAt = clock(),
                encodeAnswers = answerJson::encode,
            ),
        )
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); malformed JSON ->
     * Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors AND-340.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/**
 * AND-348 - inflates the opaque start-session `session` map into a typed [SessionState]. The start
 * response carries the session as an opaque map (not the typed [SessionState]); the required structural
 * keys are pulled out (absence -> [JsonDataException], FR-6 fail-fast) and the rest tolerated.
 */
internal fun Map<String, Any?>.toSessionState(): SessionState {
    fun req(key: String): String = (this[key] as? String)
        ?: throw JsonDataException("Required session key '$key' missing or not a string")
    return SessionState(
        response_session_id = req("response_session_id"),
        questionnaire_id = req("questionnaire_id"),
        version_id = req("version_id"),
        status = (this["status"] as? String).orEmpty(),
        current_section_index = (this["current_section_index"] as? Number)?.toInt(),
        current_question_id = this["current_question_id"] as? String,
    )
}

/**
 * AND-348 - flattens the validation response into a [SessionValidation]. Each question's error list is
 * collapsed to a single message (the FIRST blocking issue if any, else the first issue). Empty issue
 * lists are dropped so a question with no errors is absent from the field-error map (FR-4/8).
 */
internal fun QuestionnaireValidationResponse.toValidation(): SessionValidation {
    val fieldErrors = errors.mapNotNull { (questionId, issues) ->
        val chosen = issues.firstOrNull { it.blocking == true } ?: issues.firstOrNull()
        chosen?.let { questionId to it.message }
    }.toMap()
    return SessionValidation(
        isValid = is_valid,
        canSubmit = can_submit,
        hasBlockingFormError = has_blocking_form_error,
        fieldErrors = fieldErrors,
    )
}
