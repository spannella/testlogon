package com.testlogon.android.feature.questionnaire.respond.data

import android.content.Context
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.respond.SessionDraftDao
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.ResponseSessionStartReq
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.model.questionnaire.SessionState
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.questionnaire.QuestionnaireApi
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.ResponseBody
import retrofit2.HttpException
import retrofit2.Response
import java.io.File
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
     *
     * AND-350: [answersOverride] (when non-null) is the EXACT answer body to send - the caller (the
     * ViewModel) passes the VISIBLE-only subset so HIDDEN questions are excluded from
     * answers_by_question_id (FR-2). When null the persisted draft answers are used (AND-348 behaviour).
     * The validate/submit body still sends EMPTY form_rules / group_rules (the server derives them).
     */
    suspend fun validate(
        slug: String,
        finalSubmit: Boolean = false,
        answersOverride: Map<String, AnswerValue>? = null,
    ): ApiResult<SessionValidation>

    /** FR-7 - clears the draft + prior sessionId for [slug], then starts fresh. */
    suspend fun startOver(slug: String): SessionStartOutcome

    /**
     * AND-349 FR-2/3/4 - FINAL submit of the session for [slug]. Flushes any dirty draft first
     * ([syncSave]), then POSTs submit with final_submit=true (built from the current draft answers).
     * NON-idempotent, so there is NO auto-retry. A 200 with result.can_submit==false is a VALIDATION
     * FAILURE (mapped to [SubmitOutcome.ValidationFailed]), NOT a success. [fieldOrder] is the schema
     * question order used to compute the first-errored field for scroll-to-first.
     *
     * AND-350: [answersOverride] (when non-null) is the VISIBLE-only answer body (HIDDEN questions
     * excluded, FR-2); null keeps the AND-349 draft-answer behaviour.
     */
    suspend fun submit(
        slug: String,
        fieldOrder: List<String> = emptyList(),
        answersOverride: Map<String, AnswerValue>? = null,
    ): SubmitOutcome

    /**
     * AND-349 FR-5 - ensures + downloads the response PDF for [slug]. Calls generatePdf (POST) to ensure
     * generation, then downloadPdf (the @Streaming GET) and streams the bytes to
     * cacheDir/questionnaire-pdf/{sessionId}.pdf (mirrors AND-341 PdfSource). Returns the on-disk file.
     */
    suspend fun downloadSubmissionPdf(slug: String): ApiResult<java.io.File>

    /**
     * AND-349 FR-7 - re-submit guard: true when the persisted draft/session for [slug] is in a TERMINAL
     * (submitted) status, so the screen opens directly in the Submitted state rather than re-editing.
     */
    suspend fun isAlreadySubmitted(slug: String): Boolean

    /**
     * AND-395 FR-2 - confirms the published questionnaire for [slug] exists / is reachable (the
     * idempotent GET behind the public-entry "loading" state). The schema body is owned by AND-346/347;
     * the public entry only needs the typed [ApiResult] (Success / Failure(status 404/422 -> NotFound) /
     * NetworkError -> retryable Error). The call is ANONYMOUS (no CSRF, no auth-refresh on 401).
     */
    suspend fun loadPublished(slug: String): ApiResult<com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireEnvelope>

    /**
     * AND-395 FR-3/8 - the locally-persisted session for [slug], or null if none exists yet. Used by the
     * public entry to RESUME-before-START (no duplicate session) and to route a TERMINAL (submitted)
     * session straight to AND-349's confirmation. Returns [PersistedSession] (id + terminal flag); a
     * non-blank persisted sessionId whose server status is "submitted" is terminal. Errors / offline are
     * treated as non-terminal so the user can keep working.
     */
    suspend fun persistedSession(slug: String): PersistedSession?

    /**
     * AND-395 FR-3 - starts a FRESH ANONYMOUS session for [slug] (POST, NON-idempotent, NO auto-retry)
     * and persists it. The "anonymous" semantics come from the request not carrying auth/CSRF (the
     * [com.testlogon.android.core.network.Anonymous] tag on the API), not a separate endpoint. Returns
     * the started [RespondentSession] on success.
     */
    suspend fun startAnonymousSession(slug: String): ApiResult<RespondentSession>
}

/**
 * AND-395 - a locally-persisted session pointer for the public-entry resume/terminal routing.
 * [isTerminal] is true when the server reports the session as submitted (AND-349 confirmation routing).
 */
data class PersistedSession(
    val id: String,
    val isTerminal: Boolean,
)

@Singleton
class RespondentSessionRepositoryImpl(
    private val api: QuestionnaireApi,
    private val draftDao: SessionDraftDao,
    moshi: Moshi,
    private val errorParser: ApiErrorParser,
    private val cacheDir: File,
) : RespondentSessionRepository {

    /**
     * Production constructor: derives the streamed-PDF cache root from the application context (mirrors
     * AND-341 PdfSourceImpl). The five-arg constructor above is used by tests (they pass a temp dir).
     */
    @Inject
    constructor(
        api: QuestionnaireApi,
        draftDao: SessionDraftDao,
        moshi: Moshi,
        errorParser: ApiErrorParser,
        @ApplicationContext context: Context,
    ) : this(api, draftDao, moshi, errorParser, context.cacheDir)

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

    override suspend fun validate(
        slug: String,
        finalSubmit: Boolean,
        answersOverride: Map<String, AnswerValue>?,
    ): ApiResult<SessionValidation> =
        withContext(dispatcher) {
            val draft = draftDao.getBySlug(slug)
                ?: return@withContext ApiResult.Failure(
                    errorParser.fromThrowable(IllegalStateException("no draft")),
                )
            call {
                val req = QuestionnaireValidationRequest(
                    // AND-350: prefer the caller's VISIBLE-only subset (hidden excluded); else the draft.
                    answers_by_question_id = answersOverride ?: answerJson.decode(draft.answersJson),
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

    override suspend fun submit(
        slug: String,
        fieldOrder: List<String>,
        answersOverride: Map<String, AnswerValue>?,
    ): SubmitOutcome =
        withContext(dispatcher) {
            val draft = draftDao.getBySlug(slug)
                ?: return@withContext SubmitOutcome.Failed(
                    errorParser.fromThrowable(IllegalStateException("no draft")),
                )
            // AND-349 FR-2/3: flush the latest edits FIRST so submit sees the saved answers. A flush
            // failure does not abort the submit (the submit body carries the current draft answers); the
            // submit itself is the source of truth for the final verdict.
            if (draft.dirty) {
                runCatching { syncSaveLocked(slug, draft) }
            }
            // AND-349 FR-4: NON-idempotent submit; NO auto-retry. Build the request from the current draft.
            val refreshed = draftDao.getBySlug(slug) ?: draft
            val result = call {
                val req = QuestionnaireValidationRequest(
                    // AND-350: prefer the caller's VISIBLE-only subset (hidden excluded); else the draft.
                    answers_by_question_id = answersOverride ?: answerJson.decode(refreshed.answersJson),
                    final_submit = true,
                )
                val envelope = api.submit(slug, refreshed.sessionId, req)
                val state = envelope.session.toSessionState()
                SessionSubmitMapping(
                    sessionId = state.response_session_id,
                    status = SessionStatus.fromWire(state.status),
                    result = envelope.result,
                    fieldOrder = fieldOrder,
                )
            }
            when (result) {
                is ApiResult.Success -> result.data.toSubmitOutcome()
                is ApiResult.Failure -> SubmitOutcome.Failed(result.error)
                is ApiResult.NetworkError ->
                    SubmitOutcome.Failed(ApiError(ApiError.STATUS_NETWORK, OFFLINE_MESSAGE))
            }
        }

    override suspend fun downloadSubmissionPdf(slug: String): ApiResult<File> = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)
            ?: return@withContext ApiResult.Failure(
                errorParser.fromThrowable(IllegalStateException("no draft")),
            )
        val sessionId = draft.sessionId

        // AND-349 FR-5 step 1: ensure the artifact exists (POST). The descriptor is opaque/tolerated; the
        // bytes come from the streamed GET below, so a generate failure (HTTP / transport) short-circuits.
        when (val generated = call { api.generatePdf(slug, sessionId) }) {
            is ApiResult.Success -> Unit
            is ApiResult.Failure -> return@withContext ApiResult.Failure(generated.error)
            is ApiResult.NetworkError -> return@withContext generated
        }

        // AND-349 FR-5 step 2: stream the bytes to cacheDir/questionnaire-pdf/{sessionId}.pdf (mirrors
        // AND-341 PdfSource: chunked copy, between-chunk cancellation, non-empty verification).
        val target = targetPdfFile(sessionId)
        val response: Response<ResponseBody> = try {
            api.downloadPdf(slug, sessionId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            return@withContext ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
        if (!response.isSuccessful) {
            return@withContext ApiResult.Failure(errorParser.from(HttpException(response)))
        }
        val body = response.body()
            ?: return@withContext ApiResult.NetworkError(IOException("Empty PDF body"))

        val part = File(target.parentFile, target.name + PART_SUFFIX)
        try {
            body.byteStream().use { input ->
                part.outputStream().use { output ->
                    val buffer = ByteArray(PDF_BUFFER_SIZE)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val read = input.read(buffer)
                        if (read == -1) break
                        output.write(buffer, 0, read)
                    }
                    output.flush()
                }
            }
        } catch (e: CancellationException) {
            part.delete()
            throw e
        } catch (e: IOException) {
            part.delete()
            return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }

        if (part.length() <= 0L) {
            part.delete()
            return@withContext ApiResult.Failure(
                ApiError(status = ApiError.STATUS_PARSE, message = EMPTY_PDF_MESSAGE),
            )
        }
        // Commit: atomic-ish rename over any prior file.
        target.delete()
        if (!part.renameTo(target)) {
            part.copyTo(target, overwrite = true)
            part.delete()
        }
        ApiResult.Success(target)
    }

    override suspend fun isAlreadySubmitted(slug: String): Boolean = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)?.takeIf { it.sessionId.isNotBlank() }
            ?: return@withContext false
        // FR-7 re-submit guard: the local draft carries no terminal status column (no Room migration), so
        // the server session is the authority. A SUBMITTED status -> terminal. Any error (offline /
        // missing) is treated as not-yet-submitted so the user can still work / retry.
        when (val result = call { api.getSession(slug, draft.sessionId).toDomain(slug) }) {
            is ApiResult.Success -> result.data.status == SessionStatus.SUBMITTED
            is ApiResult.Failure, is ApiResult.NetworkError -> false
        }
    }

    override suspend fun loadPublished(
        slug: String,
    ): ApiResult<com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireEnvelope> =
        withContext(dispatcher) {
            // AND-395 FR-2: idempotent anonymous GET. The bounded-backoff retry is applied by the
            // OkHttp RetryInterceptor (GET-only); this layer only wraps the outcome in ApiResult.
            call { api.getPublished(slug) }
        }

    override suspend fun persistedSession(slug: String): PersistedSession? = withContext(dispatcher) {
        val draft = draftDao.getBySlug(slug)?.takeIf { it.sessionId.isNotBlank() }
            ?: return@withContext null
        // AND-395 FR-3: terminality is the server's authority (the local draft has no status column).
        // Any error (offline / missing) is treated as NON-terminal so the user can resume / retry.
        val terminal = when (val result = call { api.getSession(slug, draft.sessionId).toDomain(slug) }) {
            is ApiResult.Success -> result.data.status == SessionStatus.SUBMITTED
            is ApiResult.Failure, is ApiResult.NetworkError -> false
        }
        PersistedSession(id = draft.sessionId, isTerminal = terminal)
    }

    override suspend fun startAnonymousSession(slug: String): ApiResult<RespondentSession> =
        withContext(dispatcher) {
            // AND-395 FR-3: NON-idempotent POST (no auto-retry). Anonymous via the API's @Tag(Anonymous).
            val result = call {
                val envelope = api.startSession(slug, ResponseSessionStartReq())
                val state = envelope.session.toSessionState()
                state.toDomain(slug, emptyMap())
            }
            if (result is ApiResult.Success) {
                persistClean(result.data)
            }
            result
        }

    // ---- internals ----

    /** PUTs the dirty [draft]'s answers for [slug]; clears dirty on success. Used by the submit flush. */
    private suspend fun syncSaveLocked(slug: String, draft: com.testlogon.android.core.data.respond.SessionDraftEntity) {
        val answers = answerJson.decode(draft.answersJson)
        val result = call {
            val req = SessionSaveReq(
                answers_by_question_id = answers,
                current_section_index = draft.currentSectionIndex,
                current_question_id = draft.currentQuestionId,
            )
            api.saveAnswers(slug, draft.sessionId, req).toDomain(slug)
        }
        if (result is ApiResult.Success) {
            draftDao.setDirty(slug, dirty = false, updatedAt = clock())
        }
    }

    /** The on-disk cache target for [sessionId]'s response PDF (cacheDir/questionnaire-pdf/{id}.pdf). */
    private fun targetPdfFile(sessionId: String): File {
        val dir = File(cacheDir, PDF_DIR).apply { mkdirs() }
        return File(dir, sanitize(sessionId) + ".pdf")
    }

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

    private companion object {
        const val PDF_DIR = "questionnaire-pdf"
        const val PART_SUFFIX = ".part"
        const val PDF_BUFFER_SIZE = 16 * 1024
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
        const val EMPTY_PDF_MESSAGE = "This response could not be downloaded."

        /** Keeps the cache filename to a safe basename (session ids are opaque, but be defensive). */
        fun sanitize(sessionId: String): String =
            sessionId.map { if (it.isLetterOrDigit() || it == '_' || it == '-') it else '_' }
                .joinToString("")
                .ifEmpty { "session" }
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
        // AND-350: carry the raw wire errors (incl. group:/form: keys) for the VM's IssueReconciler.
        serverErrors = errors,
    )
}
