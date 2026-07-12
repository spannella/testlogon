package com.testlogon.android.feature.questionnaire.builder.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.questionnaire.QnrDraftCreateReq
import com.testlogon.android.core.network.questionnaire.QnrDraftUpdateReq
import com.testlogon.android.core.network.questionnaire.QnrPublishReq
import com.testlogon.android.core.network.questionnaire.QnrQuestionCreateReq
import com.testlogon.android.core.network.questionnaire.QnrQuestionUpdateReq
import com.testlogon.android.core.network.questionnaire.QnrSectionCreateReq
import com.testlogon.android.core.network.questionnaire.QnrSectionUpdateReq
import com.testlogon.android.core.network.questionnaire.QuestionnaireBuilderApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the questionnaire BUILDER (creator-authoring) surface, over the
 * [QuestionnaireBuilderApi]. Every method folds into [ApiResult] via [call] (HTTP -> Failure preserving
 * status; malformed JSON -> Failure; transport -> NetworkError; cancellation re-thrown) - the same fold
 * the apikeys repository uses.
 *
 * All builder mutations are owner-side authenticated control-plane calls; none are auto-retried here (the
 * shared RetryInterceptor only retries idempotent GETs at the transport layer). There is no caching - the
 * builder always reflects the authoritative server state after each mutation, matching the web page.
 */
interface QuestionnaireBuilderRepository {

    suspend fun listDrafts(includeArchived: Boolean = false): ApiResult<List<QnrDraft>>

    suspend fun createDraft(
        questionnaireId: String,
        title: String,
        description: String,
        visibility: String,
    ): ApiResult<QnrDraft>

    suspend fun getDraft(questionnaireId: String): ApiResult<QnrDraft>

    suspend fun updateDraft(
        questionnaireId: String,
        title: String?,
        description: String?,
        visibility: String?,
    ): ApiResult<QnrDraft>

    suspend fun archiveDraft(questionnaireId: String): ApiResult<QnrDraft>

    suspend fun listSections(questionnaireId: String): ApiResult<List<QnrSection>>

    suspend fun createSection(
        questionnaireId: String,
        sectionId: String,
        title: String,
        description: String,
    ): ApiResult<QnrSection>

    suspend fun updateSection(
        questionnaireId: String,
        sectionId: String,
        title: String?,
        description: String?,
    ): ApiResult<QnrSection>

    suspend fun deleteSection(questionnaireId: String, sectionId: String): ApiResult<Unit>

    suspend fun listQuestions(questionnaireId: String, sectionId: String): ApiResult<List<QnrQuestion>>

    suspend fun createQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
        type: QnrQuestionType,
        label: String,
        required: Boolean,
        hint: String,
        configJson: Map<String, Any?>,
    ): ApiResult<QnrQuestion>

    suspend fun updateQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
        label: String?,
        required: Boolean?,
        hint: String?,
        configJson: Map<String, Any?>?,
    ): ApiResult<QnrQuestion>

    suspend fun deleteQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
    ): ApiResult<Unit>

    suspend fun publish(questionnaireId: String, publishedSlug: String?): ApiResult<QnrPublishedVersion>
}

@Singleton
class DefaultQuestionnaireBuilderRepository @Inject constructor(
    private val api: QuestionnaireBuilderApi,
    private val errorParser: ApiErrorParser,
) : QuestionnaireBuilderRepository {

    override suspend fun listDrafts(includeArchived: Boolean): ApiResult<List<QnrDraft>> =
        withContext(Dispatchers.IO) {
            call { api.listDrafts(includeArchived).items.map { it.toDomain() } }
        }

    override suspend fun createDraft(
        questionnaireId: String,
        title: String,
        description: String,
        visibility: String,
    ): ApiResult<QnrDraft> = withContext(Dispatchers.IO) {
        call {
            api.createDraft(
                QnrDraftCreateReq(
                    questionnaireId = questionnaireId,
                    title = title,
                    description = description,
                    visibility = visibility,
                ),
            ).draft.toDomain()
        }
    }

    override suspend fun getDraft(questionnaireId: String): ApiResult<QnrDraft> =
        withContext(Dispatchers.IO) { call { api.getDraft(questionnaireId).draft.toDomain() } }

    override suspend fun updateDraft(
        questionnaireId: String,
        title: String?,
        description: String?,
        visibility: String?,
    ): ApiResult<QnrDraft> = withContext(Dispatchers.IO) {
        call {
            api.updateDraft(
                questionnaireId,
                QnrDraftUpdateReq(title = title, description = description, visibility = visibility),
            ).draft.toDomain()
        }
    }

    override suspend fun archiveDraft(questionnaireId: String): ApiResult<QnrDraft> =
        withContext(Dispatchers.IO) { call { api.archiveDraft(questionnaireId).draft.toDomain() } }

    override suspend fun listSections(questionnaireId: String): ApiResult<List<QnrSection>> =
        withContext(Dispatchers.IO) {
            call { api.listSections(questionnaireId).items.map { it.toDomain() } }
        }

    override suspend fun createSection(
        questionnaireId: String,
        sectionId: String,
        title: String,
        description: String,
    ): ApiResult<QnrSection> = withContext(Dispatchers.IO) {
        call {
            api.createSection(
                questionnaireId,
                QnrSectionCreateReq(sectionId = sectionId, title = title, description = description),
            ).section.toDomain()
        }
    }

    override suspend fun updateSection(
        questionnaireId: String,
        sectionId: String,
        title: String?,
        description: String?,
    ): ApiResult<QnrSection> = withContext(Dispatchers.IO) {
        call {
            api.updateSection(
                questionnaireId,
                sectionId,
                QnrSectionUpdateReq(title = title, description = description),
            ).section.toDomain()
        }
    }

    override suspend fun deleteSection(questionnaireId: String, sectionId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { api.deleteSection(questionnaireId, sectionId); Unit }
        }

    override suspend fun listQuestions(
        questionnaireId: String,
        sectionId: String,
    ): ApiResult<List<QnrQuestion>> = withContext(Dispatchers.IO) {
        call { api.listQuestions(questionnaireId, sectionId).items.map { it.toDomain() } }
    }

    override suspend fun createQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
        type: QnrQuestionType,
        label: String,
        required: Boolean,
        hint: String,
        configJson: Map<String, Any?>,
    ): ApiResult<QnrQuestion> = withContext(Dispatchers.IO) {
        call {
            api.createQuestion(
                questionnaireId,
                QnrQuestionCreateReq(
                    sectionId = sectionId,
                    questionId = questionId,
                    type = type.wire,
                    label = label,
                    required = required,
                    hint = hint,
                    configJson = normalizeConfig(configJson),
                ),
            ).question.toDomain()
        }
    }

    override suspend fun updateQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
        label: String?,
        required: Boolean?,
        hint: String?,
        configJson: Map<String, Any?>?,
    ): ApiResult<QnrQuestion> = withContext(Dispatchers.IO) {
        call {
            api.updateQuestion(
                questionnaireId,
                questionId,
                sectionId,
                QnrQuestionUpdateReq(
                    label = label,
                    required = required,
                    hint = hint,
                    configJson = configJson?.let { normalizeConfig(it) },
                ),
            ).question.toDomain()
        }
    }

    override suspend fun deleteQuestion(
        questionnaireId: String,
        sectionId: String,
        questionId: String,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call { api.deleteQuestion(questionnaireId, questionId, sectionId); Unit }
    }

    override suspend fun publish(
        questionnaireId: String,
        publishedSlug: String?,
    ): ApiResult<QnrPublishedVersion> = withContext(Dispatchers.IO) {
        call { api.publish(questionnaireId, QnrPublishReq(publishedSlug = publishedSlug)).version.toDomain() }
    }

    private companion object {
        /**
         * Coerces whole-number Doubles to Long so Moshi serializes them WITHOUT a decimal point. The shared
         * Moshi decodes every JSON number into [Double] for an `Any?` map, so a server-loaded text question's
         * `minLength`/`maxLength` round-trips as e.g. 200.0; the backend's text config validator rejects any
         * non-integer minLength/maxLength (422). Normalising here guarantees integer-valued config keys are
         * re-sent as integers regardless of whether they came from a fresh default or a server round-trip.
         */
        fun normalizeConfig(config: Map<String, Any?>): Map<String, Any?> =
            config.mapValues { (_, v) -> normalizeValue(v) }

        private fun normalizeValue(v: Any?): Any? = when (v) {
            is Double -> if (v.isFinite() && v == Math.floor(v) && !v.isInfinite()) v.toLong() else v
            is Float -> normalizeValue(v.toDouble())
            is List<*> -> v.map { normalizeValue(it) }
            is Map<*, *> -> v.entries.associate { (k, value) -> k to normalizeValue(value) }
            else -> v
        }
    }

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
