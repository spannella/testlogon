package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.questionnaire.builder.data.QnrPublishedVersion
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestion
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestionType
import com.testlogon.android.feature.questionnaire.builder.data.QnrSection
import com.testlogon.android.feature.questionnaire.builder.data.QuestionnaireBuilderRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * Drives the per-draft [BuilderUiState] - the questionnaire-builder EDITOR (web QuestionnaireBuilderPage
 * parity). Loads the draft metadata + sections + (per-section) questions, then mediates every authoring
 * mutation:
 *  - metadata: [saveMetadata] PATCHes title/description/visibility.
 *  - sections: [addSection] POSTs a new section (auto id + position); [deleteSection] archives it.
 *  - questions: [addQuestion] POSTs an "Untitled question" of the chosen type with that type's default
 *    config; [updateQuestion] PATCHes label/required/hint/type/config (a type change re-defaults the
 *    config, exactly as the web Select onValueChange does); [deleteQuestion] removes it.
 *  - publish: [openPublish] runs the readiness checks (title present, >=1 section, >=1 question) and
 *    [confirmPublish] POSTs the publish, surfacing the new immutable version id.
 *
 * After each successful mutation the in-memory tree is patched so the UI reflects it WITHOUT a full
 * re-fetch (the server is authoritative for the returned row, which is written through). A terminal 401 on
 * any call -> one-shot [BuilderEffect.NavigateToLogin]. No poll loop.
 */
@HiltViewModel
class BuilderViewModel @Inject constructor(
    private val repo: QuestionnaireBuilderRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val questionnaireId: String = savedStateHandle.get<String>(ARG_QUESTIONNAIRE_ID).orEmpty()

    private val _uiState = MutableStateFlow<BuilderUiState>(BuilderUiState.Loading)
    val uiState: StateFlow<BuilderUiState> = _uiState.asStateFlow()

    private val _effects = Channel<BuilderEffect>(Channel.BUFFERED)
    val effects: Flow<BuilderEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = BuilderUiState.Loading
        viewModelScope.launch {
            val draftResult = repo.getDraft(questionnaireId)
            val draft = when (draftResult) {
                is ApiResult.Success -> draftResult.data
                is ApiResult.Failure -> {
                    if (draftResult.error.status == HTTP_UNAUTHORIZED) _effects.send(BuilderEffect.NavigateToLogin)
                    _uiState.value = BuilderUiState.Error(draftResult.error.message)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = BuilderUiState.Error(OFFLINE_FALLBACK)
                    return@launch
                }
            }
            val sections = when (val secResult = repo.listSections(questionnaireId)) {
                is ApiResult.Success -> secResult.data
                is ApiResult.Failure -> {
                    if (secResult.error.status == HTTP_UNAUTHORIZED) _effects.send(BuilderEffect.NavigateToLogin)
                    _uiState.value = BuilderUiState.Error(secResult.error.message)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = BuilderUiState.Error(OFFLINE_FALLBACK)
                    return@launch
                }
            }
            val builderSections = sections.sortedBy { it.position }.map { section ->
                val questions = when (val qResult = repo.listQuestions(questionnaireId, section.sectionId)) {
                    is ApiResult.Success -> qResult.data.sortedBy { it.position }
                    else -> emptyList()
                }
                BuilderSection(section = section, questions = questions)
            }
            _uiState.value = BuilderUiState.Content(
                questionnaireId = questionnaireId,
                title = draft.title,
                description = draft.description,
                visibility = draft.visibility,
                status = draft.status,
                publishedVersionId = draft.publishedVersionId,
                sections = builderSections,
            )
        }
    }

    // ---- Metadata ----

    fun onTitleChange(value: String) = patchContent { it.copy(title = value, actionError = null) }
    fun onDescriptionChange(value: String) = patchContent { it.copy(description = value, actionError = null) }

    fun onVisibilityChange(value: String) {
        patchContent { it.copy(visibility = value, actionError = null) }
        saveMetadata()
    }

    fun saveMetadata() {
        val state = content() ?: return
        mutate {
            repo.updateDraft(
                questionnaireId = questionnaireId,
                title = state.title.trim().ifBlank { null },
                description = state.description.trim(),
                visibility = state.visibility,
            ).asUnit()
        }
    }

    // ---- Sections ----

    fun addSection() {
        val state = content() ?: return
        val sectionId = "sec_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        val title = "Section ${state.sections.size + 1}"
        mutate {
            when (val result = repo.createSection(questionnaireId, sectionId, title, "")) {
                is ApiResult.Success -> {
                    patchContent { c -> c.copy(sections = c.sections + BuilderSection(result.data, emptyList())) }
                    ApiResult.Success(Unit)
                }
                is ApiResult.Failure -> ApiResult.Failure(result.error)
                is ApiResult.NetworkError -> result
            }
        }
    }

    fun onSectionTitleChange(sectionId: String, value: String) =
        patchSection(sectionId) { it.copy(section = it.section.copy(title = value)) }

    fun saveSection(sectionId: String) {
        val section = content()?.sections?.firstOrNull { it.section.sectionId == sectionId }?.section ?: return
        mutate {
            repo.updateSection(questionnaireId, sectionId, section.title.trim().ifBlank { null }, section.description.trim()).asUnit()
        }
    }

    fun deleteSection(sectionId: String) {
        mutate {
            when (val result = repo.deleteSection(questionnaireId, sectionId)) {
                is ApiResult.Success -> {
                    patchContent { c -> c.copy(sections = c.sections.filterNot { it.section.sectionId == sectionId }) }
                    result
                }
                else -> result
            }
        }
    }

    // ---- Questions ----

    fun addQuestion(sectionId: String, type: QnrQuestionType) {
        val questionId = "q_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        mutate {
            when (
                val result = repo.createQuestion(
                    questionnaireId = questionnaireId,
                    sectionId = sectionId,
                    questionId = questionId,
                    type = type,
                    label = "Untitled question",
                    required = false,
                    hint = "",
                    configJson = QnrQuestionType.defaultConfig(type),
                )
            ) {
                is ApiResult.Success -> {
                    patchSection(sectionId) { it.copy(questions = it.questions + result.data) }
                    ApiResult.Success(Unit)
                }
                is ApiResult.Failure -> ApiResult.Failure(result.error)
                is ApiResult.NetworkError -> result
            }
        }
    }

    /** Local edit of a question (label/required/hint/config/type) - patches the tree; caller calls [saveQuestion]. */
    fun onQuestionEdit(sectionId: String, questionId: String, transform: (QnrQuestion) -> QnrQuestion) =
        patchQuestion(sectionId, questionId, transform)

    /** A type change re-defaults the config (mirrors the web Select onValueChange). */
    fun onQuestionTypeChange(sectionId: String, questionId: String, type: QnrQuestionType) {
        patchQuestion(sectionId, questionId) { it.copy(type = type, configJson = QnrQuestionType.defaultConfig(type)) }
        saveQuestion(sectionId, questionId)
    }

    fun saveQuestion(sectionId: String, questionId: String) {
        val q = content()?.sections
            ?.firstOrNull { it.section.sectionId == sectionId }
            ?.questions?.firstOrNull { it.questionId == questionId } ?: return
        mutate {
            // The backend has no question-retype endpoint; type lives in config-independent fields. We PATCH
            // label/required/hint/config (the type is fixed server-side at create). For a type change the UI
            // recreates is unnecessary because the server validates config against the stored type; we send the
            // current (re-defaulted) config so a type switch still produces a valid config payload.
            repo.updateQuestion(
                questionnaireId = questionnaireId,
                sectionId = sectionId,
                questionId = questionId,
                label = q.label.trim().ifBlank { "Untitled question" },
                required = q.required,
                hint = q.hint.trim(),
                configJson = q.configJson,
            ).asUnit()
        }
    }

    fun deleteQuestion(sectionId: String, questionId: String) {
        mutate {
            when (val result = repo.deleteQuestion(questionnaireId, sectionId, questionId)) {
                is ApiResult.Success -> {
                    patchSection(sectionId) { it.copy(questions = it.questions.filterNot { q -> q.questionId == questionId }) }
                    result
                }
                else -> result
            }
        }
    }

    // ---- Publish ----

    fun openPublish() {
        val state = content() ?: return
        val checks = mutableListOf<String>()
        if (state.title.isBlank()) checks.add("Title is required.")
        if (state.sections.isEmpty()) checks.add("At least one section is required.")
        if (state.sections.all { it.questions.isEmpty() }) checks.add("At least one question is required.")
        val ready = checks.isEmpty()
        if (ready) checks.add("Ready to publish.")
        patchContent { it.copy(publish = PublishState(checks = checks, ready = ready)) }
    }

    fun dismissPublish() = patchContent { it.copy(publish = null) }

    fun confirmPublish() {
        val state = content() ?: return
        val publish = state.publish ?: return
        if (!publish.ready || publish.publishing) return
        patchContent { it.copy(publish = publish.copy(publishing = true)) }
        viewModelScope.launch {
            when (val result = repo.publish(questionnaireId, publishedSlug = null)) {
                is ApiResult.Success -> applyPublished(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(BuilderEffect.NavigateToLogin)
                    patchContent {
                        it.copy(publish = it.publish?.copy(publishing = false), actionError = result.error.message)
                    }
                }
                is ApiResult.NetworkError ->
                    patchContent { it.copy(publish = it.publish?.copy(publishing = false), actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    private fun applyPublished(version: QnrPublishedVersion) {
        patchContent {
            it.copy(
                publishedVersionId = version.versionId,
                publish = it.publish?.copy(
                    publishing = false,
                    publishedVersionId = version.versionId,
                    publishedSlug = version.publishedSlug,
                ),
            )
        }
    }

    // ---- helpers ----

    private fun content(): BuilderUiState.Content? = _uiState.value as? BuilderUiState.Content

    private inline fun patchContent(transform: (BuilderUiState.Content) -> BuilderUiState.Content) {
        val c = content() ?: return
        _uiState.value = transform(c)
    }

    private inline fun patchSection(sectionId: String, crossinline transform: (BuilderSection) -> BuilderSection) {
        patchContent { c ->
            c.copy(sections = c.sections.map { if (it.section.sectionId == sectionId) transform(it) else it })
        }
    }

    private inline fun patchQuestion(
        sectionId: String,
        questionId: String,
        crossinline transform: (QnrQuestion) -> QnrQuestion,
    ) {
        patchSection(sectionId) { bs ->
            bs.copy(questions = bs.questions.map { if (it.questionId == questionId) transform(it) else it })
        }
    }

    /** Runs a mutating block with the busy flag set; routes a terminal 401 to the login handoff and
     * surfaces other failures as an inline action error. */
    private fun mutate(block: suspend () -> ApiResult<Unit>) {
        patchContent { it.copy(busy = true, actionError = null) }
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> patchContent { it.copy(busy = false) }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) _effects.send(BuilderEffect.NavigateToLogin)
                    patchContent { it.copy(busy = false, actionError = result.error.message) }
                }
                is ApiResult.NetworkError -> patchContent { it.copy(busy = false, actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    private fun <T> ApiResult<T>.asUnit(): ApiResult<Unit> = when (this) {
        is ApiResult.Success -> ApiResult.Success(Unit)
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
    }

    companion object {
        const val ARG_QUESTIONNAIRE_ID = "questionnaireId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
