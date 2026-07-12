package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
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
 * Drives the [CreateDraftForm] for the create-draft screen. The backend requires the client to supply the
 * `questionnaire_id` (a stable opaque id), mirroring the web's `newId("q")`; we generate a `q_<hex>` id.
 * On a successful create -> one-shot [BuilderEffect.DraftCreated] so the screen pops back and the caller
 * opens the new draft in the builder. A 422 whose loc tail is `title` -> inline title error; a terminal
 * 401 -> NavigateToLogin. Mirrors CreateApiKeyViewModel.
 */
@HiltViewModel
class CreateDraftViewModel @Inject constructor(
    private val repo: QuestionnaireBuilderRepository,
) : ViewModel() {

    private val _form = MutableStateFlow(CreateDraftForm())
    val form: StateFlow<CreateDraftForm> = _form.asStateFlow()

    private val _effects = Channel<BuilderEffect>(Channel.BUFFERED)
    val effects: Flow<BuilderEffect> = _effects.receiveAsFlow()

    fun onTitleChange(value: String) {
        _form.value = _form.value.copy(title = value, titleError = null, submitError = null)
    }

    fun onDescriptionChange(value: String) {
        _form.value = _form.value.copy(description = value, submitError = null)
    }

    fun onVisibilityChange(value: String) {
        _form.value = _form.value.copy(visibility = value, submitError = null)
    }

    fun submit() {
        val current = _form.value
        if (!current.canSubmit) return
        _form.value = current.copy(submitting = true, submitError = null, titleError = null)
        viewModelScope.launch {
            val id = "q_${UUID.randomUUID().toString().replace("-", "").take(12)}"
            when (
                val result = repo.createDraft(
                    questionnaireId = id,
                    title = current.title.trim(),
                    description = current.description.trim(),
                    visibility = current.visibility,
                )
            ) {
                is ApiResult.Success -> {
                    _form.value = _form.value.copy(submitting = false)
                    _effects.send(BuilderEffect.DraftCreated(result.data.questionnaireId))
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _form.value = _form.value.copy(submitting = false)
                        _effects.send(BuilderEffect.NavigateToLogin)
                    } else {
                        _form.value = _form.value.copy(submitting = false, submitError = result.error.message)
                    }
                }
                is ApiResult.NetworkError ->
                    _form.value = _form.value.copy(submitting = false, submitError = OFFLINE_FALLBACK)
            }
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
