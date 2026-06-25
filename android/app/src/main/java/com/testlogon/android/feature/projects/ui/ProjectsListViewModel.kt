package com.testlogon.android.feature.projects.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.feature.projects.data.ProjectsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-374 / Batch-8 (#9) - drives the PROJECTS LIST (screen 1) plus the create-project flow.
 *
 * [items] is a network Paging-3 stream (cursor-keyed) cached in [viewModelScope] so a rotation does not
 * re-fetch; the loading / empty / error / offline states come from Paging's LoadState at the UI and
 * pull-to-refresh is LazyPagingItems.refresh(). A terminal 401 on a page load surfaces as a Paging
 * LoadState.Error at the UI.
 *
 * Batch-8 (#9): [createState] drives the create dialog (name + optional description + comma tags). On a
 * successful POST the dialog closes, the new project id is emitted one-shot over [created] (so the screen
 * navigates into it) and the list is refreshed via [refreshSignal] (LazyPagingItems collects it).
 */
@HiltViewModel
class ProjectsListViewModel @Inject constructor(
    private val repository: ProjectsRepository,
) : ViewModel() {

    val items: Flow<PagingData<Project>> =
        repository.projectsPager().cachedIn(viewModelScope)

    private val _createState = MutableStateFlow(CreateProjectFormState())
    val createState: StateFlow<CreateProjectFormState> = _createState.asStateFlow()

    /** One-shot: emits the new project id on a successful create so the screen navigates into it. */
    private val _created = Channel<String>(Channel.BUFFERED)
    val created = _created.receiveAsFlow()

    /** One-shot ping the screen observes to call LazyPagingItems.refresh() after a create. */
    private val _refreshSignal = Channel<Unit>(Channel.BUFFERED)
    val refreshSignal = _refreshSignal.receiveAsFlow()

    fun openCreate() {
        _createState.value = CreateProjectFormState(visible = true)
    }

    fun dismissCreate() {
        _createState.value = CreateProjectFormState(visible = false)
    }

    fun onNameChange(value: String) =
        _createState.update { it.copy(name = value, nameError = null, submitError = null) }

    fun onDescriptionChange(value: String) =
        _createState.update { it.copy(description = value, submitError = null) }

    fun onTagsChange(value: String) =
        _createState.update { it.copy(tags = value, submitError = null) }

    fun submitCreate() {
        val form = _createState.value
        if (!form.isValid || form.submitting) return
        _createState.update { it.copy(submitting = true, nameError = null, submitError = null) }
        viewModelScope.launch {
            val tags = form.tags
                .split(',')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
            when (val result = repository.createProject(
                name = form.name.trim(),
                description = form.description.trim().takeIf { it.isNotBlank() },
                tags = tags,
            )) {
                is ApiResult.Success -> {
                    _createState.value = CreateProjectFormState(visible = false)
                    _refreshSignal.send(Unit)
                    _created.send(result.data.id)
                }
                is ApiResult.Failure ->
                    _createState.update { it.copy(submitting = false, submitError = result.error.message) }
                is ApiResult.NetworkError ->
                    _createState.update { it.copy(submitting = false, submitError = OFFLINE_FALLBACK) }
            }
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Please try again."
    }
}

/** Batch-8 (#9) - the create-project dialog form state. */
data class CreateProjectFormState(
    val visible: Boolean = false,
    val name: String = "",
    val description: String = "",
    /** Comma-separated tag entry (split at submit). */
    val tags: String = "",
    val nameError: String? = null,
    val submitError: String? = null,
    val submitting: Boolean = false,
) {
    val isValid: Boolean get() = name.trim().isNotEmpty()
}
