package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 (sub-pages) - drives the group SETTINGS screen. groupId arrives as a nav arg via
 * [SavedStateHandle]. load() fetches the group; canEdit = group.canManage (admin). save() PATCHes the
 * editable fields via updateGroup (admin-gated -> a 403 surfaces a friendly snackbar) and, on success,
 * replaces the form with the server's authoritative group. No poll loop.
 */
@HiltViewModel
class GroupSettingsViewModel @Inject constructor(
    private val repository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupSettingsUiState>(GroupSettingsUiState.Loading)
    val uiState: StateFlow<GroupSettingsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.value = GroupSettingsUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.getGroup(groupId)) {
                is ApiResult.Success -> GroupSettingsUiState.Content(
                    group = result.data,
                    canEdit = result.data.canManage,
                )
                is ApiResult.Failure -> GroupSettingsUiState.Error(result.error)
                is ApiResult.NetworkError -> GroupSettingsUiState.Error(networkError())
            }
        }
    }

    /** Saves the edited fields (admin-gated; a 403 surfaces a friendly snackbar + reload). */
    fun save(name: String, description: String, visibility: String, topic: String) {
        val content = _uiState.value as? GroupSettingsUiState.Content ?: return
        if (content.isSaving || !content.canEdit || name.isBlank()) return
        _uiState.value = content.copy(isSaving = true, notice = null)
        viewModelScope.launch {
            val result = repository.updateGroup(
                groupId = groupId,
                name = name.trim(),
                description = description.trim(),
                visibility = visibility.takeIf { it.isNotBlank() },
                topic = topic.trim().takeIf { it.isNotBlank() },
            )
            val now = _uiState.value as? GroupSettingsUiState.Content ?: return@launch
            _uiState.value = when (result) {
                is ApiResult.Success -> now.copy(
                    group = result.data,
                    canEdit = result.data.canManage,
                    isSaving = false,
                    notice = SAVED,
                )
                is ApiResult.Failure -> now.copy(isSaving = false, notice = noticeFor(result.error))
                is ApiResult.NetworkError -> now.copy(isSaving = false, notice = SAVE_FAILED)
            }
        }
    }

    fun consumeNotice() {
        val content = _uiState.value as? GroupSettingsUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    private fun noticeFor(error: ApiError): String = when {
        error.status == 403 -> NO_PERMISSION
        else -> SAVE_FAILED
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        private const val NO_PERMISSION = "Only group admins can change settings."
        private const val SAVED = "Settings saved."
        private const val SAVE_FAILED = "Couldn't save settings. Please try again."
    }
}
