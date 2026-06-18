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
 * AND-355 (sub-pages) - drives the FUNDRAISING screen. groupId arrives as a nav arg via
 * [SavedStateHandle]. load() lists the group's fundraisers. create() POSTs a new fundraiser
 * (PESSIMISTIC - awaits the server, then re-fetches); creation is admin-gated at the service layer, so a
 * 403 surfaces a friendly "you don't have permission" snackbar and the list is left unchanged. No poll
 * loop.
 */
@HiltViewModel
class GroupFundraisingViewModel @Inject constructor(
    private val repository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupFundraisingUiState>(GroupFundraisingUiState.Loading)
    val uiState: StateFlow<GroupFundraisingUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.value = GroupFundraisingUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repository.listFundraisers(groupId)) {
                is ApiResult.Success -> GroupFundraisingUiState.Content(fundraisers = result.data)
                is ApiResult.Failure -> GroupFundraisingUiState.Error(result.error)
                is ApiResult.NetworkError -> GroupFundraisingUiState.Error(networkError())
            }
        }
    }

    /** Creates a fundraiser (admin-gated; a 403 surfaces a friendly snackbar). [goalCents] may be null. */
    fun create(title: String, description: String, goalCents: Long?) {
        val content = _uiState.value as? GroupFundraisingUiState.Content ?: return
        if (content.isCreating || title.isBlank()) return
        _uiState.value = content.copy(isCreating = true, notice = null)
        viewModelScope.launch {
            when (val result = repository.createFundraiser(groupId, title, description, goalCents)) {
                is ApiResult.Success -> {
                    val refreshed = repository.listFundraisers(groupId)
                    val list = (refreshed as? ApiResult.Success)?.data
                        ?: (listOf(result.data) + content.fundraisers)
                    _uiState.value = GroupFundraisingUiState.Content(
                        fundraisers = list,
                        notice = CREATED,
                    )
                }
                is ApiResult.Failure -> {
                    val now = _uiState.value as? GroupFundraisingUiState.Content ?: return@launch
                    _uiState.value = now.copy(isCreating = false, notice = noticeFor(result.error))
                }
                is ApiResult.NetworkError -> {
                    val now = _uiState.value as? GroupFundraisingUiState.Content ?: return@launch
                    _uiState.value = now.copy(isCreating = false, notice = CREATE_FAILED)
                }
            }
        }
    }

    fun consumeNotice() {
        val content = _uiState.value as? GroupFundraisingUiState.Content ?: return
        if (content.notice != null) _uiState.value = content.copy(notice = null)
    }

    private fun noticeFor(error: ApiError): String = when {
        error.status == 403 -> NO_PERMISSION
        else -> CREATE_FAILED
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        private const val NO_PERMISSION = "Only group admins can create fundraisers."
        private const val CREATED = "Fundraiser created."
        private const val CREATE_FAILED = "Couldn't create the fundraiser. Please try again."
    }
}
