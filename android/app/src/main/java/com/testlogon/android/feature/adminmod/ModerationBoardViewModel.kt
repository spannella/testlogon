package com.testlogon.android.feature.adminmod

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminmod.ModerationAdminRepository
import com.testlogon.android.data.adminmod.ModerationCaseActionDto
import com.testlogon.android.data.adminmod.ModerationTicketDetailDto
import com.testlogon.android.data.adminmod.ModerationTicketDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** B5 - normalized, PII-free error kind for the admin moderation board. */
enum class AdminOpsErrorType { NETWORK, SERVER, AUTH }

/**
 * B5 - exhaustive UI state for the admin content-moderation board (list). Mirrors /admin/moderation.
 *  - [Forbidden] a backend 403 (non-admin / missing CONTENT_MODERATION scope): non-destructive, offers Back.
 */
sealed interface ModerationBoardUiState {
    data object Loading : ModerationBoardUiState
    data class Content(
        val tickets: List<ModerationTicketDto>,
        val statusFilter: String?,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : ModerationBoardUiState
    data class Empty(val statusFilter: String?) : ModerationBoardUiState
    data object Forbidden : ModerationBoardUiState
    data class Error(val type: AdminOpsErrorType) : ModerationBoardUiState
}

/** B5 - the queue statuses the board filters on (mirrors the web board tabs). null = all. */
val MODERATION_STATUS_FILTERS: List<String?> = listOf(null, "open", "in_review", "resolved")

@HiltViewModel
class ModerationBoardViewModel @Inject constructor(
    private val repo: ModerationAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<ModerationBoardUiState>(ModerationBoardUiState.Loading)
    val state: StateFlow<ModerationBoardUiState> = _state.asStateFlow()

    private var currentFilter: String? = null

    init {
        load(null)
    }

    fun retry() = load(currentFilter)

    fun setFilter(status: String?) {
        currentFilter = status
        load(status)
    }

    fun refresh() {
        val cur = _state.value
        if (cur is ModerationBoardUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        fetch(currentFilter, isRefresh = true)
    }

    private fun load(status: String?) {
        currentFilter = status
        _state.value = ModerationBoardUiState.Loading
        fetch(status, isRefresh = false)
    }

    private fun fetch(status: String?, isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(status)) {
                is ApiResult.Success -> {
                    val items = r.data.items
                    _state.value = if (items.isEmpty()) {
                        ModerationBoardUiState.Empty(status)
                    } else {
                        ModerationBoardUiState.Content(tickets = items, statusFilter = status)
                    }
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = ModerationBoardUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? ModerationBoardUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            ModerationBoardUiState.Error(type)
        }
    }

    fun dismissTransientError() {
        val cur = _state.value
        if (cur is ModerationBoardUiState.Content && cur.transientError != null) {
            _state.update { cur.copy(transientError = null) }
        }
    }
}

// ---------------------------------------------------------------------------
// Ticket detail

sealed interface ModerationDetailUiState {
    data object Loading : ModerationDetailUiState
    data class Content(
        val detail: ModerationTicketDetailDto,
        val actionInFlight: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : ModerationDetailUiState
    data object Forbidden : ModerationDetailUiState
    data class Error(val type: AdminOpsErrorType) : ModerationDetailUiState
}

@HiltViewModel
class ModerationDetailViewModel @Inject constructor(
    private val repo: ModerationAdminRepository,
    savedStateHandle: androidx.lifecycle.SavedStateHandle,
) : ViewModel() {

    private val ticketId: String = checkNotNull(savedStateHandle[ModerationDetailArgs.TICKET_ID])

    private val _state = MutableStateFlow<ModerationDetailUiState>(ModerationDetailUiState.Loading)
    val state: StateFlow<ModerationDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _state.value = ModerationDetailUiState.Loading
        viewModelScope.launch {
            when (val r = repo.detail(ticketId)) {
                is ApiResult.Success -> _state.value = ModerationDetailUiState.Content(r.data)
                is ApiResult.Failure -> _state.value = when (r.error.status) {
                    403 -> ModerationDetailUiState.Forbidden
                    401 -> ModerationDetailUiState.Error(AdminOpsErrorType.AUTH)
                    else -> ModerationDetailUiState.Error(AdminOpsErrorType.SERVER)
                }
                is ApiResult.NetworkError -> _state.value = ModerationDetailUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun claim() = runAction { repo.claim(ticketId) }

    fun decide(decision: String, note: String?) = runAction { repo.decide(ticketId, decision, note) }

    fun resolve(resolution: String, enforcement: String, note: String?) =
        runAction { repo.resolve(ticketId, resolution, enforcement, note) }

    // MOD-E1/E2 state-machine actions. Each reloads the detail on success so the
    // case state + hold countdown + content snapshot reflect the new state.
    fun dismissCase() = runCaseAction { repo.dismiss(ticketId) }

    fun confirmCase() = runCaseAction { repo.confirm(ticketId) }

    fun finalCall(action: String, note: String?, ban: Boolean, banDurationDays: Int?) =
        runCaseAction(
            forbiddenMessage = if (ban && (banDurationDays ?: -1) == 0) {
                "Permanent ban requires a senior moderator and dual approval."
            } else {
                "You are not authorised to perform this action."
            },
        ) { repo.finalCall(ticketId, action, note, ban, banDurationDays) }

    private fun runCaseAction(
        forbiddenMessage: String = "You are not authorised to perform this action.",
        block: suspend () -> ApiResult<ModerationCaseActionDto>,
    ) {
        val cur = _state.value
        if (cur !is ModerationDetailUiState.Content || cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> reloadAfterAction("Applied: ${r.data.state.replace('_', ' ')}.")
                is ApiResult.Failure -> when (r.error.status) {
                    // An action-level 403 (e.g. permanent-ban gating) must NOT nuke the whole
                    // screen to Forbidden - surface it as a message and keep the detail.
                    403 -> setActionMessage(forbiddenMessage)
                    401 -> reduceActionError(AdminOpsErrorType.AUTH)
                    else -> reduceActionError(AdminOpsErrorType.SERVER)
                }
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun setActionMessage(msg: String) {
        val cur = _state.value as? ModerationDetailUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, actionMessage = msg)
    }

    private suspend fun reloadAfterAction(message: String) {
        when (val r = repo.detail(ticketId)) {
            is ApiResult.Success -> _state.value = ModerationDetailUiState.Content(
                detail = r.data,
                actionInFlight = false,
                actionMessage = message,
            )
            else -> {
                val prev = _state.value as? ModerationDetailUiState.Content ?: return
                _state.value = prev.copy(actionInFlight = false, actionMessage = message)
            }
        }
    }

    private fun runAction(block: suspend () -> ApiResult<ModerationTicketDto>) {
        val cur = _state.value
        if (cur !is ModerationDetailUiState.Content || cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    val prev = _state.value as? ModerationDetailUiState.Content ?: return@launch
                    _state.value = prev.copy(
                        detail = prev.detail.copy(ticket = r.data),
                        actionInFlight = false,
                        actionMessage = "Applied.",
                    )
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? ModerationDetailUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is ModerationDetailUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
