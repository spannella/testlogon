package com.testlogon.android.feature.adminmod

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminmod.ModerationAdminRepository
import com.testlogon.android.data.adminmod.ModerationCaseActionDto
import com.testlogon.android.data.adminmod.ModerationKpisDto
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
        val topicFilter: String? = null,
        val nextCursor: String? = null,
        val isLoadingMore: Boolean = false,
        val isRefreshing: Boolean = false,
        // MODX-22: multi-select + bulk triage.
        val selectionMode: Boolean = false,
        val selectedIds: Set<String> = emptySet(),
        val bulkInFlight: Boolean = false,
        val bulkMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
        // Queue-health KPI strip (parity with web). Best-effort: null until the KPI call resolves.
        val kpis: ModerationKpisDto? = null,
    ) : ModerationBoardUiState {
        val canPaginate: Boolean get() = !nextCursor.isNullOrBlank()
    }
    data class Empty(val statusFilter: String?, val topicFilter: String? = null) : ModerationBoardUiState
    data object Forbidden : ModerationBoardUiState
    data class Error(val type: AdminOpsErrorType) : ModerationBoardUiState
}

/**
 * MODX-21 (D10): the REAL queue statuses. The old `in_review`/`resolved` chips never
 * matched a real backend status (they returned a misleading empty). null = all.
 */
val MODERATION_STATUS_FILTERS: List<String?> = listOf(null, "open", "closed")

/** MODX-18/MODX-21 (D5): the live category taxonomy the ticket filter accepts. null = all. */
val MODERATION_TOPIC_FILTERS: List<String?> =
    listOf(null, "sexual", "violence_threats", "hate", "harassment", "spam", "other", "illegal")

/**
 * MODX-22: the bulk triage actions offered from the selection bar. [destructive] actions (mass hard-delete
 * or committing many cases to a 30-day hold) require an explicit confirmation before firing.
 */
enum class ModerationBulkAction(val wire: String, val label: String, val destructive: Boolean = false) {
    DISMISS("dismiss", "Dismiss"),
    CONFIRM("confirm", "Confirm hold", destructive = true),
    REINSTATE("reinstate", "Reinstate"),
    DELETE("delete", "Delete", destructive = true),
}

@HiltViewModel
class ModerationBoardViewModel @Inject constructor(
    private val repo: ModerationAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<ModerationBoardUiState>(ModerationBoardUiState.Loading)
    val state: StateFlow<ModerationBoardUiState> = _state.asStateFlow()

    private var currentStatus: String? = null
    private var currentTopic: String? = null

    init {
        load()
    }

    fun retry() = load()

    fun setFilter(status: String?) {
        currentStatus = status
        load()
    }

    fun setTopicFilter(topic: String?) {
        currentTopic = topic
        load()
    }

    fun refresh() {
        val cur = _state.value
        if (cur is ModerationBoardUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        fetch(cursor = null, isRefresh = true)
    }

    private fun load() {
        _state.value = ModerationBoardUiState.Loading
        fetch(cursor = null, isRefresh = false)
    }

    /** MODX-21: infinite scroll — append the next page keyed by the API cursor. */
    fun loadMore() {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        if (cur.isLoadingMore || !cur.canPaginate) return
        _state.value = cur.copy(isLoadingMore = true)
        fetch(cursor = cur.nextCursor, isRefresh = false, append = true)
    }

    private fun fetch(cursor: String?, isRefresh: Boolean, append: Boolean = false) {
        viewModelScope.launch {
            when (val r = repo.listPage(currentStatus, currentTopic, cursor)) {
                is ApiResult.Success -> {
                    val prior = _state.value as? ModerationBoardUiState.Content
                    val incoming = r.data.items
                    val merged = if (append && prior != null) prior.tickets + incoming else incoming
                    _state.value = if (merged.isEmpty()) {
                        ModerationBoardUiState.Empty(currentStatus, currentTopic)
                    } else {
                        ModerationBoardUiState.Content(
                            tickets = merged,
                            statusFilter = currentStatus,
                            topicFilter = currentTopic,
                            nextCursor = r.data.nextCursor,
                            selectionMode = prior?.selectionMode ?: false,
                            selectedIds = (prior?.selectedIds ?: emptySet()).filter { id -> merged.any { it.ticketId == id } }.toSet(),
                            kpis = prior?.kpis,
                        )
                    }
                    if (!append) loadKpis()
                }
                is ApiResult.Failure -> reduceFailure(isRefresh || append, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh || append, AdminOpsErrorType.NETWORK)
            }
        }
    }

    /** Best-effort queue-health KPIs for the board strip. A failure just leaves the strip hidden. */
    private fun loadKpis() {
        viewModelScope.launch {
            val r = repo.kpis()
            if (r is ApiResult.Success) {
                val cur = _state.value as? ModerationBoardUiState.Content ?: return@launch
                _state.value = cur.copy(kpis = r.data)
            }
        }
    }

    // ---- MODX-22: selection + bulk ----
    fun toggleSelectionMode() {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        _state.value = cur.copy(selectionMode = !cur.selectionMode, selectedIds = emptySet(), bulkMessage = null)
    }

    fun toggleSelected(ticketId: String) {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        val next = if (ticketId in cur.selectedIds) cur.selectedIds - ticketId else cur.selectedIds + ticketId
        _state.value = cur.copy(selectedIds = next)
    }

    fun runBulk(action: ModerationBulkAction) {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        if (cur.bulkInFlight || cur.selectedIds.isEmpty()) return
        val ids = cur.selectedIds.toList()
        _state.value = cur.copy(bulkInFlight = true, bulkMessage = null)
        viewModelScope.launch {
            when (val r = repo.bulk(ids, action.wire, null)) {
                is ApiResult.Success -> {
                    val res = r.data
                    val msg = "${action.label}: ${res.succeeded} done, ${res.failed} failed."
                    val prior = _state.value as? ModerationBoardUiState.Content ?: return@launch
                    _state.value = prior.copy(
                        bulkInFlight = false,
                        selectionMode = false,
                        selectedIds = emptySet(),
                        bulkMessage = msg,
                    )
                    load()
                }
                is ApiResult.Failure -> setBulkError(if (r.error.status == 403) "Not authorised for that bulk action." else "Bulk action failed. Try again.")
                is ApiResult.NetworkError -> setBulkError("You appear to be offline. Check your connection.")
            }
        }
    }

    private fun setBulkError(msg: String) {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        _state.value = cur.copy(bulkInFlight = false, bulkMessage = msg)
    }

    fun clearBulkMessage() {
        val cur = _state.value as? ModerationBoardUiState.Content ?: return
        _state.value = cur.copy(bulkMessage = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = ModerationBoardUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? ModerationBoardUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isLoadingMore = false, transientError = type)
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
                    // MODX-16: an action-level 403 (scope / dual-approval gating) must NOT nuke the
                    // whole screen to Forbidden - surface an ACTIONABLE message and keep the detail.
                    403 -> setActionMessage(actionableForbidden(r.error, forbiddenMessage))
                    // MODX-16: a stale-state 409 means the case moved under the moderator.
                    409 -> setActionMessage(STALE_STATE_MESSAGE)
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

    // MODX-16: turn a backend error code / required_scope into distinct, actionable guidance.
    private fun actionableForbidden(error: ApiError, fallback: String): String = when (error.code) {
        "role_required_scope" ->
            "This action needs the Senior Moderation role. Ask a senior moderator (or root) to action it."
        "dual_approval_required" ->
            "A permanent ban needs a second approver. Add a second senior approver, then retry."
        "dual_approval_self" ->
            "The second approver must be a different admin from you."
        "dual_approval_invalid_approver" ->
            "The second approver must be an existing admin who holds the Senior Moderation scope."
        else -> error.message.ifBlank { fallback }
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is ModerationDetailUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}

private const val STALE_STATE_MESSAGE =
    "This case changed since you opened it (its state moved on). Refresh the board and try again."
