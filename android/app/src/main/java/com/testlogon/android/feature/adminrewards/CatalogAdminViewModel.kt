package com.testlogon.android.feature.adminrewards

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminrewards.AdminCatalogItemDto
import com.testlogon.android.data.adminrewards.AdminCatalogItemReq
import com.testlogon.android.data.adminrewards.AdminRewardsRepository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Operator CRUD over the redeemable rewards catalog. List / create / edit / delete + active toggle. Role-gated
 * exactly like the other admin queues (RefundAdminViewModel et al.): a backend 403 on the list -> [Forbidden]
 * ("not authorised"); a 404 on the list DEGRADES (in the repo) to an honest empty catalog. Every mutation
 * refreshes the list on success and surfaces a CLEAR error on failure (never a silent success).
 */
sealed interface CatalogAdminUiState {
    data object Loading : CatalogAdminUiState
    data class Content(
        val items: List<AdminCatalogItemDto>,
        val isRefreshing: Boolean = false,
        val actionInFlight: Boolean = false,
        val message: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : CatalogAdminUiState
    data object Empty : CatalogAdminUiState
    data object Forbidden : CatalogAdminUiState
    data class Error(val type: AdminOpsErrorType) : CatalogAdminUiState
}

@HiltViewModel
class CatalogAdminViewModel @Inject constructor(
    private val repo: AdminRewardsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<CatalogAdminUiState>(CatalogAdminUiState.Loading)
    val state: StateFlow<CatalogAdminUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur is CatalogAdminUiState.Content) _state.value = cur.copy(isRefreshing = true, transientError = null)
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = CatalogAdminUiState.Loading
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = sortAdminCatalog(r.data.rewards)
                    _state.value = if (items.isEmpty()) CatalogAdminUiState.Empty
                    else CatalogAdminUiState.Content(items = items)
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    /** CREATE a catalog item, then refresh the list. */
    fun create(draft: CatalogDraft) = runMutation("Reward created") { repo.create(draft.toReq()) }

    /** EDIT an existing item, then refresh the list. */
    fun update(id: String, draft: CatalogDraft) = runMutation("Reward updated") { repo.update(id, draft.toReq()) }

    /** DELETE an item (after confirm), then refresh the list. */
    fun delete(id: String) = runMutation("Reward deleted") { repo.delete(id) }

    /** Flip active on/off in place, then refresh the list. */
    fun toggleActive(item: AdminCatalogItemDto) {
        val next = !(item.active ?: false)
        runMutation(if (next) "Reward activated" else "Reward deactivated") {
            repo.update(item.id.orEmpty(), item.toDraft().copy(active = next).toReq())
        }
    }

    private fun <T> runMutation(successMsg: String, block: suspend () -> ApiResult<T>) {
        val cur = _state.value
        // Allow mutating from Content OR from an Empty catalog (the first CREATE).
        if (cur is CatalogAdminUiState.Content && cur.actionInFlight) return
        if (cur is CatalogAdminUiState.Content) {
            _state.value = cur.copy(actionInFlight = true, transientError = null, message = null)
        }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> reloadAfterMutation(successMsg)
                is ApiResult.Failure -> emitMutationError(r.error.status)
                is ApiResult.NetworkError -> emitMutationError(null, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private suspend fun reloadAfterMutation(successMsg: String) {
        when (val r = repo.list()) {
            is ApiResult.Success -> {
                val items = sortAdminCatalog(r.data.rewards)
                _state.value = if (items.isEmpty()) CatalogAdminUiState.Empty
                else CatalogAdminUiState.Content(items = items, message = successMsg)
            }
            is ApiResult.Failure -> reduceFailure(isRefresh = false, status = r.error.status)
            is ApiResult.NetworkError -> reduceError(isRefresh = false, type = AdminOpsErrorType.NETWORK)
        }
    }

    private fun emitMutationError(status: Int?, forced: AdminOpsErrorType? = null) {
        val type = forced ?: when (status) {
            403 -> AdminOpsErrorType.AUTH
            401 -> AdminOpsErrorType.AUTH
            else -> AdminOpsErrorType.SERVER
        }
        val cur = _state.value
        if (cur is CatalogAdminUiState.Content) {
            _state.value = cur.copy(actionInFlight = false, transientError = type)
        } else {
            _state.value = CatalogAdminUiState.Error(type)
        }
    }

    fun clearMessage() {
        val cur = _state.value
        if (cur is CatalogAdminUiState.Content) _state.value = cur.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = CatalogAdminUiState.Forbidden
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? CatalogAdminUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else CatalogAdminUiState.Error(type)
    }
}

/**
 * Order the ADMIN catalog list the SAME way members see it (RewardsMath.sortCatalog): FEATURED first,
 * then sort_order ascending (missing = 0), then name (case-insensitive) ascending. Pure + stable.
 */
internal fun sortAdminCatalog(items: List<AdminCatalogItemDto>): List<AdminCatalogItemDto> =
    items.sortedWith(
        compareByDescending<AdminCatalogItemDto> { it.featured == true }
            .thenBy { it.sortOrder ?: 0L }
            .thenBy { (it.name ?: "").trim().lowercase() },
    )

/** Map an editable draft to the create/update request body. */
internal fun CatalogDraft.toReq(): AdminCatalogItemReq = AdminCatalogItemReq(
    name = name.trim(),
    description = description.trim(),
    costPoints = costPoints,
    valueCents = valueCents,
    kind = kind.trim().lowercase(),
    active = active,
    stockLimit = stockLimit,
    featured = featured,
    sortOrder = sortOrder.coerceAtLeast(0L),
)

/** Seed an editable draft from an existing catalog item (for the EDIT form). */
internal fun AdminCatalogItemDto.toDraft(): CatalogDraft = CatalogDraft(
    name = name.orEmpty(),
    description = description.orEmpty(),
    costPoints = costPoints ?: 0L,
    valueCents = valueCents ?: 0L,
    kind = (kind ?: "perk").trim().lowercase().let { if (it in CATALOG_KINDS) it else "perk" },
    active = active ?: false,
    stockLimit = stockLimit?.coerceAtLeast(0L),
    featured = featured == true,
    sortOrder = (sortOrder ?: 0L).coerceAtLeast(0L),
)
