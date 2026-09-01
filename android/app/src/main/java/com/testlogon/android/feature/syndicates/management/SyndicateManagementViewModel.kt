package com.testlogon.android.feature.syndicates.management

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SyndicateMath
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [SyndicateManagementUiState] for the syndicate MANAGEMENT screen.
 *
 * syndicateId arrives as a nav arg via [SavedStateHandle]. load() reads the three lists (my-invites,
 * join-requests, plans) + the audit tail in parallel and folds each into the Content snapshot; a failed
 * READ degrades to an honest-empty list rather than a whole-screen error (only a fully-empty first load with
 * a hard failure surfaces Error). Mutations (invite / respond / approve / reject / transfer / create-plan /
 * subscribe / archive) refetch the affected list on success and surface a one-shot actionMessage; failures
 * set a retryable actionError. No poll loop.
 */
@HiltViewModel
class SyndicateManagementViewModel @Inject constructor(
    private val repo: SyndicateManagementRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    private val _uiState = MutableStateFlow<SyndicateManagementUiState>(SyndicateManagementUiState.Loading)
    val uiState: StateFlow<SyndicateManagementUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        if (_uiState.value !is SyndicateManagementUiState.Content) {
            _uiState.value = SyndicateManagementUiState.Loading
        }
        fetch(isRefresh = false)
    }

    fun retry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        (_uiState.value as? SyndicateManagementUiState.Content)?.let {
            _uiState.value = it.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            val invites = repo.listMyInvites()
            val requests = repo.listRequests(syndicateId)
            val plans = repo.listPlans(syndicateId)
            val audit = repo.getAudit(syndicateId)

            // A hard failure on the FIRST load (no prior Content) that yields nothing surfaces Error;
            // otherwise every list degrades to honest-empty and the screen stays usable.
            val allFailedNetwork = invites is ApiResult.NetworkError &&
                requests is ApiResult.NetworkError &&
                plans is ApiResult.NetworkError
            val prior = _uiState.value as? SyndicateManagementUiState.Content
            if (allFailedNetwork && prior == null) {
                _uiState.value = SyndicateManagementUiState.Error(OFFLINE_FALLBACK)
                return@launch
            }

            val base = prior ?: SyndicateManagementUiState.Content(syndicateId = syndicateId)
            val anyFailed = listOf(invites, requests, plans, audit).any { it !is ApiResult.Success }
            _uiState.value = base.copy(
                invites = invites.orEmptyList(base.invites),
                requests = requests.orEmptyList(base.requests),
                plans = plans.orEmptyList(base.plans),
                audit = audit.orEmptyList(base.audit),
                isRefreshing = false,
                isStale = isRefresh && anyFailed,
            )
        }
    }

    // ---- Invite form (admin) ----

    fun openInviteForm() = updateContent { it.copy(inviteForm = InviteFormState(visible = true)) }
    fun dismissInviteForm() = updateContent { it.copy(inviteForm = InviteFormState(visible = false)) }
    fun onInviteUserIdChange(value: String) = updateContent {
        it.copy(inviteForm = it.inviteForm.copy(userId = value, error = null))
    }

    fun submitInvite() {
        val content = content() ?: return
        val form = content.inviteForm
        if (!form.isValid || form.submitting) return
        updateContent { it.copy(inviteForm = it.inviteForm.copy(submitting = true, error = null)) }
        viewModelScope.launch {
            when (val r = repo.invite(syndicateId, form.userId.trim())) {
                is ApiResult.Success -> {
                    updateContent {
                        it.copy(
                            inviteForm = InviteFormState(visible = false),
                            actionMessage = "Invite sent",
                        )
                    }
                    reloadRequests()
                }
                is ApiResult.Failure ->
                    updateContent { it.copy(inviteForm = it.inviteForm.copy(submitting = false, error = r.error.message)) }
                is ApiResult.NetworkError ->
                    updateContent { it.copy(inviteForm = it.inviteForm.copy(submitting = false, error = OFFLINE_FALLBACK)) }
            }
        }
    }

    /** Accept/decline an invite the caller has received; on success drop it from the list. */
    fun respondToInvite(inviteSyndicateId: String, accept: Boolean) {
        val content = content() ?: return
        if (content.busyId != null) return
        updateContent { it.copy(busyId = inviteSyndicateId, actionError = null) }
        viewModelScope.launch {
            when (val r = repo.respondToInvite(inviteSyndicateId, accept)) {
                is ApiResult.Success -> updateContent {
                    it.copy(
                        busyId = null,
                        invites = it.invites.filterNot { inv -> inv.syndicateId == inviteSyndicateId },
                        actionMessage = if (accept) "Joined" else "Declined",
                    )
                }
                is ApiResult.Failure -> updateContent { it.copy(busyId = null, actionError = r.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(busyId = null, actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    // ---- Join-request moderation (admin) ----

    fun approveRequest(userId: String) = moderateRequest(userId, approve = true)
    fun rejectRequest(userId: String) = moderateRequest(userId, approve = false)

    private fun moderateRequest(userId: String, approve: Boolean) {
        val content = content() ?: return
        if (content.busyId != null) return
        updateContent { it.copy(busyId = userId, actionError = null) }
        viewModelScope.launch {
            val result = if (approve) repo.approveRequest(syndicateId, userId)
            else repo.rejectRequest(syndicateId, userId)
            when (result) {
                is ApiResult.Success -> {
                    updateContent {
                        it.copy(
                            busyId = null,
                            requests = it.requests.filterNot { req -> req.userId == userId },
                            actionMessage = if (approve) "Approved" else "Rejected",
                        )
                    }
                }
                is ApiResult.Failure -> updateContent { it.copy(busyId = null, actionError = result.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(busyId = null, actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    // ---- Transfer admin ----

    fun openTransferForm() = updateContent { it.copy(transferForm = TransferFormState(visible = true)) }
    fun dismissTransferForm() = updateContent { it.copy(transferForm = TransferFormState(visible = false)) }
    fun onTransferUserIdChange(value: String) = updateContent {
        it.copy(transferForm = it.transferForm.copy(newAdminUserId = value, error = null))
    }

    fun submitTransfer() {
        val content = content() ?: return
        val form = content.transferForm
        if (!form.isValid || form.submitting) return
        updateContent { it.copy(transferForm = it.transferForm.copy(submitting = true, error = null)) }
        viewModelScope.launch {
            when (val r = repo.transferAdmin(syndicateId, form.newAdminUserId.trim())) {
                is ApiResult.Success -> {
                    updateContent {
                        it.copy(transferForm = TransferFormState(visible = false), actionMessage = "Admin transferred")
                    }
                    reloadAudit()
                }
                is ApiResult.Failure ->
                    updateContent { it.copy(transferForm = it.transferForm.copy(submitting = false, error = r.error.message)) }
                is ApiResult.NetworkError ->
                    updateContent { it.copy(transferForm = it.transferForm.copy(submitting = false, error = OFFLINE_FALLBACK)) }
            }
        }
    }

    // ---- Bundle plan form (admin) ----

    fun openPlanForm() = updateContent { it.copy(planForm = PlanFormState(visible = true)) }
    fun dismissPlanForm() = updateContent { it.copy(planForm = PlanFormState(visible = false)) }
    fun onPlanNameChange(value: String) = updateContent { it.copy(planForm = it.planForm.copy(name = value, submitError = null)) }
    fun onPlanDescriptionChange(value: String) = updateContent { it.copy(planForm = it.planForm.copy(description = value, submitError = null)) }
    fun onPlanPriceChange(value: String) = updateContent { it.copy(planForm = it.planForm.copy(priceInput = value, submitError = null)) }
    fun onPlanIntervalChange(value: String) = updateContent { it.copy(planForm = it.planForm.copy(interval = value, submitError = null)) }

    fun submitPlan() {
        val content = content() ?: return
        val form = content.planForm
        if (form.submitting) return
        val cents = SyndicateMath.parsePriceToCents(form.priceInput) ?: -1
        val errors = SyndicateMath.validatePlanDraft(
            name = form.name,
            priceCents = cents,
            interval = form.interval,
            description = form.description,
        )
        if (errors.isNotEmpty()) {
            updateContent { it.copy(planForm = it.planForm.copy(fieldErrors = errors.associate { e -> e.field to e.message })) }
            return
        }
        updateContent { it.copy(planForm = it.planForm.copy(submitting = true, fieldErrors = emptyMap(), submitError = null)) }
        viewModelScope.launch {
            when (val r = repo.createPlan(syndicateId, form.name.trim(), form.description.trim(), cents, form.interval)) {
                is ApiResult.Success -> {
                    updateContent { it.copy(planForm = PlanFormState(visible = false), actionMessage = "Plan created") }
                    reloadPlans()
                }
                is ApiResult.Failure ->
                    updateContent { it.copy(planForm = it.planForm.copy(submitting = false, submitError = r.error.message)) }
                is ApiResult.NetworkError ->
                    updateContent { it.copy(planForm = it.planForm.copy(submitting = false, submitError = OFFLINE_FALLBACK)) }
            }
        }
    }

    fun archivePlan(planId: String) {
        val content = content() ?: return
        if (content.busyId != null) return
        updateContent { it.copy(busyId = planId, actionError = null) }
        viewModelScope.launch {
            when (val r = repo.archivePlan(syndicateId, planId)) {
                is ApiResult.Success -> {
                    updateContent { it.copy(busyId = null, actionMessage = "Plan archived") }
                    reloadPlans()
                }
                is ApiResult.Failure -> updateContent { it.copy(busyId = null, actionError = r.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(busyId = null, actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    /** Subscribe the caller to a bundle plan (uses the default payment method server-side). */
    fun subscribe(planId: String) {
        val content = content() ?: return
        if (content.busyId != null) return
        if (!SyndicateMath.canSubscribe(planId, content.subscribedPlanIds)) {
            updateContent { it.copy(actionMessage = "Already subscribed") }
            return
        }
        updateContent { it.copy(busyId = planId, actionError = null) }
        viewModelScope.launch {
            when (val r = repo.subscribeToPlan(syndicateId, planId, paymentMethodId = null)) {
                is ApiResult.Success -> updateContent {
                    it.copy(
                        busyId = null,
                        subscribedPlanIds = it.subscribedPlanIds + r.data.planId.ifBlank { planId },
                        actionMessage = "Subscribed",
                    )
                }
                is ApiResult.Failure -> updateContent { it.copy(busyId = null, actionError = r.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(busyId = null, actionError = OFFLINE_FALLBACK) }
            }
        }
    }

    fun consumeActionMessage() = updateContent { it.copy(actionMessage = null) }
    fun clearActionError() = updateContent { it.copy(actionError = null) }

    // ---- Targeted reloads ----

    private fun reloadRequests() = viewModelScope.launch {
        val r = repo.listRequests(syndicateId)
        if (r is ApiResult.Success) updateContent { it.copy(requests = r.data) }
    }

    private fun reloadPlans() = viewModelScope.launch {
        val r = repo.listPlans(syndicateId)
        if (r is ApiResult.Success) updateContent { it.copy(plans = r.data) }
    }

    private fun reloadAudit() = viewModelScope.launch {
        val r = repo.getAudit(syndicateId)
        if (r is ApiResult.Success) updateContent { it.copy(audit = r.data) }
    }

    // ---- Helpers ----

    private fun content(): SyndicateManagementUiState.Content? =
        _uiState.value as? SyndicateManagementUiState.Content

    private inline fun updateContent(transform: (SyndicateManagementUiState.Content) -> SyndicateManagementUiState.Content) {
        val current = _uiState.value as? SyndicateManagementUiState.Content ?: return
        _uiState.value = transform(current)
    }

    private fun <T> ApiResult<List<T>>.orEmptyList(fallback: List<T>): List<T> = when (this) {
        is ApiResult.Success -> data
        else -> fallback
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
