package com.testlogon.android.feature.sponsorship.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.DealAction
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.ViewerRole
import com.testlogon.android.core.model.sponsorship.availableActions
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.sponsorship.data.SponsorshipRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.math.BigDecimal
import javax.inject.Inject

/**
 * AND-366 - drives the [SponsorshipDealUiState] for the sponsorship DEAL DETAIL + management surface.
 *
 * dealId arrives as a nav arg via [SavedStateHandle] (survives process death). [load] reads the FULL deal
 * (idempotent GET) and, best-effort, its history (a history failure is TOLERATED -> empty list, NOT an Error).
 * The viewer's [ViewerRole] is derived CLIENT-SIDE from the current user's sub (via [AuthStateStore]) vs the
 * deal's advertiser_sub / creator_sub; [availableActions] is then a pure function of the status + role
 * (non-empty only in proposed / negotiating for a party). The gating is UX-only - the server is authoritative.
 *
 * MANAGEMENT (confirm-then-POST): the screen shows a confirm dialog (accept / reject) or the counter form
 * (negotiate) BEFORE calling [accept] / [reject] / [counter] here. Each is a NON-idempotent POST -> there is
 * NO auto-retry (a failure surfaces a one-shot retryable message; the user re-triggers). While an action is in
 * flight [SponsorshipDealUiState.Content.actionInFlight] is set and ALL actions are disabled (a second call is
 * IGNORED - no double-submit). On success the deal + history are re-read and the action set is recomputed; on
 * a 422 the counter form's field error is mapped by loc tail (compensation_cents / note). There is NO poll.
 */
@HiltViewModel
class SponsorshipDealViewModel @Inject constructor(
    private val repository: SponsorshipRepository,
    private val errorParser: ApiErrorParser,
    savedState: SavedStateHandle,
    authStateStore: AuthStateStore,
) : ViewModel() {

    val dealId: String =
        checkNotNull(savedState[ARG_DEAL_ID]) { "missing $ARG_DEAL_ID nav arg" }

    /** The current user's own sub (may be null); compared to advertiser_sub / creator_sub for the role. */
    private val currentSub: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<SponsorshipDealUiState>(SponsorshipDealUiState.Loading)
    val uiState: StateFlow<SponsorshipDealUiState> = _uiState.asStateFlow()

    private val _effects = Channel<SponsorshipDealEffect>(Channel.BUFFERED)
    val effects: Flow<SponsorshipDealEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** First load / retry: re-reads the deal (+ best-effort history) and derives role + actions. Idempotent. */
    fun load() {
        _uiState.value = SponsorshipDealUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getDeal(dealId)) {
                is ApiResult.Success -> {
                    val history = loadHistory()
                    _uiState.value = contentFor(result.data, history)
                }
                is ApiResult.Failure -> _uiState.value = SponsorshipDealUiState.Error(result.error)
                is ApiResult.NetworkError ->
                    _uiState.value = SponsorshipDealUiState.Error(
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    fun onRetry() = load()

    // ---- Management actions (confirm-then-POST; NON-idempotent; in-flight disables ALL) ----

    /** Accept the current terms (no body). Confirmed in the screen first. */
    fun accept() = runAction(DealAction.ACCEPT) { repository.accept(dealId) }

    /** Reject (the backlog's "decline") with an optional reason (trimmed + capped at 500). */
    fun reject(reason: String) {
        val cleaned = reason.trim().take(MAX_REASON_LEN)
        runAction(DealAction.REJECT) { repository.reject(dealId, cleaned) }
    }

    // ---- Counter (negotiate) form ----

    /** Opens the counter form pre-filled with the deal's current compensation (USD) + an empty note. */
    fun openCounterForm() {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        if (content.actionInFlight != null || content.counterForm != null) return
        _uiState.value = content.copy(
            counterForm = CounterForm(compensationText = centsToUsdText(content.deal.compensationCents)),
        )
    }

    /** Dismisses the counter form (only when no counter submit is in flight). */
    fun dismissCounterForm() {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        val form = content.counterForm ?: return
        if (form.submitting) return
        _uiState.value = content.copy(counterForm = null)
    }

    fun onCounterCompensationChanged(text: String) = mutateCounterForm {
        it.copy(compensationText = text, compensationError = null)
    }

    fun onCounterNoteChanged(text: String) = mutateCounterForm {
        it.copy(note = text, noteError = null)
    }

    /**
     * Submits the counter-offer. Validates CLIENT-SIDE first (compensation >= 1000 cents when present, note
     * <= 2000 chars); a blank compensation entry sends null (omitting the field). On a 422 the per-field error
     * is mapped by loc tail and the form STAYS OPEN; other failures surface a one-shot retryable message.
     */
    fun submitCounter() {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        val form = content.counterForm ?: return
        if (form.submitting || content.actionInFlight != null) return

        val rawComp = form.compensationText.trim()
        val compensationCents: Long?
        if (rawComp.isEmpty()) {
            compensationCents = null
        } else {
            val parsed = parseUsdToCents(rawComp)
            if (parsed == null) {
                _uiState.value = content.copy(
                    counterForm = form.copy(compensationError = CounterFieldError.CLIENT_COMPENSATION_INVALID),
                )
                return
            }
            if (parsed < MIN_COUNTER_CENTS) {
                _uiState.value = content.copy(
                    counterForm = form.copy(compensationError = CounterFieldError.CLIENT_COMPENSATION_TOO_LOW),
                )
                return
            }
            compensationCents = parsed
        }

        val note = form.note.trim().takeIf { it.isNotEmpty() }
        if (note != null && note.length > MAX_NOTE_LEN) {
            _uiState.value = content.copy(
                counterForm = form.copy(noteError = CounterFieldError.CLIENT_NOTE_TOO_LONG),
            )
            return
        }

        _uiState.value = content.copy(
            counterForm = form.copy(submitting = true, compensationError = null, noteError = null),
            actionInFlight = DealAction.NEGOTIATE,
        )
        viewModelScope.launch {
            when (val result = repository.counter(dealId, compensationCents, note)) {
                is ApiResult.Success -> {
                    val history = loadHistory()
                    _uiState.value = contentFor(result.data, history)
                    _effects.send(SponsorshipDealEffect.ActionSucceeded(DealAction.NEGOTIATE))
                }
                is ApiResult.Failure -> reduceCounterFailure(result.error)
                is ApiResult.NetworkError -> reduceCounterNetworkFailure()
            }
        }
    }

    // ---- internals ----

    /**
     * Shared confirm-then-POST runner for the no-form actions (accept / reject). Ignored when not on Content,
     * when an action is already in flight (NO double-submit), or when the action is not currently available.
     * On success re-reads deal + history and recomputes actions; on failure leaves Content (clearing the
     * in-flight flag) and emits a one-shot retryable message (NON-idempotent -> NO auto-retry).
     */
    private fun runAction(action: DealAction, block: suspend () -> ApiResult<SponsorshipDealDetail>) {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        if (content.actionInFlight != null) return
        if (action !in content.availableActions) return
        _uiState.value = content.copy(actionInFlight = action)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    val history = loadHistory()
                    _uiState.value = contentFor(result.data, history)
                    _effects.send(SponsorshipDealEffect.ActionSucceeded(action))
                }
                is ApiResult.Failure -> clearInFlightAndReport(action, result.error.message)
                is ApiResult.NetworkError -> clearInFlightAndReport(action, OFFLINE_FALLBACK)
            }
        }
    }

    private suspend fun clearInFlightAndReport(action: DealAction, message: String) {
        val content = _uiState.value as? SponsorshipDealUiState.Content
        if (content != null) {
            _uiState.value = content.copy(actionInFlight = null)
        }
        _effects.send(SponsorshipDealEffect.ActionFailed(action, message))
    }

    private fun reduceCounterFailure(error: ApiError) {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        val form = content.counterForm
        if (error.status == HTTP_UNPROCESSABLE && form != null) {
            val mapped = mapCounterFieldErrors(error, form)
            if (mapped.compensationError != null || mapped.noteError != null) {
                // A field-level 422: keep the form OPEN with the inline error, NO snackbar.
                _uiState.value = content.copy(counterForm = mapped, actionInFlight = null)
                return
            }
        }
        // Any other failure (or a 422 with no recognized field): clear the spinner + emit a retryable message.
        _uiState.value = content.copy(
            counterForm = form?.copy(submitting = false),
            actionInFlight = null,
        )
        viewModelScope.launch {
            _effects.send(SponsorshipDealEffect.ActionFailed(DealAction.NEGOTIATE, error.message))
        }
    }

    private fun reduceCounterNetworkFailure() {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        _uiState.value = content.copy(
            counterForm = content.counterForm?.copy(submitting = false),
            actionInFlight = null,
        )
        viewModelScope.launch {
            _effects.send(SponsorshipDealEffect.ActionFailed(DealAction.NEGOTIATE, OFFLINE_FALLBACK))
        }
    }

    /** Routes a FastAPI 422 detail[{loc,msg}] item to the counter field by its trailing loc segment. */
    private fun mapCounterFieldErrors(error: ApiError, form: CounterForm): CounterForm {
        val detail = (error.raw as? String)?.let { errorParser.parseDetail(it) } as? List<*>
            ?: return form
        var next = form.copy(submitting = false)
        for (item in detail) {
            val map = item as? Map<*, *> ?: continue
            val loc = (map["loc"] as? List<*>)?.lastOrNull() as? String ?: continue
            when (loc) {
                "compensation_cents" -> next = next.copy(compensationError = CounterFieldError.SERVER)
                "note" -> next = next.copy(noteError = CounterFieldError.SERVER)
            }
        }
        return next
    }

    /** Best-effort history read: any failure folds to an empty list (the section is optional). */
    private suspend fun loadHistory(): List<SponsorshipDealEvent> =
        (repository.getHistory(dealId) as? ApiResult.Success)?.data ?: emptyList()

    /** Builds a Content state for [deal] + [history], deriving the role + available actions. */
    private fun contentFor(
        deal: SponsorshipDealDetail,
        history: List<SponsorshipDealEvent>,
    ): SponsorshipDealUiState.Content {
        val role = ViewerRole.derive(currentSub, deal.advertiserSub, deal.creatorSub)
        return SponsorshipDealUiState.Content(
            deal = deal,
            history = history,
            viewerRole = role,
            availableActions = availableActions(deal.statusEnum, role),
            actionInFlight = null,
            counterForm = null,
        )
    }

    private inline fun mutateCounterForm(transform: (CounterForm) -> CounterForm) {
        val content = _uiState.value as? SponsorshipDealUiState.Content ?: return
        val form = content.counterForm ?: return
        if (form.submitting) return
        _uiState.value = content.copy(counterForm = transform(form))
    }

    companion object {
        /** Nav arg carrying the deal id. */
        const val ARG_DEAL_ID = "dealId"

        /** Server-authoritative caps mirrored client-side (UX only). */
        const val MAX_REASON_LEN = 500
        const val MAX_NOTE_LEN = 2000
        const val MIN_COUNTER_CENTS = 1000L

        private const val HTTP_UNPROCESSABLE = 422
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."

        /**
         * Parses a USD entry ("1000", "1,000.00", "$1000.00") into integer cents, or null when unparseable /
         * negative. Caps at two decimal places. Mirrors the AND-364 boost helper.
         */
        internal fun parseUsdToCents(text: String): Long? {
            val cleaned = text.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return null
            val dollars = cleaned.toBigDecimalOrNull() ?: return null
            if (dollars.signum() < 0) return null
            return dollars.movePointRight(2).toLong()
        }

        /** Renders flat *_cents to a plain USD-decimal entry ("250000" -> "2500.00"); null / 0 -> "". */
        internal fun centsToUsdText(cents: Long?): String {
            if (cents == null || cents <= 0L) return ""
            return BigDecimal(cents).movePointLeft(2).toPlainString()
        }
    }
}
