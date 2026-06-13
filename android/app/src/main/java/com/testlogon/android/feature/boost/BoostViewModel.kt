package com.testlogon.android.feature.boost

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.feature.boost.data.BoostRepository
import com.testlogon.android.feature.boost.data.BoostStatusCache
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-364 - presentation logic for the CONTENT BOOST surface (paid post promotion).
 *
 * FLOW: pick a total budget + duration -> submit (server charges the wallet up-front + creates the boost)
 * -> watch the boost status, with Cancel + refund offered ONLY while the boost is active.
 *
 * LOAD (FR-9): on construction the persisted last-known boost ([BoostStatusCache.get]) decides the initial
 * screen - a cached boost lands directly on [BoostUiState.Status]; otherwise the [BoostUiState.Form] with
 * defaults ($5.00 / 60 min). The cache is the DataStore divergence (see [BoostStatusCache]).
 *
 * BOUNDED POLL (ANTI-HANG): when showing a Status whose status is active, a cancellable [pollJob] refreshes
 * the boost every [pollIntervalMillis] for at most [maxPollTicks] ticks, STOPPING as soon as the status
 * leaves active (or the tick budget is exhausted). It is NEVER an init while(isActive) loop - that would
 * spin runTest's end-of-test drain (the AND-310 lesson). The poll dispatcher is the viewModelScope, which
 * the MainDispatcherRule test scheduler drives; tests set a small interval + bounded advanceTimeBy and
 * always reach a non-active status (cancelling the poll) before finishing.
 */
@HiltViewModel
class BoostViewModel @Inject constructor(
    private val repository: BoostRepository,
    private val statusCache: BoostStatusCache,
    savedState: SavedStateHandle,
) : ViewModel() {

    /** The post being boosted (nav arg). content_id on the create body; content_type is fixed to "post". */
    val postId: String = savedState.get<String>(ARG_POST_ID).orEmpty()

    /**
     * Status-poll interval (ms). NOT a constructor param - Hilt cannot provide a bare [Long] and ignores
     * Kotlin defaults. Tests set this directly after construction to drive fast bounded ticks.
     */
    internal var pollIntervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS

    /** Hard upper bound on poll ticks (forward-stop guard even if the status never leaves active). */
    internal var maxPollTicks: Int = DEFAULT_MAX_POLL_TICKS

    private val _uiState = MutableStateFlow<BoostUiState>(BoostUiState.Loading)
    val uiState: StateFlow<BoostUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    init {
        if (postId.isBlank()) {
            _uiState.value = BoostUiState.Error(NO_POST)
        } else {
            viewModelScope.launch {
                val cached = statusCache.get(postId)
                if (cached != null) {
                    showStatus(cached)
                } else {
                    _uiState.value = defaultForm()
                }
            }
        }
    }

    // ---- Form editing ----

    /** Updates the budget from a USD text entry (e.g. "5.00" -> 500 cents); recomputes [canSubmit]. */
    fun onBudgetChanged(text: String) = mutateForm { form ->
        form.copy(budgetText = text, budgetCents = parseUsdToCents(text))
    }

    /** Updates the duration from a minutes text entry (e.g. "60" -> 3600 seconds); recomputes [canSubmit]. */
    fun onDurationChanged(text: String) = mutateForm { form ->
        form.copy(durationMinutesText = text, durationSeconds = parseMinutesToSeconds(text))
    }

    /**
     * Submits the boost: POST {content_type=post, content_id=postId, budget_cents, duration_seconds}. The
     * spinner is shown + the form disabled while submitting; on success the screen moves to Status and the
     * cache is updated. NO auto-retry on failure (the user re-submits).
     */
    fun submit() {
        val form = (_uiState.value as? BoostUiState.Form) ?: return
        if (form.submitting || !form.canSubmit) return
        _uiState.value = form.copy(submitting = true, error = null)
        viewModelScope.launch {
            when (
                val result = repository.createBoost(
                    contentType = CONTENT_TYPE_POST,
                    contentId = postId,
                    budgetCents = form.budgetCents,
                    durationSeconds = form.durationSeconds,
                )
            ) {
                is ApiResult.Success -> {
                    statusCache.put(postId, result.data)
                    showStatus(result.data)
                }
                is ApiResult.Failure ->
                    _uiState.value = form.copy(submitting = false, error = result.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = form.copy(submitting = false, error = NETWORK_ERROR)
            }
        }
    }

    // ---- Status view ----

    /** A SINGLE non-looping re-read of the current boost (re-runnable; also used to retry an Error). */
    fun refresh() {
        val status = _uiState.value as? BoostUiState.Status ?: return
        if (status.refreshing) return
        _uiState.value = status.copy(refreshing = true)
        viewModelScope.launch { reloadOnce(status.boost.boostId) }
    }

    /** Retries from the Error state by rebuilding the initial screen (cache-or-form). */
    fun onRetry() {
        when (val current = _uiState.value) {
            is BoostUiState.Status -> refresh()
            else -> {
                if (postId.isBlank()) {
                    _uiState.value = BoostUiState.Error(NO_POST)
                    return
                }
                _uiState.value = BoostUiState.Loading
                viewModelScope.launch {
                    val cached = statusCache.get(postId)
                    if (cached != null) showStatus(cached) else _uiState.value = defaultForm()
                }
            }
        }
    }

    /** Cancels the active boost (offered ONLY while status == ACTIVE) -> updates Status + cache with refund. */
    fun cancel() {
        val status = _uiState.value as? BoostUiState.Status ?: return
        if (!status.canCancel || status.refreshing) return
        _uiState.value = status.copy(refreshing = true, error = null)
        val boostId = status.boost.boostId
        viewModelScope.launch {
            when (val result = repository.cancelBoost(boostId)) {
                is ApiResult.Success -> reloadOnce(boostId)
                is ApiResult.Failure ->
                    _uiState.update {
                        (it as? BoostUiState.Status)?.copy(refreshing = false, error = result.error.message) ?: it
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        (it as? BoostUiState.Status)?.copy(refreshing = false, error = NETWORK_ERROR) ?: it
                    }
            }
        }
    }

    /** Re-reads one boost and folds it into the Status state (+ cache); leaves Status on failure. */
    private suspend fun reloadOnce(boostId: String) {
        when (val result = repository.getBoost(boostId)) {
            is ApiResult.Success -> {
                statusCache.put(postId, result.data)
                showStatus(result.data)
            }
            is ApiResult.Failure ->
                _uiState.update {
                    (it as? BoostUiState.Status)?.copy(refreshing = false, error = result.error.message) ?: it
                }
            is ApiResult.NetworkError ->
                _uiState.update {
                    (it as? BoostUiState.Status)?.copy(refreshing = false, error = NETWORK_ERROR) ?: it
                }
        }
    }

    /** Moves to the Status view for [boost] and (re)arms the bounded poll iff the boost is active. */
    private fun showStatus(boost: ContentBoost) {
        _uiState.value = BoostUiState.Status(
            boost = boost,
            refreshing = false,
            canCancel = boost.statusEnum == BoostStatus.ACTIVE,
        )
        if (boost.statusEnum.isActive) startPoll(boost.boostId) else stopPoll()
    }

    /**
     * (Re)arms the BOUNDED status poll. Cancellable, started ONLY for an active boost (NEVER in init). Runs
     * at most [maxPollTicks] ticks and STOPS the moment the refreshed status is no longer active, so it can
     * never spin forever. Each tick re-reads the boost via [reloadOnce] (which itself re-arms / stops the
     * poll through [showStatus] on success).
     */
    private fun startPoll(boostId: String) {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            var ticks = 0
            while (ticks < maxPollTicks) {
                delay(pollIntervalMillis)
                ticks++
                val current = _uiState.value
                // Stop if we left the Status view, the boost changed, or it is no longer active.
                if (current !is BoostUiState.Status ||
                    current.boost.boostId != boostId ||
                    !current.boost.statusEnum.isActive
                ) {
                    return@launch
                }
                reloadOnce(boostId)
                val after = _uiState.value
                if (after !is BoostUiState.Status || !after.boost.statusEnum.isActive) return@launch
            }
        }
    }

    private fun stopPoll() {
        pollJob?.cancel()
        pollJob = null
    }

    private fun mutateForm(transform: (BoostUiState.Form) -> BoostUiState.Form) {
        val form = _uiState.value as? BoostUiState.Form ?: return
        val next = transform(form)
        _uiState.value = next.copy(canSubmit = computeCanSubmit(next), error = null)
    }

    private fun computeCanSubmit(form: BoostUiState.Form): Boolean =
        postId.isNotEmpty() && form.budgetCents >= 1L && form.durationSeconds >= 1L

    private fun defaultForm(): BoostUiState.Form {
        val form = BoostUiState.Form(
            budgetText = DEFAULT_BUDGET_TEXT,
            durationMinutesText = DEFAULT_DURATION_MINUTES_TEXT,
            budgetCents = parseUsdToCents(DEFAULT_BUDGET_TEXT),
            durationSeconds = parseMinutesToSeconds(DEFAULT_DURATION_MINUTES_TEXT),
        )
        return form.copy(canSubmit = computeCanSubmit(form))
    }

    override fun onCleared() {
        stopPoll()
    }

    companion object {
        /** Nav arg carrying the post id being boosted. */
        const val ARG_POST_ID = "postId"

        /** The wire content_type for a boosted post (the only content kind AND-364 boosts). */
        const val CONTENT_TYPE_POST = "post"

        /** Default poll interval (ms). Override via [pollIntervalMillis] in tests. */
        const val DEFAULT_POLL_INTERVAL_MILLIS = 15_000L

        /** Default hard cap on poll ticks (about 5 minutes at the default interval). */
        const val DEFAULT_MAX_POLL_TICKS = 20

        /** Default form budget ($5.00) and duration (60 minutes). */
        const val DEFAULT_BUDGET_TEXT = "5.00"
        const val DEFAULT_DURATION_MINUTES_TEXT = "60"

        private const val NO_POST = "No post is available to boost."
        private const val NETWORK_ERROR = "Couldn't reach the server. Check your connection and try again."

        /**
         * Parses a USD entry ("5", "5.0", "5.00", "$5.00") into integer cents. Tolerant: a blank / invalid
         * entry yields 0 (which fails the budget >= 1 gate). Caps at two decimal places.
         */
        internal fun parseUsdToCents(text: String): Long {
            val cleaned = text.trim().removePrefix("$").replace(",", "")
            if (cleaned.isEmpty()) return 0L
            val dollars = cleaned.toBigDecimalOrNull() ?: return 0L
            if (dollars.signum() < 0) return 0L
            return dollars.movePointRight(2).toLong()
        }

        /** Parses a whole-minutes entry into seconds. Blank / invalid -> 0 (fails the duration >= 1 gate). */
        internal fun parseMinutesToSeconds(text: String): Long {
            val minutes = text.trim().toLongOrNull() ?: return 0L
            if (minutes < 0) return 0L
            return minutes * 60L
        }
    }
}
