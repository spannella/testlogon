package com.testlogon.android.feature.vod.rental

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.rental.RentOutcome
import com.testlogon.android.data.vod.rental.RentalAccess
import com.testlogon.android.data.vod.rental.RentalCountdown
import com.testlogon.android.data.vod.rental.RentalTierOption
import com.testlogon.android.data.vod.rental.VodRentalApi
import com.testlogon.android.data.vod.rental.VodRentalRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-192 — rental UI state for the VOD detail rent/play affordance + live countdown.
 *
 * The server is authoritative; the [Active] state interpolates the countdown between fetches via a
 * viewModelScope ticker that runs ONLY while active (zero cost when locked). On the tick crossing zero
 * the state re-locks to [Locked] with reason "expired" — no app restart needed.
 */
sealed interface VodRentalUiState {
    data object Loading : VodRentalUiState
    data class Locked(
        val tiers: List<RentalTierOption>,
        val lastReason: String?,
        val isRenting: Boolean = false,
    ) : VodRentalUiState
    data class Active(
        val access: RentalAccess,
        val remainingSeconds: Long,
        val countdownLabel: String,
        val countdownA11y: String,
        val isStartingPlayback: Boolean = false,
    ) : VodRentalUiState
    data class Error(val message: String, val offline: Boolean) : VodRentalUiState
}

/** One-shot effects (Channel + receiveAsFlow so they are not replayed on recomposition). */
sealed interface VodRentalEffect {
    /** Playback grant ready; the url/token live only in this transient effect (never persisted/logged). */
    data class PlaybackReady(val url: String, val tokenExpiresAt: Long) : VodRentalEffect
    data class ShowMessage(val message: String) : VodRentalEffect
    data object PaymentsUnavailable : VodRentalEffect
}

@HiltViewModel
class VodRentalViewModel @Inject constructor(
    private val repo: VodRentalRepository,
    private val clock: Clock,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedState[ARG_VIDEO_ID]) { "missing videoId arg" }

    private val _state = MutableStateFlow<VodRentalUiState>(VodRentalUiState.Loading)
    val state: StateFlow<VodRentalUiState> = _state.asStateFlow()

    private val _effects = Channel<VodRentalEffect>(Channel.BUFFERED)
    val effects: Flow<VodRentalEffect> = _effects.receiveAsFlow()

    private var tickerJob: Job? = null
    private var anchorSeconds: Long = 0L
    private var lastAccess: RentalAccess? = null

    private fun nowSeconds(): Long = clock.now() / 1000L

    init {
        load()
    }

    fun load() {
        _state.update { VodRentalUiState.Loading }
        viewModelScope.launch {
            when (val r = repo.status(videoId)) {
                is ApiResult.Success -> reduceAccess(r.data)
                is ApiResult.Failure -> _state.update {
                    VodRentalUiState.Error(r.error.message, offline = false)
                }
                is ApiResult.NetworkError -> _state.update {
                    VodRentalUiState.Error(MSG_OFFLINE, offline = true)
                }
            }
        }
    }

    fun retry() = load()

    /** Rent at [tier] ("rental"|"view_once"). Guards against concurrent rents via isRenting. */
    fun rent(tier: String, durationHours: Int? = DEFAULT_RENTAL_HOURS) {
        val locked = _state.value as? VodRentalUiState.Locked
        if (locked?.isRenting == true) return
        _state.update { (it as? VodRentalUiState.Locked)?.copy(isRenting = true) ?: it }
        viewModelScope.launch {
            when (val outcome = repo.rent(videoId, tier, durationHours)) {
                is RentOutcome.Active -> reduceAccess(outcome.access)
                RentOutcome.PaymentsUnavailable -> {
                    _state.update {
                        (it as? VodRentalUiState.Locked)?.copy(isRenting = false) ?: it
                    }
                    _effects.send(VodRentalEffect.PaymentsUnavailable)
                }
                is RentOutcome.Cancelled -> _state.update {
                    (it as? VodRentalUiState.Locked)?.copy(isRenting = false) ?: it
                }
                is RentOutcome.Failure -> {
                    _state.update { (it as? VodRentalUiState.Locked)?.copy(isRenting = false) ?: it }
                    _effects.send(VodRentalEffect.ShowMessage(outcome.message))
                }
            }
        }
    }

    /** Requests a short-lived playback grant; emits PlaybackReady on success. */
    fun beginPlayback() {
        val active = _state.value as? VodRentalUiState.Active ?: return
        if (active.isStartingPlayback) return
        _state.update { (it as? VodRentalUiState.Active)?.copy(isStartingPlayback = true) ?: it }
        viewModelScope.launch {
            when (val r = repo.beginPlayback(videoId)) {
                is ApiResult.Success -> {
                    // Access may be embedded (lapse detectable inside a 200).
                    if (!r.data.access.isActiveAt(nowSeconds())) {
                        reduceAccess(r.data.access.copy(reason = "expired"))
                    } else {
                        _state.update {
                            (it as? VodRentalUiState.Active)?.copy(isStartingPlayback = false) ?: it
                        }
                        _effects.send(
                            VodRentalEffect.PlaybackReady(r.data.playbackUrl, r.data.tokenExpiresAt),
                        )
                    }
                }
                is ApiResult.Failure -> {
                    _state.update {
                        (it as? VodRentalUiState.Active)?.copy(isStartingPlayback = false) ?: it
                    }
                    // 403 (defensive) => access lapsed mid-session; re-confirm + re-lock.
                    if (r.error.status == HTTP_FORBIDDEN) refreshAccess() else
                        _effects.send(VodRentalEffect.ShowMessage(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _state.update {
                        (it as? VodRentalUiState.Active)?.copy(isStartingPlayback = false) ?: it
                    }
                    _effects.send(VodRentalEffect.ShowMessage(MSG_OFFLINE))
                }
            }
        }
    }

    /** Reports playback finished (decrements the view budget) then refreshes access. */
    fun finishPlayback() {
        viewModelScope.launch {
            repo.finishPlayback(videoId)
            refreshAccess()
        }
    }

    private fun refreshAccess() {
        viewModelScope.launch {
            (repo.access(videoId) as? ApiResult.Success)?.let { reduceAccess(it.data) }
        }
    }

    /** Reduces a fresh authoritative access state into Active/Locked, (re)starting the ticker. */
    private fun reduceAccess(access: RentalAccess) {
        lastAccess = access
        anchorSeconds = nowSeconds()
        if (access.isActiveAt(nowSeconds())) {
            startTicker()
            emitActive(access)
        } else {
            stopTicker()
            _state.update { VodRentalUiState.Locked(tiers = defaultTiers(), lastReason = access.reason) }
        }
    }

    private fun emitActive(access: RentalAccess) {
        val remaining = access.remainingAt(nowSeconds(), anchorSeconds)
        val prevStarting = (_state.value as? VodRentalUiState.Active)?.isStartingPlayback ?: false
        _state.update {
            VodRentalUiState.Active(
                access = access,
                remainingSeconds = remaining,
                countdownLabel = RentalCountdown.label(remaining),
                countdownA11y = RentalCountdown.accessibilityLabel(remaining),
                isStartingPlayback = prevStarting,
            )
        }
    }

    private fun startTicker() {
        if (tickerJob?.isActive == true) return
        // Only run the per-second ticker for a finite window (a countdown to show). An unlimited
        // rental (expiresAt == null, views != 0) is Active with no ticking — no perpetual loop.
        if (lastAccess?.expiresAt == null) return
        tickerJob = viewModelScope.launch {
            while (isActive) {
                val access = lastAccess ?: break
                if (!access.isActiveAt(nowSeconds())) {
                    // Crossed zero: re-lock in-process (no restart) with reason "expired".
                    stopTicker()
                    _state.update {
                        VodRentalUiState.Locked(tiers = defaultTiers(), lastReason = "expired")
                    }
                    break
                }
                emitActive(access)
                delay(1_000L)
            }
        }
    }

    private fun stopTicker() {
        tickerJob?.cancel()
        tickerJob = null
    }

    override fun onCleared() {
        stopTicker()
        super.onCleared()
    }

    /**
     * AND-192 §13 Risk 1 — the rental endpoints do not return a purchasable-tier list; until AND-193's
     * access offer is wired into this surface a single default tier from config is used.
     */
    private fun defaultTiers(): List<RentalTierOption> = listOf(
        RentalTierOption(VodRentalApi.TIER_RENTAL, amountCents = 0, durationHours = DEFAULT_RENTAL_HOURS),
        RentalTierOption(VodRentalApi.TIER_VIEW_ONCE, amountCents = 0, durationHours = null),
    )

    companion object {
        const val ARG_VIDEO_ID = "videoId"
        const val DEFAULT_RENTAL_HOURS = 48
        private const val HTTP_FORBIDDEN = 403
        private const val MSG_OFFLINE = "You're offline. Try again."
    }
}
