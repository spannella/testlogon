package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contacts.ContactsRepository
import com.testlogon.android.data.contacts.SocialGraphMath
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the per-user "snooze this following" affordance on the public-profile screen.
 *
 * Mirrors the shape of [com.testlogon.android.feature.blocking.BlockInteractionViewModel]: the viewed
 * counterpart is bound via [hydrate] (Hilt cannot pass a runtime arg through the ctor), the current
 * snooze state is read from the viewer's snoozed-following list, and the snooze / un-snooze mutations
 * are single-flight guarded. All reads degrade-on-404 at the repository layer, so a viewer who does
 * not follow the target simply sees the neutral "not snoozed" state.
 *
 * Snooze math (active?, remaining label, day clamping) lives in the pure [SocialGraphMath] object so
 * it is unit-tested off-device.
 */
@HiltViewModel
class SnoozeInteractionViewModel @Inject constructor(
    private val repository: ContactsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SnoozeInteractionUiState())
    val uiState: StateFlow<SnoozeInteractionUiState> = _uiState.asStateFlow()

    /** Bind the counterpart and read whether they are currently snoozed. Idempotent. */
    fun hydrate(userId: String) {
        if (userId.isBlank()) return
        _uiState.update { it.copy(targetUserId = userId) }
        refresh(userId)
    }

    private fun refresh(userId: String) {
        viewModelScope.launch {
            when (val result = repository.snoozedFollowing()) {
                is ApiResult.Success -> {
                    val row = result.data.firstOrNull { it.userId == userId }
                    val nowSeconds = System.currentTimeMillis() / 1000
                    val active = row != null &&
                        SocialGraphMath.isSnoozeActive(row.snoozedUntilSeconds, nowSeconds)
                    _uiState.update {
                        it.copy(
                            snoozedUntilSeconds = if (active) row!!.snoozedUntilSeconds else null,
                            label = if (active) {
                                SocialGraphMath.snoozeLabel(row!!.snoozedUntilSeconds, nowSeconds)
                            } else {
                                null
                            },
                        )
                    }
                }
                // Degrade quietly: keep neutral "not snoozed" state on a failed read.
                is ApiResult.Failure, is ApiResult.NetworkError -> Unit
            }
        }
    }

    /** Snooze the target for [days] (default 7); clamped to 1..90 by the repository. */
    fun onSnooze(days: Int = DEFAULT_SNOOZE_DAYS) {
        val target = _uiState.value.targetUserId
        if (target.isEmpty() || _uiState.value.inFlight) return
        _uiState.update { it.copy(inFlight = true) }
        viewModelScope.launch {
            when (val result = repository.snoozeFollowing(target, days)) {
                is ApiResult.Success -> {
                    val until = result.data
                    val nowSeconds = System.currentTimeMillis() / 1000
                    _uiState.update {
                        it.copy(
                            inFlight = false,
                            snoozedUntilSeconds = until,
                            label = SocialGraphMath.snoozeLabel(until, nowSeconds),
                        )
                    }
                }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _uiState.update { it.copy(inFlight = false) }
            }
        }
    }

    /** Remove the snooze (idempotent; a 404 is treated as success by the repository). */
    fun onUnsnooze() {
        val target = _uiState.value.targetUserId
        if (target.isEmpty() || _uiState.value.inFlight) return
        _uiState.update { it.copy(inFlight = true) }
        viewModelScope.launch {
            when (repository.unsnoozeFollowing(target)) {
                is ApiResult.Success ->
                    _uiState.update { it.copy(inFlight = false, snoozedUntilSeconds = null, label = null) }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _uiState.update { it.copy(inFlight = false) }
            }
        }
    }

    private companion object {
        const val DEFAULT_SNOOZE_DAYS = 7
    }
}

/** Render-ready state for the per-user snooze affordance. */
data class SnoozeInteractionUiState(
    val targetUserId: String = "",
    val snoozedUntilSeconds: Long? = null,
    val label: String? = null,
    val inFlight: Boolean = false,
) {
    /** True when the target is currently snoozed (show "Unsnooze"). */
    val isSnoozed: Boolean get() = snoozedUntilSeconds != null
}
