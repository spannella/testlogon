package com.testlogon.android.feature.health

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.BackendStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/** Banner presentation state (AND-042). [visible] drives show/hide; [messageRes]==0 when hidden. */
data class HealthBannerUiState(
    val visible: Boolean = false,
)

/**
 * AND-042 — maps [HealthProbe]'s `Flow<BackendStatus>` into a debounced banner-visibility state.
 *
 * Show is immediate (one Down emission shows the banner); hide is held for a settle window so a
 * single lucky probe between failures does not flap the banner. `flatMapLatest` cancels the pending
 * hide if the host flips back to Down inside the window. An upstream error degrades to "hidden".
 */
@HiltViewModel
class HealthBannerViewModel @Inject constructor(
    monitor: BackendStatusMonitor,
) : ViewModel() {

    @OptIn(ExperimentalCoroutinesApi::class)
    val uiState: StateFlow<HealthBannerUiState> =
        monitor.status
            .map { it.isDown() }
            .distinctUntilChanged()
            .flatMapLatest { down ->
                if (down) flowOf(true) else hideAfterSettle()
            }
            .map { HealthBannerUiState(visible = it) }
            .catch { emit(HealthBannerUiState(visible = false)) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), HealthBannerUiState())

    private fun hideAfterSettle(): Flow<Boolean> = flow {
        delay(SETTLE_MILLIS)
        emit(false)
    }

    private fun BackendStatus.isDown(): Boolean = this == BackendStatus.Down

    private companion object {
        const val SETTLE_MILLIS = 1_500L
    }
}
