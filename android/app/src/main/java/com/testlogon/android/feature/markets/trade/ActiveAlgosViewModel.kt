package com.testlogon.android.feature.markets.trade

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/** UI state for the Active-Algos monitor: the algo list + a wall-clock tick driving the countdowns. */
data class ActiveAlgosUiState(
    val algos: List<AlgoOrder> = emptyList(),
    val nowMs: Long = System.currentTimeMillis(),
) {
    val hasFinished: Boolean get() = algos.any { it.isTerminal }
}

/**
 * Drives the Active-Algos monitor screen. Observes the process-wide [AlgoManager] (algos survive this
 * ViewModel), restores persisted algos once, and runs a 1s ticker so slice/clip countdowns recompute.
 * Pause / resume / cancel / clear delegate straight to the manager (no orphaned timers).
 */
@HiltViewModel
class ActiveAlgosViewModel @Inject constructor(
    private val algoManager: AlgoManager,
) : ViewModel() {

    private val tick = MutableStateFlow(System.currentTimeMillis())

    val uiState: StateFlow<ActiveAlgosUiState> =
        combine(algoManager.algos, tick) { algos, now -> ActiveAlgosUiState(algos = algos, nowMs = now) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000L), ActiveAlgosUiState())

    init {
        algoManager.restore()
        viewModelScope.launch {
            while (isActive) {
                delay(1_000L)
                tick.value = System.currentTimeMillis()
            }
        }
    }

    fun pause(id: String) = algoManager.pause(id)
    fun resume(id: String) = algoManager.resume(id)
    fun cancel(id: String) = algoManager.cancel(id)
    fun clearFinished() = algoManager.clearFinished()
}
