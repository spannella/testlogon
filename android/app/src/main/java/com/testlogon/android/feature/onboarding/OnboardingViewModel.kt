package com.testlogon.android.feature.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Shared Hilt ViewModel backing BOTH onboarding UIs (the first-run welcome tour and every per-surface
 * intro callout). It exposes the persisted seen-set as a [StateFlow] and forwards mark/reset to the
 * [OnboardingStore]. Keeping this a plain injected VM means individual screens gain onboarding with a
 * single `OnboardingHost { ... }` / `SurfaceIntro(id)` call and no signature changes.
 */
@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val store: OnboardingStore,
) : ViewModel() {

    /** The live seen-set; null while the first value is still loading (so nothing flashes prematurely). */
    val seenIds: StateFlow<Set<String>?> = store.seenIds()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = null,
        )

    /** Record [id] as seen (welcome-tour completion or an intro dismissal). */
    fun markSeen(id: String) {
        viewModelScope.launch { store.markSeen(id) }
    }

    /** Replay everything: clears the whole seen-set (Settings "Product tour" control). */
    fun resetAll() {
        viewModelScope.launch { store.resetAll() }
    }
}
