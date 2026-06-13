package com.testlogon.android.feature.delegates.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.delegates.DelegationContext
import com.testlogon.android.feature.delegates.data.DelegationContextProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-360 - drives the persistent manage-as-creator banner. Re-exposes the typed delegation context
 * (StateFlow) for the banner host to observe and forwards Exit to the AND-359 pure-local exit. No screen
 * state of its own beyond the shared overlay context.
 */
@HiltViewModel
class DelegationBannerViewModel @Inject constructor(
    private val contextProvider: DelegationContextProvider,
) : ViewModel() {

    /** The active typed [DelegationContext], or null when acting as oneself (the banner hides). */
    val delegationContext: StateFlow<DelegationContext?> = contextProvider.delegationContext

    /** EXIT manage-as mode (AND-359 pure-local exit). */
    fun exit() {
        viewModelScope.launch { contextProvider.exit() }
    }
}
