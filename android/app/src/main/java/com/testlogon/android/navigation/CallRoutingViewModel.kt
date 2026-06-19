package com.testlogon.android.navigation

import androidx.lifecycle.ViewModel
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallSessionState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

/**
 * Exposes the app-scoped call session so the root NavHost can route to the in-call (video) screen as
 * soon as a 1:1 call reaches Connecting/Connected. The outgoing screen (caller) and the separate
 * IncomingCallActivity (callee) only own the pre-connect UI; the connected media view lives at
 * CallRoutes.incall and was previously never navigated to. This observer closes that gap for BOTH sides.
 */
@HiltViewModel
class CallRoutingViewModel @Inject constructor(
    callManager: CallManager,
) : ViewModel() {
    val callState: StateFlow<CallSessionState> = callManager.state
}
