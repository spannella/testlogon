package com.testlogon.android.feature.shell

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.auth.BiometricAuthenticator
import com.testlogon.android.data.auth.BiometricCredentialStore
import com.testlogon.android.data.auth.BiometricEnrollmentBuffer
import com.testlogon.android.data.auth.BiometricOutcome
import com.testlogon.android.data.auth.StoredCredential
import com.testlogon.android.feature.auth.biometric.BiometricEnrollDialog
import com.testlogon.android.feature.auth.passkey.findActivity
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * One-time "enable biometric sign-in?" offer, hosted in the authenticated shell.
 *
 * Login/registration stash the just-used credential in [BiometricEnrollmentBuffer]; this gate
 * (created when the shell first composes after the auth-graph swap) reads it and — if the device
 * has biometrics and nothing is enrolled yet — offers to store it behind a BiometricPrompt. It
 * lives here rather than on the login screen because the auth-state graph swap tears the login
 * screen down the instant authentication succeeds.
 */
@HiltViewModel
class BiometricEnrollGateViewModel @Inject constructor(
    private val buffer: BiometricEnrollmentBuffer,
    private val authenticator: BiometricAuthenticator,
    private val credentialStore: BiometricCredentialStore,
) : ViewModel() {

    data class State(val visible: Boolean = false, val busy: Boolean = false)

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    private var pending: StoredCredential? = null

    init {
        val cred = buffer.peek()
        if (cred != null && authenticator.canAuthenticate() && !credentialStore.hasCredential()) {
            pending = cred
            _state.value = State(visible = true)
        } else {
            buffer.clear()
        }
    }

    fun enroll(activity: FragmentActivity) {
        val cred = pending ?: return dismiss()
        if (_state.value.busy) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val outcome = authenticator.authenticate(
                activity,
                "Enable biometric sign-in",
                "Confirm it's you to enable quick sign-in",
            )
            when (outcome) {
                is BiometricOutcome.Succeeded -> {
                    credentialStore.save(cred.email, cred.password)
                    pending = null
                    buffer.clear()
                    _state.value = State(visible = false)
                }
                is BiometricOutcome.Cancelled -> _state.update { it.copy(busy = false) }
                is BiometricOutcome.Failed -> _state.update { it.copy(busy = false) }
            }
        }
    }

    fun dismiss() {
        pending = null
        buffer.clear()
        _state.value = State(visible = false)
    }
}

@Composable
fun BiometricEnrollGate(viewModel: BiometricEnrollGateViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    if (state.visible) {
        BiometricEnrollDialog(
            busy = state.busy,
            onEnable = { (context.findActivity() as? FragmentActivity)?.let(viewModel::enroll) },
            onSkip = viewModel::dismiss,
        )
    }
}
