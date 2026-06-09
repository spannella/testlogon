package com.testlogon.android.feature.auth.passkey

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/** Walks the Compose [Context] chain to the host Activity (Credential Manager needs an Activity). */
internal fun Context.findActivity(): Activity? {
    var ctx: Context? = this
    while (ctx is ContextWrapper) {
        if (ctx is Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}

/**
 * AND-062 — "Add a passkey" section for Account/Security. Hidden entirely on devices that don't
 * support platform passkeys (capability gating). The trigger is disabled while a ceremony is in
 * flight so TalkBack users can't double-activate.
 */
@Composable
fun AddPasskeySection(
    modifier: Modifier = Modifier,
    viewModel: PasskeyRegisterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val supported = (state as? PasskeyRegisterUiState.Idle)?.supported ?: (state !is PasskeyRegisterUiState.Idle)
    if (!supported) return

    Column(
        modifier = modifier.fillMaxWidth().testTag("passkey_register_section"),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        when (val s = state) {
            is PasskeyRegisterUiState.Success ->
                Text(
                    text = "Passkey added.",
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .testTag("passkey_register_success")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            is PasskeyRegisterUiState.Error ->
                Text(
                    text = s.message,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier
                        .testTag("passkey_register_error")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            else -> Unit
        }

        TlButton(
            text = "Add a passkey",
            onClick = { context.findActivity()?.let { viewModel.register(it, label = null) } },
            variant = TlButtonVariant.Secondary,
            loading = state is PasskeyRegisterUiState.InProgress,
            modifier = Modifier.fillMaxWidth().testTag("passkey_register_button"),
        )
    }
}

/**
 * AND-062 — "Sign in with a passkey" action for the sign-in screen. Hidden on unsupported devices.
 * Requires a non-blank username (the contract has no usernameless flow); [enabled] is gated by the
 * caller (login screen) on the entered username + in-flight state.
 */
@Composable
fun PasskeySignInButton(
    enabled: Boolean,
    loading: Boolean,
    supported: Boolean,
    onSignIn: (activity: Activity) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (!supported) return
    val context = LocalContext.current
    TlButton(
        text = "Sign in with a passkey",
        onClick = { context.findActivity()?.let(onSignIn) },
        variant = TlButtonVariant.Secondary,
        enabled = enabled,
        loading = loading,
        modifier = modifier.fillMaxWidth().testTag("login_passkey"),
    )
}
