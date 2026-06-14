package com.testlogon.android.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton

/** Route-level server-URL settings entry (AND-041), reachable pre-login. */
@Composable
fun ServerUrlSettingsRoute(
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ServerUrlViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    ServerUrlSettingsScreen(
        state = state,
        onInputChange = viewModel::onInputChange,
        onSave = viewModel::onSave,
        onReset = viewModel::onResetToDefault,
        onMessageShown = viewModel::onMessageShown,
        onNavigateBack = onNavigateBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerUrlSettingsScreen(
    state: ServerUrlUiState,
    onInputChange: (String) -> Unit,
    onSave: () -> Unit,
    onReset: () -> Unit,
    onMessageShown: () -> Unit,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(state.message) {
        val msg = state.message ?: return@LaunchedEffect
        val text = when (msg) {
            SettingsMessage.Saved -> "Server URL saved"
            SettingsMessage.ResetDone -> "Reset to default"
            is SettingsMessage.Failed -> msg.reason
        }
        snackbarHostState.showSnackbar(text)
        onMessageShown()
    }

    Scaffold(
        modifier = modifier.testTag("server_url_screen"),
        topBar = {
            TopAppBar(
                title = { Text("Server URL") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack, modifier = Modifier.testTag("server_url_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Current: ${state.persistedUrl}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("server_url_current"),
            )

            OutlinedTextField(
                value = state.input,
                onValueChange = onInputChange,
                label = { Text("Base URL") },
                singleLine = true,
                isError = state.error != null,
                supportingText = {
                    val errText = state.error?.let(::errorMessage)
                    when {
                        errText != null -> Text(errText)
                        state.cleartextWarning -> Text("Connection is not encrypted (HTTP)")
                    }
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    capitalization = KeyboardCapitalization.None,
                ),
                modifier = Modifier.fillMaxWidth().testTag("server_url_input"),
            )

            TlButton(
                text = "Save",
                onClick = onSave,
                enabled = state.canSave,
                loading = state.saving,
                modifier = Modifier.fillMaxWidth().testTag("server_url_save"),
            )

            TextButton(
                onClick = onReset,
                enabled = state.canReset && !state.saving,
                modifier = Modifier.testTag("server_url_reset"),
            ) {
                Text("Reset to default")
            }
        }
    }
}

private fun errorMessage(error: UrlError): String = when (error) {
    UrlError.BLANK -> "Enter a server URL"
    UrlError.MALFORMED -> "That doesn't look like a valid URL"
    UrlError.BAD_SCHEME -> "URL must start with http:// or https://"
    UrlError.NO_HOST -> "URL must include a host"
    UrlError.BAD_PORT -> "Port must be between 1 and 65535"
}
