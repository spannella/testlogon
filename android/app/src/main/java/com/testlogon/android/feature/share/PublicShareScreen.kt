@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.share

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.share.model.PublicShareState

/** AND-335 - testTags for the public share screen (used by the androidTest UI test). */
object PublicShareTestTags {
    const val SCREEN = "public_share_screen"
    const val PASSWORD = "public_share_password"
    const val DOWNLOAD = "public_share_download"
    const val TERMINAL = "public_share_terminal"
}

/**
 * AND-335 - the session-free public share route. Reachable from the testlogon://share/<linkId> deep link
 * while signed OUT (registered in both nav graphs). [onBack] pops or falls back to the graph start.
 */
@Composable
fun PublicShareRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PublicShareViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PublicShareScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::resolve,
        onPasswordChange = viewModel::onPasswordChange,
        onSubmitPassword = viewModel::submitPassword,
        onDownload = viewModel::download,
        modifier = modifier,
    )
}

/** Stateless public share screen (driven by the androidTest in-test reducer). */
@Composable
fun PublicShareScreen(
    state: PublicShareUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPasswordChange: (String) -> Unit,
    onSubmitPassword: () -> Unit,
    onDownload: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PublicShareTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.public_share_title)) },
                navigationIcon = {
                    Button(onClick = onBack) { Text(stringResource(R.string.public_share_back)) }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (state) {
                is PublicShareUiState.Loading ->
                    CircularProgressIndicator()

                is PublicShareUiState.Error -> {
                    Text(text = state.message)
                    if (state.retryable) {
                        Button(onClick = onRetry) { Text(stringResource(R.string.public_share_retry)) }
                    }
                }

                is PublicShareUiState.Terminal ->
                    TerminalPanel(state.state)

                is PublicShareUiState.Info ->
                    InfoPanel(
                        state = state,
                        onPasswordChange = onPasswordChange,
                        onSubmitPassword = onSubmitPassword,
                        onDownload = onDownload,
                    )
            }
        }
    }
}

@Composable
private fun InfoPanel(
    state: PublicShareUiState.Info,
    onPasswordChange: (String) -> Unit,
    onSubmitPassword: () -> Unit,
    onDownload: () -> Unit,
) {
    val share = state.share
    Text(text = share.fileName ?: stringResource(R.string.public_share_unknown_name))
    share.sizeBytes?.let { Text(text = stringResource(R.string.public_share_size, it)) }
    share.contentType?.let { Text(text = it) }

    if (state.needsPassword) {
        OutlinedTextField(
            value = state.password,
            onValueChange = onPasswordChange,
            singleLine = true,
            label = { Text(stringResource(R.string.public_share_password_hint)) },
            isError = state.passwordError != null,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(PublicShareTestTags.PASSWORD),
        )
        state.passwordError?.let { Text(text = it) }
        Button(onClick = onSubmitPassword, enabled = state.password.isNotBlank()) {
            Text(stringResource(R.string.public_share_unlock))
        }
    } else {
        if (state.downloading) {
            if (state.progress != null) {
                LinearProgressIndicator(
                    progress = { state.progress },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
        state.passwordError?.let { Text(text = it) }
        state.savedFileName?.let { Text(text = stringResource(R.string.public_share_saved, it)) }
        Button(
            onClick = onDownload,
            enabled = !state.downloading,
            modifier = Modifier.testTag(PublicShareTestTags.DOWNLOAD),
        ) {
            Text(stringResource(R.string.public_share_download))
        }
    }
}

@Composable
private fun TerminalPanel(terminal: PublicShareState) {
    val messageRes = when (terminal) {
        PublicShareState.EXPIRED -> R.string.public_share_expired
        PublicShareState.REVOKED -> R.string.public_share_revoked
        PublicShareState.EXHAUSTED -> R.string.public_share_exhausted
        PublicShareState.UNAVAILABLE -> R.string.public_share_unavailable
        // AVAILABLE never renders a terminal panel; map defensively.
        PublicShareState.AVAILABLE -> R.string.public_share_unavailable
    }
    Text(
        text = stringResource(messageRes),
        modifier = Modifier.testTag(PublicShareTestTags.TERMINAL),
    )
}
