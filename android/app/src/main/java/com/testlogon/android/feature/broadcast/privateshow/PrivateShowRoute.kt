@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.privateshow

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/**
 * AND-315 — private-show host entry. Drives [PrivateShowViewModel.refreshStatus] once + the request poll loop
 * (and, transitively, the cost ticker that only runs while Active) for the lifetime of the composition via a
 * DisposableEffect, then renders the lifecycle surfaces. Reached from the host control surface
 * (BroadcastPrivateShowDest).
 */
@Composable
fun PrivateShowRoute(
    onBack: () -> Unit,
    viewModel: PrivateShowViewModel = hiltViewModel(),
) {
    val ui by viewModel.uiState.collectAsStateWithLifecycle()
    DisposableEffect(viewModel) {
        // Rehydrate from server status, then start polling. stopPolling() cancels BOTH the poll loop AND the
        // cost ticker so nothing keeps running once the surface leaves the composition.
        viewModel.refreshStatus()
        viewModel.startPolling()
        onDispose { viewModel.stopPolling() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.private_show_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.tips_config_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.TopCenter) {
            when (val state = ui.state) {
                is PrivateShowState.Idle, is PrivateShowState.Ending -> EmptyState(
                    title = stringResource(R.string.private_show_title),
                    body = null,
                    imageVector = Icons.Outlined.Lock,
                )

                is PrivateShowState.Pending -> PrivateShowRequestSheet(
                    request = state.request,
                    inFlight = ui.inFlightAction,
                    onAccept = { behavior -> viewModel.accept(state.request.requestId, behavior) },
                    onDecline = { viewModel.decline(state.request.requestId) },
                    onDismiss = { /* host stays on the surface; decline is the explicit dismissal */ },
                )

                is PrivateShowState.Active -> PrivateShowActiveBar(
                    elapsedSeconds = state.elapsedSeconds,
                    accruedCents = state.accruedCents,
                    ending = ui.inFlightAction,
                    onEnd = viewModel::endShow,
                )

                is PrivateShowState.Ended -> PrivateShowSummaryDialog(
                    summary = state.summary,
                    onDismiss = onBack,
                )
            }
        }
    }
}
