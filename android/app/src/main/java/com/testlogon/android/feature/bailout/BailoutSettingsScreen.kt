@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bailout

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Auto-bailout protection setting: a toggle that, when on, auto-opens a pre-emptive bailout auction on
 * distress-band entry (else the trader opens it manually), plus a default max position-share. Wired to
 * `GET/PUT me/prefs/bailout`; degrades to a device-local copy (labelled "saved on this device") when the
 * server endpoint is undeployed.
 */
@Composable
fun BailoutSettingsRoute(
    onBack: () -> Unit,
    viewModel: BailoutSettingsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.consumeActionMessage()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Auto-bailout protection") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Card {
                Column(Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Auto-open on distress", fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.height(2.dp))
                            Text(
                                "When a margin position enters the volatility-scaled distress band, automatically open a pre-emptive bailout auction. Off = you open it manually.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Switch(
                            checked = state.autoEnabled,
                            enabled = !state.saving && !state.loading,
                            onCheckedChange = viewModel::setAutoEnabled,
                            modifier = Modifier.testTag("auto_bailout_toggle"),
                        )
                    }
                }
            }

            Card {
                Column(Modifier.padding(16.dp)) {
                    Text("Default max position-share", fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(2.dp))
                    Text(
                        "The most of the position an auto-opened auction offers rescuers. Currently ${BailoutMath.formatBps(state.defaultMaxShareBps)}.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(1_000, 2_000, 3_000, 5_000).forEach { bps ->
                            val selected = state.defaultMaxShareBps == bps
                            if (selected) {
                                Button(
                                    onClick = { viewModel.setDefaultMaxShareBps(bps) },
                                    enabled = !state.saving,
                                    modifier = Modifier.testTag("share_$bps"),
                                ) { Text(BailoutMath.formatBps(bps)) }
                            } else {
                                OutlinedButton(
                                    onClick = { viewModel.setDefaultMaxShareBps(bps) },
                                    enabled = !state.saving,
                                    modifier = Modifier.testTag("share_$bps"),
                                ) { Text(BailoutMath.formatBps(bps)) }
                            }
                        }
                    }
                }
            }

            if (state.deviceLocal) {
                Text(
                    "Saved on this device - the server preference endpoint (me/prefs/bailout) is not available yet, so this is stored locally and will sync when the backend lands.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
