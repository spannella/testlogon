@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlTextField

/** AND-340 - stable testTags for the Signing ENTRY screen. */
object SigningEntryTestTags {
    const val SCREEN = "signing_entry"
    const val PACKET_ID = "signing_packet_id"
    const val LOAD = "signing_load"
    const val CREATE = "signing_create"
}

/**
 * AND-340 - route-level Signing ENTRY screen. There is NO backend packet-list endpoint, so this is a
 * load-by-id / create-draft entry (NOT a browse list). Both paths land on the packet DETAIL screen via
 * [onOpenPacket]. The "Create draft" affordance only appears when a [SigningEntryViewModel.sourcePath]
 * was handed in (e.g. from the Files feature).
 */
@Composable
fun SigningEntryRoute(
    onBack: () -> Unit,
    onOpenPacket: (packetId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SigningEntryViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is SigningEntryEvent.OpenPacket -> onOpenPacket(event.packetId)
                is SigningEntryEvent.CreateFailed -> Unit
            }
        }
    }
    SigningEntryScreen(
        state = state,
        onBack = onBack,
        onPacketIdChange = viewModel::onPacketIdChange,
        onLoadPacket = viewModel::onLoadPacket,
        onCreateDraft = { viewModel.onCreateDraft() },
        modifier = modifier,
    )
}

@Composable
fun SigningEntryScreen(
    state: SigningEntryUiState,
    onBack: () -> Unit,
    onPacketIdChange: (String) -> Unit,
    onLoadPacket: () -> Unit,
    onCreateDraft: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SigningEntryTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.signing_entry_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.signing_entry_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            TlTextField(
                value = state.packetId,
                onValueChange = onPacketIdChange,
                label = stringResource(R.string.signing_packet_id_label),
                modifier = Modifier.testTag(SigningEntryTestTags.PACKET_ID),
            )

            Button(
                onClick = onLoadPacket,
                enabled = state.packetId.isNotBlank(),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(SigningEntryTestTags.LOAD),
            ) {
                Text(stringResource(R.string.signing_load_packet))
            }

            if (state.canCreateDraft) {
                OutlinedButton(
                    onClick = onCreateDraft,
                    enabled = !state.creating,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(SigningEntryTestTags.CREATE),
                ) {
                    Text(stringResource(R.string.signing_create_draft))
                }
            }
        }
    }
}
