@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing.packetlist

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Draw
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** SUX-008 — stable testTags for the signing INBOX screen. */
object SigningInboxTestTags {
    const val SCREEN = "signing_inbox_screen"
    const val RETRY = "signing_inbox_retry"
    const val EMPTY = "signing_inbox_empty"

    /** Per-row tag, suffixed by the packet id. */
    fun row(packetId: String): String = "signing_inbox_row_$packetId"
}

/**
 * SUX-008 — the signing INBOX ("list packets") route. Groups the four browse buckets and opens the
 * EXISTING packet DETAIL (view + SIGN + mark-done) on row tap.
 */
@Composable
fun SigningInboxRoute(
    onBack: () -> Unit,
    onOpenPacket: (String) -> Unit,
    viewModel: SigningInboxViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SigningInboxScreen(
        state = state,
        onBack = onBack,
        onOpenPacket = onOpenPacket,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
    )
}

@Composable
fun SigningInboxScreen(
    state: SigningInboxUiState,
    onBack: () -> Unit,
    onOpenPacket: (String) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(SigningInboxTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Signatures") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is SigningInboxUiState.Loading -> {
                    CircularProgressIndicator(Modifier.align(Alignment.Center))
                }

                is SigningInboxUiState.Empty -> {
                    Column(
                        modifier = Modifier.align(Alignment.Center).testTag(SigningInboxTestTags.EMPTY),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(Icons.Outlined.Draw, contentDescription = null)
                        Text("No documents to sign", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Packets sent to you for signature will appear here.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }

                is SigningInboxUiState.Error -> {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(state.error.message, style = MaterialTheme.typography.bodyMedium)
                        Button(
                            onClick = onRetry,
                            modifier = Modifier.testTag(SigningInboxTestTags.RETRY),
                        ) { Text("Retry") }
                    }
                }

                is SigningInboxUiState.Content -> {
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                    ) {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            state.sections.forEach { section ->
                                item(key = "header_${section.bucket.name}") {
                                    Text(
                                        text = sectionTitle(section.bucket, section.count),
                                        style = MaterialTheme.typography.titleSmall,
                                        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                                    )
                                }
                                items(section.items, key = { it.packetId }) { row ->
                                    SigningInboxRow(row = row, onClick = { onOpenPacket(row.packetId) })
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SigningInboxRow(row: SigningInboxItem, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SigningInboxTestTags.row(row.packetId))
            .clickable(onClick = onClick),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = row.displayTitle,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val subtitle = row.statusText?.takeIf { it.isNotBlank() }
                ?: row.statusChip?.takeIf { it.isNotBlank() }
                ?: row.status.token
            Text(text = subtitle, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

private fun sectionTitle(bucket: SigningInboxBucket, count: Int): String {
    val label = when (bucket) {
        SigningInboxBucket.AWAITING -> "Awaiting my signature"
        SigningInboxBucket.SENT -> "Sent"
        SigningInboxBucket.COMPLETED -> "Completed"
        SigningInboxBucket.DRAFTS -> "Drafts"
    }
    return "$label ($count)"
}
