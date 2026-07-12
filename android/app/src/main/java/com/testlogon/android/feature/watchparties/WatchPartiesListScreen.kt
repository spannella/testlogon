@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.watchparties

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.LiveTv
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.watchparties.WatchParty

/** Stable testTags for the watch-parties list screen. */
object WatchPartiesListTestTags {
    const val SCREEN = "watch_parties_screen"
    const val LIST = "watch_parties_list"
    const val LOADING = "watch_parties_loading"
    const val EMPTY = "watch_parties_empty"
    const val ERROR = "watch_parties_error"
    const val OFFLINE = "watch_parties_offline"
    const val SESSION_EXPIRED = "watch_parties_session_expired"
    const val CREATE_FAB = "watch_parties_create_fab"
    const val ROW_PREFIX = "watch_parties_row_"
}

/** Route-level watch-parties list entry (reached from the More hub). */
@Composable
fun WatchPartiesListRoute(
    onBack: () -> Unit,
    onOpenParty: (String) -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WatchPartiesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WatchPartiesListEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
                is WatchPartiesListEffect.OpenParty -> onOpenParty(effect.partyId)
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == WatchPartiesListUiState.Phase.SessionExpired) onSessionExpired()
    }

    WatchPartiesListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onPartyClick = onOpenParty,
        onCreateParty = viewModel::onCreateParty,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun WatchPartiesListScreen(
    state: WatchPartiesListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onPartyClick: (String) -> Unit,
    onCreateParty: (videoId: String, title: String, maxParticipants: Int?) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(WatchPartiesListTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.watch_parties_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("watch_parties_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == WatchPartiesListUiState.Phase.Content ||
                state.phase == WatchPartiesListUiState.Phase.Empty
            ) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.testTag(WatchPartiesListTestTags.CREATE_FAB),
                ) {
                    Icon(
                        Icons.Outlined.Add,
                        contentDescription = stringResource(R.string.watch_parties_create_action),
                    )
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                WatchPartiesListUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(WatchPartiesListTestTags.LOADING))

                WatchPartiesListUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage
                            ?: stringResource(R.string.watch_parties_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(WatchPartiesListTestTags.ERROR),
                    )

                WatchPartiesListUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage
                            ?: stringResource(R.string.watch_parties_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(WatchPartiesListTestTags.OFFLINE),
                    )

                WatchPartiesListUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.watch_parties_session_expired_title),
                        body = stringResource(R.string.watch_parties_session_expired_body),
                        modifier = Modifier.testTag(WatchPartiesListTestTags.SESSION_EXPIRED),
                    )

                WatchPartiesListUiState.Phase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.watch_parties_empty_title),
                            body = stringResource(R.string.watch_parties_empty_body),
                            imageVector = Icons.Outlined.LiveTv,
                            modifier = Modifier.testTag(WatchPartiesListTestTags.EMPTY),
                        )
                    }

                WatchPartiesListUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(WatchPartiesListTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (state.isStale) {
                                item { OfflineBanner(onRetry = onRetry) }
                            }
                            items(state.parties, key = { it.id }) { party ->
                                WatchPartyCard(party = party, onClick = { onPartyClick(party.id) })
                            }
                        }
                    }
            }
        }
    }

    if (showCreate) {
        CreateWatchPartyDialog(
            isSubmitting = state.create.isSubmitting,
            onDismiss = { if (!state.create.isSubmitting) showCreate = false },
            onConfirm = { videoId, title, max -> onCreateParty(videoId, title, max) },
        )
    }
}

@Composable
private fun WatchPartyCard(party: WatchParty, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(WatchPartiesListTestTags.ROW_PREFIX + party.id)
            .clickable(onClick = onClick),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = party.displayTitle,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(
                    onClick = {},
                    label = { Text(statusLabel(party.status)) },
                )
            }
            if (party.videoTitle.isNotBlank()) {
                Text(
                    text = party.videoTitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val meta = buildList {
                add(stringResource(
                    R.string.watch_parties_participants_count,
                    party.participantCount,
                    party.maxParticipants,
                ))
                party.formattedCreated().takeIf { it.isNotBlank() }?.let { add(it) }
            }.joinToString("   -   ")
            Text(
                text = meta,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (party.inviteCode.isNotBlank()) {
                Text(
                    text = stringResource(R.string.watch_parties_invite_code, party.inviteCode),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
