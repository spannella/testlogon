@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tickets.ui

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.core.network.tickets.TicketConstants
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-372 - stable testTags for the ticket-spaces list screen + its rows. */
object SpacesListTestTags {
    const val SCREEN = "tickets_spaces_screen"
    const val EMPTY = "tickets_empty"
    const val ERROR_RETRY = "tickets_error_retry"

    fun row(spaceId: String) = "ticket_space_row_$spaceId"
}

/**
 * AND-372 - route-level entry for the ticket-spaces list (screen 1). Collects the state, wires the one-shot
 * NavigateToLogin effect to the re-auth handoff, and taps through to a space's ticket list.
 */
@Composable
fun SpacesListRoute(
    onBack: () -> Unit,
    onOpenSpace: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: SpacesListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is TicketsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    SpacesListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onSpaceClick = onOpenSpace,
    )
}

/** AND-372 - stateless READ-ONLY ticket-spaces list (name + visibility badge + member count + updated time). */
@Composable
fun SpacesListScreen(
    state: SpacesListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSpaceClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SpacesListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tickets_spaces_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.tickets_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? SpacesListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is SpacesListUiState.Loading -> LoadingState()

                is SpacesListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(SpacesListTestTags.EMPTY),
                        title = stringResource(R.string.tickets_spaces_empty_title),
                        body = stringResource(R.string.tickets_spaces_empty_body),
                        imageVector = Icons.Outlined.SupportAgent,
                    )

                is SpacesListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(SpacesListTestTags.ERROR_RETRY),
                        message = state.error.message,
                        onRetry = onRetry,
                    )

                is SpacesListUiState.Content ->
                    SpacesContent(state = state, onRetry = onRetry, onSpaceClick = onSpaceClick)
            }
        }
    }
}

@Composable
private fun SpacesContent(
    state: SpacesListUiState.Content,
    onRetry: () -> Unit,
    onSpaceClick: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(items = state.spaces, key = { it.spaceId }) { space ->
                SpaceRow(space = space, onClick = { onSpaceClick(space.spaceId) })
            }
        }
    }
}

@Composable
private fun SpaceRow(
    space: TicketSpace,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(SpacesListTestTags.row(space.spaceId))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = space.name?.ifBlank { null } ?: stringResource(R.string.tickets_space_untitled),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                VisibilityBadge(space.visibility)
                Text(
                    text = stringResource(R.string.tickets_member_count, space.memberCount),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val updated = relativeTime(space.updatedAt)
            if (updated.isNotBlank()) {
                Text(
                    text = stringResource(R.string.tickets_updated, updated),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun VisibilityBadge(visibility: String?) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(visibilityLabel(visibility)) },
        colors = AssistChipDefaults.assistChipColors(),
    )
}

/**
 * AND-372 - the human visibility label. A recognized constant uses a localized string; an unknown value falls
 * back to the RAW wire token (or a generic label when blank), forward-compat for any new server value.
 */
@Composable
private fun visibilityLabel(visibility: String?): String = when (visibility) {
    TicketConstants.SpaceVisibility.PRIVATE -> stringResource(R.string.tickets_visibility_private)
    TicketConstants.SpaceVisibility.SHARED -> stringResource(R.string.tickets_visibility_shared)
    else -> visibility?.ifBlank { null } ?: stringResource(R.string.tickets_visibility_unknown)
}

/**
 * AND-372 - relative-time copy from an EPOCH-SECONDS value. UI-only (android.text.format); returns "" for null
 * / non-positive timestamps. Mirrors the AND-365 sponsorship helper.
 */
internal fun relativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
