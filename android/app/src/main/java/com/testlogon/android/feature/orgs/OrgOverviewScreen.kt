@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.MarkEmailUnread
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-354 - stable testTags for the org overview hub screen. */
object OrgOverviewTestTags {
    const val SCREEN = "org_overview_screen"
    const val NAME = "org_overview_name"
    const val MEMBERS_NAV = "org_overview_members_nav"
    const val INVITES_NAV = "org_overview_invites_nav"
}

/**
 * AND-354 - route-level org OVERVIEW entry (the org hub reached from the More-hub "Organizations" entry).
 * Surfaces the active org's name/role/member-count and routes onward to the AND-353 Members screen and the
 * new My-Invites screen.
 */
@Composable
fun OrgOverviewRoute(
    onBack: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    viewModel: OrgOverviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    OrgOverviewScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onOpenMembers = onOpenMembers,
        onOpenInvites = onOpenInvites,
    )
}

/** AND-354 - stateless org overview hub screen. */
@Composable
fun OrgOverviewScreen(
    state: OrgOverviewUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(OrgOverviewTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.org_overview_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.orgs_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is OrgOverviewUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is OrgOverviewUiState.Empty ->
                EmptyState(
                    title = stringResource(R.string.org_overview_empty_title),
                    body = stringResource(R.string.org_overview_empty_body),
                    modifier = Modifier.padding(padding),
                )

            is OrgOverviewUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is OrgOverviewUiState.Content ->
                OrgOverviewContent(
                    state = state,
                    onRetry = onRetry,
                    onOpenMembers = onOpenMembers,
                    onOpenInvites = onOpenInvites,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun OrgOverviewContent(
    state: OrgOverviewUiState.Content,
    onRetry: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // FR-9: a stale banner sits above cached content when a refresh failed.
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = state.org.name ?: state.org.orgId,
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.testTag(OrgOverviewTestTags.NAME),
            )
            Text(
                text = stringResource(R.string.org_overview_your_role, roleLabel(state.callerRole)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = if (state.memberCount != null) {
                    stringResource(R.string.org_overview_member_count, state.memberCount)
                } else {
                    stringResource(R.string.org_overview_member_count_unknown)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OrgNavRow(
                icon = Icons.Outlined.Group,
                label = stringResource(R.string.org_overview_members),
                onClick = onOpenMembers,
                modifier = Modifier.testTag(OrgOverviewTestTags.MEMBERS_NAV),
            )
            OrgNavRow(
                icon = Icons.Outlined.MarkEmailUnread,
                label = stringResource(R.string.org_overview_my_invites),
                onClick = onOpenInvites,
                modifier = Modifier.testTag(OrgOverviewTestTags.INVITES_NAV),
            )
        }
    }
}

/** A tappable nav row leading to a sub-screen (Members / My Invites). */
@Composable
private fun OrgNavRow(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(icon, contentDescription = null)
            Text(
                text = label,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
        }
    }
}
