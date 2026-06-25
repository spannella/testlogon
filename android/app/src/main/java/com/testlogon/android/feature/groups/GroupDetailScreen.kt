@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import kotlinx.coroutines.flow.collectLatest

/** AND-355 - stable testTags for the social-group detail screen. */
object GroupDetailTestTags {
    const val SCREEN = "group_detail_screen"
    const val LEAVE = "group_leave"
    const val FEED = "group_detail_feed"
    const val MEMBERS = "group_detail_members"
    const val TREASURY = "group_detail_treasury"
    const val FUNDRAISING = "group_detail_fundraising"
    const val ADS = "group_detail_ads"
    const val SETTINGS = "group_detail_settings"
}

/** AND-355 - route-level group detail entry. Observes the one-shot LeftGroup effect to pop back. */
@Composable
fun GroupDetailRoute(
    onBack: () -> Unit,
    onLeft: (String) -> Unit,
    onOpenFeed: (String) -> Unit,
    onOpenMembers: (String) -> Unit,
    onOpenTreasury: (String) -> Unit,
    onOpenFundraising: (String) -> Unit,
    onOpenAds: (String) -> Unit,
    onOpenSettings: (String) -> Unit,
    viewModel: GroupDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.effects.collectLatest { effect ->
            when (effect) {
                is GroupDetailEffect.LeftGroup -> onLeft(effect.groupId)
            }
        }
    }
    GroupDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onLeave = viewModel::leave,
        onOpenFeed = { onOpenFeed(viewModel.groupId) },
        onOpenMembers = { onOpenMembers(viewModel.groupId) },
        onOpenTreasury = { onOpenTreasury(viewModel.groupId) },
        onOpenFundraising = { onOpenFundraising(viewModel.groupId) },
        onOpenAds = { onOpenAds(viewModel.groupId) },
        onOpenSettings = { onOpenSettings(viewModel.groupId) },
    )
}

/** AND-355 - stateless social-group detail screen. */
@Composable
fun GroupDetailScreen(
    state: GroupDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onLeave: () -> Unit,
    onOpenFeed: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenTreasury: () -> Unit,
    onOpenFundraising: () -> Unit,
    onOpenAds: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GroupDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.groups_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is GroupDetailUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupDetailUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupDetailUiState.Content ->
                GroupDetailContent(
                    state = state,
                    onLeave = onLeave,
                    onOpenFeed = onOpenFeed,
                    onOpenMembers = onOpenMembers,
                    onOpenTreasury = onOpenTreasury,
                    onOpenFundraising = onOpenFundraising,
                    onOpenAds = onOpenAds,
                    onOpenSettings = onOpenSettings,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun GroupDetailContent(
    state: GroupDetailUiState.Content,
    onLeave: () -> Unit,
    onOpenFeed: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenTreasury: () -> Unit,
    onOpenFundraising: () -> Unit,
    onOpenAds: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val group = state.group
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Cover(group)
        Text(text = group.name, style = MaterialTheme.typography.headlineSmall)
        if (!group.description.isNullOrBlank()) {
            Text(
                text = group.description!!,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = stringResource(R.string.groups_your_role, roleLabel(group.myRole)),
            style = MaterialTheme.typography.labelLarge,
        )
        val count = group.memberCount
        if (count != null) {
            Text(
                text = stringResource(R.string.groups_member_count, count),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Button(
            onClick = onOpenFeed,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.FEED),
        ) {
            Text(text = stringResource(R.string.group_feed_open))
        }
        OutlinedButton(
            onClick = onOpenMembers,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.MEMBERS),
        ) {
            Icon(Icons.Outlined.Group, contentDescription = null)
            Text(
                text = stringResource(R.string.groups_view_members),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        OutlinedButton(
            onClick = onOpenTreasury,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.TREASURY),
        ) {
            Text(text = stringResource(R.string.group_treasury_open))
        }
        OutlinedButton(
            onClick = onOpenFundraising,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.FUNDRAISING),
        ) {
            Text(text = stringResource(R.string.group_fundraising_open))
        }
        OutlinedButton(
            onClick = onOpenAds,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.ADS),
        ) {
            Text(text = stringResource(R.string.group_ads_open))
        }
        OutlinedButton(
            onClick = onOpenSettings,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GroupDetailTestTags.SETTINGS),
        ) {
            Text(text = stringResource(R.string.group_settings_open))
        }
        if (state.canLeave) {
            Button(
                onClick = onLeave,
                enabled = !state.isLeaving,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(GroupDetailTestTags.LEAVE),
            ) {
                if (state.isLeaving) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    Text(text = stringResource(R.string.groups_leave))
                }
            }
        }
    }
}

@Composable
private fun Cover(group: Group) {
    val url = group.coverImageUrl ?: return
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(2.5f)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        SubcomposeAsyncImage(
            model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
            contentDescription = group.name,
            loading = { Box(Modifier.fillMaxSize()) },
            modifier = Modifier.fillMaxSize(),
        )
    }
}
