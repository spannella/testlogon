@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)

package com.testlogon.android.feature.fanclub

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.Tag
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.fanclub.FanClubChannelItem
import com.testlogon.android.data.fanclub.FanClubTierSection

/** AND-238 — stable testTags for the fan-club channels screen. */
object FanClubChannelsTestTags {
    const val SCREEN = "fanclub_channels_screen"
    const val LIST = "fanclub_channels_list"
    const val EMPTY = "fanclub_channels_empty"
    const val ERROR = "fanclub_channels_error"
    const val ROW = "fanclub_channel_row"
    const val LOCK = "fanclub_channel_lock"
    fun header(level: Int) = "fanclub_tier_header_$level"
}

/**
 * AND-238 — route-level fan-club channels entry. Collects [ChannelsViewModel.events] for one-shot
 * navigation / upgrade / members effects and renders [uiState] as a pure function.
 *
 * INTEGRATION SEAM: [onChannelClick] is the AND-239 integration point (an accessible channel row),
 * [onUpgrade] routes to the AND-236 subscribe browse, [onMembers] opens the AND-240 roster.
 */
@Composable
fun FanClubChannelsRoute(
    onChannelClick: (channelId: String, channelName: String) -> Unit,
    onUpgrade: (tierId: String?) -> Unit,
    onMembers: (tierId: String, tierName: String?) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ChannelsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ChannelsEvent.NavigateToMessages -> onChannelClick(event.channelId, event.channelName)
                is ChannelsEvent.ShowUpgrade -> onUpgrade(event.tierId)
                is ChannelsEvent.NavigateToMembers -> onMembers(event.tierId, event.tierName)
                is ChannelsEvent.ShowMessage -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    FanClubChannelsScreen(
        state = state,
        title = viewModel.creatorDisplayName,
        snackbarHostState = snackbarHostState,
        onChannelClick = viewModel::onChannelClick,
        onMembersClick = viewModel::onMembersClick,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun FanClubChannelsScreen(
    state: ChannelsUiState,
    title: String?,
    snackbarHostState: SnackbarHostState,
    onChannelClick: (FanClubChannelItem) -> Unit,
    onMembersClick: (FanClubTierSection) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(FanClubChannelsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(title?.takeIf { it.isNotBlank() } ?: stringResource(R.string.fanclub_channels_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("fanclub_channels_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ChannelsUiState.Loading ->
                    LoadingState(message = stringResource(R.string.fanclub_channels_loading))

                is ChannelsUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.fanclub_channels_empty),
                        modifier = Modifier.testTag(FanClubChannelsTestTags.EMPTY),
                    )

                is ChannelsUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(FanClubChannelsTestTags.ERROR),
                    )

                is ChannelsUiState.Content ->
                    ChannelsContent(
                        state = state,
                        onChannelClick = onChannelClick,
                        onMembersClick = onMembersClick,
                        onRefresh = onRefresh,
                    )
            }
        }
    }
}

@Composable
private fun ChannelsContent(
    state: ChannelsUiState.Content,
    onChannelClick: (FanClubChannelItem) -> Unit,
    onMembersClick: (FanClubTierSection) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = state.isRefreshing, onRetry = onRefresh)
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize().testTag(FanClubChannelsTestTags.LIST),
            ) {
                state.sections.forEach { section ->
                    stickyHeader(key = "header_${section.key}") {
                        TierSectionHeader(section = section, onMembersClick = { onMembersClick(section) })
                    }
                    items(section.channels, key = { it.channel.id }) { item ->
                        ChannelRow(item = item, onClick = { onChannelClick(item) })
                    }
                }
            }
        }
    }
}

@Composable
private fun TierSectionHeader(
    section: FanClubTierSection,
    onMembersClick: () -> Unit,
) {
    val tierName = section.tier?.name ?: stringResource(R.string.fanclub_tier_free)
    val locked = !section.isUnlocked
    val headerCd = if (locked) {
        stringResource(R.string.fanclub_tier_header_locked_cd, tierName)
    } else {
        tierName
    }
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(FanClubChannelsTestTags.header(section.level)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            section.tier?.badgeEmoji?.takeIf { it.isNotBlank() }?.let { emoji ->
                Text(text = emoji, modifier = Modifier.padding(end = 8.dp))
            }
            Text(
                text = tierName,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f).semantics { contentDescription = headerCd },
            )
            if (locked) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = stringResource(R.string.fanclub_channel_locked),
                    modifier = Modifier.size(18.dp).padding(end = 4.dp),
                )
            }
            if (section.tier != null) {
                TextButton(onClick = onMembersClick) {
                    Icon(
                        Icons.Outlined.Group,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp).padding(end = 4.dp),
                    )
                    Text(stringResource(R.string.fanclub_tier_members_action))
                }
            }
        }
    }
}

@Composable
private fun ChannelRow(
    item: FanClubChannelItem,
    onClick: () -> Unit,
) {
    val channel = item.channel
    val locked = !item.isAccessible
    val rowCd = if (locked) {
        stringResource(R.string.fanclub_channel_row_locked_cd, channel.name)
    } else {
        channel.name
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(FanClubChannelsTestTags.ROW)
            .clearAndSetSemantics { contentDescription = rowCd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            Icons.Outlined.Tag,
            contentDescription = null,
            modifier = Modifier.size(20.dp).padding(end = 12.dp),
        )
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = channel.name,
                style = MaterialTheme.typography.bodyLarge,
                color = if (locked) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
            )
            val secondary = channel.lastMessagePreview ?: channel.description
            if (!secondary.isNullOrBlank()) {
                Text(
                    text = secondary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (locked) {
            Icon(
                Icons.Filled.Lock,
                contentDescription = stringResource(R.string.fanclub_channel_locked),
                modifier = Modifier.size(18.dp).testTag(FanClubChannelsTestTags.LOCK),
            )
        }
    }
}
