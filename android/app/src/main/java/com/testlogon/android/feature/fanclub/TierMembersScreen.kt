@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.fanclub

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.fanclub.FanClubMember

/** AND-240 — stable testTags for the tier members screen. */
object TierMembersTestTags {
    const val SCREEN = "fanclub_members_screen"
    const val LIST = "fanclub_members_list"
    const val EMPTY = "fanclub_members_empty"
    const val ERROR = "fanclub_members_error"
    const val ROW = "fanclub_member_row"
    const val APPEND_FOOTER = "fanclub_members_append_footer"
    const val APPEND_RETRY = "fanclub_members_append_retry"
}

/** AND-240 — route-level tier members entry, reached from the AND-238 channels overview. */
@Composable
fun TierMembersRoute(
    onMemberClick: (memberId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TierMembersViewModel = hiltViewModel(),
) {
    val members = viewModel.members.collectAsLazyPagingItems()
    val header by viewModel.header.collectAsStateWithLifecycle()
    TierMembersScreen(
        members = members,
        header = header,
        onMemberClick = onMemberClick,
        onRefresh = { viewModel.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun TierMembersScreen(
    members: LazyPagingItems<FanClubMember>,
    header: TierMembersHeaderState,
    onMemberClick: (String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TierMembersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(header.tierName ?: stringResource(R.string.fanclub_members_title))
                        header.totalCount?.let { count ->
                            Text(
                                text = pluralStringResource(R.plurals.fanclub_member_count, count, count),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("fanclub_members_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val refreshState = members.loadState.refresh
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && members.itemCount == 0 ->
                    LoadingState(message = stringResource(R.string.fanclub_members_loading))

                refreshState is LoadState.Error && members.itemCount == 0 -> {
                    val message = (refreshState.error as? TierMembersLoadException)?.message
                        ?: stringResource(R.string.fanclub_members_error_generic)
                    ErrorState(
                        message = message,
                        onRetry = members::retry,
                        modifier = Modifier.testTag(TierMembersTestTags.ERROR),
                    )
                }

                refreshState is LoadState.NotLoading && members.itemCount == 0 ->
                    EmptyState(
                        title = stringResource(R.string.fanclub_members_empty),
                        modifier = Modifier.testTag(TierMembersTestTags.EMPTY),
                    )

                else -> MembersList(members = members, onRefresh = onRefresh, onMemberClick = onMemberClick)
            }
        }
    }
}

@Composable
private fun MembersList(
    members: LazyPagingItems<FanClubMember>,
    onRefresh: () -> Unit,
    onMemberClick: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = members.loadState.refresh is LoadState.Loading && members.itemCount > 0,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize().testTag(TierMembersTestTags.LIST)) {
            items(count = members.itemCount, key = { index -> members.peek(index)?.userId ?: index }) { index ->
                val member = members[index]
                if (member != null) {
                    TierMemberRow(member = member, onClick = { onMemberClick(member.userId) })
                }
            }

            when (members.loadState.append) {
                is LoadState.Loading -> item {
                    Box(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(TierMembersTestTags.APPEND_FOOTER),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
                is LoadState.Error -> item {
                    Row(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(TierMembersTestTags.APPEND_FOOTER),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(R.string.fanclub_members_append_error),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        TextButton(
                            onClick = members::retry,
                            modifier = Modifier.testTag(TierMembersTestTags.APPEND_RETRY),
                        ) { Text(stringResource(R.string.action_retry)) }
                    }
                }
                else -> Unit
            }
        }
    }
}

@Composable
private fun TierMemberRow(member: FanClubMember, onClick: () -> Unit) {
    val cd = buildString {
        append(member.displayName)
        member.handle?.let { append(", "); append(it) }
        member.tierLabel?.let { append(", "); append(it) }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(TierMembersTestTags.ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (member.avatarUrl != null) {
            AsyncImage(
                model = member.avatarUrl,
                contentDescription = null,
                modifier = Modifier.size(40.dp).padding(end = 12.dp),
            )
        } else {
            Icon(
                Icons.Outlined.Person,
                contentDescription = null,
                modifier = Modifier.size(40.dp).padding(end = 12.dp),
            )
        }
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = member.displayName,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val secondary = member.handle ?: member.tierLabel
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
    }
}
