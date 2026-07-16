@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.ui

import android.text.format.DateUtils
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.People
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.ui.layout.ContentScale
import coil.compose.AsyncImage
import com.testlogon.android.core.model.syndicates.SyndicateMember
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.Policy
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-356 - stable testTags for the syndicate overview screen + its tabs. */
object SyndicateOverviewTestTags {
    const val SCREEN = "syndicate_overview_screen"
    const val TAB_FEED = "syndicate_tab_feed"
    const val TAB_TREASURY = "syndicate_tab_treasury"
    const val TAB_SPLIT = "syndicate_tab_split"
    const val TAB_MEMBERS = "syndicate_tab_members"
    const val COMPOSE_INPUT = "syndicate_compose_input"
    const val COMPOSE_SEND = "syndicate_compose_send"
    const val COMPOSE_ATTACH = "syndicate_compose_attach"
    const val HEADER_NAME = "syndicate_header_name"
    const val ROLE_BADGE = "syndicate_role_badge"
    const val SPLIT_MISMATCH = "syndicate_split_mismatch"
    const val NOT_MEMBER = "syndicate_not_member"
    const val STALE = "syndicate_stale"
    const val OPEN_LICENSING_ACTION = "syndicate_open_licensing_action"
    const val MANAGE_ADS_ACTION = "syndicate_manage_ads_action"

    fun feedItem(postId: String) = "syndicate_feed_item_$postId"
    fun ledgerItem(index: Int) = "syndicate_ledger_item_$index"
    fun splitRow(userId: String) = "syndicate_split_row_$userId"
}

/** The three overview tabs (read-only). */
private enum class OverviewTab { FEED, TREASURY, SPLIT, MEMBERS }

/** AND-356 - route-level overview entry; collects the paged feed + ledger and the header state. */
/** Provides the arbitrary-poll vote client + current user id down to the feed poll cards. */
val LocalSyndicatePollVoter = androidx.compose.runtime.compositionLocalOf<com.testlogon.android.data.poll.PollVoter?> { null }
val LocalSyndicateCurrentUserId = androidx.compose.runtime.compositionLocalOf<String?> { null }

/**
 * ADV syndicate-feed ads — impression / click callbacks for a sponsored feed unit, provided down to the
 * (otherwise deeply-nested, stateless) [FeedItemRow]. Mirrors the poll-voter CompositionLocal pattern so
 * the many intermediate feed composables need not thread two extra parameters.
 */
val LocalSyndicateSponsoredImpression = androidx.compose.runtime.compositionLocalOf<(SyndicateFeedItem) -> Unit> { {} }
val LocalSyndicateSponsoredClick = androidx.compose.runtime.compositionLocalOf<(SyndicateFeedItem) -> Unit> { {} }
// MOD-C1 - report a syndicate feed post (reported as feed_post by its post id).
val LocalSyndicateReport = androidx.compose.runtime.compositionLocalOf<(SyndicateFeedItem) -> Unit> { {} }

@Composable
fun SyndicateOverviewRoute(
    onBack: () -> Unit,
    onOpenLicensing: () -> Unit,
    onManageAds: () -> Unit = {},
    viewModel: SyndicateOverviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val feed = viewModel.feed.collectAsLazyPagingItems()
    val ledger = viewModel.ledger.collectAsLazyPagingItems()
    val compose by viewModel.compose.collectAsStateWithLifecycle()
    val members by viewModel.members.collectAsStateWithLifecycle()
    val currentUserId by viewModel.currentUserId.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.feedRefresh.collect { feed.refresh() }
    }
    // MOD-C1 - syndicate post report target; the sheet is hosted once in this route.
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    androidx.compose.runtime.CompositionLocalProvider(
        LocalSyndicatePollVoter provides viewModel.pollVoter,
        LocalSyndicateCurrentUserId provides currentUserId,
        LocalSyndicateSponsoredImpression provides viewModel::onSponsoredImpression,
        LocalSyndicateSponsoredClick provides viewModel::onSponsoredClick,
        LocalSyndicateReport provides { post -> reportTarget = ReportTarget.Content(post.postId, "syndicate_post", syndicateId = viewModel.syndicateId) },
    ) {
    SyndicateOverviewScreen(
        state = state,
        feed = feed,
        ledger = ledger,
        compose = compose,
        members = members,
        onBack = onBack,
        onOpenLicensing = onOpenLicensing,
        onManageAds = onManageAds,
        onRetry = viewModel::onRetry,
        onRefresh = {
            viewModel.refresh()
            feed.refresh()
            ledger.refresh()
        },
        onComposeTextChange = viewModel::onComposeTextChange,
        onAttachImage = viewModel::attachImage,
        onClearImage = viewModel::clearImage,
        onSubmitPost = viewModel::submitPost,
        onLoadMembers = { viewModel.loadMembers() },
        onRetryMembers = { viewModel.loadMembers(force = true) },
        onPollEnabledChange = viewModel::onPollEnabledChange,
        onPollDraftChange = viewModel::onPollDraftChange,
    )
    // MOD-C1/C3 - syndicate post report sheet host (six categories + licensing/IP -> DMCA).
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
    }
}

/** AND-356 - stateless 3-tab READ-ONLY syndicate overview screen. */
@Composable
fun SyndicateOverviewScreen(
    state: SyndicateOverviewUiState,
    feed: LazyPagingItems<SyndicateFeedItem>,
    ledger: LazyPagingItems<TreasuryEntry>,
    compose: SyndicateComposeState = SyndicateComposeState(),
    members: SyndicateMembersState = SyndicateMembersState(),
    onBack: () -> Unit,
    onOpenLicensing: () -> Unit,
    onManageAds: () -> Unit = {},
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onComposeTextChange: (String) -> Unit = {},
    onAttachImage: (android.net.Uri) -> Unit = {},
    onClearImage: () -> Unit = {},
    onSubmitPost: () -> Unit = {},
    onLoadMembers: () -> Unit = {},
    onRetryMembers: () -> Unit = {},
    onPollEnabledChange: (Boolean) -> Unit = {},
    onPollDraftChange: (com.testlogon.android.feature.common.poll.PollDraft) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SyndicateOverviewTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.syndicate_overview_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.syndicate_back),
                        )
                    }
                },
                actions = {
                    // ADV2-709 (F7) - admin-only entry to SYNDICATE-ADS management.
                    if ((state as? SyndicateOverviewUiState.Content)?.overview?.isAdmin == true) {
                        IconButton(
                            onClick = onManageAds,
                            modifier = Modifier.testTag(SyndicateOverviewTestTags.MANAGE_ADS_ACTION),
                        ) {
                            Icon(
                                Icons.Outlined.Campaign,
                                contentDescription = stringResource(R.string.syndicate_ads_title),
                            )
                        }
                    }
                    // AND-357 - entry point to the open-licensing sub-screen.
                    IconButton(
                        onClick = onOpenLicensing,
                        modifier = Modifier.testTag(SyndicateOverviewTestTags.OPEN_LICENSING_ACTION),
                    ) {
                        Icon(
                            Icons.Outlined.Policy,
                            contentDescription = stringResource(R.string.syndicate_open_licensing_action),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is SyndicateOverviewUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is SyndicateOverviewUiState.NotMember ->
                EmptyState(
                    title = stringResource(R.string.syndicate_not_member_title),
                    body = stringResource(R.string.syndicate_not_member_body),
                    imageVector = Icons.Outlined.Groups,
                    modifier = Modifier
                        .padding(padding)
                        .testTag(SyndicateOverviewTestTags.NOT_MEMBER),
                )

            is SyndicateOverviewUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is SyndicateOverviewUiState.Content ->
                ContentBody(
                    state = state,
                    feed = feed,
                    ledger = ledger,
                    compose = compose,
                    members = members,
                    onRefresh = onRefresh,
                    onComposeTextChange = onComposeTextChange,
                    onAttachImage = onAttachImage,
                    onClearImage = onClearImage,
                    onSubmitPost = onSubmitPost,
                    onLoadMembers = onLoadMembers,
                    onRetryMembers = onRetryMembers,
                    onPollEnabledChange = onPollEnabledChange,
                    onPollDraftChange = onPollDraftChange,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun ContentBody(
    state: SyndicateOverviewUiState.Content,
    feed: LazyPagingItems<SyndicateFeedItem>,
    ledger: LazyPagingItems<TreasuryEntry>,
    compose: SyndicateComposeState,
    members: SyndicateMembersState,
    onRefresh: () -> Unit,
    onComposeTextChange: (String) -> Unit,
    onAttachImage: (android.net.Uri) -> Unit,
    onClearImage: () -> Unit,
    onSubmitPost: () -> Unit,
    onLoadMembers: () -> Unit,
    onRetryMembers: () -> Unit,
    onPollEnabledChange: (Boolean) -> Unit = {},
    onPollDraftChange: (com.testlogon.android.feature.common.poll.PollDraft) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    var selected by rememberSaveable { mutableStateOf(OverviewTab.FEED.ordinal) }
    androidx.compose.runtime.LaunchedEffect(selected) {
        if (selected == OverviewTab.MEMBERS.ordinal) onLoadMembers()
    }
    Column(modifier = modifier.fillMaxSize()) {
        if (state.isStale) {
            StaleRow()
        }
        Header(state.overview)
        TabRow(selectedTabIndex = selected) {
            Tab(
                selected = selected == OverviewTab.FEED.ordinal,
                onClick = { selected = OverviewTab.FEED.ordinal },
                text = { Text(stringResource(R.string.syndicate_tab_feed)) },
                modifier = Modifier.testTag(SyndicateOverviewTestTags.TAB_FEED),
            )
            Tab(
                selected = selected == OverviewTab.TREASURY.ordinal,
                onClick = { selected = OverviewTab.TREASURY.ordinal },
                text = { Text(stringResource(R.string.syndicate_tab_treasury)) },
                modifier = Modifier.testTag(SyndicateOverviewTestTags.TAB_TREASURY),
            )
            Tab(
                selected = selected == OverviewTab.SPLIT.ordinal,
                onClick = { selected = OverviewTab.SPLIT.ordinal },
                text = { Text(stringResource(R.string.syndicate_tab_split)) },
                modifier = Modifier.testTag(SyndicateOverviewTestTags.TAB_SPLIT),
            )
            Tab(
                selected = selected == OverviewTab.MEMBERS.ordinal,
                onClick = { selected = OverviewTab.MEMBERS.ordinal },
                text = { Text(stringResource(R.string.syndicate_tab_members)) },
                modifier = Modifier.testTag(SyndicateOverviewTestTags.TAB_MEMBERS),
            )
        }
        Box(modifier = Modifier.weight(1f)) {
            when (selected) {
                OverviewTab.FEED.ordinal -> Column(modifier = Modifier.fillMaxSize()) {
                    if (state.overview.isMember) {
                        SyndicateComposeBox(
                            state = compose,
                            onTextChange = onComposeTextChange,
                            onAttachImage = onAttachImage,
                            onClearImage = onClearImage,
                            onSubmit = onSubmitPost,
                            onPollEnabledChange = onPollEnabledChange,
                            onPollDraftChange = onPollDraftChange,
                        )
                        HorizontalDivider()
                    }
                    Box(modifier = Modifier.weight(1f)) { FeedTab(feed = feed, onRefresh = onRefresh) }
                }
                OverviewTab.TREASURY.ordinal -> TreasuryTab(state.treasury, ledger)
                OverviewTab.SPLIT.ordinal -> RevenueSplitTab(state.split)
                else -> MembersTab(members, onRetryMembers)
            }
        }
    }
}

@Composable
private fun StaleRow() {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateOverviewTestTags.STALE),
    ) {
        Text(
            text = stringResource(R.string.syndicate_stale_banner),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun Header(overview: SyndicateOverview) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = overview.name,
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.testTag(SyndicateOverviewTestTags.HEADER_NAME),
            )
            val badge = if (overview.isAdmin) {
                stringResource(R.string.syndicate_role_admin)
            } else {
                stringResource(R.string.syndicate_role_member)
            }
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text(badge) },
                colors = AssistChipDefaults.assistChipColors(),
                modifier = Modifier.testTag(SyndicateOverviewTestTags.ROLE_BADGE),
            )
        }
        val count = overview.memberCount
        if (count != null) {
            Text(
                text = stringResource(R.string.syndicate_member_count, count),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---- Feed tab ----

@Composable
private fun FeedTab(
    feed: LazyPagingItems<SyndicateFeedItem>,
    onRefresh: () -> Unit,
) {
    val refresh = feed.loadState.refresh
    when {
        refresh is LoadState.Loading && feed.itemCount == 0 ->
            LoadingState()

        refresh is LoadState.Error && feed.itemCount == 0 ->
            ErrorState(
                message = stringResource(R.string.syndicate_feed_error),
                onRetry = onRefresh,
            )

        feed.itemCount == 0 ->
            EmptyState(
                title = stringResource(R.string.syndicate_feed_empty_title),
                body = stringResource(R.string.syndicate_feed_empty_body),
            )

        else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(
                count = feed.itemCount,
                key = { index -> feed[index]?.postId ?: "feed_$index" },
            ) { index ->
                val post = feed[index] ?: return@items
                FeedItemRow(post)
            }
        }
    }
}

@Composable
private fun FeedItemRow(post: SyndicateFeedItem) {
    // ADV syndicate-feed ads — a server-injected sponsored (paid) unit renders as the shared, NON-tippable
    // Sponsored card (the syndicate feed has no tip affordance either, so FEATURE 2 holds by construction).
    val ad = post.sponsored
    if (ad != null) {
        val onImpression = LocalSyndicateSponsoredImpression.current
        val onClick = LocalSyndicateSponsoredClick.current
        com.testlogon.android.feature.feed.SponsoredFeedCard(
            label = ad.label,
            headline = ad.headline,
            body = ad.body,
            ctaText = ad.ctaText,
            impressionKey = ad.impressionKey,
            modifier = Modifier.testTag(SyndicateOverviewTestTags.feedItem(post.postId)),
            onImpression = { onImpression(post) },
            onClick = { onClick(post) },
            media = {
                ad.imageUrls.firstOrNull()?.let { url -> PostImage(url) }
            },
        )
        return
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateOverviewTestTags.feedItem(post.postId))
            .padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(url = post.authorAvatarUrl, name = post.authorName)
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = post.authorName ?: stringResource(R.string.syndicate_author_unknown),
                    style = MaterialTheme.typography.titleSmall,
                )
                val relative = relativeTime(post.createdAt)
                if (relative.isNotBlank()) {
                    Text(
                        text = relative,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                androidx.compose.foundation.layout.Spacer(Modifier.weight(1f))
                // MOD-C1 - report this syndicate post.
                val onReport = LocalSyndicateReport.current
                IconButton(
                    onClick = { onReport(post) },
                    modifier = Modifier.size(36.dp).testTag("syndicate_post_report_" + post.postId),
                ) {
                    Icon(
                        Icons.Outlined.Flag,
                        contentDescription = stringResource(R.string.msg_action_report),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
            if (!post.text.isNullOrBlank()) {
                Text(text = post.text!!, style = MaterialTheme.typography.bodyMedium)
            }
            val poll = post.poll
            val voter = LocalSyndicatePollVoter.current
            if (poll != null && voter != null) {
                val me = LocalSyndicateCurrentUserId.current
                com.testlogon.android.feature.common.poll.ArbitraryPollCard(
                    initial = poll,
                    isOwner = me != null && me == poll.owner,
                    voter = voter,
                )
            }
            PostImage(post.imageUrl)
        }
    }
}

@Composable
private fun PostImage(url: String?) {
    if (url.isNullOrBlank()) return
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        SubcomposeAsyncImage(
            model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
            contentDescription = stringResource(R.string.syndicate_post_image_cd),
            loading = { Box(Modifier.fillMaxWidth().size(160.dp)) },
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun Avatar(url: String?, name: String?) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        if (!url.isNullOrBlank()) {
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
                contentDescription = name ?: stringResource(R.string.syndicate_author_unknown),
                loading = { Box(Modifier.fillMaxSize()) },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Icon(Icons.Outlined.Groups, contentDescription = null, modifier = Modifier.size(20.dp))
        }
    }
}

// ---- Treasury tab ----

@Composable
private fun TreasuryTab(
    summary: TabState<TreasurySummary>,
    ledger: LazyPagingItems<TreasuryEntry>,
) {
    when (summary) {
        is TabState.Loading -> LoadingState()
        is TabState.Error ->
            ErrorState(message = summary.error.message, onRetry = { ledger.refresh() })
        is TabState.Content -> {
            val s = summary.data
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                item(key = "treasury_summary") {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        MoneyLine(
                            label = stringResource(R.string.syndicate_treasury_balance),
                            value = formatCents(s.balanceCents, s.currency),
                            emphasize = true,
                        )
                        MoneyLine(
                            label = stringResource(R.string.syndicate_treasury_deposited),
                            value = formatCents(s.depositedCents, s.currency),
                        )
                        MoneyLine(
                            label = stringResource(R.string.syndicate_treasury_disbursed),
                            value = formatCents(s.disbursedCents, s.currency),
                        )
                        Text(
                            text = stringResource(R.string.syndicate_treasury_ledger_heading),
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                }
                if (ledger.itemCount == 0 && ledger.loadState.refresh !is LoadState.Loading) {
                    item(key = "ledger_empty") {
                        Text(
                            text = stringResource(R.string.syndicate_ledger_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        )
                    }
                }
                items(
                    count = ledger.itemCount,
                    key = { index -> ledger[index]?.entryId ?: "ledger_$index" },
                ) { index ->
                    val entry = ledger[index] ?: return@items
                    LedgerRow(entry = entry, index = index, currency = s.currency)
                }
            }
        }
    }
}

@Composable
private fun LedgerRow(entry: TreasuryEntry, index: Int, currency: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateOverviewTestTags.ledgerItem(index))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.padding(end = 12.dp)) {
            Text(
                text = entry.reason ?: stringResource(R.string.syndicate_ledger_no_reason),
                style = MaterialTheme.typography.bodyMedium,
            )
            val relative = relativeTime(entry.ts)
            if (relative.isNotBlank()) {
                Text(
                    text = relative,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val sign = if (entry.isCredit) "+" else "-"
        Text(
            text = sign + formatCents(entry.amountCents, currency),
            style = MaterialTheme.typography.titleSmall,
            color = if (entry.isCredit) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.error
            },
        )
    }
}

@Composable
private fun MoneyLine(label: String, value: String, emphasize: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = value,
            style = if (emphasize) {
                MaterialTheme.typography.titleMedium
            } else {
                MaterialTheme.typography.bodyMedium
            },
        )
    }
}

// ---- Revenue-split tab ----

@Composable
private fun RevenueSplitTab(split: TabState<RevenueSplitPolicy>) {
    when (split) {
        is TabState.Loading -> LoadingState()
        is TabState.Error -> ErrorState(message = split.error.message, onRetry = {})
        is TabState.Content -> {
            val policy = split.data
            LazyColumn(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                item(key = "split_header") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        MoneyLine(
                            label = stringResource(R.string.syndicate_split_mode),
                            value = splitModeLabel(policy.mode),
                        )
                        val feeBps = policy.platformFeeBps
                        if (feeBps != null) {
                            MoneyLine(
                                label = stringResource(R.string.syndicate_split_platform_fee),
                                value = stringResource(R.string.syndicate_bps_format, feeBps),
                            )
                        }
                        if (!policy.weightSumOk) {
                            Surface(
                                color = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag(SyndicateOverviewTestTags.SPLIT_MISMATCH),
                            ) {
                                Text(
                                    text = stringResource(
                                        R.string.syndicate_split_mismatch,
                                        policy.weightSumBps,
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(12.dp),
                                )
                            }
                        }
                        if (policy.weightsBps.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.syndicate_split_weights_heading),
                                style = MaterialTheme.typography.titleSmall,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                    }
                }
                val rows = policy.weightsBps.entries.toList()
                items(count = rows.size, key = { rows[it].key }) { i ->
                    val (userId, bps) = rows[i]
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(SyndicateOverviewTestTags.splitRow(userId))
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(text = userId, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            text = stringResource(R.string.syndicate_bps_format, bps),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                if (policy.mode == SplitMode.UNKNOWN) {
                    item(key = "split_unknown") {
                        Text(
                            text = stringResource(R.string.syndicate_split_unknown_note),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun splitModeLabel(mode: SplitMode): String = stringResource(
    when (mode) {
        SplitMode.EQUAL -> R.string.syndicate_split_mode_equal
        SplitMode.WEIGHTED -> R.string.syndicate_split_mode_weighted
        SplitMode.PERFORMANCE -> R.string.syndicate_split_mode_performance
        SplitMode.UNKNOWN -> R.string.syndicate_split_mode_unknown
    },
)

/**
 * AND-356 - relative-time copy from an INTEGER epoch-SECONDS value. UI-only (android.text.format), returns
 * "" for unknown / epoch timestamps. Mirrors the AND-099 feed helper.
 */
private fun relativeTime(epochSeconds: Long, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}

// ---- Batch-9 (#12): feed composer (group parity) ----

@Composable
private fun SyndicateComposeBox(
    state: SyndicateComposeState,
    onTextChange: (String) -> Unit,
    onAttachImage: (android.net.Uri) -> Unit,
    onClearImage: () -> Unit,
    onSubmit: () -> Unit,
    onPollEnabledChange: (Boolean) -> Unit = {},
    onPollDraftChange: (com.testlogon.android.feature.common.poll.PollDraft) -> Unit = {},
) {
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) onAttachImage(uri) }

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = state.text,
            onValueChange = onTextChange,
            enabled = !state.sending,
            label = { Text(stringResource(R.string.syndicate_compose_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(SyndicateOverviewTestTags.COMPOSE_INPUT),
        )
        val img = state.imageUrl
        if (img != null) {
            Box {
                AsyncImage(
                    model = img,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(72.dp).clip(RoundedCornerShape(8.dp)),
                )
                IconButton(
                    onClick = onClearImage,
                    modifier = Modifier.align(Alignment.TopEnd).size(24.dp),
                ) {
                    Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.syndicate_compose_remove_image))
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Poll", style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
            androidx.compose.material3.Switch(
                checked = state.pollEnabled,
                onCheckedChange = onPollEnabledChange,
                modifier = Modifier.testTag("syndicate_poll_toggle"),
            )
        }
        if (state.pollEnabled) {
            com.testlogon.android.feature.common.poll.PollComposer(
                draft = state.pollDraft,
                onChange = onPollDraftChange,
                enabled = !state.sending,
            )
        }
        val err = state.error
        if (err != null) {
            Text(text = err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            IconButton(
                onClick = { imagePicker.launch("image/*") },
                enabled = !state.uploadingImage && !state.sending,
                modifier = Modifier.testTag(SyndicateOverviewTestTags.COMPOSE_ATTACH),
            ) {
                if (state.uploadingImage) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Outlined.Image, contentDescription = stringResource(R.string.syndicate_compose_attach_image))
                }
            }
            Box(modifier = Modifier.weight(1f))
            Button(
                onClick = onSubmit,
                enabled = (state.text.isNotBlank() || (state.pollEnabled && state.pollDraft.isValid)) && !state.sending,
                modifier = Modifier.testTag(SyndicateOverviewTestTags.COMPOSE_SEND),
            ) {
                if (state.sending) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.syndicate_compose_send))
                }
            }
        }
    }
}

// ---- Batch-9 (#12): members tab (group parity) ----

@Composable
private fun MembersTab(state: SyndicateMembersState, onRetry: () -> Unit) {
    when {
        state.loading && state.members.isEmpty() -> LoadingState()
        state.error != null && state.members.isEmpty() ->
            ErrorState(message = state.error, onRetry = onRetry)
        state.loaded && state.members.isEmpty() ->
            EmptyState(
                title = stringResource(R.string.syndicate_members_empty_title),
                body = stringResource(R.string.syndicate_members_empty_body),
                imageVector = Icons.Outlined.People,
            )
        else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(state.members, key = { it.userId }) { member ->
                MemberRow(member)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun MemberRow(member: SyndicateMember) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(text = member.displayName, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        AssistChip(onClick = {}, enabled = false, label = { Text(member.role.replaceFirstChar { it.uppercase() }) })
    }
}
