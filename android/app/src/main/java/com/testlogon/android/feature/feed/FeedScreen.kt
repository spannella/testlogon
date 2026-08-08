package com.testlogon.android.feature.feed

import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.feature.ads.cta.AdCtaRouter
import com.testlogon.android.feature.ads.cta.CtaDestination
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import kotlinx.coroutines.launch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.blocking.BlockConfirmDialog
import com.testlogon.android.feature.blocking.BlockInteractionViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.feed.FeedPost

/** Stable test tags for the feed surface (AND-098). */
object FeedTestTags {
    const val SCREEN = "feed_screen"
    const val LIST = "feed_list"
    const val APPEND_FOOTER = "feed_append_footer"
    const val APPEND_RETRY = "feed_append_retry"
    const val EMPTY = "feed_empty"
    const val ERROR = "feed_error"
}

/**
 * AND-098 / AND-102 — feed tab route. Hosts the Paging 3 stream, pull-to-refresh, and the
 * loading/empty/error/append-footer scaffolding; rows are [PostItem] (AND-099). [onPostClick] opens
 * the post-detail destination. The unlock CTA is a deferred stub routed through the ViewModel.
 */
@Composable
fun FeedRoute(
    onPostClick: (postId: String) -> Unit,
    onComposePost: () -> Unit = {},
    onOpenDiscover: () -> Unit = {},
    onOpenMyPosts: () -> Unit = {},
    onOpenScheduledPosts: () -> Unit = {},
    onEditPost: (postId: String) -> Unit = {},
    modifier: Modifier = Modifier,
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onOpenStory: (userId: String) -> Unit = {},
    onCreateStory: () -> Unit = {},
    onCtaNavigate: (CtaDestination) -> Unit = {},
    viewModel: FeedViewModel = hiltViewModel(),
    paywallViewModel: PaywallViewModel = hiltViewModel(),
    tipViewModel: TipViewModel = hiltViewModel(),
    storiesTrayViewModel: com.testlogon.android.feature.stories.StoriesTrayViewModel = hiltViewModel(),
) {
    val items = viewModel.items.collectAsLazyPagingItems()
    val storyTray by storiesTrayViewModel.tray.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val shareLauncher = remember { ShareLauncher() }
    val savedIds by viewModel.savedIds.collectAsState()
    val currentUserSub by viewModel.currentUserSub.collectAsState()
    val pollStates by viewModel.pollUiStates.collectAsState()
    val authorNames by viewModel.authorNames.collectAsState()
    val authorPhotos by viewModel.authorPhotos.collectAsState()
    val unlockStates by paywallViewModel.states.collectAsState()
    val tipState by tipViewModel.state.collectAsState()

    val hiddenLabel = stringResource(R.string.feed_hidden_snackbar)
    val notInterestedLabel = stringResource(R.string.feed_not_interested_snackbar)
    val undoLabel = stringResource(R.string.feed_action_undo)
    val retryLabel = stringResource(R.string.comments_retry)
    val bookmarkRetryLabel = stringResource(R.string.feed_bookmark_retry)
    val shareNoTargetLabel = stringResource(R.string.feed_share_no_target)

    // Drain feed one-shot effects: like errors, hide Undo/Retry, bookmark Retry.
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is FeedEvent.UnlockRequested -> paywallViewModel.unlock(event.postId)
                is FeedEvent.ShowError ->
                    snackbarHostState.showSnackbar(event.message)
                is FeedEvent.Suppressed -> {
                    val msg = when (event.action) {
                        is FeedAction.Hide -> hiddenLabel
                        is FeedAction.NotInterested -> notInterestedLabel
                    }
                    val result = snackbarHostState.showSnackbar(
                        message = msg,
                        actionLabel = undoLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) viewModel.onUndo(event.action)
                }
                is FeedEvent.SuppressFailed -> {
                    val result = snackbarHostState.showSnackbar(
                        message = event.message,
                        actionLabel = retryLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) viewModel.onRetry(event.action)
                }
                is FeedEvent.BookmarkFailed -> {
                    val result = snackbarHostState.showSnackbar(
                        message = event.message,
                        actionLabel = bookmarkRetryLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) {
                        viewModel.onRetryBookmark(event.postId, event.desired)
                    }
                }
            }
        }
    }

    // Drain tip one-shot effects (host snackbar).
    LaunchedEffect(tipViewModel) {
        tipViewModel.effects.collect { effect ->
            when (effect) {
                is TipEffect.ShowSnackbar -> snackbarHostState.showSnackbar(effect.message)
                is TipEffect.ReactionBadge -> viewModel.applyTipReactionBadge(effect.postId, effect.badge)
                is TipEffect.TotalUpdated -> viewModel.applyTipTotal(effect.postId, effect.tipTotalCents)
            }
        }
    }

    // AND-177 — when a post becomes unlocked (entitlement confirmed + cached), re-fetch the feed so the
    // server returns the now-unlocked content. Content is NEVER revealed client-side before this (the
    // locked post was redacted at the mapper); the entitlement cache prevents a re-charge on refetch.
    val anyUnlocked = unlockStates.values.any { it is UnlockState.Unlocked }
    LaunchedEffect(anyUnlocked) {
        if (anyUnlocked) items.refresh()
    }

    // AND-199 — refresh the stories bar when the feed becomes active (web parity: poll/refresh on view).
    LaunchedEffect(storiesTrayViewModel) { storiesTrayViewModel.refresh() }

    // FD10 — refresh the feed whenever it resumes (e.g. on return from the composer) so a newly
    // published post shows up immediately without a manual pull-to-refresh.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        var first = true
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                if (first) { first = false } else { items.refresh() }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    FeedScreen(
        items = items,
        onComposePost = onComposePost,
        onOpenDiscover = onOpenDiscover,
        onOpenMyPosts = onOpenMyPosts,
        onOpenScheduledPosts = onOpenScheduledPosts,
        currentUserSub = currentUserSub,
        onEditPost = onEditPost,
        snackbarHostState = snackbarHostState,
        savedIds = savedIds,
        pollStates = pollStates,
        unlockStates = unlockStates,
        storyTray = storyTray,
        onOpenStory = onOpenStory,
        onCreateStory = onCreateStory,
        onRefresh = { items.refresh() },
        onPostClick = { post ->
            // ADV2-409 (F4): opening a creator-authored paid_partnership post fires the advertiser CLICK
            // charge (no-op for an organic post); the post itself opens normally.
            viewModel.onPaidPartnershipClick(post)
            onPostClick(post.id)
        },
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
        onUnlockClick = viewModel::onUnlockClick,
        onLikeToggle = viewModel::onLikeToggle,
        onToggleReaction = viewModel::onToggleReaction,
        onCommentClick = { post -> onPostClick(post.id) },
        // ADV2-409 (F4): impression on first-visible for a creator-authored paid_partnership post.
        onPaidPartnershipImpression = viewModel::onPaidPartnershipImpression,
        onHide = { post, index -> viewModel.onHide(post.id, index) },
        onNotInterested = { post, index -> viewModel.onNotInterested(post.id, index) },
        onToggleBookmark = { post -> viewModel.onToggleBookmark(post.id, post.id in savedIds) },
        onShare = { post ->
            val ok = shareLauncher.share(context, ShareContent(PostShare.urlFor(post.id), PostShare.subjectFor(post.authorId)))
            if (!ok) coroutineScope.launch { snackbarHostState.showSnackbar(shareNoTargetLabel) }
        },
        onTip = { post -> tipViewModel.open(post.id) },
        onTipReact = { post, emoji -> tipViewModel.openReaction(post.id, emoji) },
        // SOCIAL-002 — repost / quote-repost / undo-repost.
        onRepost = viewModel::onRepost,
        onQuoteRepost = viewModel::onQuoteRepost,
        onUndoRepost = viewModel::onUndoRepost,
        // ADV-106 — sponsored-unit tracking. Impression on first-visible; click also opens the ad's CTA url.
        onSponsoredImpression = viewModel::onSponsoredImpression,
        onSponsoredClick = { post ->
            viewModel.onSponsoredClick(post)
            post.sponsored?.ctaUrl?.let { onLinkClick(it) }
        },
        // ADV2-209 (F2): a structured CTA tap → CPC + CPA-stash (or tip = no charge), then route.
        onSubscribeClick = { creatorId ->
            if (creatorId.isNotBlank()) onCtaNavigate(CtaDestination.Subscriptions(creatorId))
        },
        onSponsoredCta = { post, action ->
            viewModel.onCtaTap(post, action)
            onCtaNavigate(AdCtaRouter.destinationFor(action, post.sponsored?.creatorId ?: ""))
        },
        onEnsurePoll = viewModel::ensurePollState,
        authorNames = authorNames,
        authorPhotos = authorPhotos,
        onEnsureAuthorName = viewModel::resolveAuthor,
        onPollOptionClick = viewModel::onPollOptionSelected,
        onPollRetry = viewModel::onPollRetry,
        onPollWriteIn = viewModel::onPollWriteIn,
        onPollShowMore = viewModel::onPollShowMore,
        modifier = modifier,
    )

    // AND-178 — the tip bottom sheet, host-scoped.
    TipSheet(
        state = tipState,
        onSelectPreset = tipViewModel::selectPreset,
        onCustomAmount = tipViewModel::setCustomAmount,
        onSend = tipViewModel::send,
        onDismiss = tipViewModel::dismiss,
        onVisibility = tipViewModel::setVisibility,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedScreen(
    items: LazyPagingItems<FeedPost>,
    onRefresh: () -> Unit,
    onComposePost: () -> Unit = {},
    onOpenDiscover: () -> Unit = {},
    onOpenMyPosts: () -> Unit = {},
    onOpenScheduledPosts: () -> Unit = {},
    currentUserSub: String? = null,
    onEditPost: (postId: String) -> Unit = {},
    onPostClick: (FeedPost) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    savedIds: Set<String> = emptySet(),
    pollStates: Map<String, PollCardState> = emptyMap(),
    unlockStates: Map<String, UnlockState> = emptyMap(),
    storyTray: com.testlogon.android.core.model.ApiResult<List<com.testlogon.android.data.stories.StoryBarItem>> =
        com.testlogon.android.core.model.ApiResult.Success(emptyList()),
    onOpenStory: (userId: String) -> Unit = {},
    onCreateStory: () -> Unit = {},
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onUnlockClick: (postId: String) -> Unit = {},
    onLikeToggle: (FeedPost) -> Unit = {},
    onToggleReaction: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    onCommentClick: (FeedPost) -> Unit = {},
    onHide: (post: FeedPost, index: Int) -> Unit = { _, _ -> },
    onNotInterested: (post: FeedPost, index: Int) -> Unit = { _, _ -> },
    onToggleBookmark: (FeedPost) -> Unit = {},
    onShare: (FeedPost) -> Unit = {},
    onTip: (FeedPost) -> Unit = {},
    onTipReact: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    // SOCIAL-002 — repost affordances.
    onRepost: (FeedPost) -> Unit = {},
    onQuoteRepost: (post: FeedPost, quote: String) -> Unit = { _, _ -> },
    onUndoRepost: (FeedPost) -> Unit = {},
    onSponsoredImpression: (FeedPost) -> Unit = {},
    onPaidPartnershipImpression: (FeedPost) -> Unit = {},
    onSponsoredClick: (FeedPost) -> Unit = {},
    onSponsoredCta: (FeedPost, CtaAction) -> Unit = { _, _ -> },
    // SUB-E3-2 - open the subscribe flow for a subscriber-only post lock card.
    onSubscribeClick: (creatorId: String) -> Unit = {},
    onEnsurePoll: (FeedPost) -> Unit = {},
    authorNames: Map<String, String> = emptyMap(),
    authorPhotos: Map<String, String> = emptyMap(),
    onEnsureAuthorName: (authorId: String) -> Unit = {},
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    onPollWriteIn: (postId: String, questionId: String, text: String) -> Unit = { _, _, _ -> },
    onPollShowMore: (postId: String, questionId: String, offset: Int) -> Unit = { _, _, _ -> },
) {
    val listState = rememberLazyListState()
    // MOD-C1 - main newsfeed post report target; the sheet is hosted once below.
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    // P0-BLOCK — block-author interaction for the feed overflow. One VM hydrated on demand with the
    // chosen author; the confirm dialog is hosted once below. On success the repository blocked-id
    // set updates and suppresses that author.
    val blockVm: BlockInteractionViewModel = hiltViewModel()
    val blockState by blockVm.uiState.collectAsStateWithLifecycle()
    Scaffold(
        modifier = modifier.testTag(FeedTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Feed") },
                actions = {
                    // PAR-13 — jump to the scheduled-posts management screen.
                    androidx.compose.material3.IconButton(
                        onClick = onOpenScheduledPosts,
                        modifier = Modifier.testTag("feed_scheduled_posts_action"),
                    ) {
                        Icon(
                            Icons.Outlined.Schedule,
                            contentDescription = stringResource(R.string.scheduled_posts_title),
                        )
                    }
                    androidx.compose.material3.IconButton(
                        onClick = onOpenMyPosts,
                        modifier = Modifier.testTag("feed_my_posts_action"),
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.ListAlt,
                            contentDescription = "Your posts",
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onComposePost, modifier = Modifier.testTag("feed_compose_fab")) {
                Icon(Icons.Filled.Edit, contentDescription = "New post")
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val refreshState = items.loadState.refresh
        val isRefreshing = refreshState is LoadState.Loading && items.itemCount > 0
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            androidx.compose.foundation.layout.Column(Modifier.fillMaxSize()) {
                // FD1 — always-visible inline composer entry: tapping anywhere opens the full composer,
                // so making a post is one tap from the top of the feed (not hidden behind the FAB only).
                InlineComposerBar(onClick = onComposePost)
                // AND-199 — stories tray above the feed (collapses to 0 height when empty).
                com.testlogon.android.feature.stories.StoriesTray(
                    state = storyTray,
                    onRingClick = onOpenStory,
                    onCreateClick = onCreateStory,
                )
                Box(Modifier.fillMaxSize()) {
                when {
                    refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                    refreshState is LoadState.Error && items.itemCount == 0 -> {
                        val message = (refreshState.error as? FeedLoadException)?.message
                            ?: "Couldn't load your feed."
                        ErrorState(
                            message = message,
                            onRetry = items::retry,
                            modifier = Modifier.testTag(FeedTestTags.ERROR),
                        )
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(
                            title = "Your feed is empty",
                            body = "New posts will show up here.",
                            actionLabel = stringResource(R.string.feed_empty_cta),
                            onAction = onOpenDiscover,
                            modifier = Modifier.testTag(FeedTestTags.EMPTY),
                        )

                    else -> FeedList(
                        items = items,
                        listState = listState,
                        onReport = { post -> reportTarget = ReportTarget.Content(post.id, "feed_post") },
                        onBlockAuthor = { authorId, authorName ->
                            blockVm.hydrate(authorId, authorName ?: authorId)
                            blockVm.onBlockRequested()
                        },
                        savedIds = savedIds,
                        currentUserSub = currentUserSub,
                        onEditPost = onEditPost,
                        pollStates = pollStates,
                        unlockStates = unlockStates,
                        onPostClick = onPostClick,
                        onAuthorClick = onAuthorClick,
                        onLinkClick = onLinkClick,
                        onUnlockClick = onUnlockClick,
                        onLikeToggle = onLikeToggle,
                        onToggleReaction = onToggleReaction,
                        onCommentClick = onCommentClick,
                        onHide = onHide,
                        onNotInterested = onNotInterested,
                        onToggleBookmark = onToggleBookmark,
                        onShare = onShare,
                        onTip = onTip,
                        onTipReact = onTipReact,
                        onRepost = onRepost,
                        onQuoteRepost = onQuoteRepost,
                        onUndoRepost = onUndoRepost,
                        onSponsoredImpression = onSponsoredImpression,
                        onPaidPartnershipImpression = onPaidPartnershipImpression,
                        onSponsoredClick = onSponsoredClick,
                        onSponsoredCta = onSponsoredCta,
                        onSubscribeClick = onSubscribeClick,
                        onEnsurePoll = onEnsurePoll,
                        authorNames = authorNames,
                        authorPhotos = authorPhotos,
                        onEnsureAuthorName = onEnsureAuthorName,
                        onPollOptionClick = onPollOptionClick,
                        onPollRetry = onPollRetry,
                        onPollWriteIn = onPollWriteIn,
                        onPollShowMore = onPollShowMore,
                    )
                }
                }
            }
        }
        // MOD-C1/C3 - one host renders the six-category report sheet + the licensing/IP -> DMCA route.
        ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
        if (blockState.confirmVisible) {
            BlockConfirmDialog(
                title = stringResource(R.string.block_confirm_title, blockState.targetHandle),
                body = stringResource(R.string.block_confirm_body),
                confirmLabel = stringResource(R.string.block_confirm_cta),
                dismissLabel = stringResource(R.string.block_confirm_cancel),
                onConfirm = blockVm::onBlockConfirmed,
                onDismiss = blockVm::onBlockDismissed,
            )
        }
    }
}

/**
 * FD1 — a prominent "What's on your mind?" entry pinned to the top of the feed. Always visible (even
 * when the feed has content), giving a one-tap path into the full compose screen.
 */
@Composable
private fun InlineComposerBar(onClick: () -> Unit) {
    Surface(
        tonalElevation = 1.dp,
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .clickable(onClick = onClick)
                .testTag("feed_inline_composer"),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(18.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Filled.Edit,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
            }
            Surface(
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = "What’s on your mind?",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                )
            }
        }
    }
}

@Composable
private fun FeedList(
    items: LazyPagingItems<FeedPost>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onReport: (FeedPost) -> Unit = {},
    onBlockAuthor: (authorId: String, authorName: String?) -> Unit = { _, _ -> },
    savedIds: Set<String>,
    currentUserSub: String? = null,
    onEditPost: (postId: String) -> Unit = {},
    pollStates: Map<String, PollCardState>,
    unlockStates: Map<String, UnlockState>,
    onPostClick: (FeedPost) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onLinkClick: (url: String) -> Unit,
    onUnlockClick: (postId: String) -> Unit,
    onLikeToggle: (FeedPost) -> Unit,
    onToggleReaction: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    onCommentClick: (FeedPost) -> Unit,
    onHide: (post: FeedPost, index: Int) -> Unit,
    onNotInterested: (post: FeedPost, index: Int) -> Unit,
    onToggleBookmark: (FeedPost) -> Unit,
    onShare: (FeedPost) -> Unit,
    onTip: (FeedPost) -> Unit,
    onTipReact: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    onRepost: (FeedPost) -> Unit = {},
    onQuoteRepost: (post: FeedPost, quote: String) -> Unit = { _, _ -> },
    onUndoRepost: (FeedPost) -> Unit = {},
    onSponsoredImpression: (FeedPost) -> Unit = {},
    onPaidPartnershipImpression: (FeedPost) -> Unit = {},
    onSponsoredClick: (FeedPost) -> Unit = {},
    onSponsoredCta: (FeedPost, CtaAction) -> Unit = { _, _ -> },
    onSubscribeClick: (creatorId: String) -> Unit = {},
    onEnsurePoll: (FeedPost) -> Unit,
    authorNames: Map<String, String>,
    authorPhotos: Map<String, String>,
    onEnsureAuthorName: (authorId: String) -> Unit,
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit,
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit,
    onPollWriteIn: (postId: String, questionId: String, text: String) -> Unit = { _, _, _ -> },
    onPollShowMore: (postId: String, questionId: String, offset: Int) -> Unit = { _, _, _ -> },
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(FeedTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                // Seed per-post poll state once the post is composed (idempotent).
                LaunchedEffect(item.id) { if (item.poll != null) onEnsurePoll(item) }
                // ADV2-409 (F4) — fire the advertiser IMPRESSION charge the first time a creator-authored
                // paid_partnership post is composed/visible (deduped in the VM; no-op for organic posts).
                LaunchedEffect(item.id) { if (item.paidPartnership) onPaidPartnershipImpression(item) }
                // Resolve the author's display name once the post is composed (idempotent + cached).
                LaunchedEffect(item.authorId) { onEnsureAuthorName(item.authorId) }
                PostItem(
                    post = item,
                    authorName = authorNames[item.authorId],
                    authorPhotoUrl = authorPhotos[item.authorId],
                    onPostClick = onPostClick,
                    onAuthorClick = onAuthorClick,
                    onMediaClick = { post, _ -> onPostClick(post) },
                    onLinkClick = onLinkClick,
                    onUnlockClick = onUnlockClick,
                    onSubscribeClick = onSubscribeClick,
                    onLikeToggle = onLikeToggle,
                    onToggleReaction = onToggleReaction,
                    onCommentClick = onCommentClick,
                    onHide = { post -> onHide(post, index) },
                    onNotInterested = { post -> onNotInterested(post, index) },
                    isBookmarked = item.id in savedIds,
                    onToggleBookmark = onToggleBookmark,
                    onShare = onShare,
                    onTip = onTip,
                    onTipReact = onTipReact,
                    onRepost = onRepost,
                    onQuoteRepost = onQuoteRepost,
                    onUndoRepost = onUndoRepost,
                    onSponsoredImpression = onSponsoredImpression,
                    onSponsoredClick = onSponsoredClick,
                    onSponsoredCta = onSponsoredCta,
                    showTip = !(currentUserSub != null && item.authorId == currentUserSub),
                    // #3 — show the priced "Locked · $X" badge on the viewer's own locked posts.
                    isOwnPost = currentUserSub != null && item.authorId == currentUserSub,
                    onEdit = if (currentUserSub != null && item.authorId == currentUserSub) {
                        { post -> onEditPost(post.id) }
                    } else null,
                    onReport = { post -> onReport(post) },
                    onBlockAuthor = { authorId, authorName -> onBlockAuthor(authorId, authorName) },
                    unlockState = unlockStates[item.id] ?: UnlockState.Idle,
                    pollState = pollStates[item.id],
                    onPollOptionClick = onPollOptionClick,
                    onPollRetry = onPollRetry,
                    onPollWriteIn = onPollWriteIn,
                    onPollShowMore = onPollShowMore,
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(FeedTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more posts" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                androidx.compose.foundation.layout.Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(FeedTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Couldn't load more.", style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(FeedTestTags.APPEND_RETRY),
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }
    }
}
