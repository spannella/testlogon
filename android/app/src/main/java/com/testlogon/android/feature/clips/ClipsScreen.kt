@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.clips

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.VerticalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
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
import com.testlogon.android.data.clips.Clip
import kotlinx.coroutines.flow.distinctUntilChanged

/** AND-196 — stable test tags for the clips vertical pager. */
object ClipsScreenTestTags {
    const val SCREEN = "clips_screen"
    const val PAGER = "clips_pager"
    const val PAGE_POSTER = "clips_page_poster"
}

/**
 * AND-196 — route-level clips vertical pager. Hoists [ClipsViewModel], collects the paged feed, and
 * renders the full-bleed [VerticalPager]. The settled page drives [ClipsViewModel.setActivePage] so the
 * playback controller (and telemetry) track the active clip. Each page renders the clip poster +
 * [ClipOverlay] chrome; per the verified contract a clip carries NO stream URL, so the feed renders
 * thumbnails (web parity) and full HLS autoplay is gated on a resolvable per-clip source (§16 A1).
 */
@Composable
fun ClipsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenProfile: (profileId: String) -> Unit = {},
    onClipAction: (Clip, ClipAction) -> Unit = { _, _ -> },
    viewModel: ClipsViewModel = hiltViewModel(),
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val clips = viewModel.clips.collectAsLazyPagingItems()

    ClipsScreen(
        clips = clips,
        muted = ui.muted,
        activePage = ui.activePage,
        onSettledPage = viewModel::setActivePage,
        onAction = { clip, action ->
            when (action) {
                ClipAction.MUTE -> viewModel.toggleMute()
                ClipAction.AUTHOR -> onOpenProfile(clip.profileId.ifBlank { clip.creatorUserId })
                else -> onClipAction(clip, action)
            }
        },
        onBack = onBack,
        onRefresh = viewModel::refresh,
        modifier = modifier,
    )
}

@Composable
fun ClipsScreen(
    clips: LazyPagingItems<Clip>,
    muted: Boolean,
    activePage: Int,
    onSettledPage: (Int) -> Unit,
    onAction: (Clip, ClipAction) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ClipsScreenTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.clips_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            val refresh = clips.loadState.refresh
            when {
                refresh is LoadState.Loading && clips.itemCount == 0 -> LoadingState()
                refresh is LoadState.Error && clips.itemCount == 0 -> ErrorState(
                    message = stringResource(R.string.clips_load_error),
                    onRetry = { clips.retry() },
                )
                clips.itemCount == 0 -> EmptyState(
                    title = stringResource(R.string.clips_empty),
                    actionLabel = stringResource(R.string.action_retry),
                    onAction = onRefresh,
                )
                else -> ClipsPager(
                    clips = clips,
                    muted = muted,
                    activePage = activePage,
                    onSettledPage = onSettledPage,
                    onAction = onAction,
                )
            }
        }
    }
}

@Composable
private fun ClipsPager(
    clips: LazyPagingItems<Clip>,
    muted: Boolean,
    activePage: Int,
    onSettledPage: (Int) -> Unit,
    onAction: (Clip, ClipAction) -> Unit,
) {
    val pagerState = rememberPagerState(initialPage = activePage) { clips.itemCount }

    // settledPage is the authoritative active-page source; mirror it for the controller + telemetry.
    LaunchedEffect(pagerState) {
        snapshotSettledPage(pagerState).distinctUntilChanged().collect { onSettledPage(it) }
    }

    VerticalPager(
        state = pagerState,
        modifier = Modifier.fillMaxSize().testTag(ClipsScreenTestTags.PAGER),
    ) { page ->
        val clip = clips[page]
        if (clip != null) {
            ClipPage(
                clip = clip,
                muted = muted,
                onAction = onAction,
            )
        }
    }
}

/** A single full-bleed clip page: poster background (web parity) + the overlay chrome. */
@Composable
private fun ClipPage(
    clip: Clip,
    muted: Boolean,
    onAction: (Clip, ClipAction) -> Unit,
) {
    Box(modifier = Modifier.fillMaxSize().background(Color.Black)) {
        AsyncImage(
            model = clip.thumbnailUrl,
            contentDescription = clip.title,
            contentScale = ContentScale.Fit,
            modifier = Modifier.fillMaxSize().testTag(ClipsScreenTestTags.PAGE_POSTER),
        )
        ClipOverlay(
            clip = clip,
            muted = muted,
            onAction = { action -> onAction(clip, action) },
        )
    }
}

/** Pure flow of the pager's settled page, extracted so the LaunchedEffect import stays minimal. */
private fun snapshotSettledPage(pagerState: androidx.compose.foundation.pager.PagerState) =
    androidx.compose.runtime.snapshotFlow { pagerState.settledPage }
