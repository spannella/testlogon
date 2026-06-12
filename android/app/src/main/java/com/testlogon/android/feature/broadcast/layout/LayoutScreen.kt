@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.layout

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.PictureInPicture
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.ViewColumn
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-311 — stable testTags for the layout-management surface. */
object LayoutTestTags {
    const val SCREEN = "layout_screen"
    const val LIVE_BADGE = "layout_live_badge"
    const val PENDING = "layout_pending"
    const val ERROR = "layout_error"
    const val STALE_BANNER = "layout_stale_banner"
    const val NEEDS_SOURCE = "layout_needs_source"

    /** Stable per-card tag: layout_mode_<wire>. */
    fun mode(mode: LayoutModeUi): String = "layout_mode_${mode.wire}"
}

/**
 * AND-311 — layout-management entry. Collects [LayoutViewModel] state and delegates to the stateless
 * [LayoutScreen]. Reached from the host control surface (BroadcastLayoutDest). Drives the live-refresh poll
 * loop only while this surface is composed (mirrors AND-310's InputsRoute).
 */
@Composable
fun LayoutRoute(
    onBack: () -> Unit,
    viewModel: LayoutViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DisposableEffect(viewModel) {
        viewModel.startPolling()
        onDispose { viewModel.stopPolling() }
    }
    LayoutScreen(
        state = state,
        onSelectMode = viewModel::onSelectMode,
        onRetry = viewModel::onRetry,
        onBack = onBack,
    )
}

/**
 * AND-311 — stateless layout chooser. A grid of the four fixed mode cards (icon + label), with a "LIVE"
 * badge on the current card. The pending card shows a centered progress indicator and the whole grid is
 * non-interactive while a switch is in flight. A card with no active source shows a non-blocking hint but
 * stays selectable. Loading / Error reuse core-ui state composables (there is NO empty state — the modes are
 * always present).
 */
@Composable
fun LayoutScreen(
    state: LayoutUiState,
    onSelectMode: (LayoutModeUi) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(LayoutTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.layout_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.layout_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is LayoutUiState.Loading -> LoadingState()

                is LayoutUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    title = stringResource(R.string.layout_error_title),
                    modifier = Modifier.testTag(LayoutTestTags.ERROR),
                )

                is LayoutUiState.Content -> Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isStale) {
                        StaleBanner(
                            stale = true,
                            refreshing = false,
                            onRetry = onRetry,
                            modifier = Modifier.testTag(LayoutTestTags.STALE_BANNER),
                        )
                    }
                    // The live (current) mode is announced via a polite live region for screen readers.
                    val currentCd = stringResource(
                        R.string.layout_current_mode_cd,
                        stringResource(modeLabelRes(state.currentMode)),
                    )
                    Text(
                        text = currentCd,
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                            .semantics {
                                liveRegion = LiveRegionMode.Polite
                                contentDescription = currentCd
                            },
                    )
                    LazyVerticalGrid(
                        columns = GridCells.Fixed(2),
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(state.cards, key = { it.mode.name }) { card ->
                            ModeCardItem(
                                card = card,
                                isPending = state.pendingMode == card.mode,
                                gridLocked = state.pendingMode != null,
                                onSelectMode = onSelectMode,
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * AND-311 — a single mode card. Shows the mode icon + label and, on the live card, a "LIVE" badge. While
 * [isPending] the card shows a centered progress indicator. The card is clickable only when selectable and
 * the grid is not locked by an in-flight switch.
 */
@Composable
fun ModeCardItem(
    card: ModeCard,
    isPending: Boolean,
    gridLocked: Boolean,
    onSelectMode: (LayoutModeUi) -> Unit,
    modifier: Modifier = Modifier,
) {
    val label = stringResource(modeLabelRes(card.mode))
    val switchCd = stringResource(R.string.layout_switch_cd, label)
    val liveBadgeCd = stringResource(R.string.layout_live_badge_cd, label)
    val pendingCd = stringResource(R.string.layout_pending_cd, label)
    val clickable = card.isSelectable && !gridLocked

    OutlinedCard(
        onClick = { if (clickable) onSelectMode(card.mode) },
        enabled = clickable,
        colors = if (card.isLive) {
            CardDefaults.outlinedCardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        } else {
            CardDefaults.outlinedCardColors()
        },
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 120.dp)
            .testTag(LayoutTestTags.mode(card.mode))
            // The card's own action is conveyed via a single content description (switch vs. live).
            .semantics {
                contentDescription = if (card.isLive) liveBadgeCd else switchCd
            },
    ) {
        Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            Column(
                modifier = Modifier.align(Alignment.Center),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = iconFor(card.mode),
                    contentDescription = null,
                    modifier = Modifier.size(36.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleSmall,
                    textAlign = TextAlign.Center,
                )
            }

            if (card.isLive) {
                LiveBadge(
                    cd = liveBadgeCd,
                    modifier = Modifier.align(Alignment.TopEnd),
                )
            }

            if (card.needsSource) {
                Text(
                    text = stringResource(R.string.layout_needs_source),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .testTag(LayoutTestTags.NEEDS_SOURCE),
                )
            }

            if (isPending) {
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(28.dp)
                        .testTag(LayoutTestTags.PENDING)
                        .clearAndSetSemantics { contentDescription = pendingCd },
                )
            }
        }
    }
}

/** The "LIVE" badge shown on the current-mode card (state described for screen readers). */
@Composable
private fun LiveBadge(cd: String, modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = modifier
            .testTag(LayoutTestTags.LIVE_BADGE)
            .semantics { stateDescription = cd },
    ) {
        Text(
            text = stringResource(R.string.layout_live_badge),
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

private fun iconFor(mode: LayoutModeUi): ImageVector = when (mode) {
    LayoutModeUi.SINGLE -> Icons.Filled.Videocam
    LayoutModeUi.SIDE_BY_SIDE -> Icons.Filled.ViewColumn
    LayoutModeUi.PIP -> Icons.Filled.PictureInPicture
    LayoutModeUi.GRID -> Icons.Filled.GridView
    LayoutModeUi.UNKNOWN -> Icons.Filled.Videocam
}

private fun modeLabelRes(mode: LayoutModeUi): Int = when (mode) {
    LayoutModeUi.SINGLE -> R.string.layout_mode_single
    LayoutModeUi.SIDE_BY_SIDE -> R.string.layout_mode_side_by_side
    LayoutModeUi.PIP -> R.string.layout_mode_pip
    LayoutModeUi.GRID -> R.string.layout_mode_grid
    LayoutModeUi.UNKNOWN -> R.string.layout_mode_unknown
}
