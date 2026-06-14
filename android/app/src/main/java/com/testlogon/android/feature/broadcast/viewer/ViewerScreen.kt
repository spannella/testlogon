package com.testlogon.android.feature.broadcast.viewer

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.broadcast.chat.LiveChatPanel
import com.testlogon.android.feature.broadcast.qna.LiveQaPanel
import com.testlogon.android.feature.broadcast.shelf.ProductsShelfPanel
import com.testlogon.android.feature.broadcast.tips.TipsGoalsPanel
import com.testlogon.android.feature.player.VideoPlayer
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import kotlinx.coroutines.delay

/**
 * AND-280 — viewer playback entry point. Hosts the reused AND-168 [VideoPlayer] for the live HLS
 * stream, wires the AND-171 [PlaybackReporter] (join/heartbeat/leave) via the lifecycle owner, drives
 * the proactive URL refresh at 75% of remaining lifetime, and composes the AND-281 live chat panel
 * beneath the player. The player/controller lifecycle is owned by the ViewModel (released in
 * onCleared); this surface only binds it.
 */
@Composable
fun ViewerScreen(
    onBack: () -> Unit,
    onBuyProduct: (categoryId: String, itemId: String) -> Unit = { _, _ -> },
    viewModel: ViewerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val lifecycleOwner = LocalLifecycleOwner.current

    // Attach analytics once the player exists (Ready); detach on dispose.
    DisposableEffect(state is ViewerUiState.Ready, lifecycleOwner) {
        if (state is ViewerUiState.Ready) {
            viewModel.attachAnalytics(lifecycleOwner)
        }
        onDispose { viewModel.detachAnalytics() }
    }

    // Proactive URL refresh at 75% of remaining lifetime (bounded; re-armed after each refresh).
    LaunchedEffect(state) {
        val delayMs = viewModel.refreshDelayMs() ?: return@LaunchedEffect
        delay(delayMs)
        viewModel.refreshUrl()
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(16f / 9f),
                contentAlignment = Alignment.Center,
            ) {
                when (state) {
                    ViewerUiState.Loading ->
                        LoadingState(message = stringResource(R.string.viewer_loading))
                    is ViewerUiState.Ready ->
                        VideoPlayer(controller = viewModel.controller, modifier = Modifier.fillMaxSize())
                    is ViewerUiState.Unavailable ->
                        UnavailablePanel((state as ViewerUiState.Unavailable).reason, onBack)
                    is ViewerUiState.Error ->
                        ErrorPanel((state as ViewerUiState.Error).retryable, viewModel::retry, onBack)
                    ViewerUiState.Offline ->
                        ErrorPanel(retryable = true, onRetry = viewModel::retry, onBack = onBack, offline = true)
                }
                IconButton(
                    onClick = onBack,
                    modifier = Modifier.align(Alignment.TopStart).padding(4.dp),
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.viewer_back_cd),
                        tint = Color.White,
                    )
                }

                // AND-285 FR-4 — live viewer-count badge, fed by the reused heartbeat presence count.
                val count = (state as? ViewerUiState.Ready)?.viewerCount
                if (count != null) {
                    ViewerCountBadge(
                        count = count,
                        modifier = Modifier.align(Alignment.TopEnd).padding(8.dp),
                    )
                }
            }

            val ready = state as? ViewerUiState.Ready
            if (ready != null && ready.atLiveEdge.not()) {
                Button(onClick = viewModel::goLive, modifier = Modifier.padding(8.dp)) {
                    Text(stringResource(R.string.viewer_go_live))
                }
            }

            if (ready != null) {
                // AND-283 — the products shelf overlay (hidden by default; toggled on the chrome).
                ProductsShelfPanel(
                    sessionId = viewModel.sessionId,
                    onBuy = onBuyProduct,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )

                // AND-282 — tips summary + goals + a tip composer for the same session.
                TipsGoalsPanel(
                    sessionId = viewModel.sessionId,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )

                // AND-281 — the live chat panel for the same session, beneath the player (portrait).
                LiveChatPanel(
                    sessionId = viewModel.sessionId,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )

                // AND-284 — the live Q&A panel (separate pollable surface; not on the chat SSE).
                LiveQaPanel(
                    sessionId = viewModel.sessionId,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun UnavailablePanel(reason: PlaybackUnavailable, onBack: () -> Unit) {
    val message = when (reason) {
        PlaybackUnavailable.NOT_AUTHORIZED -> R.string.viewer_unavailable_not_authorized
        PlaybackUnavailable.SESSION_ENDED -> R.string.viewer_unavailable_ended
        PlaybackUnavailable.NOT_STARTED -> R.string.viewer_unavailable_not_started
        PlaybackUnavailable.UNKNOWN -> R.string.viewer_unavailable_generic
    }
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.padding(24.dp),
    ) {
        Text(stringResource(message), style = MaterialTheme.typography.bodyLarge, color = Color.White)
        Button(onClick = onBack) { Text(stringResource(R.string.viewer_back_cd)) }
    }
}

/**
 * AND-285 FR-4 / AC-8 — live viewer-count badge overlaid on the player. Uses the existing
 * `broadcast_viewer_count` plurals for a localized "N viewers" label + a polite live region so
 * TalkBack announces count changes without stealing focus from the playback controls.
 */
@Composable
fun ViewerCountBadge(count: Int, modifier: Modifier = Modifier) {
    val label = pluralStringResource(R.plurals.broadcast_viewer_count, count, count)
    Box(
        modifier = modifier
            .background(Color.Black.copy(alpha = 0.55f), RoundedCornerShape(12.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp)
            .semantics {
                contentDescription = label
                liveRegion = LiveRegionMode.Polite
            },
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = Color.White,
        )
    }
}

@Composable
private fun ErrorPanel(
    retryable: Boolean,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    offline: Boolean = false,
) {
    val message = when {
        offline -> R.string.viewer_offline
        else -> R.string.viewer_error_generic
    }
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.padding(24.dp),
    ) {
        Text(stringResource(message), style = MaterialTheme.typography.bodyLarge, color = Color.White)
        if (retryable) {
            Button(onClick = onRetry) { Text(stringResource(R.string.viewer_retry)) }
        } else {
            Button(onClick = onBack) { Text(stringResource(R.string.viewer_back_cd)) }
        }
    }
}
