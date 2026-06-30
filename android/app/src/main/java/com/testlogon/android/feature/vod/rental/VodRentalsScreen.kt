@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.vod.rental

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.vod.rental.RentalCountdown
import com.testlogon.android.data.vod.rental.RentalListItem

/**
 * "My Rentals" route (web VodRentalsPage parity). A row tap opens the video detail via [onVideoClick].
 */
@Composable
fun VodRentalsRoute(
    onBack: () -> Unit,
    onVideoClick: (videoId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VodRentalsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    VodRentalsScreen(
        state = state,
        onBack = onBack,
        onVideoClick = onVideoClick,
        onRetry = viewModel::load,
        modifier = modifier,
    )
}

@Composable
fun VodRentalsScreen(
    state: VodRentalsUiState,
    onBack: () -> Unit,
    onVideoClick: (String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(VodRentalsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.vod_rentals_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.vod_rentals_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                VodRentalsUiState.Loading -> LoadingState()
                is VodRentalsUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(VodRentalsTestTags.ERROR_RETRY),
                )
                is VodRentalsUiState.Content -> if (state.items.isEmpty()) {
                    EmptyState(
                        title = stringResource(R.string.vod_rentals_empty_title),
                        body = stringResource(R.string.vod_rentals_empty_body),
                        modifier = Modifier.testTag(VodRentalsTestTags.EMPTY),
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(VodRentalsTestTags.LIST),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(state.items, key = { it.rentalId.ifBlank { it.videoId } }) { item ->
                            RentalRow(item = item, onClick = { onVideoClick(item.videoId) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun RentalRow(item: RentalListItem, onClick: () -> Unit) {
    Surface(
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().testTag(VodRentalsTestTags.ROW),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.videoId,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(
                        R.string.vod_rentals_tier_price,
                        tierLabel(item.tier),
                        item.amountCents / 100.0,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            AssistChip(
                onClick = onClick,
                label = { Text(statusLabel(item)) },
                colors = AssistChipDefaults.assistChipColors(),
            )
        }
    }
}

@Composable
private fun tierLabel(tier: String): String = when (tier) {
    "rental" -> stringResource(R.string.vod_rentals_tier_rental)
    "view_once" -> stringResource(R.string.vod_rentals_tier_view_once)
    else -> tier.replace("_", " ")
}

/**
 * Status label mirroring the web StatusBadge: active rental -> "Expires in HH:MM:SS" (or "Ready to play"
 * before first play); active view-once -> "{n} view left"; reason expired/consumed -> Expired/Watched; else
 * the raw reason.
 */
@Composable
private fun statusLabel(item: RentalListItem): String = when {
    item.active && item.tier == "rental" ->
        if (item.started) {
            stringResource(R.string.vod_rentals_expires_in, RentalCountdown.label(item.remainingSeconds))
        } else {
            stringResource(R.string.vod_rentals_ready)
        }
    item.active && item.tier == "view_once" ->
        stringResource(R.string.vod_rentals_views_left, item.viewsRemaining.coerceAtLeast(0))
    item.reason == "expired" -> stringResource(R.string.vod_rentals_expired)
    item.reason == "consumed" -> stringResource(R.string.vod_rentals_watched)
    else -> item.reason.replace("_", " ")
}
