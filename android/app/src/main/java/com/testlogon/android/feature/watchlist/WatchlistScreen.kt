@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.watchlist

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Card
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.exchange.watchlist.WatchItem
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.data.exchange.watchlist.kindLabel

/**
 * UNIFIED Watchlist screen: one list of every starred item across exchange SYMBOLs, creator TOKENs,
 * and STRATEGY funds, each with a per-kind badge, live price/NAV + change (degrades to "—" on 404),
 * a remove (un-star) affordance, and a tap that deep-links to the item's detail. New navigable
 * destination reached from the More hub.
 */
@Composable
fun WatchlistRoute(
    onBack: () -> Unit,
    onOpen: (route: String) -> Unit,
    viewModel: WatchlistViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Watchlist") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                WatchlistUiState.Phase.Loading -> LoadingState(message = "Loading watchlist")
                WatchlistUiState.Phase.Empty -> EmptyState(
                    title = "Your watchlist is empty",
                    body = "Star a symbol, creator token, or strategy fund to follow it here.",
                )
                WatchlistUiState.Phase.Content -> WatchlistContent(
                    rows = state.rows,
                    onOpen = onOpen,
                    onRemove = viewModel::remove,
                )
            }
        }
    }
}

@Composable
private fun WatchlistContent(
    rows: List<WatchRow>,
    onOpen: (String) -> Unit,
    onRemove: (WatchItem) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("watchlist_list"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(rows, key = { it.item.key }) { row ->
            WatchRowCard(row = row, onOpen = onOpen, onRemove = onRemove)
        }
    }
}

@Composable
private fun WatchRowCard(
    row: WatchRow,
    onOpen: (String) -> Unit,
    onRemove: (WatchItem) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpen(row.route) }
            .testTag("watch_row_${row.item.key}"),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            KindBadge(row.item.kind)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = row.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = row.subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = row.priceText ?: "—",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium,
                )
                if (row.changeText != null) {
                    val color = when (row.changeUp) {
                        true -> Color(0xFF2E7D32)
                        false -> Color(0xFFC62828)
                        null -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                    Text(text = row.changeText, style = MaterialTheme.typography.bodySmall, color = color)
                }
            }
            IconButton(
                onClick = { onRemove(row.item) },
                modifier = Modifier.testTag("watch_remove_${row.item.key}"),
            ) {
                Icon(
                    imageVector = Icons.Filled.Star,
                    contentDescription = "Remove from watchlist",
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun KindBadge(kind: WatchKind) {
    val bg = when (kind) {
        WatchKind.SYMBOL -> MaterialTheme.colorScheme.primaryContainer
        WatchKind.TOKEN -> MaterialTheme.colorScheme.tertiaryContainer
        WatchKind.STRATEGY -> MaterialTheme.colorScheme.secondaryContainer
    }
    val fg = when (kind) {
        WatchKind.SYMBOL -> MaterialTheme.colorScheme.onPrimaryContainer
        WatchKind.TOKEN -> MaterialTheme.colorScheme.onTertiaryContainer
        WatchKind.STRATEGY -> MaterialTheme.colorScheme.onSecondaryContainer
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .padding(horizontal = 8.dp, vertical = 4.dp),
    ) {
        Text(
            text = kindLabel(kind),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = fg,
        )
    }
}
