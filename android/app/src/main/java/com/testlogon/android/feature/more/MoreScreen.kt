package com.testlogon.android.feature.more

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState

/**
 * AND-067 — route-level "More" hub entry. [onOpenHub] drills into a hub-detail screen; [onNavigate]
 * is wired to the shared NavController (kept for the hub-detail screen's item taps).
 */
@Composable
fun MoreRoute(
    onOpenHub: (MoreHub) -> Unit,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MoreViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MoreScreen(state = state, onOpenHub = onOpenHub, modifier = modifier)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MoreScreen(
    state: MoreUiState,
    onOpenHub: (MoreHub) -> Unit,
    modifier: Modifier = Modifier,
) {
    androidx.compose.material3.Scaffold(
        modifier = modifier.testTag("more_screen"),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.more_title)) }) },
    ) { padding ->
        when (state) {
            MoreUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            MoreUiState.Empty -> EmptyState(
                title = stringResource(R.string.more_empty),
                modifier = Modifier.padding(padding).testTag("more_empty"),
            )
            is MoreUiState.Content -> MoreHubGrid(
                hubs = state.hubs,
                onOpenHub = onOpenHub,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun MoreHubGrid(
    hubs: List<MoreHubUi>,
    onOpenHub: (MoreHub) -> Unit,
    modifier: Modifier = Modifier,
) {
    val gridState = rememberLazyGridState()
    LazyVerticalGrid(
        state = gridState,
        columns = GridCells.Fixed(2),
        modifier = modifier.fillMaxSize().testTag("more_grid"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(hubs, key = { it.hub.name }) { hubUi ->
            MoreHubTile(hubUi = hubUi, onOpenHub = onOpenHub)
        }
    }
}

/** A circular chip holding a tinted icon — the key visual-polish element shared by hub surfaces. */
@Composable
internal fun AccentIconCircle(
    accent: HubAccent,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier,
    size: androidx.compose.ui.unit.Dp = 44.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(accent.container),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = accent.onAccent)
    }
}

@Composable
private fun MoreHubTile(
    hubUi: MoreHubUi,
    onOpenHub: (MoreHub) -> Unit,
) {
    val title = stringResource(hubUi.hub.titleRes)
    val count = hubUi.items.size
    val subtitle = stringResource(R.string.more_hub_item_count, count)
    Card(
        onClick = { onOpenHub(hubUi.hub) },
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 112.dp)
            .testTag("more_hub_${hubUi.hub.name.lowercase()}")
            .semantics { contentDescription = "$title. $subtitle" },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            AccentIconCircle(accent = hubUi.hub.accent(), icon = hubUi.hub.icon)
            Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * Shared item card — renders one [MoreItemUi] with its availability state and routes through
 * [onNavigate] on tap. Reused by both the legacy flat grid and the hub-detail screen.
 */
@Composable
internal fun MoreEntryCard(
    item: MoreItemUi,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val entry = item.entry
    val label = stringResource(entry.labelRes)
    val disabled = item.availability is EntryAvailability.Disabled
    val reason = (item.availability as? EntryAvailability.Disabled)?.let { stringResource(it.reasonRes) }
    val cd = if (disabled && reason != null) "$label. $reason" else label

    val cardModifier = modifier
        .fillMaxWidth()
        .heightIn(min = 96.dp)
        .testTag("more_entry_${entry.id}")
        .then(
            if (disabled) {
                Modifier.alpha(0.5f).semantics {
                    this.disabled()
                    contentDescription = cd
                }
            } else {
                Modifier.semantics { contentDescription = cd }
            },
        )

    val onClick: () -> Unit = if (disabled) ({}) else ({ onNavigate(entry.route) })

    Card(
        onClick = onClick,
        enabled = !disabled,
        modifier = cardModifier,
        colors = CardDefaults.cardColors(),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            AccentIconCircle(accent = entry.hub.accent(), icon = entry.icon, size = 40.dp)
            Text(label, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
            if (disabled && reason != null) {
                Text(
                    text = reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
