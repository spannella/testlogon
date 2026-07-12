package com.testlogon.android.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/**
 * AND-067 — hub-detail screen: lists the items belonging to a single [MoreHub], sub-grouped by
 * their [MoreSection]. Item taps route through [onNavigate] (the same mechanism the More tab uses),
 * so every destination keeps working. [hub] comes from the nav arg via [MoreHubRoute].
 */
@Composable
fun MoreHubRoute(
    hub: MoreHub,
    onBack: () -> Unit,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MoreViewModel = hiltViewModel(),
) {
    val items = viewModel.itemsForHub(hub)
    MoreHubScreen(
        hub = hub,
        items = items,
        onBack = onBack,
        onNavigate = onNavigate,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MoreHubScreen(
    hub: MoreHub,
    items: List<MoreItemUi>,
    onBack: () -> Unit,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("more_hub_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(hub.titleRes)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("more_hub_back")) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.more_hub_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        if (items.isEmpty()) {
            EmptyState(
                title = stringResource(R.string.more_empty),
                modifier = Modifier.padding(padding).testTag("more_hub_empty"),
            )
        } else {
            MoreHubItems(
                items = items,
                onNavigate = onNavigate,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun MoreHubItems(
    items: List<MoreItemUi>,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    // Sub-group by section, preserving catalog order, only surfacing non-empty sections.
    val grouped = MoreSection.entries.mapNotNull { section ->
        val sectionItems = items.filter { it.entry.section == section }
        if (sectionItems.isEmpty()) null else section to sectionItems
    }
    val gridState = rememberLazyGridState()
    LazyVerticalGrid(
        state = gridState,
        columns = GridCells.Adaptive(minSize = 160.dp),
        modifier = modifier.fillMaxSize().testTag("more_hub_grid"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        grouped.forEach { (section, sectionItems) ->
            item(span = { GridItemSpan(maxLineSpan) }) {
                Text(
                    text = stringResource(section.titleRes),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("more_hub_section_${section.name.lowercase()}"),
                )
            }
            items(sectionItems, key = { it.entry.id }) { item ->
                MoreEntryCard(item = item, onNavigate = onNavigate)
            }
        }
    }
}
