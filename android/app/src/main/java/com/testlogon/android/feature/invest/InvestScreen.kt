@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.invest

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.onboarding.SurfaceIntro
import com.testlogon.android.feature.onboarding.OnboardingModel

/**
 * The unified INVEST hub — one front door aggregating every investable/tradeable product (markets,
 * creator tokens, strategy funds, staking, and open opportunities). A single search box filters ALL
 * sections live; each section is a horizontally-scrollable card row with a "See all" into its existing
 * screen. Sections degrade INDEPENDENTLY to an honest "pending backend" note on 404.
 *
 * [onOpenRoute] navigates to any resolved in-app route (detail screens + the per-section "see all").
 */
@Composable
fun InvestRoute(
    onBack: () -> Unit,
    onOpenRoute: (route: String) -> Unit,
    viewModel: InvestViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Invest") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            InvestUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            InvestUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Something went wrong.",
                onRetry = viewModel::onRetry,
                modifier = Modifier.padding(padding),
            )
            InvestUiState.Phase.Content -> InvestContent(
                state = state,
                onQueryChange = viewModel::onQueryChange,
                onOpenRoute = onOpenRoute,
                contentPadding = padding,
            )
        }
    }
}

@Composable
private fun InvestContent(
    state: InvestUiState,
    onQueryChange: (String) -> Unit,
    onOpenRoute: (String) -> Unit,
    contentPadding: PaddingValues,
) {
    val sections = listOf(
        "Markets" to state.markets,
        "Creator Tokens" to state.tokens,
        "Strategy Funds" to state.strategies,
        "Staking" to state.staking,
        "Opportunities" to state.opportunities,
    )
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .testTag("invest_list"),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item { SurfaceIntro(OnboardingModel.INTRO_INVEST) }
        item {
            OutlinedTextField(
                value = state.query,
                onValueChange = onQueryChange,
                singleLine = true,
                leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
                placeholder = { Text("Search markets, tokens, funds…") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .testTag("invest_search"),
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "${state.totalCount} products",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
        }

        if (state.noSearchResults) {
            item {
                Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                    EmptyState(title = "No matches", body = "Nothing matches \"${state.query}\".")
                }
            }
        } else {
            sections.forEach { (title, section) ->
                val visible = state.visibleItems(section)
                // Hide a section entirely once a search filters it to nothing (keeps results tight),
                // but with a blank query show every section (incl. its honest pending note).
                if (state.query.isBlank() || visible.isNotEmpty()) {
                    item(key = "section_${section.kind}") {
                        InvestSection(
                            title = title,
                            items = visible,
                            pending = section.pending,
                            seeAllRoute = section.seeAllRoute,
                            onOpenRoute = onOpenRoute,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun InvestSection(
    title: String,
    items: List<InvestItem>,
    pending: Boolean,
    seeAllRoute: String,
    onOpenRoute: (String) -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            if (seeAllRoute.isNotBlank()) {
                TextButton(
                    onClick = { onOpenRoute(seeAllRoute) },
                    modifier = Modifier.testTag("invest_seeall_$title"),
                ) { Text("See all") }
            }
        }
        Spacer(Modifier.height(4.dp))
        when {
            items.isEmpty() && pending -> Text(
                text = "Pending backend — not available yet.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            items.isEmpty() -> Text(
                text = "Nothing here yet.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            else -> LazyRow(
                contentPadding = PaddingValues(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(items, key = { it.kind.name + ":" + it.id }) { di ->
                    InvestCard(item = di, onOpenRoute = onOpenRoute)
                }
            }
        }
    }
}

@Composable
private fun InvestCard(item: InvestItem, onOpenRoute: (String) -> Unit) {
    Card(
        modifier = Modifier
            .width(180.dp)
            .then(if (item.route.isNotBlank()) Modifier.clickable { onOpenRoute(item.route) } else Modifier)
            .testTag("invest_card_${item.id}"),
    ) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            Text(
                text = item.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (item.subtitle.isNotBlank()) {
                Text(
                    text = item.subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (item.metric.isNotBlank()) {
                Spacer(Modifier.height(6.dp))
                Text(
                    text = item.metric,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
