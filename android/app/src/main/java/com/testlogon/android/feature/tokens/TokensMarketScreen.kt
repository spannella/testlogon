@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tokens

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
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Card
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.data.shopads.SponsoredProduct
import com.testlogon.android.feature.ads.SlotEntry
import com.testlogon.android.feature.ads.SponsoredSlotCard
import com.testlogon.android.feature.onboarding.SurfaceIntro
import com.testlogon.android.feature.onboarding.OnboardingModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.tokens.Token

/**
 * Creator revenue-share TOKEN market/browse list. Two tabs: the LISTED market (browse) and the
 * caller's ISSUED tokens. A row taps through to detail; a FAB opens Mint. Every read degrades to an
 * honest empty state when the (not-yet-built) backend 404s.
 *
 * FE-161 (EPIC G) — the MARKET (token-discovery) tab additionally interleaves clearly-labeled
 * SPONSORED slots (served best-effort) every ~5 organic rows; impression fires when a slot is shown,
 * a tap fires the CLICK beacon + opens the ad cta_url. Degrade-on-404 -> no slots, organic list
 * unchanged.
 */
@Composable
fun TokensMarketRoute(
    onBack: () -> Unit,
    onOpenToken: (tokenId: String) -> Unit,
    onMint: () -> Unit,
    viewModel: TokensMarketViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Creator Tokens") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onMint,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("Mint") },
                modifier = Modifier.testTag("tokens_mint_fab"),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            SurfaceIntro(OnboardingModel.INTRO_TOKENS)
            TabRow(selectedTabIndex = if (state.tab == TokenListTab.MARKET) 0 else 1) {
                Tab(
                    selected = state.tab == TokenListTab.MARKET,
                    onClick = { viewModel.selectTab(TokenListTab.MARKET) },
                    text = { Text("Market (${state.market.size})") },
                    modifier = Modifier.testTag("tokens_tab_market"),
                )
                Tab(
                    selected = state.tab == TokenListTab.ISSUED,
                    onClick = { viewModel.selectTab(TokenListTab.ISSUED) },
                    text = { Text("My tokens (${state.issued.size})") },
                    modifier = Modifier.testTag("tokens_tab_issued"),
                )
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    TokensMarketUiState.Phase.Loading -> LoadingState(message = "Loading tokens")
                    TokensMarketUiState.Phase.Error -> ErrorState(
                        message = state.errorMessage ?: "Something went wrong.",
                        onRetry = viewModel::onRetry,
                    )
                    TokensMarketUiState.Phase.Content ->
                        if (state.rows.isEmpty()) {
                            EmptyState(
                                title = if (state.tab == TokenListTab.MARKET) "No listed tokens" else "No tokens yet",
                                body = if (state.tab == TokenListTab.MARKET) {
                                    "No creator tokens are listed yet. Check back once creators list their revenue-share tokens."
                                } else {
                                    "You haven't minted a creator token yet. Tap Mint to tokenize your revenue share."
                                },
                            )
                        } else {
                            TokenList(
                                slots = state.marketSlots,
                                onOpenToken = onOpenToken,
                                onSponsoredImpression = viewModel::onSponsoredImpression,
                                onSponsoredClick = { product ->
                                    viewModel.onSponsoredClick(product)
                                    product.tracking.ctaUrl?.takeIf { it.isNotBlank() }?.let { url ->
                                        runCatching { uriHandler.openUri(url) }
                                    }
                                },
                            )
                        }
                }
            }
        }
    }
}

@Composable
private fun TokenList(
    slots: List<SlotEntry<Token, SponsoredProduct>>,
    onOpenToken: (String) -> Unit,
    onSponsoredImpression: (SponsoredProduct) -> Unit,
    onSponsoredClick: (SponsoredProduct) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("tokens_list"),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(
            items = slots,
            key = { slot ->
                when (slot) {
                    is SlotEntry.Organic -> "token_" + slot.item.tokenId
                    is SlotEntry.Sponsored -> slot.key
                }
            },
        ) { slot ->
            when (slot) {
                is SlotEntry.Organic ->
                    TokenRowCard(token = slot.item, onClick = { onOpenToken(slot.item.tokenId) })
                is SlotEntry.Sponsored ->
                    SponsoredSlotCard(
                        product = slot.ad,
                        onImpression = { onSponsoredImpression(slot.ad) },
                        onClick = { onSponsoredClick(slot.ad) },
                    )
            }
        }
    }
}

@Composable
private fun TokenRowCard(token: Token, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("token_row_${token.tokenId}"),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = token.ticker.ifBlank { "—" },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(Modifier.width(8.dp))
                    TokenStatusPill(text = token.status.label())
                }
                Text(
                    text = token.name.ifBlank { "Unnamed token" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "Revenue share ${TokenMath.formatBps(token.revenueShareBps)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = token.clearingPrice?.let { TokenMath.formatCents(it) } ?: "—",
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "price",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
    Spacer(Modifier.height(0.dp))
}
