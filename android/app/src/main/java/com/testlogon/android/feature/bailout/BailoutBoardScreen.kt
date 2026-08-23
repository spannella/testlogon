@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bailout

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.feature.onboarding.SurfaceIntro
import com.testlogon.android.feature.onboarding.OnboardingModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.bailout.BailoutAuction

/**
 * Bailouts discovery board: open pre-emptive bailout auctions a rescuer can inject capital into. Honest
 * empty/pending state on 404 (never fabricates a distress opportunity). Tapping a row opens the auction
 * (addressed by its symbolId).
 */
@Composable
fun BailoutBoardRoute(
    onBack: () -> Unit,
    onOpenAuction: (symbolId: Int) -> Unit,
    viewModel: BailoutBoardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Open bailouts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            BailoutBoardUiState.Phase.Loading -> LoadingState(message = "Loading bailouts")
            BailoutBoardUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Something went wrong.",
                onRetry = viewModel::onRetry,
                modifier = Modifier.padding(padding),
            )
            BailoutBoardUiState.Phase.Content -> LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item { SurfaceIntro(OnboardingModel.INTRO_BAILOUTS) }
                item {
                    Text(
                        "Inject rescue capital into a distressed-but-solvent position for a slice of it (and its uPnL). Bids clear at a single least-dilutive share.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (state.auctions.isEmpty()) {
                    item { EmptyBoard() }
                } else {
                    items(state.auctions.size, key = { "b_" + state.auctions[it].auctionId }) { i ->
                        BoardRow(state.auctions[i], onOpenAuction)
                    }
                }
            }
        }
    }
}

@Composable
private fun BoardRow(auction: BailoutAuction, onOpenAuction: (Int) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onOpenAuction(auction.symbolId) },
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    "${auction.side.label()} ${auction.qty} · symbol ${auction.symbolId}",
                    fontWeight = FontWeight.SemiBold,
                )
                BailoutStatusPill(auction.status.label())
            }
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(Modifier.height(6.dp))
            BailoutKeyValueRow("Capital needed", BailoutMath.formatCents(auction.capitalNeededCents))
            auction.raisedCents?.let { BailoutKeyValueRow("Raised", BailoutMath.formatCents(it)) }
            BailoutKeyValueRow("Max share offered", BailoutMath.formatBps(auction.maxShareBps))
            BailoutKeyValueRow("Liq / mark", "${auction.liqPrice} / ${auction.markPrice}")
            BailoutKeyValueRow("Rescuers", auction.rescuers.size.toString())
        }
    }
}

@Composable
private fun EmptyBoard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(24.dp)) {
            Text("No open bailouts", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "There are no open bailout auctions to rescue right now. (If the me/bailouts backend is still pending, this stays empty rather than inventing opportunities.)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
