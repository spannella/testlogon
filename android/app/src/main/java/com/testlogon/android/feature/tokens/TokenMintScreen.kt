@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tokens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Mint a creator revenue-share token: name / ticker / supply / revenue-share %. The creator holds
 * 100% of supply on mint. Submitting arms a "$100 creation fee" money-safety CONFIRM (mirrors the
 * trade-ticket deposit confirm) before the server-charged mint call. On success the route opens the
 * new token's detail.
 */
@Composable
fun TokenMintRoute(
    onBack: () -> Unit,
    onMinted: (tokenId: String) -> Unit,
    viewModel: TokenMintViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showFeeConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(state.mintedTokenId) {
        state.mintedTokenId?.let { id ->
            viewModel.consumeMinted()
            onMinted(id)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Mint creator token") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Text(
                "Tokenize your revenue share. You hold 100% of supply on mint; you can list a slice later via a single-clearing-price IPO.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = state.name,
                onValueChange = viewModel::onName,
                label = { Text("Token name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("mint_name"),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.ticker,
                onValueChange = viewModel::onTicker,
                label = { Text("Ticker") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("mint_ticker"),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.supplyText,
                onValueChange = viewModel::onSupply,
                label = { Text("Total supply") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag("mint_supply"),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.revenueSharePctText,
                onValueChange = viewModel::onRevenueShare,
                label = { Text("Revenue share %") },
                supportingText = {
                    Text(
                        "Holders receive pro-rata distributions of this % of your ongoing content revenue.",
                    )
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag("mint_revenue_share"),
            )
            Spacer(Modifier.height(16.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Creation fee", style = MaterialTheme.typography.labelLarge)
                    Text(
                        TokenMath.formatCents(TokenMath.CREATION_FEE_CENTS),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        "Charged once when you mint. You'll confirm before we charge.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            state.errorMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("mint_error"),
                )
            }
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { showFeeConfirm = true },
                enabled = state.canSubmit,
                modifier = Modifier.fillMaxWidth().testTag("mint_submit"),
            ) {
                if (state.submitting) {
                    CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
                } else {
                    Text("Mint token")
                }
            }
        }
    }

    if (showFeeConfirm) {
        AlertDialog(
            onDismissRequest = { showFeeConfirm = false },
            title = { Text("Confirm creation fee") },
            text = {
                Column {
                    TokenKeyValueRow("Action", "Mint creator token")
                    TokenKeyValueRow("Name", state.name)
                    TokenKeyValueRow("Ticker", state.ticker)
                    TokenKeyValueRow("Total supply", state.supplyText.ifBlank { "0" })
                    TokenKeyValueRow(
                        "Revenue share",
                        state.revenueShareBps?.let { TokenMath.formatBps(it) } ?: "—",
                    )
                    TokenKeyValueRow(
                        "Creation fee",
                        TokenMath.formatCents(TokenMath.CREATION_FEE_CENTS),
                        emphasize = true,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "This charges your account ${TokenMath.formatCents(TokenMath.CREATION_FEE_CENTS)} now.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showFeeConfirm = false
                        viewModel.confirmMint()
                    },
                    modifier = Modifier.testTag("mint_fee_confirm"),
                ) { Text("Pay & mint") }
            },
            dismissButton = {
                TextButton(onClick = { showFeeConfirm = false }) { Text("Cancel") }
            },
        )
    }
}
