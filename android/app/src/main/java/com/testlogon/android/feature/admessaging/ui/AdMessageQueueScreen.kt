@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admessaging.ui

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
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.admessaging.data.AdMessageOffer

/** ADV2-507 — stable testTags for the creator sponsored-message approval queue. */
object AdMessageQueueTestTags {
    const val SCREEN = "admsg_queue_screen"
    const val EMPTY = "admsg_queue_empty"
    const val ERROR_RETRY = "admsg_queue_error_retry"

    fun row(id: String) = "admsg_queue_row_$id"
    fun approve(id: String) = "admsg_queue_approve_$id"
    fun reject(id: String) = "admsg_queue_reject_$id"
}

/** ADV2-507 — route-level creator approval-queue entry. */
@Composable
fun AdMessageQueueRoute(
    onBack: () -> Unit,
    viewModel: AdMessageQueueViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val acting by viewModel.acting.collectAsStateWithLifecycle()
    val sendResult by viewModel.lastSendResult.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val sentTemplate = sendResult?.let {
        pluralStringResource(R.plurals.admsg_queue_sent_snackbar, it, it)
    }
    LaunchedEffect(sendResult) {
        if (sentTemplate != null) {
            snackbarHostState.showSnackbar(sentTemplate)
            viewModel.consumeSendResult()
        }
    }
    AdMessageQueueScreen(
        state = state,
        acting = acting,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onApprove = viewModel::approve,
        onReject = viewModel::reject,
    )
}

/** ADV2-507 — stateless creator approval queue. Each pending offer -> Approve (send) / Reject. */
@Composable
fun AdMessageQueueScreen(
    state: AdMessageQueueUiState,
    acting: Set<String>,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onApprove: (String) -> Unit,
    onReject: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdMessageQueueTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.admsg_queue_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.admsg_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is AdMessageQueueUiState.Loading -> LoadingState()

                is AdMessageQueueUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(AdMessageQueueTestTags.EMPTY),
                        title = stringResource(R.string.admsg_queue_empty_title),
                        body = stringResource(R.string.admsg_queue_empty_body),
                        imageVector = Icons.Outlined.Campaign,
                    )

                is AdMessageQueueUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(AdMessageQueueTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )

                is AdMessageQueueUiState.Content ->
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(items = state.offers, key = { it.offerId }) { offer ->
                            OfferCard(
                                offer = offer,
                                busy = offer.offerId in acting,
                                onApprove = { onApprove(offer.offerId) },
                                onReject = { onReject(offer.offerId) },
                            )
                        }
                    }
            }
        }
    }
}

@Composable
private fun OfferCard(
    offer: AdMessageOffer,
    busy: Boolean,
    onApprove: () -> Unit,
    onReject: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag(AdMessageQueueTestTags.row(offer.offerId)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(
                    R.string.admsg_queue_from,
                    offer.advertiserSub ?: stringResource(R.string.admsg_queue_advertiser_unknown),
                ),
                style = MaterialTheme.typography.titleSmall,
            )
            val body = offer.body
            if (!body.isNullOrBlank()) {
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 6,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            val cta = offer.ctaUrl
            if (!cta.isNullOrBlank()) {
                Text(
                    text = stringResource(R.string.admsg_queue_cta_link, cta),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = stringResource(R.string.admsg_queue_send_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onReject,
                    enabled = !busy,
                    modifier = Modifier.testTag(AdMessageQueueTestTags.reject(offer.offerId)),
                ) {
                    Text(stringResource(R.string.admsg_queue_reject))
                }
                Button(
                    onClick = onApprove,
                    enabled = !busy,
                    modifier = Modifier.testTag(AdMessageQueueTestTags.approve(offer.offerId)),
                ) {
                    Text(stringResource(R.string.admsg_queue_approve))
                }
            }
        }
    }
}
