@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.refunds

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.refunds.RefundRequest

/** AND-244 — stable testTags for the refund detail screen. */
object RefundDetailTestTags {
    const val SCREEN = "refund_detail_screen"
    const val CONTENT = "refund_detail_content"
    const val STATUS = "refund_detail_status"
}

/** AND-244 — route-level refund detail (status, amount, reason, admin decision note). */
@Composable
fun RefundDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RefundDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    RefundDetailScreen(state = state, onRetry = viewModel::refresh, onBack = onBack, modifier = modifier)
}

@Composable
fun RefundDetailScreen(
    state: RefundDetailUiState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(RefundDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.refunds_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                is RefundDetailUiState.Loading -> LoadingState()
                is RefundDetailUiState.Error ->
                    ErrorState(
                        message = s.message.asString(),
                        onRetry = if (s.retryable) onRetry else { {} },
                    )
                is RefundDetailUiState.Content -> RefundDetailContent(s.refund)
            }
        }
    }
}

@Composable
private fun RefundDetailContent(refund: RefundRequest) {
    val statusText = stringResource(refundStatusLabelRes(refund.status))
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(RefundDetailTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(formatRefundMoney(refund.amount), style = MaterialTheme.typography.headlineSmall)
                AssistChip(
                    onClick = {},
                    label = { Text(statusText) },
                    modifier = Modifier.testTag(RefundDetailTestTags.STATUS),
                )
                formatRefundDate(refund.createdAtEpochSeconds)?.let {
                    Text(
                        stringResource(R.string.refunds_detail_requested_on, it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.refunds_detail_reason_label), style = MaterialTheme.typography.titleSmall)
                Text(refund.reason, style = MaterialTheme.typography.bodyMedium)
            }
        }
        refund.adminNotes?.let { notes ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        stringResource(R.string.refunds_detail_admin_notes_label),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(notes, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
