@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.ads.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
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

/** ADV2-710 - stable testTags for the syndicate ad-split editor. */
object SyndicateAdSplitTestTags {
    const val SCREEN = "syndicate_ad_split_screen"
    const val SLIDER = "syndicate_ad_split_slider"
    const val SAVE = "syndicate_ad_split_save"
}

/** ADV2-710 - route-level syndicate ad-placement split editor. */
@Composable
fun SyndicateAdSplitRoute(
    onBack: () -> Unit,
    viewModel: SyndicateAdSplitViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SyndicateAdSplitScreen(
        state = state,
        onBack = onBack,
        onDraftChange = viewModel::onDraftChange,
        onReset = viewModel::resetToDefault,
        onSave = viewModel::save,
        onRetry = viewModel::load,
    )
}

/** ADV2-710 - stateless syndicate ad-placement split editor. */
@Composable
fun SyndicateAdSplitScreen(
    state: SyndicateAdSplitUiState,
    onBack: () -> Unit,
    onDraftChange: (Int) -> Unit,
    onReset: () -> Unit,
    onSave: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SyndicateAdSplitTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.syndicate_ad_split_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_create_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (state) {
                is SyndicateAdSplitUiState.Loading ->
                    CircularProgressIndicator()
                is SyndicateAdSplitUiState.Forbidden ->
                    Text(
                        stringResource(R.string.syndicate_ads_forbidden),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                is SyndicateAdSplitUiState.Error -> {
                    Text(state.message, color = MaterialTheme.colorScheme.error)
                    OutlinedButton(onClick = onRetry) {
                        Text(stringResource(R.string.syndicate_ads_retry))
                    }
                }
                is SyndicateAdSplitUiState.Content -> ContentBody(
                    state = state,
                    onDraftChange = onDraftChange,
                    onReset = onReset,
                    onSave = onSave,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: SyndicateAdSplitUiState.Content,
    onDraftChange: (Int) -> Unit,
    onReset: () -> Unit,
    onSave: () -> Unit,
) {
    val draftBps = state.draftMemberShareBps
    val memberPct = (draftBps + 50) / 100
    val treasuryPct = (10000 - draftBps + 50) / 100
    // Net of a $1.00 syndicate ad on a member: owner share is 70c, split member/treasury; platform keeps 30c.
    val memberNet = draftBps * 70 / 10000
    val treasuryNet = 70 - memberNet

    Text(
        stringResource(R.string.syndicate_ad_split_desc),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.syndicate_ad_split_member, memberPct),
                style = MaterialTheme.typography.titleMedium,
            )
            Slider(
                value = draftBps.toFloat(),
                onValueChange = { onDraftChange(it.toInt()) },
                valueRange = 0f..SyndicateAdSplitViewModel.MAX_BPS.toFloat(),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(SyndicateAdSplitTestTags.SLIDER),
            )
            Text(
                stringResource(R.string.syndicate_ad_split_treasury, treasuryPct),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(
                    R.string.syndicate_ad_split_net,
                    centsUsd(memberNet),
                    centsUsd(treasuryNet),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    OutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.syndicate_ad_split_reset, (state.config.defaultMemberShareBps + 50) / 100))
    }

    state.error?.let {
        Text(it, color = MaterialTheme.colorScheme.error)
    }
    if (state.saved) {
        Text(
            stringResource(R.string.syndicate_ad_split_saved),
            color = MaterialTheme.colorScheme.primary,
        )
    }

    Button(
        onClick = onSave,
        enabled = state.dirty && !state.saving,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateAdSplitTestTags.SAVE),
    ) {
        if (state.saving) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
        Text(stringResource(R.string.syndicate_ad_split_save))
    }
}

private fun centsUsd(cents: Int): String = "$" + "%.2f".format(cents / 100.0)
