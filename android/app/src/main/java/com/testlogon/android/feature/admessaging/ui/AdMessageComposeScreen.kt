@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admessaging.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** ADV2-501/507 — stable testTags for the advertiser sponsored-message composer. */
object AdMessageComposeTestTags {
    const val SCREEN = "admsg_compose_screen"
    const val CREATOR = "admsg_compose_creator"
    const val BODY = "admsg_compose_body"
    const val CTA = "admsg_compose_cta"
    const val ACCOUNT = "admsg_compose_account"
    const val CAMPAIGN = "admsg_compose_campaign"
    const val SUBMIT = "admsg_compose_submit"
    const val SUCCESS = "admsg_compose_success"
    const val DONE = "admsg_compose_done"
}

/** ADV2-501/507 — route-level advertiser sponsored-message composer entry. */
@Composable
fun AdMessageComposeRoute(
    onBack: () -> Unit,
    onDone: () -> Unit,
    viewModel: AdMessageComposeViewModel = hiltViewModel(),
) {
    val creator by viewModel.creatorSub.collectAsStateWithLifecycle()
    val body by viewModel.body.collectAsStateWithLifecycle()
    val cta by viewModel.ctaUrl.collectAsStateWithLifecycle()
    val account by viewModel.accountId.collectAsStateWithLifecycle()
    val campaign by viewModel.campaignId.collectAsStateWithLifecycle()
    val label by viewModel.sponsorLabel.collectAsStateWithLifecycle()
    val submit by viewModel.submitState.collectAsStateWithLifecycle()
    AdMessageComposeScreen(
        creator = creator,
        body = body,
        cta = cta,
        account = account,
        campaign = campaign,
        label = label,
        submitState = submit,
        canSubmit = viewModel.canSubmit,
        onCreator = viewModel::onCreatorSub,
        onBody = viewModel::onBody,
        onCta = viewModel::onCtaUrl,
        onAccount = viewModel::onAccountId,
        onCampaign = viewModel::onCampaignId,
        onLabel = viewModel::onSponsorLabel,
        onSubmit = viewModel::submit,
        onDone = onDone,
        onBack = onBack,
    )
}

/** ADV2-501/507 — stateless advertiser sponsored-message composer form. */
@Composable
fun AdMessageComposeScreen(
    creator: String,
    body: String,
    cta: String,
    account: String,
    campaign: String,
    label: String,
    submitState: AdMessageComposeViewModel.SubmitState,
    canSubmit: Boolean,
    onCreator: (String) -> Unit,
    onBody: (String) -> Unit,
    onCta: (String) -> Unit,
    onAccount: (String) -> Unit,
    onCampaign: (String) -> Unit,
    onLabel: (String) -> Unit,
    onSubmit: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = submitState is AdMessageComposeViewModel.SubmitState.Submitting
    Scaffold(
        modifier = modifier.testTag(AdMessageComposeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.admsg_compose_title)) },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            val success = submitState as? AdMessageComposeViewModel.SubmitState.Success
            if (success != null) {
                OfferSentCard(onDone = onDone)
                return@Column
            }

            Text(
                text = stringResource(R.string.admsg_compose_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = creator,
                onValueChange = onCreator,
                label = { Text(stringResource(R.string.admsg_compose_creator_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.CREATOR),
            )
            OutlinedTextField(
                value = body,
                onValueChange = onBody,
                label = { Text(stringResource(R.string.admsg_compose_body_label)) },
                minLines = 4,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.BODY),
            )
            OutlinedTextField(
                value = cta,
                onValueChange = onCta,
                label = { Text(stringResource(R.string.admsg_compose_cta_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.CTA),
            )

            Text(
                text = stringResource(R.string.admsg_compose_billing_header),
                style = MaterialTheme.typography.titleSmall,
            )
            OutlinedTextField(
                value = account,
                onValueChange = onAccount,
                label = { Text(stringResource(R.string.admsg_compose_account_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.ACCOUNT),
            )
            OutlinedTextField(
                value = campaign,
                onValueChange = onCampaign,
                label = { Text(stringResource(R.string.admsg_compose_campaign_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.CAMPAIGN),
            )
            OutlinedTextField(
                value = label,
                onValueChange = onLabel,
                label = { Text(stringResource(R.string.admsg_compose_label_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth(),
            )

            (submitState as? AdMessageComposeViewModel.SubmitState.Error)?.let {
                Text(
                    text = it.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = canSubmit && !submitting,
                modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.SUBMIT),
            ) {
                if (submitting) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text(stringResource(R.string.admsg_compose_submit))
            }
            Text(
                text = stringResource(R.string.admsg_compose_footnote),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun OfferSentCard(onDone: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdMessageComposeTestTags.SUCCESS)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = stringResource(R.string.admsg_compose_sent_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.admsg_compose_sent_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onDone,
                modifier = Modifier.testTag(AdMessageComposeTestTags.DONE),
            ) {
                Text(stringResource(R.string.admsg_compose_done))
            }
        }
    }
}
