@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sponsoredpost.ui

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

/** ADV2-407 - stable testTags for the advertiser sponsored-post composer. */
object SponsoredPostComposeTestTags {
    const val SCREEN = "spcp_compose_screen"
    const val CREATOR = "spcp_compose_creator"
    const val BODY = "spcp_compose_body"
    const val ACCOUNT = "spcp_compose_account"
    const val CAMPAIGN = "spcp_compose_campaign"
    const val SUBMIT = "spcp_compose_submit"
    const val SUCCESS = "spcp_compose_success"
    const val DONE = "spcp_compose_done"
}

/** ADV2-407 - route-level advertiser composer entry. */
@Composable
fun SponsoredPostComposeRoute(
    onBack: () -> Unit,
    onDone: () -> Unit,
    viewModel: SponsoredPostComposeViewModel = hiltViewModel(),
) {
    val creator by viewModel.creatorSub.collectAsStateWithLifecycle()
    val body by viewModel.body.collectAsStateWithLifecycle()
    val account by viewModel.accountId.collectAsStateWithLifecycle()
    val campaign by viewModel.campaignId.collectAsStateWithLifecycle()
    val label by viewModel.sponsorLabel.collectAsStateWithLifecycle()
    val disclosure by viewModel.disclosure.collectAsStateWithLifecycle()
    val submit by viewModel.submitState.collectAsStateWithLifecycle()
    SponsoredPostComposeScreen(
        creator = creator,
        body = body,
        account = account,
        campaign = campaign,
        label = label,
        disclosure = disclosure,
        submitState = submit,
        canSubmit = viewModel.canSubmit,
        onCreator = viewModel::onCreatorSub,
        onBody = viewModel::onBody,
        onAccount = viewModel::onAccountId,
        onCampaign = viewModel::onCampaignId,
        onLabel = viewModel::onSponsorLabel,
        onDisclosure = viewModel::onDisclosure,
        onSubmit = viewModel::submit,
        onDone = onDone,
        onBack = onBack,
    )
}

/** ADV2-407 - stateless advertiser sponsored-post composer form. */
@Composable
fun SponsoredPostComposeScreen(
    creator: String,
    body: String,
    account: String,
    campaign: String,
    label: String,
    disclosure: String,
    submitState: SponsoredPostComposeViewModel.SubmitState,
    canSubmit: Boolean,
    onCreator: (String) -> Unit,
    onBody: (String) -> Unit,
    onAccount: (String) -> Unit,
    onCampaign: (String) -> Unit,
    onLabel: (String) -> Unit,
    onDisclosure: (String) -> Unit,
    onSubmit: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = submitState is SponsoredPostComposeViewModel.SubmitState.Submitting
    Scaffold(
        modifier = modifier.testTag(SponsoredPostComposeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.spcp_compose_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.spcp_back),
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
            val success = submitState as? SponsoredPostComposeViewModel.SubmitState.Success
            if (success != null) {
                ProposalSentCard(onDone = onDone)
                return@Column
            }

            Text(
                text = stringResource(R.string.spcp_compose_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = creator,
                onValueChange = onCreator,
                label = { Text(stringResource(R.string.spcp_compose_creator_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.CREATOR),
            )
            OutlinedTextField(
                value = body,
                onValueChange = onBody,
                label = { Text(stringResource(R.string.spcp_compose_body_label)) },
                minLines = 4,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.BODY),
            )

            Text(
                text = stringResource(R.string.spcp_compose_billing_header),
                style = MaterialTheme.typography.titleSmall,
            )
            OutlinedTextField(
                value = account,
                onValueChange = onAccount,
                label = { Text(stringResource(R.string.spcp_compose_account_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.ACCOUNT),
            )
            OutlinedTextField(
                value = campaign,
                onValueChange = onCampaign,
                label = { Text(stringResource(R.string.spcp_compose_campaign_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.CAMPAIGN),
            )

            OutlinedTextField(
                value = label,
                onValueChange = onLabel,
                label = { Text(stringResource(R.string.spcp_compose_label_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = disclosure,
                onValueChange = onDisclosure,
                label = { Text(stringResource(R.string.spcp_compose_disclosure_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth(),
            )

            (submitState as? SponsoredPostComposeViewModel.SubmitState.Error)?.let {
                Text(
                    text = it.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = canSubmit && !submitting,
                modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.SUBMIT),
            ) {
                if (submitting) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text(stringResource(R.string.spcp_compose_submit))
            }
            Text(
                text = stringResource(R.string.spcp_compose_footnote),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ProposalSentCard(onDone: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SponsoredPostComposeTestTags.SUCCESS)) {
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
                text = stringResource(R.string.spcp_compose_sent_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.spcp_compose_sent_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onDone,
                modifier = Modifier.testTag(SponsoredPostComposeTestTags.DONE),
            ) {
                Text(stringResource(R.string.spcp_compose_done))
            }
        }
    }
}
