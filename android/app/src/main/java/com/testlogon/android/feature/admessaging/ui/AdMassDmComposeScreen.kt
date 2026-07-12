@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admessaging.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Group
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.admessaging.data.AdDmAudience
import com.testlogon.android.feature.admessaging.data.AdMessageSend

/** ADV2-607 — stable testTags for the advertiser mass-DM composer. */
object AdMassDmComposeTestTags {
    const val SCREEN = "admsg_massdm_screen"
    const val AUDIENCE = "admsg_massdm_audience"
    const val BODY = "admsg_massdm_body"
    const val CTA = "admsg_massdm_cta"
    const val ACCOUNT = "admsg_massdm_account"
    const val CAMPAIGN = "admsg_massdm_campaign"
    const val SEND = "admsg_massdm_send"
    const val SUCCESS = "admsg_massdm_success"
    const val DONE = "admsg_massdm_done"
}

/** ADV2-607 — route-level advertiser mass-DM composer entry. */
@Composable
fun AdMassDmComposeRoute(
    onBack: () -> Unit,
    onDone: () -> Unit,
    viewModel: AdMassDmComposeViewModel = hiltViewModel(),
) {
    val audience by viewModel.audience.collectAsStateWithLifecycle()
    val body by viewModel.body.collectAsStateWithLifecycle()
    val cta by viewModel.ctaUrl.collectAsStateWithLifecycle()
    val account by viewModel.accountId.collectAsStateWithLifecycle()
    val campaign by viewModel.campaignId.collectAsStateWithLifecycle()
    val label by viewModel.sponsorLabel.collectAsStateWithLifecycle()
    val send by viewModel.sendState.collectAsStateWithLifecycle()
    AdMassDmComposeScreen(
        audience = audience,
        body = body,
        cta = cta,
        account = account,
        campaign = campaign,
        label = label,
        sendState = send,
        canSend = viewModel.canSend,
        onBody = viewModel::onBody,
        onCta = viewModel::onCtaUrl,
        onAccount = viewModel::onAccountId,
        onCampaign = viewModel::onCampaignId,
        onLabel = viewModel::onSponsorLabel,
        onReloadAudience = viewModel::loadAudience,
        onSend = viewModel::send,
        onDone = onDone,
        onBack = onBack,
    )
}

/** ADV2-607 — stateless advertiser mass-DM composer form. */
@Composable
fun AdMassDmComposeScreen(
    audience: AdMassDmComposeViewModel.AudienceState,
    body: String,
    cta: String,
    account: String,
    campaign: String,
    label: String,
    sendState: AdMassDmComposeViewModel.SendState,
    canSend: Boolean,
    onBody: (String) -> Unit,
    onCta: (String) -> Unit,
    onAccount: (String) -> Unit,
    onCampaign: (String) -> Unit,
    onLabel: (String) -> Unit,
    onReloadAudience: () -> Unit,
    onSend: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val sending = sendState is AdMassDmComposeViewModel.SendState.Sending
    Scaffold(
        modifier = modifier.testTag(AdMassDmComposeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.admsg_massdm_title)) },
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
            (sendState as? AdMassDmComposeViewModel.SendState.Success)?.let {
                MassDmSentCard(send = it.send, onDone = onDone)
                return@Column
            }

            Text(
                text = stringResource(R.string.admsg_massdm_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            AudienceCard(audience = audience, onReload = onReloadAudience)

            OutlinedTextField(
                value = body,
                onValueChange = onBody,
                label = { Text(stringResource(R.string.admsg_massdm_body_label)) },
                minLines = 4,
                enabled = !sending,
                modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.BODY),
            )
            OutlinedTextField(
                value = cta,
                onValueChange = onCta,
                label = { Text(stringResource(R.string.admsg_compose_cta_label)) },
                singleLine = true,
                enabled = !sending,
                modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.CTA),
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
                enabled = !sending,
                modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.ACCOUNT),
            )
            OutlinedTextField(
                value = campaign,
                onValueChange = onCampaign,
                label = { Text(stringResource(R.string.admsg_compose_campaign_label)) },
                singleLine = true,
                enabled = !sending,
                modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.CAMPAIGN),
            )
            OutlinedTextField(
                value = label,
                onValueChange = onLabel,
                label = { Text(stringResource(R.string.admsg_compose_label_label)) },
                singleLine = true,
                enabled = !sending,
                modifier = Modifier.fillMaxWidth(),
            )

            (sendState as? AdMassDmComposeViewModel.SendState.Error)?.let {
                Text(
                    text = it.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSend,
                enabled = canSend && !sending,
                modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.SEND),
            ) {
                if (sending) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text(stringResource(R.string.admsg_massdm_send))
            }
            Text(
                text = stringResource(R.string.admsg_massdm_footnote),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AudienceCard(
    audience: AdMassDmComposeViewModel.AudienceState,
    onReload: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.AUDIENCE)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Outlined.Group,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = stringResource(R.string.admsg_massdm_audience_title),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            when (audience) {
                is AdMassDmComposeViewModel.AudienceState.Loading ->
                    CircularProgressIndicator(modifier = Modifier.padding(top = 4.dp))

                is AdMassDmComposeViewModel.AudienceState.Error -> {
                    Text(
                        text = audience.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    OutlinedButton(onClick = onReload) {
                        Text(stringResource(R.string.admsg_massdm_audience_retry))
                    }
                }

                is AdMassDmComposeViewModel.AudienceState.Loaded -> AudienceSummary(audience.audience)
            }
        }
    }
}

@Composable
private fun AudienceSummary(audience: AdDmAudience) {
    Text(
        text = pluralStringResource(R.plurals.admsg_massdm_reachable, audience.count, audience.count),
        style = MaterialTheme.typography.bodyLarge,
    )
    Text(
        text = stringResource(R.string.admsg_massdm_audience_explainer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (audience.excludedOptoutCount > 0) {
        Text(
            text = pluralStringResource(
                R.plurals.admsg_massdm_excluded_optout,
                audience.excludedOptoutCount,
                audience.excludedOptoutCount,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun MassDmSentCard(send: AdMessageSend, onDone: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdMassDmComposeTestTags.SUCCESS)) {
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
                text = pluralStringResource(
                    R.plurals.admsg_massdm_sent_title,
                    send.deliveredCount,
                    send.deliveredCount,
                ),
                style = MaterialTheme.typography.titleMedium,
            )
            if (send.paused) {
                Text(
                    text = stringResource(R.string.admsg_massdm_paused_funds),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            OutlinedButton(
                onClick = onDone,
                modifier = Modifier.testTag(AdMassDmComposeTestTags.DONE),
            ) {
                Text(stringResource(R.string.admsg_compose_done))
            }
        }
    }
}
