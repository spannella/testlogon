@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.ads.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Percent
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.SyndicateAdPlacementConfig

/** ADV2-709/710/711 - stable testTags for the syndicate-ads hub. */
object SyndicateAdsTestTags {
    const val SCREEN = "syndicate_ads_screen"
    const val COMPANY = "syndicate_ads_company"
    const val EMAIL = "syndicate_ads_email"
    const val CREATE = "syndicate_ads_create"
    const val EDIT_SPLIT = "syndicate_ads_edit_split"
    const val ACCOUNT_ROW = "syndicate_ads_account_row"
}

/**
 * ADV2-709/710/711 - route-level syndicate-ads hub. Selecting/creating an account records it as the studio
 * selection (in the VM) so the REUSED create-campaign / create-creative / fund (billing) / earnings
 * (analytics/ROAS) destinations open against the SYNDICATE account.
 */
@Composable
fun SyndicateAdsRoute(
    onBack: () -> Unit,
    onCreateCampaign: () -> Unit,
    onCreateCreative: () -> Unit,
    onFund: (accountId: String) -> Unit,
    onViewEarnings: (accountId: String) -> Unit,
    onEditSplit: (syndicateId: String) -> Unit,
    viewModel: SyndicateAdsViewModel = hiltViewModel(),
) {
    val accounts by viewModel.accountsState.collectAsStateWithLifecycle()
    val config by viewModel.configState.collectAsStateWithLifecycle()
    val company by viewModel.companyName.collectAsStateWithLifecycle()
    val email by viewModel.billingEmail.collectAsStateWithLifecycle()
    val create by viewModel.createState.collectAsStateWithLifecycle()

    SyndicateAdsScreen(
        accountsState = accounts,
        configState = config,
        company = company,
        email = email,
        createState = create,
        canCreate = viewModel.canCreate,
        onCompany = viewModel::onCompanyName,
        onEmail = viewModel::onBillingEmail,
        onCreate = viewModel::createAccount,
        onRetry = viewModel::load,
        onEditSplit = { onEditSplit(viewModel.syndicateId) },
        onFund = { id -> viewModel.selectAccount(id); onFund(id) },
        onNewCampaign = { id -> viewModel.selectAccount(id); onCreateCampaign() },
        onNewCreative = { id -> viewModel.selectAccount(id); onCreateCreative() },
        onEarnings = { id -> viewModel.selectAccount(id); onViewEarnings(id) },
        onBack = onBack,
    )
}

/** ADV2-709/710/711 - stateless syndicate-ads hub. */
@Composable
fun SyndicateAdsScreen(
    accountsState: SyndicateAdsAccountsState,
    configState: SyndicateAdConfigState,
    company: String,
    email: String,
    createState: SyndicateAdCreateState,
    canCreate: Boolean,
    onCompany: (String) -> Unit,
    onEmail: (String) -> Unit,
    onCreate: () -> Unit,
    onRetry: () -> Unit,
    onEditSplit: () -> Unit,
    onFund: (String) -> Unit,
    onNewCampaign: (String) -> Unit,
    onNewCreative: (String) -> Unit,
    onEarnings: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = createState is SyndicateAdCreateState.Submitting
    Scaffold(
        modifier = modifier.testTag(SyndicateAdsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.syndicate_ads_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_create_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onEditSplit,
                        modifier = Modifier.testTag(SyndicateAdsTestTags.EDIT_SPLIT),
                    ) {
                        Icon(
                            Icons.Outlined.Percent,
                            contentDescription = stringResource(R.string.syndicate_ads_edit_split),
                        )
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    text = stringResource(R.string.syndicate_ads_subtitle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 12.dp),
                )
            }

            (configState as? SyndicateAdConfigState.Content)?.let { c ->
                item { SplitSummaryCard(config = c.config, onEditSplit = onEditSplit) }
            }

            item {
                CreateAccountCard(
                    company = company,
                    email = email,
                    createState = createState,
                    canCreate = canCreate,
                    submitting = submitting,
                    onCompany = onCompany,
                    onEmail = onEmail,
                    onCreate = onCreate,
                )
            }

            item {
                Text(
                    text = stringResource(R.string.syndicate_ads_accounts_title),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }

            when (accountsState) {
                is SyndicateAdsAccountsState.Loading ->
                    item { CircularProgressIndicator(modifier = Modifier.padding(16.dp)) }
                is SyndicateAdsAccountsState.Forbidden ->
                    item { InfoText(stringResource(R.string.syndicate_ads_forbidden)) }
                is SyndicateAdsAccountsState.Empty ->
                    item { InfoText(stringResource(R.string.syndicate_ads_empty)) }
                is SyndicateAdsAccountsState.Error -> item {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        InfoText(accountsState.message)
                        OutlinedButton(onClick = onRetry) {
                            Text(stringResource(R.string.syndicate_ads_retry))
                        }
                    }
                }
                is SyndicateAdsAccountsState.Content -> items(
                    accountsState.accounts,
                    key = { it.accountId ?: it.hashCode().toString() },
                ) { acct ->
                    AccountCard(
                        account = acct,
                        onFund = onFund,
                        onNewCampaign = onNewCampaign,
                        onNewCreative = onNewCreative,
                        onEarnings = onEarnings,
                    )
                }
            }

            item { Spacer(Modifier.padding(8.dp)) }
        }
    }
}

@Composable
private fun SplitSummaryCard(config: SyndicateAdPlacementConfig, onEditSplit: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                stringResource(R.string.syndicate_ads_split_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                stringResource(
                    R.string.syndicate_ads_split_summary,
                    config.memberPercentOfOwner,
                    config.treasuryPercentOfOwner,
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onEditSplit,
                modifier = Modifier.testTag(SyndicateAdsTestTags.EDIT_SPLIT + "_card"),
            ) {
                Text(stringResource(R.string.syndicate_ads_edit_split))
            }
        }
    }
}

@Composable
private fun CreateAccountCard(
    company: String,
    email: String,
    createState: SyndicateAdCreateState,
    canCreate: Boolean,
    submitting: Boolean,
    onCompany: (String) -> Unit,
    onEmail: (String) -> Unit,
    onCreate: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.syndicate_ads_create_title),
                style = MaterialTheme.typography.titleSmall,
            )
            OutlinedTextField(
                value = company,
                onValueChange = onCompany,
                label = { Text(stringResource(R.string.syndicate_ads_company_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(SyndicateAdsTestTags.COMPANY),
            )
            OutlinedTextField(
                value = email,
                onValueChange = onEmail,
                label = { Text(stringResource(R.string.syndicate_ads_email_label)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(SyndicateAdsTestTags.EMAIL),
            )
            (createState as? SyndicateAdCreateState.Error)?.let {
                Text(
                    it.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            (createState as? SyndicateAdCreateState.Success)?.let {
                Text(
                    stringResource(R.string.syndicate_ads_created, it.status ?: "pending_review"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Button(
                onClick = onCreate,
                enabled = canCreate && !submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(SyndicateAdsTestTags.CREATE),
            ) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.syndicate_ads_create_submit))
            }
        }
    }
}

@Composable
private fun AccountCard(
    account: AdAccountSummary,
    onFund: (String) -> Unit,
    onNewCampaign: (String) -> Unit,
    onNewCreative: (String) -> Unit,
    onEarnings: (String) -> Unit,
) {
    val id = account.accountId ?: return
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateAdsTestTags.ACCOUNT_ROW),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                account.companyName ?: id,
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                stringResource(
                    R.string.syndicate_ads_balance,
                    usd(account.balanceCents),
                    account.status ?: "-",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider()
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = { onFund(id) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.syndicate_ads_fund))
                }
                FilledTonalButton(onClick = { onEarnings(id) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.syndicate_ads_earnings))
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { onNewCampaign(id) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.syndicate_ads_new_campaign))
                }
                OutlinedButton(onClick = { onNewCreative(id) }, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.syndicate_ads_new_creative))
                }
            }
        }
    }
}

@Composable
private fun InfoText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 8.dp),
    )
}

private fun usd(cents: Long): String = "$" + "%.2f".format(cents / 100.0)
