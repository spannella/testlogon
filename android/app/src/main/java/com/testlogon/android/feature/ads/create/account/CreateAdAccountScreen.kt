@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.create.account

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
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
import com.testlogon.android.core.model.ads.AdAccountRef

/** ADV-107 - stable testTags for the create-ad-account screen. */
object CreateAdAccountTestTags {
    const val SCREEN = "create_ad_account_screen"
    const val COMPANY = "create_ad_account_company"
    const val EMAIL = "create_ad_account_email"
    const val SUBMIT = "create_ad_account_submit"
    const val SUCCESS = "create_ad_account_success"
    const val CONTINUE = "create_ad_account_continue"
}

/**
 * ADV-107 - route-level create-ad-account entry. On success, [onCreated] carries the new account id so the
 * flow can continue into campaign creation.
 */
@Composable
fun CreateAdAccountRoute(
    onBack: () -> Unit,
    onCreated: (accountId: String) -> Unit,
    viewModel: CreateAdAccountViewModel = hiltViewModel(),
) {
    val company by viewModel.companyName.collectAsStateWithLifecycle()
    val email by viewModel.billingEmail.collectAsStateWithLifecycle()
    val submit by viewModel.submitState.collectAsStateWithLifecycle()
    CreateAdAccountScreen(
        company = company,
        email = email,
        submitState = submit,
        canSubmit = viewModel.canSubmit,
        onCompany = viewModel::onCompanyName,
        onEmail = viewModel::onBillingEmail,
        onSubmit = viewModel::submit,
        onContinue = onCreated,
        onBack = onBack,
    )
}

/** ADV-107 - stateless create-ad-account form. */
@Composable
fun CreateAdAccountScreen(
    company: String,
    email: String,
    submitState: CreateAdAccountViewModel.SubmitState,
    canSubmit: Boolean,
    onCompany: (String) -> Unit,
    onEmail: (String) -> Unit,
    onSubmit: () -> Unit,
    onContinue: (accountId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = submitState is CreateAdAccountViewModel.SubmitState.Submitting
    Scaffold(
        modifier = modifier.testTag(CreateAdAccountTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_ad_account_title)) },
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
            val success = submitState as? CreateAdAccountViewModel.SubmitState.Success
            if (success != null) {
                AccountCreatedCard(account = success.account, onContinue = onContinue)
                return@Column
            }

            Text(
                text = stringResource(R.string.create_ad_account_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = company,
                onValueChange = onCompany,
                label = { Text(stringResource(R.string.create_ad_account_company_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateAdAccountTestTags.COMPANY),
            )

            OutlinedTextField(
                value = email,
                onValueChange = onEmail,
                label = { Text(stringResource(R.string.create_ad_account_email_label)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateAdAccountTestTags.EMAIL),
            )

            (submitState as? CreateAdAccountViewModel.SubmitState.Error)?.let {
                Text(
                    text = it.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = canSubmit && !submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateAdAccountTestTags.SUBMIT),
            ) {
                if (submitting) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text(stringResource(R.string.create_ad_account_submit))
            }
        }
    }
}

@Composable
private fun AccountCreatedCard(
    account: AdAccountRef,
    onContinue: (accountId: String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CreateAdAccountTestTags.SUCCESS),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.create_ad_account_success_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(
                    R.string.create_ad_account_success_body,
                    account.companyName ?: account.accountId,
                    account.status ?: "pending_review",
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { onContinue(account.accountId) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateAdAccountTestTags.CONTINUE),
            ) {
                Text(stringResource(R.string.create_ad_account_continue))
            }
        }
    }
}
