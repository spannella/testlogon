@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.GroupFundraiser
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-355 (sub-pages) - stable testTags for the group fundraising screen. */
object GroupFundraisingTestTags {
    const val SCREEN = "group_fundraising_screen"
    const val CREATE = "group_fundraising_create"
    const val ROW_PREFIX = "group_fundraising_row_"
}

@Composable
fun GroupFundraisingRoute(
    onBack: () -> Unit,
    viewModel: GroupFundraisingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupFundraisingScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onCreate = viewModel::create,
        onNoticeShown = viewModel::consumeNotice,
    )
}

@Composable
fun GroupFundraisingScreen(
    state: GroupFundraisingUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (title: String, description: String, goalCents: Long?) -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    (state as? GroupFundraisingUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }
    Scaffold(
        modifier = modifier.testTag(GroupFundraisingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_fundraising_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is GroupFundraisingUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupFundraisingUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupFundraisingUiState.Content ->
                GroupFundraisingContent(
                    state = state,
                    onCreate = onCreate,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun GroupFundraisingContent(
    state: GroupFundraisingUiState.Content,
    onCreate: (title: String, description: String, goalCents: Long?) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { CreateFundraiserCard(enabled = !state.isCreating, onCreate = onCreate) }

        item {
            Text(
                text = stringResource(R.string.group_fundraising_list_section),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (state.fundraisers.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.group_fundraising_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(state.fundraisers, key = { it.fundraiserId }) { f ->
                FundraiserCard(f)
            }
        }
    }
}

@Composable
private fun CreateFundraiserCard(
    enabled: Boolean,
    onCreate: (title: String, description: String, goalCents: Long?) -> Unit,
) {
    var title by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var goal by remember { mutableStateOf("") }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.group_fundraising_create_section),
                style = MaterialTheme.typography.titleSmall,
            )
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text(stringResource(R.string.group_fundraising_title_label)) },
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = description,
                onValueChange = { description = it },
                label = { Text(stringResource(R.string.group_fundraising_description_label)) },
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = goal,
                onValueChange = { v -> goal = v.filter { it.isDigit() } },
                label = { Text(stringResource(R.string.group_fundraising_goal_label)) },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    val goalCents = goal.toLongOrNull()?.times(100)
                    onCreate(title.trim(), description.trim(), goalCents)
                    title = ""
                    description = ""
                    goal = ""
                },
                enabled = enabled && title.isNotBlank(),
                modifier = Modifier.testTag(GroupFundraisingTestTags.CREATE),
            ) {
                if (!enabled) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    Text(stringResource(R.string.group_fundraising_create_action))
                }
            }
        }
    }
}

@Composable
private fun FundraiserCard(f: GroupFundraiser) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupFundraisingTestTags.ROW_PREFIX + f.fundraiserId),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = f.title,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                Text(text = f.status, style = MaterialTheme.typography.labelMedium)
            }
            if (!f.description.isNullOrBlank()) {
                Text(
                    text = f.description!!,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val raised = formatMoney(f.raisedCents, f.currency)
            val goalText = f.goalCents?.let { formatMoney(it, f.currency) }
            Text(
                text = if (goalText != null) {
                    stringResource(R.string.group_fundraising_raised_of_goal, raised, goalText)
                } else {
                    stringResource(R.string.group_fundraising_raised, raised)
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            f.progress?.let { p ->
                LinearProgressIndicator(progress = { p }, modifier = Modifier.fillMaxWidth())
            }
            Text(
                text = stringResource(R.string.group_fundraising_donations, f.donationCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
