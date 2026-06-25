@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.capitalize
import androidx.compose.ui.text.intl.Locale
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * B-SUP (batch 7) - USER create-a-ticket form. POST /tickets {subject,description,priority}; on success it
 * invokes [onCreated] with the new ticket id so the caller can open the thread.
 */
@Composable
fun CreateTicketRoute(
    onBack: () -> Unit,
    onCreated: (ticketId: String) -> Unit,
    viewModel: CreateTicketViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(state.createdTicketId) {
        val id = state.createdTicketId
        if (id != null) {
            viewModel.consumeCreated()
            onCreated(id)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("New support ticket") },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { p ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(p)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.subject,
                onValueChange = viewModel::onSubjectChange,
                label = { Text("Subject") },
                singleLine = true,
                isError = state.subject.isNotEmpty() && !state.subjectValid,
                supportingText = { Text("3-160 characters") },
                modifier = Modifier.fillMaxWidth().testTag(SupportTestTags.CREATE_SUBJECT),
            )
            OutlinedTextField(
                value = state.description,
                onValueChange = viewModel::onDescriptionChange,
                label = { Text("How can we help?") },
                minLines = 4,
                isError = state.description.isNotEmpty() && !state.descriptionValid,
                modifier = Modifier.fillMaxWidth().testTag(SupportTestTags.CREATE_DESCRIPTION),
            )
            Text("Priority", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                viewModel.priorities.forEach { pr ->
                    FilterChip(
                        selected = state.priority == pr,
                        onClick = { viewModel.onPriorityChange(pr) },
                        label = { Text(pr.capitalize(Locale.current)) },
                    )
                }
            }
            if (state.error != null) {
                Text(state.error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(4.dp))
            Button(
                onClick = viewModel::submit,
                enabled = state.canSubmit,
                modifier = Modifier.fillMaxWidth().testTag(SupportTestTags.CREATE_SUBMIT),
            ) {
                if (state.submitting) {
                    CircularProgressIndicator(Modifier.height(20.dp), strokeWidth = 2.dp)
                } else {
                    Text("Submit ticket")
                }
            }
        }
    }
}
