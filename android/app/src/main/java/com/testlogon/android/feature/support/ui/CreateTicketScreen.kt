@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.InsertDriveFile
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.text.capitalize
import androidx.compose.ui.text.intl.Locale
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * B-SUP (batch 7) - USER create-a-ticket form. POST /tickets {subject,description,priority,media[]}; on
 * success it invokes [onCreated] with the new ticket id so the caller can open the thread.
 *
 * B10 B-HELPMEDIA #5 - the opening message can attach a LIST of images / videos / files (device pickers)
 * AND files from the in-app file manager, like a newsfeed post.
 */
@Composable
fun CreateTicketRoute(
    onBack: () -> Unit,
    onCreated: (ticketId: String) -> Unit,
    viewModel: CreateTicketViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addImage(uri) }
    val videoPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addVideo(uri) }
    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.addFile(uri) }

    var showFilePicker by remember { mutableStateOf(false) }
    if (showFilePicker) {
        FileManagerPickerDialog(
            onDismiss = { showFilePicker = false },
            onPick = { node -> showFilePicker = false; viewModel.addFileRef(node) },
        )
    }

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

            // B10 B-HELPMEDIA #5 - multi-media attachments.
            Text("Attachments", style = MaterialTheme.typography.labelLarge)
            AttachmentActions(
                enabled = !state.submitting && !state.mediaFull,
                onImage = { imagePicker.launch("image/*") },
                onVideo = { videoPicker.launch("video/*") },
                onFile = { filePicker.launch("*/*") },
                onFromFiles = { showFilePicker = true },
            )
            StagedMediaStrip(media = state.media, onRemove = viewModel::removeMedia)
            if (state.mediaFull) {
                Text(
                    "Attachment limit reached.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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

/** The image / video / file / from-Files attach buttons shared by both composers. */
@Composable
fun AttachmentActions(
    enabled: Boolean,
    onImage: () -> Unit,
    onVideo: () -> Unit,
    onFile: () -> Unit,
    onFromFiles: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        AssistChip(
            onClick = onImage,
            enabled = enabled,
            leadingIcon = { Icon(Icons.Outlined.Image, contentDescription = null, modifier = Modifier.height(18.dp)) },
            label = { Text("Image") },
            modifier = Modifier.testTag(SupportTestTags.ATTACH_IMAGE),
        )
        AssistChip(
            onClick = onVideo,
            enabled = enabled,
            leadingIcon = { Icon(Icons.Outlined.Videocam, contentDescription = null, modifier = Modifier.height(18.dp)) },
            label = { Text("Video") },
            modifier = Modifier.testTag(SupportTestTags.ATTACH_VIDEO),
        )
        AssistChip(
            onClick = onFile,
            enabled = enabled,
            leadingIcon = {
                Icon(Icons.AutoMirrored.Outlined.InsertDriveFile, contentDescription = null, modifier = Modifier.height(18.dp))
            },
            label = { Text("File") },
            modifier = Modifier.testTag(SupportTestTags.ATTACH_FILE),
        )
        AssistChip(
            onClick = onFromFiles,
            enabled = enabled,
            leadingIcon = { Icon(Icons.Outlined.Folder, contentDescription = null, modifier = Modifier.height(18.dp)) },
            label = { Text("Files") },
            colors = AssistChipDefaults.assistChipColors(),
            modifier = Modifier.testTag(SupportTestTags.ATTACH_FROM_FILES),
        )
    }
}
