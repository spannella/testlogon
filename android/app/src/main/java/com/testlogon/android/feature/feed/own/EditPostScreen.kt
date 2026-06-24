package com.testlogon.android.feature.feed.own

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * FD1 -- edit an owned post's text. Loads the current body on entry and saves via PATCH /posts/{id}.
 */
@Composable
fun EditPostRoute(
    postId: String,
    onBack: () -> Unit,
    viewModel: EditPostViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(postId) { viewModel.load(postId) }
    LaunchedEffect(state.saved) { if (state.saved) onBack() }

    EditPostScreen(
        state = state,
        onBack = onBack,
        onBodyChange = viewModel::onBodyChange,
        onSave = viewModel::save,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditPostScreen(
    state: EditPostUiState,
    onBack: () -> Unit,
    onBodyChange: (String) -> Unit,
    onSave: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag("edit_post_screen"),
        topBar = {
            TopAppBar(
                title = { Text("Edit post") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(
                        onClick = onSave,
                        enabled = state.canSave,
                        modifier = Modifier.testTag("edit_post_save"),
                    ) { Text("Save") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (state.loading) {
                Box(Modifier.fillMaxWidth().padding(top = 24.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
            } else {
                OutlinedTextField(
                    value = state.body,
                    onValueChange = onBodyChange,
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("edit_post_body"),
                    placeholder = { Text("Update your post...") },
                    minLines = 4,
                )
                state.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                if (state.submitting) {
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp))
                    }
                }
            }
        }
    }
}
