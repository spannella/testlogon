@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.run.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.clickable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.agentrun.AgentRunType

/**
 * AGENT-RUN (web-parity) - landing hub for the run console: lists the six executable agent types + an optional
 * typeId override (defaults to the type name, matching the AgentConfig hub idiom), then drills into the ONE
 * parametrized [AgentRunConsoleScreen] keyed by {type}/{typeId}.
 */
object AgentRunHubTestTags {
    const val SCREEN = "agent_run_hub_screen"
    fun row(typeName: String) = "agent_run_hub_row_$typeName"
}

@Composable
fun AgentRunHubRoute(
    onBack: () -> Unit,
    onOpen: (type: String, typeId: String) -> Unit,
) {
    var typeId by remember { mutableStateOf("") }
    Scaffold(
        modifier = Modifier.testTag(AgentRunHubTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent run console") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Agent type id (optional)")
                    OutlinedTextField(
                        value = typeId,
                        onValueChange = { typeId = it },
                        placeholder = { Text("defaults to the type name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(AgentRunType.entries.toList(), key = { it.typeName }) { type ->
                    val resolved = typeId.trim().ifBlank { type.typeName }
                    ListItem(
                        headlineContent = { Text(type.title) },
                        supportingContent = { Text("type: ${type.typeName}") },
                        leadingContent = { Icon(Icons.Outlined.SmartToy, contentDescription = null) },
                        trailingContent = {
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(AgentRunHubTestTags.row(type.typeName))
                            .clickable { onOpen(type.typeName, resolved) },
                    )
                }
            }
        }
    }
}
