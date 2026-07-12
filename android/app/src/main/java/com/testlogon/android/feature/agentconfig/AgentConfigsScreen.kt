@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agentconfig

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
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.foundation.clickable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.agentconfig.AgentConfigType

object AgentConfigsHubTestTags {
    const val SCREEN = "agent_configs_hub_screen"
    const val TYPE_ID = "agent_configs_type_id"
    fun row(type: String) = "agent_configs_row_$type"
}

/**
 * Landing hub for the five agent-type config surfaces (web /agents/types/:typeId config pages). There is no agent-types
 * dashboard on the mobile client to source the runtime typeId, so this screen lets the operator enter the
 * typeId (defaults to each type's canonical name, e.g. "coder") and drill into the parametrized config screen.
 * Operator-gated on the backend - non-operators get 403 inside the config screen (Forbidden state).
 */
@Composable
fun AgentConfigsRoute(
    onBack: () -> Unit,
    onOpen: (type: String, typeId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var typeId by rememberSaveable { mutableStateOf("") }

    Scaffold(
        modifier = modifier.testTag(AgentConfigsHubTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent Type Configs") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    "Operator-only. Configure per-agent-type behaviour (coder, QA, DevOps, architect, PM).",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            item {
                OutlinedTextField(
                    value = typeId,
                    onValueChange = { typeId = it },
                    label = { Text("Agent type id (optional)") },
                    supportingText = { Text("Leave blank to use the canonical type name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(AgentConfigsHubTestTags.TYPE_ID),
                )
            }
            items(AgentConfigType.entries, key = { it.typeName }) { type ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AgentConfigsHubTestTags.row(type.typeName))
                        .clickable {
                            onOpen(type.typeName, typeId.trim().ifEmpty { type.typeName })
                        },
                ) {
                    ListItem(
                        headlineContent = { Text(type.title) },
                        supportingContent = { Text("${type.fields.size} settings") },
                        trailingContent = {
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                        },
                    )
                }
            }
        }
    }
}
