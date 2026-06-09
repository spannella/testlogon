package com.testlogon.android.feature.settings.language

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import com.testlogon.android.core.model.locale.LocaleTag
import com.testlogon.android.R
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** AND-114 — route-level in-app language picker. */
@Composable
fun LanguagePickerRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LanguagePickerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LanguagePickerScreen(
        state = state,
        onSelect = viewModel::onSelect,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguagePickerScreen(
    state: LanguagePickerUiState,
    onSelect: (LocaleTag?) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("language_picker_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.language_picker_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("language_picker_back")) {
                        // AutoMirrored back arrow mirrors correctly under RTL (AND-114 RTL audit).
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.language_picker_back),
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
                .selectableGroup(),
        ) {
            state.options.forEach { option ->
                LocaleRow(
                    option = option,
                    selected = option.tag == state.selectedTag,
                    onSelect = { onSelect(option.tag) },
                )
            }
        }
    }
}

@Composable
private fun LocaleRow(
    option: LocaleOption,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    val label = if (option.tag == null) {
        stringResource(R.string.language_picker_system_default)
    } else {
        option.displayName
    }
    val tag = "language_option_${option.tag?.value ?: "system"}"
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag)
            // start/end-safe selectable row; Role.RadioButton gives TalkBack the selected state.
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
        headlineContent = { Text(label) },
        leadingContent = { RadioButton(selected = selected, onClick = null) },
    )
}
