@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.input.TlButton

/** AND-353 - stable testTags for the invite-member screen. */
object InviteMemberTestTags {
    const val SCREEN = "invite_member_screen"
    const val EMAIL = "invite_email"
    const val ROLE = "invite_role"
    const val SUBMIT = "invite_submit"
}

/**
 * AND-353 - route-level invite-member entry. Shares the [OrgMembersViewModel] (folded invite logic) with
 * the members screen so the new pending invite lands in the shared roster state; on a successful submit
 * the caller pops back to the roster.
 */
@Composable
fun InviteMemberRoute(
    onBack: () -> Unit,
    viewModel: OrgMembersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val content = state as? OrgMembersUiState.Content
    val isInviting = content?.isInviting == true
    val pendingCount = content?.pendingInvites?.size ?: 0

    // Pop back to the roster once a new pending invite has been appended (count grew while not inviting).
    var baseline by remember { mutableStateOf(-1) }
    LaunchedEffect(content != null) {
        if (baseline < 0 && content != null) baseline = pendingCount
    }
    LaunchedEffect(pendingCount, isInviting) {
        if (baseline >= 0 && !isInviting && pendingCount > baseline) {
            onBack()
        }
    }

    InviteMemberScreen(
        isSubmitting = isInviting,
        onSubmit = { email, role -> viewModel.inviteMember(email, role) },
        onBack = onBack,
    )
}

/** AND-353 - stateless invite-member form (email + role picker admin/member/viewer). */
@Composable
fun InviteMemberScreen(
    isSubmitting: Boolean,
    onSubmit: (email: String, role: OrgRole) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var email by remember { mutableStateOf("") }
    var role by remember { mutableStateOf(OrgRole.MEMBER) }

    Scaffold(
        modifier = modifier.testTag(InviteMemberTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.invite_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.orgs_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text(stringResource(R.string.invite_email_label)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(InviteMemberTestTags.EMAIL),
            )

            InviteRolePicker(
                selected = role,
                onSelect = { role = it },
                modifier = Modifier.testTag(InviteMemberTestTags.ROLE),
            )

            // email regex per the wire contract: required, length 3..254 (light client guard).
            val emailValid = email.trim().length in 3..254 && email.contains("@")
            TlButton(
                text = stringResource(R.string.invite_submit),
                onClick = { onSubmit(email.trim(), role) },
                enabled = emailValid && !isSubmitting,
                loading = isSubmitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(InviteMemberTestTags.SUBMIT),
            )
        }
    }
}

/** AND-353 - role picker offering admin/member/viewer ONLY (owner is NOT invitable). */
@Composable
private fun InviteRolePicker(
    selected: OrgRole,
    onSelect: (OrgRole) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = roleLabel(selected),
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.orgs_role_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            OrgRole.ASSIGNABLE.forEach { option ->
                DropdownMenuItem(
                    text = { Text(roleLabel(option)) },
                    onClick = {
                        expanded = false
                        onSelect(option)
                    },
                )
            }
        }
    }
}
