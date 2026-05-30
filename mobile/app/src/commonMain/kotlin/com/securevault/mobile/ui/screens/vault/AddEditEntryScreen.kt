@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
package com.securevault.mobile.ui.screens.vault

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.securevault.mobile.di.koinInject
import kotlinx.coroutines.flow.collectLatest

@Composable
fun AddEditEntryScreen(
    entryId: Long?,
    onNavigateBack: () -> Unit,
    onSaveSuccess: () -> Unit,
    onReload: () -> Unit = {}
) {
    val viewModel: AddEditEntryViewModel = koinInject()
    val state by viewModel.state.collectAsState()
    val errorMessage = state.error

    LaunchedEffect(entryId) {
        if (entryId != null) {
            viewModel.handleIntent(AddEditEntryIntent.LoadEntry(entryId))
        }
    }

    LaunchedEffect(Unit) {
        viewModel.effect.collectLatest { effect ->
            when (effect) {
                is AddEditEntryEffect.NavigateBack -> onSaveSuccess()
                is AddEditEntryEffect.ReloadVault -> onReload()
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (state.isEditing) "Edit Entry" else "Add Entry") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.handleIntent(AddEditEntryIntent.Save) },
                        enabled = !state.isLoading
                    ) {
                        Icon(Icons.Default.Check, contentDescription = "Save")
                    }
                }
            )
        }
    ) { paddingValues ->
        if (state.isFetching) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedTextField(
                    value = state.title,
                    onValueChange = { viewModel.handleIntent(AddEditEntryIntent.TitleChanged(it)) },
                    label = { Text("Title *") },
                    leadingIcon = { Icon(Icons.Default.Check, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = state.username,
                    onValueChange = { viewModel.handleIntent(AddEditEntryIntent.UsernameChanged(it)) },
                    label = { Text("Username / Email") },
                    leadingIcon = { Icon(Icons.Default.Person, contentDescription = null) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = state.password,
                    onValueChange = { viewModel.handleIntent(AddEditEntryIntent.PasswordChanged(it)) },
                    label = { Text("Password") },
                    leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) },
                    trailingIcon = {
                        IconButton(onClick = { viewModel.handleIntent(AddEditEntryIntent.TogglePasswordVisibility) }) {
                            Icon(
                                if (state.passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = if (state.passwordVisible) "Hide password" else "Show password"
                            )
                        }
                    },
                    visualTransformation = if (state.passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = if (state.passwordVisible) KeyboardType.Text else KeyboardType.Password),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = state.url,
                    onValueChange = { viewModel.handleIntent(AddEditEntryIntent.UrlChanged(it)) },
                    label = { Text("Website URL") },
                    leadingIcon = { Icon(Icons.Default.Check, contentDescription = null) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = state.notes,
                    onValueChange = { viewModel.handleIntent(AddEditEntryIntent.NotesChanged(it)) },
                    label = { Text("Notes") },
                    leadingIcon = { Icon(Icons.Default.Check, contentDescription = null) },
                    minLines = 3,
                    maxLines = 5,
                    modifier = Modifier.fillMaxWidth()
                )

if (errorMessage != null) {
                    Text(
                        text = errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = { viewModel.handleIntent(AddEditEntryIntent.Save) },
                    enabled = !state.isLoading && state.title.isNotBlank(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                ) {
                    if (state.isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Text(if (state.isEditing) "Update" else "Save")
                    }
                }
            }
        }
    }
}