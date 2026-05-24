package com.securevault.mobile.ui.screens.settings

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.securevault.mobile.data.local.BiometricStorage
import com.securevault.mobile.domain.entity.DeviceEntity
import kotlinx.coroutines.flow.collectLatest
import org.koin.androidx.compose.koinViewModel

@Composable
fun SettingsScreen(
    onNavigateBack: () -> Unit,
    onLogout: () -> Unit,
    viewModel: SettingsViewModel
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val biometricStorage = remember { BiometricStorage(context) }

    LaunchedEffect(Unit) {
        viewModel.effect.collectLatest { effect ->
            when (effect) {
                is SettingsEffect.NavigateToLogin -> onLogout()
            }
        }
    }

    LaunchedEffect(state.showBiometricPrompt) {
        if (state.showBiometricPrompt) {
            val vaultKey = state.vaultKeyForBiometric ?: return@LaunchedEffect
            val activity = context as? FragmentActivity ?: return@LaunchedEffect

            if (!biometricStorage.isAvailable()) {
                viewModel.handleIntent(SettingsIntent.BiometricSetupResult(false))
                return@LaunchedEffect
            }

            val cipher = biometricStorage.getEncryptionCipher()
            biometricStorage.showBiometricPrompt(
                activity = activity,
                title = "Enable Biometric Unlock",
                subtitle = "Authenticate to enable biometric unlock for SecureVault",
                cipher = cipher,
                onSuccess = { authenticatedCipher ->
                    val success = biometricStorage.onEncryptComplete(authenticatedCipher, vaultKey)
                    viewModel.handleIntent(SettingsIntent.BiometricSetupResult(success))
                },
                onError = { error ->
                    viewModel.handleIntent(SettingsIntent.BiometricSetupResult(false))
                },
                onCancel = {
                    viewModel.handleIntent(SettingsIntent.BiometricSetupResult(false))
                }
            )
        }
    }

    LaunchedEffect(state.biometricClearRequested) {
        if (state.biometricClearRequested) {
            biometricStorage.clear()
            viewModel.handleIntent(SettingsIntent.BiometricClearDone)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                Text(
                    text = "Security",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            item {
                SettingsItem(
                    icon = Icons.Default.Add,
                    title = "Two-Factor Authentication",
                    subtitle = when (state.twoFactorEnabled) {
                        true -> "Enabled"
                        false -> "Disabled"
                        null -> "Unknown"
                    },
                    onClick = { /* TODO */ }
                )
            }

            item {
                BiometricSettingsItem(
                    isAvailable = biometricStorage.isAvailable(),
                    isEnabled = state.biometricEnabled,
                    onToggle = { enabled ->
                        if (enabled) {
                            viewModel.handleIntent(SettingsIntent.ToggleBiometricOn)
                        } else {
                            viewModel.handleIntent(SettingsIntent.ToggleBiometricOff)
                        }
                    }
                )
            }

            val bioError = state.biometricError
            if (bioError != null) {
                item {
                    Text(
                        text = bioError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 16.dp)
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Devices",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            if (state.isLoading) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator()
                    }
                }
            } else if (state.devices.isEmpty()) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "No registered devices",
                            modifier = Modifier.padding(16.dp),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                items(state.devices) { device ->
                    DeviceItem(device = device)
                }
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Account",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            item {
                SettingsItem(
                    icon = Icons.Default.Add,
                    title = "Logout",
                    subtitle = "Sign out of your account",
                    onClick = { viewModel.handleIntent(SettingsIntent.LogoutClicked) },
                    isDestructive = true
                )
            }

            item {
                Spacer(modifier = Modifier.height(32.dp))
                Text(
                    text = "SecureVault v1.0.0",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }

    if (state.showLogoutDialog) {
        AlertDialog(
            onDismissRequest = { viewModel.handleIntent(SettingsIntent.DismissLogoutDialog) },
            title = { Text("Logout") },
            text = { Text("Are you sure you want to logout?") },
            confirmButton = {
                TextButton(onClick = { viewModel.handleIntent(SettingsIntent.ConfirmLogout) }) {
                    Text("Logout")
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.handleIntent(SettingsIntent.DismissLogoutDialog) }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
fun SettingsItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    isDestructive: Boolean = false
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, contentDescription = null, tint = if (isDestructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.bodyLarge, color = if (isDestructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                Text(text = subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(Icons.Default.Add, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun BiometricSettingsItem(
    isAvailable: Boolean,
    isEnabled: Boolean,
    onToggle: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Fingerprint,
                contentDescription = null,
                tint = if (isEnabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Biometric Unlock",
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    text = when {
                        !isAvailable -> "Not available on this device"
                        isEnabled -> "Enabled"
                        else -> "Disabled"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = isEnabled,
                onCheckedChange = { if (isAvailable) onToggle(it) },
                enabled = isAvailable
            )
        }
    }
}

@Composable
fun DeviceItem(device: DeviceEntity) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Add, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = device.deviceName, style = MaterialTheme.typography.bodyLarge)
                Text(text = "Registered: ${device.registeredAt}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
