package com.securevault.mobile.ui.screens.auth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.securevault.mobile.data.local.BiometricStorage
import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.di.koinInject
import com.securevault.mobile.ui.currentPlatformContext
import kotlinx.coroutines.flow.collectLatest

@Composable
fun UnlockScreen(
    onUnlockSuccess: () -> Unit,
    onLogout: () -> Unit
) {
    val viewModel: UnlockViewModel = koinInject()
    val state by viewModel.state.collectAsState()
    val platformContext = currentPlatformContext()
    val biometricStorage = remember { BiometricStorage(platformContext) }
    var biometricTriggered by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        viewModel.effect.collectLatest { effect ->
            when (effect) {
                is UnlockEffect.NavigateToVault -> onUnlockSuccess()
            }
        }
    }

    LaunchedEffect(Unit) {
        if (!biometricTriggered
            && SessionManager.getBiometricEnabled()
            && biometricStorage.hasEncryptedVaultKey()
            && biometricStorage.isAvailable()
            && !biometricStorage.isLockedOut()
        ) {
            biometricTriggered = true
            biometricStorage.authenticate(
                title = "Unlock SecureVault",
                subtitle = "Authenticate to unlock your vault",
                onSuccess = {
                    val vaultKey = biometricStorage.retrieveVaultKey()
                    if (vaultKey != null) {
                        viewModel.handleIntent(UnlockIntent.BiometricUnlockSuccess(vaultKey))
                    } else {
                        viewModel.handleIntent(UnlockIntent.BiometricUnlockError)
                    }
                },
                onError = {
                    viewModel.handleIntent(UnlockIntent.BiometricUnlockError)
                },
                onCancel = {
                    viewModel.handleIntent(UnlockIntent.BiometricUnlockError)
                }
            )
        }
    }

    val errorMessage = state.error
    var passwordVisible by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Default.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(64.dp)
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Unlock Vault",
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Enter your master password to unlock the vault",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedTextField(
            value = state.password,
            onValueChange = { viewModel.handleIntent(UnlockIntent.PasswordChanged(it)) },
            label = { Text("Master Password") },
            leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null) },
            trailingIcon = {
                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                    Icon(
                        if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (passwordVisible) "Hide password" else "Show password"
                    )
                }
            },
            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = if (passwordVisible) KeyboardType.Text else KeyboardType.Password),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = errorMessage,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { viewModel.handleIntent(UnlockIntent.UnlockClicked) },
            enabled = !state.isLoading && state.password.isNotBlank(),
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
                Text("Unlock")
            }
        }

        if (biometricStorage.isAvailable() && biometricStorage.hasEncryptedVaultKey() && SessionManager.getBiometricEnabled()) {
            Spacer(modifier = Modifier.height(12.dp))
            if (biometricStorage.isLockedOut()) {
                Text(
                    text = "Biometric unlock locked out after too many failures. Use your master password.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            } else {
                OutlinedButton(
                    onClick = {
                        biometricStorage.authenticate(
                            title = "Unlock SecureVault",
                            subtitle = "Authenticate to unlock your vault",
                            onSuccess = {
                                val vaultKey = biometricStorage.retrieveVaultKey()
                                if (vaultKey != null) {
                                    viewModel.handleIntent(UnlockIntent.BiometricUnlockSuccess(vaultKey))
                                }
                            },
                            onError = { }
                        )
                    },
                    modifier = Modifier.fillMaxWidth().height(50.dp)
                ) {
                    Icon(Icons.Default.Fingerprint, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Use Biometrics")
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onLogout) {
            Text("Sign out")
        }
    }
}
