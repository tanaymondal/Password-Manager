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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.securevault.mobile.data.local.BiometricStorage
import com.securevault.mobile.data.repository.SessionManager
import kotlinx.coroutines.flow.collectLatest
import org.koin.androidx.compose.koinViewModel

@Composable
fun UnlockScreen(
    onUnlockSuccess: () -> Unit,
    onLogout: () -> Unit
) {
    val viewModel: UnlockViewModel = koinViewModel()
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val biometricStorage = remember { BiometricStorage(context) }
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
        ) {
            biometricTriggered = true
            val activity = context as? FragmentActivity ?: return@LaunchedEffect
            val cipher = biometricStorage.getDecryptionCipher()
            biometricStorage.showBiometricPrompt(
                activity = activity,
                title = "Unlock SecureVault",
                subtitle = "Authenticate to unlock your vault",
                cipher = cipher,
                onSuccess = { authenticatedCipher ->
                    val vaultKey = biometricStorage.onDecryptComplete(authenticatedCipher)
                    if (vaultKey != null) {
                        viewModel.handleIntent(UnlockIntent.BiometricUnlockSuccess(vaultKey))
                    } else {
                        viewModel.handleIntent(UnlockIntent.BiometricUnlockError)
                    }
                },
                onError = { error ->
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
            OutlinedButton(
                onClick = {
                    val activity = context as? FragmentActivity ?: return@OutlinedButton
                    val cipher = biometricStorage.getDecryptionCipher()
                    biometricStorage.showBiometricPrompt(
                        activity = activity,
                        title = "Unlock SecureVault",
                        subtitle = "Authenticate to unlock your vault",
                        cipher = cipher,
                        onSuccess = { authenticatedCipher ->
                            val vaultKey = biometricStorage.onDecryptComplete(authenticatedCipher)
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

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onLogout) {
            Text("Sign out")
        }
    }
}
