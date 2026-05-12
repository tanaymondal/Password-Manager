package com.securevault.mobile.ui.screens.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class ChangePasswordIntent : MviIntent {
    data class CurrentPasswordChanged(val value: String) : ChangePasswordIntent()
    data class NewPasswordChanged(val value: String) : ChangePasswordIntent()
    data class ConfirmPasswordChanged(val value: String) : ChangePasswordIntent()
    data object ToggleCurrentVisibility : ChangePasswordIntent()
    data object ToggleNewVisibility : ChangePasswordIntent()
    data object ToggleConfirmVisibility : ChangePasswordIntent()
    data object ChangePasswordClicked : ChangePasswordIntent()
}

data class ChangePasswordState(
    val currentPassword: String = "",
    val newPassword: String = "",
    val confirmPassword: String = "",
    val showCurrentPassword: Boolean = false,
    val showNewPassword: Boolean = false,
    val showConfirmPassword: Boolean = false,
    val isLoading: Boolean = false,
    val error: String? = null,
    val currentPasswordStrength: Int = 0
) : MviState

sealed class ChangePasswordEffect : MviEffect {
    data object NavigateBack : ChangePasswordEffect()
    data class ShowError(val message: String) : ChangePasswordEffect()
}

class ChangePasswordViewModel(
    private val authRepository: AuthRepository
) : MviViewModel<ChangePasswordIntent, ChangePasswordState, ChangePasswordEffect>(ChangePasswordState()) {

    override fun handleIntent(intent: ChangePasswordIntent) {
        when (intent) {
            is ChangePasswordIntent.CurrentPasswordChanged -> {
                setState { copy(currentPassword = intent.value, error = null) }
            }
            is ChangePasswordIntent.NewPasswordChanged -> {
                setState { copy(newPassword = intent.value, error = null) }
            }
            is ChangePasswordIntent.ConfirmPasswordChanged -> {
                setState { copy(confirmPassword = intent.value, error = null) }
            }
            is ChangePasswordIntent.ToggleCurrentVisibility -> {
                setState { copy(showCurrentPassword = !showCurrentPassword) }
            }
            is ChangePasswordIntent.ToggleNewVisibility -> {
                setState { copy(showNewPassword = !showNewPassword) }
            }
            is ChangePasswordIntent.ToggleConfirmVisibility -> {
                setState { copy(showConfirmPassword = !showConfirmPassword) }
            }
            is ChangePasswordIntent.ChangePasswordClicked -> {
                changePassword()
            }
        }
    }

    private fun changePassword() {
        val currentState = state.value

        if (currentState.currentPassword.isEmpty()) {
            setState { copy(error = "Current password is required") }
            return
        }

        if (currentState.newPassword.isEmpty()) {
            setState { copy(error = "New password is required") }
            return
        }

        if (currentState.newPassword.length < 8) {
            setState { copy(error = "New password must be at least 8 characters") }
            return
        }

        if (currentState.newPassword != currentState.confirmPassword) {
            setState { copy(error = "Passwords do not match") }
            return
        }

        if (currentState.newPassword == currentState.currentPassword) {
            setState { copy(error = "New password must be different from current password") }
            return
        }

        setState { copy(isLoading = true, error = null) }

        runInBackground(
            block = { authRepository.changePassword(currentState.currentPassword, currentState.newPassword) },
            onResult = { result ->
                if (result.isSuccess) {
                    setState { copy(isLoading = false) }
                    setEffect(ChangePasswordEffect.NavigateBack)
                } else {
                    setState { copy(isLoading = false, error = result.exceptionOrNull()?.message ?: "Password change failed") }
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChangePasswordScreen(
    onNavigateBack: () -> Unit,
    viewModel: ChangePasswordViewModel
) {
    val state by viewModel.state.collectAsState()

    LaunchedEffect(Unit) {
        viewModel.effect.collect { effect ->
            when (effect) {
                is ChangePasswordEffect.NavigateBack -> onNavigateBack()
                is ChangePasswordEffect.ShowError -> {}
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Change Password") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedTextField(
                value = state.currentPassword,
                onValueChange = { viewModel.handleIntent(ChangePasswordIntent.CurrentPasswordChanged(it)) },
                label = { Text("Current Password") },
                visualTransformation = if (state.showCurrentPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    IconButton(onClick = { viewModel.handleIntent(ChangePasswordIntent.ToggleCurrentVisibility) }) {
                        Icon(
                            if (state.showCurrentPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = "Toggle visibility"
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = state.newPassword,
                onValueChange = { viewModel.handleIntent(ChangePasswordIntent.NewPasswordChanged(it)) },
                label = { Text("New Password") },
                visualTransformation = if (state.showNewPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    IconButton(onClick = { viewModel.handleIntent(ChangePasswordIntent.ToggleNewVisibility) }) {
                        Icon(
                            if (state.showNewPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = "Toggle visibility"
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = state.confirmPassword,
                onValueChange = { viewModel.handleIntent(ChangePasswordIntent.ConfirmPasswordChanged(it)) },
                label = { Text("Confirm New Password") },
                visualTransformation = if (state.showConfirmPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    IconButton(onClick = { viewModel.handleIntent(ChangePasswordIntent.ToggleConfirmVisibility) }) {
                        Icon(
                            if (state.showConfirmPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = "Toggle visibility"
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            if (state.error != null) {
                Text(
                    text = state.error!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = { viewModel.handleIntent(ChangePasswordIntent.ChangePasswordClicked) },
                enabled = !state.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (state.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Change Password")
                }
            }
        }
    }
}