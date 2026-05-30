package com.securevault.mobile.ui.screens.auth

import com.securevault.mobile.domain.usecase.auth.RegisterUseCase
import com.securevault.mobile.domain.usecase.auth.GetAuthStateUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class RegisterIntent : MviIntent {
    data class EmailChanged(val email: String) : RegisterIntent()
    data class PasswordChanged(val password: String) : RegisterIntent()
    data class ConfirmPasswordChanged(val confirmPassword: String) : RegisterIntent()
    data object RegisterClicked : RegisterIntent()
    data object DismissError : RegisterIntent()
}

data class RegisterState(
    val email: String = "",
    val password: String = "",
    val confirmPassword: String = "",
    val isLoading: Boolean = false,
    val error: String? = null
) : MviState

sealed class RegisterEffect : MviEffect {
    data object NavigateToVault : RegisterEffect()
}

class RegisterViewModel(
    private val registerUseCase: RegisterUseCase,
    private val getAuthStateUseCase: GetAuthStateUseCase
) : MviViewModel<RegisterIntent, RegisterState, RegisterEffect>(RegisterState()) {

    override fun handleIntent(intent: RegisterIntent) {
        when (intent) {
            is RegisterIntent.EmailChanged -> setState { copy(email = intent.email) }
            is RegisterIntent.PasswordChanged -> setState { copy(password = intent.password) }
            is RegisterIntent.ConfirmPasswordChanged -> setState { copy(confirmPassword = intent.confirmPassword) }
            is RegisterIntent.RegisterClicked -> register()
            is RegisterIntent.DismissError -> setState { copy(error = null) }
        }
    }

    private fun register() {
        val email = currentState.email.trim()
        val password = currentState.password
        val confirmPassword = currentState.confirmPassword

        if (email.isBlank()) {
            setState { copy(error = "Email is required") }
            return
        }

        if (password.isBlank()) {
            setState { copy(error = "Password is required") }
            return
        }

        if (password.length < 8) {
            setState { copy(error = "Password must be at least 8 characters") }
            return
        }

        // Check password doesn't contain the email's local part
        val emailLocalPart = email.substringBefore("@").lowercase()
        if (password.lowercase().contains(emailLocalPart)) {
            setState { copy(error = "Password cannot be based on your email address") }
            return
        }

        if (password != confirmPassword) {
            setState { copy(error = "Passwords do not match") }
            return
        }

        setState { copy(isLoading = true, error = null) }

        runInBackground(
            block = { registerUseCase(email, password) },
            onResult = { result ->
                setState { copy(isLoading = false) }
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.auth.RegisterResult.Success -> setEffect(RegisterEffect.NavigateToVault)
                    is com.securevault.mobile.domain.usecase.auth.RegisterResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message ?: "Unknown error") }
                }
            }
        )
    }
}