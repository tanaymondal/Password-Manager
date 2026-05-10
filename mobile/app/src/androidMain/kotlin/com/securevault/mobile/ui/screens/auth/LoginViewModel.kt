package com.securevault.mobile.ui.screens.auth

import com.securevault.mobile.domain.usecase.auth.LoginUseCase
import com.securevault.mobile.domain.usecase.auth.GetAuthStateUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class LoginIntent : MviIntent {
    data class EmailChanged(val email: String) : LoginIntent()
    data class PasswordChanged(val password: String) : LoginIntent()
    data object LoginClicked : LoginIntent()
    data object DismissError : LoginIntent()
}

data class LoginState(
    val email: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val error: String? = null
) : MviState

sealed class LoginEffect : MviEffect {
    data object NavigateToVault : LoginEffect()
}

class LoginViewModel(
    private val loginUseCase: LoginUseCase,
    private val getAuthStateUseCase: GetAuthStateUseCase
) : MviViewModel<LoginIntent, LoginState, LoginEffect>(LoginState()) {

    override fun handleIntent(intent: LoginIntent) {
        when (intent) {
            is LoginIntent.EmailChanged -> setState { copy(email = intent.email) }
            is LoginIntent.PasswordChanged -> setState { copy(password = intent.password) }
            is LoginIntent.LoginClicked -> login()
            is LoginIntent.DismissError -> setState { copy(error = null) }
        }
    }

    private fun login() {
        val email = currentState.email.trim()
        val password = currentState.password

        if (email.isBlank()) {
            setState { copy(error = "Email is required") }
            return
        }

        if (password.isBlank()) {
            setState { copy(error = "Password is required") }
            return
        }

        setState { copy(isLoading = true, error = null) }

        runInBackground(
            block = { loginUseCase(email, password) },
            onResult = { result ->
                setState { copy(isLoading = false) }
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.auth.LoginResult.Success -> setEffect(LoginEffect.NavigateToVault)
                    is com.securevault.mobile.domain.usecase.auth.LoginResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message ?: "Unknown error") }
                }
            }
        )
    }
}