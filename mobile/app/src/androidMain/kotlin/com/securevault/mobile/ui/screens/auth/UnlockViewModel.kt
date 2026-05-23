package com.securevault.mobile.ui.screens.auth

import com.securevault.mobile.domain.usecase.auth.UnlockVaultResult
import com.securevault.mobile.domain.usecase.auth.UnlockVaultUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class UnlockIntent : MviIntent {
    data class PasswordChanged(val password: String) : UnlockIntent()
    data object UnlockClicked : UnlockIntent()
    data object DismissError : UnlockIntent()
}

data class UnlockState(
    val password: String = "",
    val isLoading: Boolean = false,
    val error: String? = null
) : MviState

sealed class UnlockEffect : MviEffect {
    data object NavigateToVault : UnlockEffect()
}

class UnlockViewModel(
    private val unlockVaultUseCase: UnlockVaultUseCase
) : MviViewModel<UnlockIntent, UnlockState, UnlockEffect>(UnlockState()) {

    override fun handleIntent(intent: UnlockIntent) {
        when (intent) {
            is UnlockIntent.PasswordChanged -> setState { copy(password = intent.password) }
            is UnlockIntent.UnlockClicked -> unlock()
            is UnlockIntent.DismissError -> setState { copy(error = null) }
        }
    }

    private fun unlock() {
        val password = currentState.password

        if (password.isBlank()) {
            setState { copy(error = "Master password is required") }
            return
        }

        setState { copy(isLoading = true, error = null) }

        runInBackground(
            block = { unlockVaultUseCase(password) },
            onResult = { result ->
                setState { copy(isLoading = false) }
                when (val r = result.getOrNull()) {
                    is UnlockVaultResult.Success -> setEffect(UnlockEffect.NavigateToVault)
                    is UnlockVaultResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message ?: "Failed to unlock vault") }
                }
            }
        )
    }
}
