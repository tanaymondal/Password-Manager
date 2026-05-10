package com.securevault.mobile.ui.screens.vault

import com.securevault.mobile.domain.entity.VaultEntryEntity
import com.securevault.mobile.domain.usecase.vault.CreateVaultEntryUseCase
import com.securevault.mobile.domain.usecase.vault.GetVaultEntryUseCase
import com.securevault.mobile.domain.usecase.vault.UpdateVaultEntryUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class AddEditEntryIntent : MviIntent {
    data class LoadEntry(val id: Long) : AddEditEntryIntent()
    data class TitleChanged(val title: String) : AddEditEntryIntent()
    data class UsernameChanged(val username: String) : AddEditEntryIntent()
    data class PasswordChanged(val password: String) : AddEditEntryIntent()
    data class UrlChanged(val url: String) : AddEditEntryIntent()
    data class NotesChanged(val notes: String) : AddEditEntryIntent()
    data object TogglePasswordVisibility : AddEditEntryIntent()
    data object Save : AddEditEntryIntent()
    data object DismissError : AddEditEntryIntent()
}

data class AddEditEntryState(
    val entryId: Long? = null,
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    val passwordVisible: Boolean = false,
    val isLoading: Boolean = false,
    val isFetching: Boolean = false,
    val error: String? = null,
    val isEditing: Boolean = false
) : MviState

sealed class AddEditEntryEffect : MviEffect {
    data object NavigateBack : AddEditEntryEffect()
}

class AddEditEntryViewModel(
    private val getVaultEntryUseCase: GetVaultEntryUseCase,
    private val createVaultEntryUseCase: CreateVaultEntryUseCase,
    private val updateVaultEntryUseCase: UpdateVaultEntryUseCase
) : MviViewModel<AddEditEntryIntent, AddEditEntryState, AddEditEntryEffect>(AddEditEntryState()) {

    override fun handleIntent(intent: AddEditEntryIntent) {
        when (intent) {
            is AddEditEntryIntent.LoadEntry -> loadEntry(intent.id)
            is AddEditEntryIntent.TitleChanged -> setState { copy(title = intent.title) }
            is AddEditEntryIntent.UsernameChanged -> setState { copy(username = intent.username) }
            is AddEditEntryIntent.PasswordChanged -> setState { copy(password = intent.password) }
            is AddEditEntryIntent.UrlChanged -> setState { copy(url = intent.url) }
            is AddEditEntryIntent.NotesChanged -> setState { copy(notes = intent.notes) }
            is AddEditEntryIntent.TogglePasswordVisibility -> setState { copy(passwordVisible = !currentState.passwordVisible) }
            is AddEditEntryIntent.Save -> save()
            is AddEditEntryIntent.DismissError -> setState { copy(error = null) }
        }
    }

    private fun loadEntry(id: Long) {
        setState { copy(isFetching = true, entryId = id, isEditing = true) }

        runInBackground(
            block = { getVaultEntryUseCase(id) },
            onResult = { result ->
                setState { copy(isFetching = false) }
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.vault.VaultEntryResult.Success -> {
                        val entry = r.entry
                        setState {
                            copy(
                                title = entry.title,
                                username = entry.username,
                                password = entry.password,
                                url = entry.url ?: "",
                                notes = entry.notes ?: ""
                            )
                        }
                    }
                    is com.securevault.mobile.domain.usecase.vault.VaultEntryResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message) }
                }
            }
        )
    }

    private fun save() {
        val title = currentState.title.trim()

        if (title.isBlank()) {
            setState { copy(error = "Title is required") }
            return
        }

        setState { copy(isLoading = true, error = null) }

        val entry = VaultEntryEntity(
            id = currentState.entryId ?: 0,
            title = title,
            username = currentState.username.trim(),
            password = currentState.password,
            url = currentState.url.trim().ifBlank { null },
            notes = currentState.notes.trim().ifBlank { null },
            folder = null
        )

        val entryIdToUse = currentState.entryId

        runInBackground(
            block = {
                if (currentState.isEditing && entryIdToUse != null) {
                    updateVaultEntryUseCase(entryIdToUse, entry)
                } else {
                    createVaultEntryUseCase(entry)
                }
            },
            onResult = { result ->
                setState { copy(isLoading = false) }
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.vault.CreateVaultEntryResult.Success -> setEffect(AddEditEntryEffect.NavigateBack)
                    is com.securevault.mobile.domain.usecase.vault.UpdateVaultEntryResult.Success -> setEffect(AddEditEntryEffect.NavigateBack)
                    is com.securevault.mobile.domain.usecase.vault.CreateVaultEntryResult.Error -> setState { copy(error = r.message) }
                    is com.securevault.mobile.domain.usecase.vault.UpdateVaultEntryResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message) }
                }
            }
        )
    }
}