package com.securevault.mobile.ui.screens.vault

import com.securevault.mobile.domain.entity.VaultEntryEntity
import com.securevault.mobile.domain.usecase.auth.LogoutUseCase
import com.securevault.mobile.domain.usecase.auth.GetAuthStateUseCase
import com.securevault.mobile.domain.usecase.vault.DeleteVaultEntryUseCase
import com.securevault.mobile.domain.usecase.vault.GetVaultEntriesUseCase
import com.securevault.mobile.ui.mvi.MviEffect
import com.securevault.mobile.ui.mvi.MviIntent
import com.securevault.mobile.ui.mvi.MviState
import com.securevault.mobile.ui.mvi.MviViewModel

sealed class VaultIntent : MviIntent {
    data object LoadEntries : VaultIntent()
    data class SearchChanged(val query: String) : VaultIntent()
    data class DeleteEntry(val id: Long) : VaultIntent()
    data class ConfirmDeleteEntry(val id: Long) : VaultIntent()
    data object DismissError : VaultIntent()
    data object ShowLogoutDialog : VaultIntent()
    data object DismissLogoutDialog : VaultIntent()
    data object LogoutConfirmed : VaultIntent()
}

data class VaultState(
    val entries: List<VaultEntryEntity> = emptyList(),
    val filteredEntries: List<VaultEntryEntity> = emptyList(),
    val searchQuery: String = "",
    val isLoading: Boolean = false,
    val error: String? = null,
    val showDeleteDialog: Long? = null,
    val showLogoutDialog: Boolean = false
) : MviState

sealed class VaultEffect : MviEffect {
    data object NavigateToLogin : VaultEffect()
    data class NavigateToEditEntry(val entryId: Long) : VaultEffect()
    data object NavigateToAddEntry : VaultEffect()
    data object NavigateToSettings : VaultEffect()
}

class VaultViewModel(
    private val getVaultEntriesUseCase: GetVaultEntriesUseCase,
    private val deleteVaultEntryUseCase: DeleteVaultEntryUseCase,
    private val logoutUseCase: LogoutUseCase
) : MviViewModel<VaultIntent, VaultState, VaultEffect>(VaultState()) {

    init {
        handleIntent(VaultIntent.LoadEntries)
    }

    override fun handleIntent(intent: VaultIntent) {
        when (intent) {
            is VaultIntent.LoadEntries -> loadEntries()
            is VaultIntent.SearchChanged -> search(intent.query)
            is VaultIntent.DeleteEntry -> setState { copy(showDeleteDialog = intent.id) }
            is VaultIntent.ConfirmDeleteEntry -> deleteEntry(intent.id)
            is VaultIntent.DismissError -> setState { copy(error = null, showDeleteDialog = null) }
            is VaultIntent.ShowLogoutDialog -> setState { copy(showLogoutDialog = true) }
            is VaultIntent.DismissLogoutDialog -> setState { copy(showLogoutDialog = false) }
            is VaultIntent.LogoutConfirmed -> logout()
        }
    }

    private fun loadEntries() {
        setState { copy(isLoading = true, error = null) }

        runInBackground(
            block = { getVaultEntriesUseCase() },
            onResult = { result ->
                setState { copy(isLoading = false) }
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.vault.VaultEntriesResult.Success -> {
                        val filtered = filterEntries(r.entries, currentState.searchQuery)
                        setState { copy(entries = r.entries, filteredEntries = filtered) }
                    }
                    is com.securevault.mobile.domain.usecase.vault.VaultEntriesResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message) }
                }
            }
        )
    }

    private fun search(query: String) {
        val filtered = filterEntries(currentState.entries, query)
        setState { copy(searchQuery = query, filteredEntries = filtered) }
    }

    private fun filterEntries(entries: List<VaultEntryEntity>, query: String): List<VaultEntryEntity> {
        return if (query.isBlank()) entries
        else entries.filter { it.title.contains(query, ignoreCase = true) }
    }

    private fun deleteEntry(id: Long) {
        setState { copy(showDeleteDialog = null) }

        runInBackground(
            block = { deleteVaultEntryUseCase(id) },
            onResult = { result ->
                when (val r = result.getOrNull()) {
                    is com.securevault.mobile.domain.usecase.vault.DeleteVaultEntryResult.Success -> {
                        val updatedEntries = currentState.entries.filter { it.id != id }
                        val filtered = filterEntries(updatedEntries, currentState.searchQuery)
                        setState { copy(entries = updatedEntries, filteredEntries = filtered) }
                    }
                    is com.securevault.mobile.domain.usecase.vault.DeleteVaultEntryResult.Error -> setState { copy(error = r.message) }
                    null -> setState { copy(error = result.exceptionOrNull()?.message) }
                }
            }
        )
    }

    private fun logout() {
        setState { copy(showLogoutDialog = false) }

        runInBackground(
            block = { logoutUseCase() },
            onResult = {
                setEffect(VaultEffect.NavigateToLogin)
            }
        )
    }

    fun onAddEntryClick() = setEffect(VaultEffect.NavigateToAddEntry)
    fun onEntryClick(entryId: Long) = setEffect(VaultEffect.NavigateToEditEntry(entryId))
    fun onSettingsClick() = setEffect(VaultEffect.NavigateToSettings)
}