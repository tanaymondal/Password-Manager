package com.securevault.mobile.domain.usecase.vault

import com.securevault.mobile.domain.entity.VaultEntryEntity

interface GetVaultEntriesUseCase {
    suspend operator fun invoke(): VaultEntriesResult
}

sealed class VaultEntriesResult {
    data class Success(val entries: List<VaultEntryEntity>) : VaultEntriesResult()
    data class Error(val message: String) : VaultEntriesResult()
}

interface GetVaultEntryUseCase {
    suspend operator fun invoke(id: Long): VaultEntryResult
}

sealed class VaultEntryResult {
    data class Success(val entry: VaultEntryEntity) : VaultEntryResult()
    data class Error(val message: String) : VaultEntryResult()
}

interface CreateVaultEntryUseCase {
    suspend operator fun invoke(entry: VaultEntryEntity): CreateVaultEntryResult
}

sealed class CreateVaultEntryResult {
    data class Success(val entry: VaultEntryEntity) : CreateVaultEntryResult()
    data class Error(val message: String) : CreateVaultEntryResult()
}

interface UpdateVaultEntryUseCase {
    suspend operator fun invoke(id: Long, entry: VaultEntryEntity): UpdateVaultEntryResult
}

sealed class UpdateVaultEntryResult {
    data class Success(val entry: VaultEntryEntity) : UpdateVaultEntryResult()
    data class Error(val message: String) : UpdateVaultEntryResult()
}

interface DeleteVaultEntryUseCase {
    suspend operator fun invoke(id: Long): DeleteVaultEntryResult
}

sealed class DeleteVaultEntryResult {
    data object Success : DeleteVaultEntryResult()
    data class Error(val message: String) : DeleteVaultEntryResult()
}

interface DeleteAllVaultEntriesUseCase {
    suspend operator fun invoke(): DeleteAllVaultEntriesResult
}

sealed class DeleteAllVaultEntriesResult {
    data object Success : DeleteAllVaultEntriesResult()
    data class Error(val message: String) : DeleteAllVaultEntriesResult()
}