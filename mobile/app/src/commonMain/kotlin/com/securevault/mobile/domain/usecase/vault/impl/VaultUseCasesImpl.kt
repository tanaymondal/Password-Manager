package com.securevault.mobile.domain.usecase.vault.impl

import com.securevault.mobile.domain.entity.VaultEntryEntity
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.VaultRepository
import com.securevault.mobile.domain.usecase.vault.*

class GetVaultEntriesUseCaseImpl(
    private val vaultRepository: VaultRepository
) : GetVaultEntriesUseCase {
    override suspend operator fun invoke(): VaultEntriesResult {
        return when (val result = vaultRepository.getEntries()) {
            is Result.Success -> VaultEntriesResult.Success(result.data.map { it.toEntity() })
            is Result.Error -> VaultEntriesResult.Error(result.message)
            is Result.Loading -> VaultEntriesResult.Error("Loading...")
        }
    }

    private fun com.securevault.mobile.domain.model.VaultEntry.toEntity() = VaultEntryEntity(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )
}

class GetVaultEntryUseCaseImpl(
    private val vaultRepository: VaultRepository
) : GetVaultEntryUseCase {
    override suspend operator fun invoke(id: Long): VaultEntryResult {
        return when (val result = vaultRepository.getEntry(id)) {
            is Result.Success -> VaultEntryResult.Success(result.data.toEntity())
            is Result.Error -> VaultEntryResult.Error(result.message)
            is Result.Loading -> VaultEntryResult.Error("Loading...")
        }
    }

    private fun com.securevault.mobile.domain.model.VaultEntry.toEntity() = VaultEntryEntity(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )
}

class CreateVaultEntryUseCaseImpl(
    private val vaultRepository: VaultRepository
) : CreateVaultEntryUseCase {
    override suspend operator fun invoke(entry: VaultEntryEntity): CreateVaultEntryResult {
        return when (val result = vaultRepository.createEntry(entry.toDomain())) {
            is Result.Success -> CreateVaultEntryResult.Success(result.data.toEntity())
            is Result.Error -> CreateVaultEntryResult.Error(result.message)
            is Result.Loading -> CreateVaultEntryResult.Error("Loading...")
        }
    }

    private fun VaultEntryEntity.toDomain() = com.securevault.mobile.domain.model.VaultEntry(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )

    private fun com.securevault.mobile.domain.model.VaultEntry.toEntity() = VaultEntryEntity(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )
}

class UpdateVaultEntryUseCaseImpl(
    private val vaultRepository: VaultRepository
) : UpdateVaultEntryUseCase {
    override suspend operator fun invoke(id: Long, entry: VaultEntryEntity): UpdateVaultEntryResult {
        return when (val result = vaultRepository.updateEntry(id, entry.toDomain())) {
            is Result.Success -> UpdateVaultEntryResult.Success(result.data.toEntity())
            is Result.Error -> UpdateVaultEntryResult.Error(result.message)
            is Result.Loading -> UpdateVaultEntryResult.Error("Loading...")
        }
    }

    private fun VaultEntryEntity.toDomain() = com.securevault.mobile.domain.model.VaultEntry(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )

    private fun com.securevault.mobile.domain.model.VaultEntry.toEntity() = VaultEntryEntity(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )
}

class DeleteVaultEntryUseCaseImpl(
    private val vaultRepository: VaultRepository
) : DeleteVaultEntryUseCase {
    override suspend operator fun invoke(id: Long): DeleteVaultEntryResult {
        return when (val result = vaultRepository.deleteEntry(id)) {
            is Result.Success -> DeleteVaultEntryResult.Success
            is Result.Error -> DeleteVaultEntryResult.Error(result.message)
            is Result.Loading -> DeleteVaultEntryResult.Error("Loading...")
        }
    }
}

class DeleteAllVaultEntriesUseCaseImpl(
    private val vaultRepository: VaultRepository
) : DeleteAllVaultEntriesUseCase {
    override suspend operator fun invoke(): DeleteAllVaultEntriesResult {
        return when (val result = vaultRepository.deleteAllEntries()) {
            is Result.Success -> DeleteAllVaultEntriesResult.Success
            is Result.Error -> DeleteAllVaultEntriesResult.Error(result.message)
            is Result.Loading -> DeleteAllVaultEntriesResult.Error("Loading...")
        }
    }
}