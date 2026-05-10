package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry
import com.securevault.mobile.domain.repository.VaultRepository

class CachedVaultRepository(
    private val api: SecureVaultApi,
    private val repository: VaultRepository
) : VaultRepository {

    private var cachedEntries: List<VaultEntry>? = null

    override suspend fun getEntries(): Result<List<VaultEntry>> {
        return try {
            val result = repository.getEntries()
            if (result is Result.Success) {
                cachedEntries = result.data
            }
            result
        } catch (e: Exception) {
            cachedEntries?.let { Result.Success(it) } ?: Result.Error("No cached data available")
        }
    }

    override suspend fun getEntry(id: Long): Result<VaultEntry> {
        cachedEntries?.find { it.id == id }?.let {
            return Result.Success(it)
        }
        return repository.getEntry(id)
    }

    override suspend fun createEntry(entry: VaultEntry): Result<VaultEntry> {
        val result = repository.createEntry(entry)
        if (result is Result.Success) {
            cachedEntries = null
        }
        return result
    }

    override suspend fun updateEntry(id: Long, entry: VaultEntry): Result<VaultEntry> {
        val result = repository.updateEntry(id, entry)
        if (result is Result.Success) {
            cachedEntries = null
        }
        return result
    }

    override suspend fun deleteEntry(id: Long): Result<Unit> {
        val result = repository.deleteEntry(id)
        if (result is Result.Success) {
            cachedEntries = null
        }
        return result
    }

    override suspend fun deleteAllEntries(): Result<Unit> {
        val result = repository.deleteAllEntries()
        if (result is Result.Success) {
            cachedEntries = null
        }
        return result
    }
}