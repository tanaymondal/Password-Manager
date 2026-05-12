package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry
import com.securevault.mobile.domain.repository.VaultRepository

class VaultRepositoryImpl(
    private val api: SecureVaultApi,
    private val encryptor: EntryEncryptor
) : VaultRepository {

    override suspend fun getEntries(): Result<List<VaultEntry>> {
        return try {
            val token = getValidToken()
            val response = api.getVaultEntries(token)
            response.fold(
                onSuccess = { entries ->
                    val decryptedEntries = entries.map { decryptEntry(it) }
                    Result.Success(decryptedEntries)
                },
                onFailure = { Result.Error(it.message ?: "Failed to fetch entries", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to fetch entries", e)
        }
    }

    override suspend fun getEntry(id: Long): Result<VaultEntry> {
        return try {
            val token = getValidToken()
            val response = api.getVaultEntry(token, id.toString())
            response.fold(
                onSuccess = { entry ->
                    Result.Success(decryptEntry(entry))
                },
                onFailure = { Result.Error(it.message ?: "Failed to fetch entry", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to fetch entry", e)
        }
    }

    override suspend fun createEntry(entry: VaultEntry): Result<VaultEntry> {
        return try {
            val token = getValidToken()
            val encryptedRequest = encryptEntry(entry)
            val response = api.createVaultEntry(token, encryptedRequest)
            response.fold(
                onSuccess = { created ->
                    Result.Success(decryptEntry(created))
                },
                onFailure = { Result.Error(it.message ?: "Failed to create entry", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to create entry", e)
        }
    }

    override suspend fun updateEntry(id: Long, entry: VaultEntry): Result<VaultEntry> {
        return try {
            val token = getValidToken()
            val encryptedRequest = encryptEntry(entry.copy(id = id))
            val response = api.updateVaultEntry(token, id.toString(), encryptedRequest)
            response.fold(
                onSuccess = { updated ->
                    Result.Success(decryptEntry(updated))
                },
                onFailure = { Result.Error(it.message ?: "Failed to update entry", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to update entry", e)
        }
    }

    override suspend fun deleteEntry(id: Long): Result<Unit> {
        return try {
            val token = getValidToken()
            val response = api.deleteVaultEntry(token, id.toString())
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Failed to delete entry", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to delete entry", e)
        }
    }

    override suspend fun deleteAllEntries(): Result<Unit> {
        return try {
            val token = getValidToken()
            val response = api.deleteAllVaultEntries(token)
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Failed to delete entries", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to delete entries", e)
        }
    }

    private fun getValidToken(): String {
        val token = SessionManager.getAccessToken()
        if (token.isEmpty()) throw IllegalStateException("Not authenticated")
        return token
    }

    private fun encryptEntry(entry: VaultEntry): VaultEntryRequest {
        return encryptor.encrypt(entry)
    }

    private fun decryptEntry(entry: VaultEntryResponse): VaultEntry {
        return encryptor.decrypt(entry)
    }
}
