package com.securevault.mobile.data.repository

import com.securevault.mobile.data.local.VaultEntryDao
import com.securevault.mobile.data.local.VaultEntryEntity
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry
import com.securevault.mobile.domain.repository.VaultRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class RoomVaultRepository(
    private val dao: VaultEntryDao
) : VaultRepository {

    override suspend fun getEntries(): Result<List<VaultEntry>> {
        return try {
            val entries = dao.getUnsyncedEntries().map { it.toDomainModel() }
            Result.Success(entries)
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to get entries")
        }
    }

    override suspend fun getEntry(id: Long): Result<VaultEntry> {
        return try {
            val entry = dao.getEntryById(id)
            entry?.let { Result.Success(it.toDomainModel()) } ?: Result.Error("Entry not found")
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to get entry")
        }
    }

    override suspend fun createEntry(entry: VaultEntry): Result<VaultEntry> {
        return try {
            val entity = entry.toEntity(isSynced = false)
            dao.insertEntry(entity)
            Result.Success(entry)
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to create entry")
        }
    }

    override suspend fun updateEntry(id: Long, entry: VaultEntry): Result<VaultEntry> {
        return try {
            val existing = dao.getEntryById(id)
            if (existing != null) {
                val updated = entry.toEntity(isSynced = false).copy(id = id)
                dao.updateEntry(updated)
                Result.Success(entry)
            } else {
                Result.Error("Entry not found")
            }
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to update entry")
        }
    }

    override suspend fun deleteEntry(id: Long): Result<Unit> {
        return try {
            dao.deleteEntryById(id)
            Result.Success(Unit)
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to delete entry")
        }
    }

    override suspend fun deleteAllEntries(): Result<Unit> {
        return try {
            dao.deleteAllEntries()
            Result.Success(Unit)
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to delete all entries")
        }
    }

    fun getAllEntriesFlow(): Flow<List<VaultEntryEntity>> = dao.getAllEntries()

    fun searchEntries(query: String): Flow<List<VaultEntryEntity>> = dao.searchEntries(query)

    suspend fun syncFromRemote(entries: List<VaultEntry>) {
        val entities = entries.map { it.toEntity(isSynced = true) }
        dao.insertEntries(entities)
    }

    suspend fun getUnsyncedEntries(): List<VaultEntry> {
        return dao.getUnsyncedEntries().map { it.toDomainModel() }
    }

    private fun VaultEntryEntity.toDomainModel() = VaultEntry(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder
    )

    private fun VaultEntry.toEntity(isSynced: Boolean) = VaultEntryEntity(
        id = id,
        title = title,
        username = username,
        password = password,
        url = url,
        notes = notes,
        folder = folder,
        isSynced = isSynced
    )
}