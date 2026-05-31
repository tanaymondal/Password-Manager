package com.securevault.mobile.data.local

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface VaultEntryDao {

    @Query("SELECT * FROM vault_entries ORDER BY updatedAt DESC")
    fun getAllEntries(): Flow<List<VaultEntryEntity>>

    @Query("SELECT * FROM vault_entries WHERE id = :id")
    suspend fun getEntryById(id: Long): VaultEntryEntity?

    @Query("SELECT * FROM vault_entries WHERE folder = :folder ORDER BY title ASC")
    fun getEntriesByFolder(folder: String): Flow<List<VaultEntryEntity>>

    @Query("SELECT * FROM vault_entries WHERE title LIKE :query || '%' OR username LIKE :query || '%'")
    fun searchEntriesPrefix(query: String): Flow<List<VaultEntryEntity>>

    @Query("SELECT * FROM vault_entries WHERE title LIKE '%' || :query || '%' OR username LIKE '%' || :query || '%'")
    fun searchEntries(query: String): Flow<List<VaultEntryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEntry(entry: VaultEntryEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEntries(entries: List<VaultEntryEntity>)

    @Update
    suspend fun updateEntry(entry: VaultEntryEntity)

    @Delete
    suspend fun deleteEntry(entry: VaultEntryEntity)

    @Query("DELETE FROM vault_entries WHERE id = :id")
    suspend fun deleteEntryById(id: Long)

    @Query("DELETE FROM vault_entries")
    suspend fun deleteAllEntries()

    @Query("SELECT * FROM vault_entries WHERE isSynced = 0")
    suspend fun getUnsyncedEntries(): List<VaultEntryEntity>

    @Query("UPDATE vault_entries SET isSynced = 1 WHERE id = :id")
    suspend fun markAsSynced(id: Long)

    @Query("SELECT COUNT(*) FROM vault_entries")
    suspend fun getEntryCount(): Int
}
