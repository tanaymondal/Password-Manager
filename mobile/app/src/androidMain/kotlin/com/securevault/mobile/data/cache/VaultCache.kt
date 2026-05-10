package com.securevault.mobile.data.cache

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.securevault.mobile.domain.entity.VaultEntryEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val Context.vaultDataStore: DataStore<Preferences> by preferencesDataStore(name = "vault_cache")

class VaultCache(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true }
    
    companion object {
        private val VAULT_ENTRIES_KEY = stringPreferencesKey("vault_entries")
        private val LAST_SYNC_KEY = stringPreferencesKey("last_sync_timestamp")
    }

    suspend fun saveEntries(entries: List<VaultEntryEntity>) {
        context.vaultDataStore.edit { preferences ->
            val serialized = json.encodeToString(entries.map { it.toCacheModel() })
            preferences[VAULT_ENTRIES_KEY] = serialized
            preferences[LAST_SYNC_KEY] = System.currentTimeMillis().toString()
        }
    }

    fun getEntries(): Flow<List<VaultEntryEntity>> {
        return context.vaultDataStore.data.map { preferences ->
            val serialized = preferences[VAULT_ENTRIES_KEY]
            if (serialized != null) {
                try {
                    json.decodeFromString<List<VaultCacheEntry>>(serialized).map { it.toEntity() }
                } catch (e: Exception) {
                    emptyList()
                }
            } else {
                emptyList()
            }
        }
    }

    suspend fun clearCache() {
        context.vaultDataStore.edit { preferences ->
            preferences.clear()
        }
    }

    suspend fun getLastSyncTime(): Long? {
        var timestamp: Long? = null
        context.vaultDataStore.data.collect { preferences ->
            timestamp = preferences[LAST_SYNC_KEY]?.toLongOrNull()
        }
        return timestamp
    }
}

@kotlinx.serialization.Serializable
private data class VaultCacheEntry(
    val id: Long,
    val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val notes: String?,
    val folder: String?
) {
    fun toEntity() = VaultEntryEntity(id, title, username, password, url, notes, folder)
}

private fun VaultEntryEntity.toCacheModel() = VaultCacheEntry(id, title, username, password, url, notes, folder)