package com.securevault.mobile.data.repository

import android.content.Context
import com.securevault.mobile.data.local.DatabaseKeyManager
import com.securevault.mobile.data.local.SecureVaultDatabase
import com.securevault.mobile.data.local.VaultEntryDao
import com.securevault.mobile.data.local.VaultEntryEntity
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry
import com.securevault.mobile.domain.repository.VaultRepository
import kotlinx.coroutines.flow.first

class CachedVaultRepository(
    private val context: Context,
    private val apiRepository: VaultRepository
) : VaultRepository {

    private val daoLock = Any()
    private var _dao: VaultEntryDao? = null

    private fun getOrCreateDao(): VaultEntryDao {
        var dao = _dao
        if (dao == null) {
            synchronized(daoLock) {
                dao = _dao
                if (dao == null) {
                    dao = createDao()
                    _dao = dao
                }
            }
        }
        return dao!!
    }

    private fun createDao(): VaultEntryDao {
        val keyManager = DatabaseKeyManager(context)
        val passphrase = keyManager.getOrCreatePassphrase()
        return try {
            val db = SecureVaultDatabase.getInstance(context, passphrase)
            db.openHelper.writableDatabase
            db.vaultEntryDao()
        } catch (e: Exception) {
            SecureVaultDatabase.clearInstance()
            context.deleteDatabase(SecureVaultDatabase.DATABASE_NAME)
            keyManager.clearPassphrase()
            val newPassphrase = keyManager.getOrCreatePassphrase()
            val db = SecureVaultDatabase.getInstance(context, newPassphrase)
            db.openHelper.writableDatabase
            db.vaultEntryDao()
        }
    }

    private fun resetDao() {
        synchronized(daoLock) {
            SecureVaultDatabase.clearInstance()
            _dao = null
        }
    }

    private suspend fun <T> withDao(block: suspend (VaultEntryDao) -> T): T {
        return try {
            block(getOrCreateDao())
        } catch (e: Exception) {
            context.deleteDatabase(SecureVaultDatabase.DATABASE_NAME)
            DatabaseKeyManager(context).clearPassphrase()
            resetDao()
            block(getOrCreateDao())
        }
    }

    override suspend fun getEntries(): Result<List<VaultEntry>> {
        val apiResult = apiRepository.getEntries()
        return if (apiResult is Result.Success) {
            withDao { dao -> dao.syncFromRemote(apiResult.data) }
            apiResult
        } else {
            val cached = withDao { dao -> dao.getAllEntriesSnapshot() }
            if (cached.isNotEmpty()) {
                Result.Success(cached)
            } else {
                apiResult
            }
        }
    }

    override suspend fun getEntry(id: Long): Result<VaultEntry> {
        val apiResult = apiRepository.getEntry(id)
        return if (apiResult is Result.Success) {
            withDao { dao ->
                dao.getEntryById(id)?.let { dao.insertEntry(apiResult.data.toEntity(true)) }
            }
            apiResult
        } else {
            val cached = withDao { dao -> dao.getEntryById(id) }
            if (cached != null) {
                Result.Success(cached.toDomainModel())
            } else {
                apiResult
            }
        }
    }

    override suspend fun createEntry(entry: VaultEntry): Result<VaultEntry> {
        val result = apiRepository.createEntry(entry)
        if (result is Result.Success) {
            withDao { dao -> dao.insertEntry(result.data.toEntity(true)) }
        }
        return result
    }

    override suspend fun updateEntry(id: Long, entry: VaultEntry): Result<VaultEntry> {
        val result = apiRepository.updateEntry(id, entry)
        if (result is Result.Success) {
            withDao { dao -> dao.insertEntry(result.data.toEntity(true).copy(id = id)) }
        }
        return result
    }

    override suspend fun deleteEntry(id: Long): Result<Unit> {
        val result = apiRepository.deleteEntry(id)
        if (result is Result.Success) {
            withDao { dao -> dao.deleteEntryById(id) }
        }
        return result
    }

    override suspend fun deleteAllEntries(): Result<Unit> {
        val result = apiRepository.deleteAllEntries()
        if (result is Result.Success) {
            withDao { dao -> dao.deleteAllEntries() }
        }
        return result
    }

    private suspend fun VaultEntryDao.syncFromRemote(entries: List<VaultEntry>) {
        insertEntries(entries.map { it.toEntity(true) })
    }

    private suspend fun VaultEntryDao.getAllEntriesSnapshot(): List<VaultEntry> {
        return getAllEntries().first().map { it.toDomainModel() }
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
