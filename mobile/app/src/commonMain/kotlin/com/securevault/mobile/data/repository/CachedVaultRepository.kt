package com.securevault.mobile.data.repository

import com.securevault.mobile.data.local.SecureVaultDatabase
import com.securevault.mobile.data.local.VaultEntryDao
import com.securevault.mobile.data.local.VaultEntryEntity
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry
import com.securevault.mobile.domain.repository.VaultRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class CachedVaultRepository(
    private val dbProvider: () -> SecureVaultDatabase,
    private val apiRepository: VaultRepository,
    private val encryptor: EntryEncryptor
) : VaultRepository {

    private val daoMutex = Mutex()
    @kotlin.concurrent.Volatile
    private var _dao: VaultEntryDao? = null

    private suspend fun getOrCreateDao(): VaultEntryDao {
        var dao = _dao
        if (dao == null) {
            daoMutex.withLock {
                dao = _dao
                if (dao == null) {
                    val db = dbProvider()
                    dao = db.vaultEntryDao()
                    _dao = dao
                }
            }
        }
        return dao!!
    }

    private suspend fun <T> withDao(block: suspend (VaultEntryDao) -> T): T {
        return block(getOrCreateDao())
    }

    override suspend fun getEntries(): Result<List<VaultEntry>> {
        val apiResult = apiRepository.getEntries()
        return if (apiResult is Result.Success) {
            withDao { dao -> dao.syncFromRemote(apiResult.data) }
            apiResult
        } else if (apiResult is Result.Error && isAuthError(apiResult.message)) {
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
        } else if (apiResult is Result.Error && isAuthError(apiResult.message)) {
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
        title = decryptFieldNotNull(title),
        username = decryptFieldNotNull(username),
        password = decryptFieldNotNull(password),
        url = decryptField(url),
        notes = notes?.let { decryptField(it) },
        folder = decryptField(folder)
    )

    private fun VaultEntry.toEntity(isSynced: Boolean) = VaultEntryEntity(
        id = id,
        title = encryptFieldNotNull(title),
        username = encryptFieldNotNull(username),
        password = encryptFieldNotNull(password),
        url = encryptField(url),
        notes = notes?.let { encryptField(it) },
        folder = encryptField(folder),
        isSynced = isSynced
    )

    private fun decryptField(value: String?): String? {
        if (value == null) return null
        return if (value.startsWith("e1:")) encryptor.decryptField(value.removePrefix("e1:")) else value
    }

    private fun decryptFieldNotNull(value: String): String {
        return if (value.startsWith("e1:")) encryptor.decryptField(value.removePrefix("e1:")) else value
    }

    private fun encryptField(value: String?): String? {
        if (value == null) return null
        return "e1:" + encryptor.encryptField(value)
    }

    private fun encryptFieldNotNull(value: String): String {
        return "e1:" + encryptor.encryptField(value)
    }

    private fun isAuthError(message: String?): Boolean {
        if (message == null) return false
        val lower = message.lowercase()
        return lower.contains("session expired") ||
                lower.contains("token expired") ||
                lower.contains("not authenticated") ||
                lower.contains("unauthorized") ||
                lower.contains("login again")
    }
}
