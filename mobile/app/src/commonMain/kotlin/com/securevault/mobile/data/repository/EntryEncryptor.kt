package com.securevault.mobile.data.repository

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.domain.model.VaultEntry

interface EntryEncryptor {
    fun encrypt(entry: VaultEntry): VaultEntryRequest
    fun decrypt(response: com.securevault.mobile.data.model.VaultEntryResponse): VaultEntry
}

interface VaultKeyManager {
    fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String)
    fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String
    fun generateVaultKey(): String
    fun generateEncryptionSalt(): String
    fun getCachedVaultKey(): String?
    fun setCachedVaultKey(key: String)
    fun clearCachedVaultKey()
}