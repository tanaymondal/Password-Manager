package com.securevault.mobile.data.local

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.VaultKeyManager
import com.securevault.mobile.domain.model.VaultEntry

class IosEntryEncryptor : EntryEncryptor, VaultKeyManager {
    override fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String) {
        throw NotImplementedError("Vault unlock not implemented for iOS")
    }

    override fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String {
        throw NotImplementedError("Vault key wrapping not implemented for iOS")
    }

    override fun generateVaultKey(): String {
        throw NotImplementedError("Vault key generation not implemented for iOS")
    }

    override fun generateEncryptionSalt(): String {
        throw NotImplementedError("Salt generation not implemented for iOS")
    }

    override fun getCachedVaultKey(): String? = null

    override fun setCachedVaultKey(key: String) {}

    override fun clearCachedVaultKey() {}

    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        throw NotImplementedError("Encryption not implemented for iOS")
    }

    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        throw NotImplementedError("Decryption not implemented for iOS")
    }
}
