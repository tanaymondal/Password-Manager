package com.securevault.mobile.data.local

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.domain.model.VaultEntry

class IosEntryEncryptor : EntryEncryptor {
    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        throw NotImplementedError("Encryption not implemented for iOS")
    }

    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        throw NotImplementedError("Decryption not implemented for iOS")
    }
}
