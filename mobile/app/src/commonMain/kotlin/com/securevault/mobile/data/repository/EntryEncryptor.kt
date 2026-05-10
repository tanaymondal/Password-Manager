package com.securevault.mobile.data.repository

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.domain.model.VaultEntry

interface EntryEncryptor {
    fun encrypt(entry: VaultEntry): VaultEntryRequest
    fun decrypt(response: com.securevault.mobile.data.model.VaultEntryResponse): VaultEntry
}
