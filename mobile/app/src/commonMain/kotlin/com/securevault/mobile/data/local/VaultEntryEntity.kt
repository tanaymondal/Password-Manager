package com.securevault.mobile.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "vault_entries")
data class VaultEntryEntity(
    @PrimaryKey
    val id: Long,
    val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val notes: String?,
    val folder: String?,
    val createdAt: Long? = null,
    val updatedAt: Long? = null,
    val isSynced: Boolean = true
)
