package com.securevault.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VaultEntryRequest(
    val id: String? = null,
    val encryptedData: String,
    val iv: String
)

@Serializable
data class VaultEntryResponse(
    val id: String,
    val encryptedData: String,
    val iv: String,
    val version: Int,
    val createdAt: String? = null,
    val updatedAt: String? = null
)

@Serializable
data class VaultEntriesApiResponse(
    val success: Boolean,
    val message: String? = null,
    val data: VaultEntriesData? = null,
    val timestamp: String? = null
)

@Serializable
data class VaultEntriesData(
    val entries: List<VaultEntryResponse>,
    val count: Int? = null
)

@Serializable
data class VaultEntryApiResponse(
    val success: Boolean,
    val message: String? = null,
    val data: VaultEntryResponse? = null,
    val timestamp: String? = null
)

@Serializable
data class DecryptedVaultEntry(
    val id: Long,
    val title: String,
    val username: String,
    val password: String,
    val url: String? = null,
    val notes: String? = null,
    val folder: String? = null
)