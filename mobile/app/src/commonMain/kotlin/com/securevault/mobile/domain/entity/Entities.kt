package com.securevault.mobile.domain.entity

data class User(
    val id: Long,
    val email: String
)

data class AuthTokens(
    val accessToken: String,
    val refreshToken: String,
    val encryptionSalt: String,
    val userId: Long,
    val email: String
)

data class VaultEntryEntity(
    val id: Long,
    val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val notes: String?,
    val folder: String?,
    val createdAt: String? = null,
    val updatedAt: String? = null
)

data class DeviceEntity(
    val id: Long,
    val deviceName: String,
    val deviceId: String,
    val registeredAt: String,
    val lastAccessed: String?
)

data class TwoFactorSetup(
    val secret: String,
    val qrCodeUrl: String
)