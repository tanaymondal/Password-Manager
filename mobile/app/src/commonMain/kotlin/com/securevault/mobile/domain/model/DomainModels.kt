package com.securevault.mobile.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

data class User(
    val id: Long,
    val email: String
)

data class AuthState(
    val user: User?,
    val accessToken: String?,
    val refreshToken: String?,
    val encryptionSalt: String?,
    val isAuthenticated: Boolean,
    val encryptionVersion: Int = 2
) {
    companion object {
        fun unauthenticated() = AuthState(
            user = null,
            accessToken = null,
            refreshToken = null,
            encryptionSalt = null,
            isAuthenticated = false,
            encryptionVersion = 2
        )
    }
}

@Serializable
data class VaultEntry(
    val id: Long,
    @SerialName("name") val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val notes: String?,
    val folder: String?,
    val createdAt: String? = null,
    val updatedAt: String? = null
)

data class Device(
    val id: Long,
    val deviceName: String,
    val deviceId: String,
    val registeredAt: String,
    val lastAccessed: String?
)

sealed class Result<out T> {
    data class Success<T>(val data: T) : Result<T>()
    data class Error(val message: String, val exception: Throwable? = null) : Result<Nothing>()
    data object Loading : Result<Nothing>()
}