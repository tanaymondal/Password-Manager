package com.securevault.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LoginRequest(
    val email: String,
    val password: String
)

@Serializable
data class RegisterRequest(
    val email: String,
    val password: String
)

@Serializable
data class AuthResponse(
    val accessToken: String,
    val refreshToken: String,
    @SerialName("encryptionSalt") val encryptionSalt: String,
    val userId: String,
    val email: String,
    @SerialName("wrappedVaultKey") val wrappedVaultKey: String? = null,
    @SerialName("encryptionVersion") val encryptionVersion: Int = 2
)

@Serializable
data class ChangePasswordRequest(
    @SerialName("current_password") val currentPassword: String,
    @SerialName("new_password") val newPassword: String,
    @SerialName("wrapped_vault_key") val wrappedVaultKey: String? = null,
    @SerialName("new_encryption_salt") val newEncryptionSalt: String? = null,
    val entries: List<VaultEntryRequest>? = null
)

@Serializable
data class ChangePasswordResponse(
    val accessToken: String,
    val refreshToken: String,
    @SerialName("encryptionSalt") val encryptionSalt: String,
    @SerialName("userId") val userId: String,
    val email: String,
    @SerialName("wrappedVaultKey") val wrappedVaultKey: String? = null,
    @SerialName("encryptionVersion") val encryptionVersion: Int = 2
)

@Serializable
data class ApiResponse<T>(
    val success: Boolean,
    val message: String? = null,
    val data: T? = null,
    val timestamp: String? = null
)

@Serializable
data class AuthApiResponse(
    val success: Boolean,
    val message: String? = null,
    val data: AuthResponse? = null,
    val timestamp: String? = null
)

@Serializable
data class RefreshTokenRequest(
    @SerialName("refresh_token") val refreshToken: String
)