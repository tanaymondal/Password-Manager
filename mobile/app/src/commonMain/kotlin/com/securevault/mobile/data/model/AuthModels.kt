package com.securevault.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class LoginRequest(
    val email: String,
    val authHash: String,
    val deviceName: String? = null,
    val deviceId: String? = null
)

@Serializable
data class RegisterRequest(
    val email: String,
    val authHash: String,
    val authSalt: String,
    val encryptionSalt: String,
    val wrappedVaultKey: String,
    val encryptionVersion: Int,
    val deviceId: String? = null,
    @SerialName("kdfIterations") val kdfIterations: Int? = null,
    @SerialName("kdfMemory") val kdfMemory: Int? = null,
    @SerialName("kdfParallelism") val kdfParallelism: Int? = null
)

@Serializable
data class AuthResponse(
    val accessToken: String? = null,
    val refreshToken: String? = null,
    @SerialName("encryptionSalt") val encryptionSalt: String? = null,
    val userId: String? = null,
    val email: String? = null,
    val challengeId: String? = null,
    @SerialName("wrappedVaultKey") val wrappedVaultKey: String? = null,
    @SerialName("encryptionVersion") val encryptionVersion: Int = 2,
    @SerialName("twoFactorRequired") val twoFactorRequired: Boolean = false,
    @SerialName("twoFactorMethods") val twoFactorMethods: List<String> = emptyList(),
    @SerialName("kdfIterations") val kdfIterations: Int? = null,
    @SerialName("kdfMemory") val kdfMemory: Int? = null,
    @SerialName("kdfParallelism") val kdfParallelism: Int? = null
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
    val refreshToken: String
)

@Serializable
data class TwoFactorVerifyRequest(
    val email: String,
    val challengeId: String,
    val code: String = ""
)

@Serializable
data class PreLoginRequest(
    val email: String
)

@Serializable
data class PreLoginResponse(
    val authSalt: String,
    @SerialName("kdfIterations") val kdfIterations: Int? = null,
    @SerialName("kdfMemory") val kdfMemory: Int? = null,
    @SerialName("kdfParallelism") val kdfParallelism: Int? = null
)