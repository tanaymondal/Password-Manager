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
    val accessToken: String? = null,
    val refreshToken: String? = null,
    @SerialName("encryptionSalt") val encryptionSalt: String? = null,
    val userId: String? = null,
    val email: String? = null,
    @SerialName("wrappedVaultKey") val wrappedVaultKey: String? = null,
    @SerialName("encryptionVersion") val encryptionVersion: Int = 2,
    @SerialName("twoFactorRequired") val twoFactorRequired: Boolean = false
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
    val code: String
)