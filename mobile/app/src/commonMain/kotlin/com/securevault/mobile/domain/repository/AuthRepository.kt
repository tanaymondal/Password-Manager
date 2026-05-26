package com.securevault.mobile.domain.repository

import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.TwoFactorInfo

sealed class LoginResponse {
    data class Success(val authState: AuthState) : LoginResponse()
    data class TwoFactorRequired(val info: TwoFactorInfo) : LoginResponse()
}

interface AuthRepository {
    suspend fun register(email: String, password: String): Result<AuthState>
    suspend fun login(email: String, password: String): Result<LoginResponse>
    suspend fun verifyTwoFactor(email: String, challengeId: String, code: String, password: String): Result<AuthState>
    suspend fun logout(): Result<Unit>
    suspend fun refreshToken(): Result<AuthState>
    suspend fun unlockVault(password: String): Result<Unit>
    fun getAuthState(): AuthState
    fun observeAuthState(): kotlinx.coroutines.flow.Flow<AuthState>
}