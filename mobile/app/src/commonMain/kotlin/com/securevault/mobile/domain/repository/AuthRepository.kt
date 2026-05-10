package com.securevault.mobile.domain.repository

import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result

interface AuthRepository {
    suspend fun register(email: String, password: String): Result<AuthState>
    suspend fun login(email: String, password: String): Result<AuthState>
    suspend fun logout(): Result<Unit>
    suspend fun refreshToken(): Result<AuthState>
    suspend fun changePassword(currentPassword: String, newPassword: String): Result<Unit>
    fun getAuthState(): AuthState
    fun observeAuthState(): kotlinx.coroutines.flow.Flow<AuthState>
}