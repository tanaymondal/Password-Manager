package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.model.ChangePasswordRequest
import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.RefreshTokenRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.User
import com.securevault.mobile.domain.repository.AuthRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class AuthRepositoryImpl(
    private val api: SecureVaultApi
) : AuthRepository {

    private val _authState = MutableStateFlow(getAuthStateFromStorage())

    override suspend fun register(email: String, password: String): Result<AuthState> {
        return try {
            val response = api.register(RegisterRequest(email, password))
            response.fold(
                onSuccess = { authResponse ->
                    saveSession(authResponse.accessToken, authResponse.refreshToken, authResponse.encryptionSalt, authResponse.userId, email, password)
                    Result.Success(getCurrentAuthState())
                },
                onFailure = { Result.Error(it.message ?: "Registration failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Registration failed", e)
        }
    }

    override suspend fun login(email: String, password: String): Result<AuthState> {
        return try {
            val response = api.login(LoginRequest(email, password))
            response.fold(
                onSuccess = { authResponse ->
                    saveSession(authResponse.accessToken, authResponse.refreshToken, authResponse.encryptionSalt, authResponse.userId, email, password)
                    Result.Success(getCurrentAuthState())
                },
                onFailure = { Result.Error(it.message ?: "Login failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Login failed", e)
        }
    }

    override suspend fun logout(): Result<Unit> {
        return try {
            val token = SessionManager.getAccessToken()
            if (token.isNotEmpty()) {
                api.logout(token)
            }
            SessionManager.clearSession()
            _authState.value = AuthState.unauthenticated()
            Result.Success(Unit)
        } catch (e: Exception) {
            SessionManager.clearSession()
            _authState.value = AuthState.unauthenticated()
            Result.Success(Unit)
        }
    }

    override suspend fun refreshToken(): Result<AuthState> {
        return try {
            val currentRefreshToken = SessionManager.getRefreshToken()
            if (currentRefreshToken.isEmpty()) {
                return Result.Error("No refresh token available")
            }

            val response = api.refreshToken(RefreshTokenRequest(currentRefreshToken))
            response.fold(
                onSuccess = { authResponse ->
                    val existingPassword = SessionManager.getMasterPassword()
                    saveSession(authResponse.accessToken, authResponse.refreshToken, authResponse.encryptionSalt, authResponse.userId, authResponse.email, existingPassword)
                    Result.Success(getCurrentAuthState())
                },
                onFailure = {
                    SessionManager.clearSession()
                    _authState.value = AuthState.unauthenticated()
                    Result.Error(it.message ?: "Token refresh failed", it)
                }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Token refresh failed", e)
        }
    }

    override suspend fun changePassword(currentPassword: String, newPassword: String): Result<Unit> {
        return try {
            val token = SessionManager.getAccessToken()
            if (token.isEmpty()) {
                return Result.Error("Not authenticated")
            }

            val response = api.changePassword(token, ChangePasswordRequest(currentPassword, newPassword))
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Password change failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Password change failed", e)
        }
    }

    override fun getAuthState(): AuthState {
        return getCurrentAuthState()
    }

    override fun observeAuthState(): Flow<AuthState> = _authState.asStateFlow()

    private fun getCurrentAuthState(): AuthState {
        val token = SessionManager.getAccessToken()
        val userId = SessionManager.getUserId()
        val email = SessionManager.getUserEmail()

        return if (token.isNotEmpty() && userId.isNotEmpty() && email.isNotEmpty()) {
            AuthState(
                user = User(userId.hashCode().toLong(), email),
                accessToken = token,
                refreshToken = SessionManager.getRefreshToken(),
                encryptionSalt = SessionManager.getEncryptionSalt(),
                isAuthenticated = true
            )
        } else {
            AuthState.unauthenticated()
        }
    }

    private fun getAuthStateFromStorage(): AuthState = getCurrentAuthState()

    private fun saveSession(accessToken: String, refreshToken: String, encryptionSalt: String, userId: String, email: String, masterPassword: String) {
        SessionManager.setAccessToken(accessToken)
        SessionManager.setRefreshToken(refreshToken)
        SessionManager.setEncryptionSalt(encryptionSalt)
        SessionManager.setUserId(userId)
        SessionManager.setUserEmail(email)
        SessionManager.setMasterPassword(masterPassword)
        _authState.value = AuthState(
            user = User(userId.hashCode().toLong(), email),
            accessToken = accessToken,
            refreshToken = refreshToken,
            encryptionSalt = encryptionSalt,
            isAuthenticated = true
        )
    }
}