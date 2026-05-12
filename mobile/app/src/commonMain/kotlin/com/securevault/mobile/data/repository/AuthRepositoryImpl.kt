package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.model.ChangePasswordRequest
import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.RefreshTokenRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.User
import com.securevault.mobile.domain.repository.AuthRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class AuthRepositoryImpl(
    private val api: SecureVaultApi,
    private val encryptor: EntryEncryptor,
    private val vaultKeyManager: VaultKeyManager
) : AuthRepository {

    private val _authState = MutableStateFlow(getAuthStateFromStorage())

    override suspend fun register(email: String, password: String): Result<AuthState> {
        return try {
            val response = api.register(RegisterRequest(email, password))
            response.fold(
                onSuccess = { authResponse ->
                    saveSession(
                        authResponse.accessToken,
                        authResponse.refreshToken,
                        authResponse.encryptionSalt,
                        authResponse.userId,
                        email,
                        password,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
                    )
                    if (authResponse.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unwrapVaultKey(authResponse.wrappedVaultKey)
                        } catch (e: Exception) {
                            return Result.Error("Failed to initialize vault encryption: ${e.message}")
                        }
                    }
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
                    saveSession(
                        authResponse.accessToken,
                        authResponse.refreshToken,
                        authResponse.encryptionSalt,
                        authResponse.userId,
                        email,
                        password,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
                    )
                    if (authResponse.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unwrapVaultKey(authResponse.wrappedVaultKey)
                        } catch (e: Exception) {
                            return Result.Error("Failed to initialize vault encryption: ${e.message}")
                        }
                    }
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
            vaultKeyManager.clearCachedVaultKey()
            SessionManager.clearSession()
            _authState.value = AuthState.unauthenticated()
            Result.Success(Unit)
        } catch (e: Exception) {
            vaultKeyManager.clearCachedVaultKey()
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
                    if (authResponse.wrappedVaultKey != null) {
                        try {
                            val existingPassword = SessionManager.getMasterPassword()
                            SessionManager.setMasterPassword(existingPassword)
                            vaultKeyManager.unwrapVaultKey(authResponse.wrappedVaultKey)
                        } catch (e: Exception) {
                            SessionManager.clearSession()
                            _authState.value = AuthState.unauthenticated()
                            return Result.Error("Failed to re-initialize vault: ${e.message}")
                        }
                    }
                    saveSession(
                        authResponse.accessToken,
                        authResponse.refreshToken,
                        authResponse.encryptionSalt,
                        authResponse.userId,
                        authResponse.email,
                        SessionManager.getMasterPassword(),
                        authResponse.encryptionVersion
                    )
                    Result.Success(getCurrentAuthState())
                },
                onFailure = {
                    SessionManager.clearSession()
                    _authState.value = AuthState.unauthenticated()
                    Result.Error(it.message ?: "Token refresh failed")
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

            val entriesResult = api.getVaultEntries(token)
            val entries = entriesResult.getOrNull()
                ?: return Result.Error(entriesResult.exceptionOrNull()?.message ?: "Failed to fetch vault entries")

            val oldCachedVaultKey = vaultKeyManager.getCachedVaultKey()
                ?: return Result.Error("Vault key not available. Please login again.")

            val oldEncryptionSalt = SessionManager.getEncryptionSalt()
            val newEncryptionSalt = vaultKeyManager.generateEncryptionSalt()
            val newVaultKey = vaultKeyManager.generateVaultKey()

            val reEncryptedEntries = entries.map { entryResponse ->
                vaultKeyManager.setCachedVaultKey(oldCachedVaultKey)
                val decrypted = encryptor.decrypt(entryResponse)
                vaultKeyManager.setCachedVaultKey(newVaultKey)
                val request = encryptor.encrypt(decrypted)
                VaultEntryRequest(
                    id = entryResponse.id,
                    encryptedData = request.encryptedData,
                    iv = request.iv
                )
            }

            SessionManager.setEncryptionSalt(newEncryptionSalt)
            SessionManager.setMasterPassword(newPassword)
            println("CP: newEncryptionSalt=$newEncryptionSalt, newPassword=$newPassword")
            val newWrappedVaultKey = vaultKeyManager.wrapVaultKey(newVaultKey)
            println("CP: wrapVaultKey done")

            val changeResponse = api.changePassword(
                token,
                ChangePasswordRequest(
                    currentPassword = currentPassword,
                    newPassword = newPassword,
                    wrappedVaultKey = newWrappedVaultKey,
                    newEncryptionSalt = newEncryptionSalt,
                    entries = reEncryptedEntries
                )
            )

            changeResponse.fold(
                onSuccess = { result ->
                    saveSession(
                        result.accessToken,
                        result.refreshToken,
                        result.encryptionSalt,
                        result.userId,
                        result.email,
                        newPassword,
                        result.encryptionVersion,
                        result.wrappedVaultKey
                    )
                    if (result.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unwrapVaultKey(result.wrappedVaultKey)
                        } catch (e: Exception) {
                            vaultKeyManager.clearCachedVaultKey()
                            return Result.Error("Password changed but vault re-sync failed: ${e.message}")
                        }
                    }
                    Result.Success(Unit)
                },
                onFailure = {
                    SessionManager.setMasterPassword(currentPassword)
                    vaultKeyManager.clearCachedVaultKey()
                    Result.Error(it.message ?: "Password change failed")
                }
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
                isAuthenticated = true,
                encryptionVersion = SessionManager.getEncryptionVersion()
            )
        } else {
            AuthState.unauthenticated()
        }
    }

    private fun getAuthStateFromStorage(): AuthState = getCurrentAuthState()

    private fun saveSession(
        accessToken: String,
        refreshToken: String,
        encryptionSalt: String,
        userId: String,
        email: String,
        masterPassword: String,
        encryptionVersion: Int,
        wrappedVaultKey: String? = null
    ) {
        SessionManager.setAccessToken(accessToken)
        SessionManager.setRefreshToken(refreshToken)
        SessionManager.setEncryptionSalt(encryptionSalt)
        SessionManager.setUserId(userId)
        SessionManager.setUserEmail(email)
        SessionManager.setMasterPassword(masterPassword)
        SessionManager.setEncryptionVersion(encryptionVersion)
        if (wrappedVaultKey != null) {
            SessionManager.setWrappedVaultKey(wrappedVaultKey)
        }
        _authState.value = AuthState(
            user = User(userId.hashCode().toLong(), email),
            accessToken = accessToken,
            refreshToken = refreshToken,
            encryptionSalt = encryptionSalt,
            isAuthenticated = true,
            encryptionVersion = encryptionVersion
        )
    }
}