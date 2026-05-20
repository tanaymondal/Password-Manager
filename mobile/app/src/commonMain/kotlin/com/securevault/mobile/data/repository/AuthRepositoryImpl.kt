package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.model.ChangePasswordRequest
import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.RefreshTokenRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.TwoFactorInfo
import com.securevault.mobile.domain.model.User
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.LoginResponse
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
                        authResponse.accessToken!!,
                        authResponse.refreshToken!!,
                        authResponse.encryptionSalt!!,
                        authResponse.userId!!,
                        email,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
                    )
                    if (authResponse.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unlockVault(
                                password,
                                authResponse.encryptionSalt!!,
                                authResponse.wrappedVaultKey
                            )
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

    override suspend fun login(email: String, password: String): Result<LoginResponse> {
        return try {
            val response = api.login(LoginRequest(email, password))
            response.fold(
                onSuccess = { authResponse ->
                    if (authResponse.twoFactorRequired) {
                        val info = TwoFactorInfo(
                            userId = authResponse.userId!!,
                            email = authResponse.email!!,
                            encryptionSalt = authResponse.encryptionSalt!!,
                            wrappedVaultKey = authResponse.wrappedVaultKey
                        )
                        Result.Success(LoginResponse.TwoFactorRequired(info))
                    } else {
                        saveSession(
                            authResponse.accessToken!!,
                            authResponse.refreshToken!!,
                            authResponse.encryptionSalt!!,
                            authResponse.userId!!,
                            email,
                            authResponse.encryptionVersion,
                            authResponse.wrappedVaultKey
                        )
                        if (authResponse.wrappedVaultKey != null) {
                            try {
                                vaultKeyManager.unlockVault(
                                    password,
                                    authResponse.encryptionSalt!!,
                                    authResponse.wrappedVaultKey
                                )
                            } catch (e: Exception) {
                                return Result.Error("Failed to initialize vault encryption: ${e.message}")
                            }
                        }
                        Result.Success(LoginResponse.Success(getCurrentAuthState()))
                    }
                },
                onFailure = { Result.Error(it.message ?: "Login failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Login failed", e)
        }
    }

    override suspend fun verifyTwoFactor(email: String, code: String, password: String): Result<AuthState> {
        return try {
            val response = api.verifyTwoFactor(email, code)
            response.fold(
                onSuccess = { authResponse ->
                    saveSession(
                        authResponse.accessToken!!,
                        authResponse.refreshToken!!,
                        authResponse.encryptionSalt!!,
                        authResponse.userId!!,
                        email,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
                    )
                    if (authResponse.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unlockVault(
                                password,
                                authResponse.encryptionSalt!!,
                                authResponse.wrappedVaultKey
                            )
                        } catch (e: Exception) {
                            return Result.Error("Failed to initialize vault encryption: ${e.message}")
                        }
                    }
                    Result.Success(getCurrentAuthState())
                },
                onFailure = { Result.Error(it.message ?: "2FA verification failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "2FA verification failed", e)
        }
    }

    override suspend fun logout(): Result<Unit> {
        return try {
            api.logout()
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
                    saveSession(
                        authResponse.accessToken!!,
                        authResponse.refreshToken!!,
                        authResponse.encryptionSalt!!,
                        authResponse.userId!!,
                        authResponse.email!!,
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

    override suspend fun unlockVault(password: String): Result<Unit> {
        return try {
            val encryptionSalt = SessionManager.getEncryptionSalt()
            val wrappedVaultKey = SessionManager.getWrappedVaultKey()

            if (encryptionSalt.isEmpty() || wrappedVaultKey.isEmpty()) {
                return Result.Error("Vault key material not available. Please login again.")
            }

            vaultKeyManager.unlockVault(password, encryptionSalt, wrappedVaultKey)
            Result.Success(Unit)
        } catch (e: Exception) {
            Result.Error("Failed to unlock vault: ${e.message}")
        }
    }

    override suspend fun changePassword(currentPassword: String, newPassword: String): Result<Unit> {
        return try {
            val entriesResult = api.getVaultEntries()
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

            val newWrappedVaultKey = vaultKeyManager.wrapVaultKey(
                newVaultKey,
                newPassword,
                newEncryptionSalt
            )

            SessionManager.setEncryptionSalt(newEncryptionSalt)

            val changeResponse = api.changePassword(
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
                        result.encryptionVersion,
                        result.wrappedVaultKey
                    )
                    if (result.wrappedVaultKey != null) {
                        try {
                            vaultKeyManager.unlockVault(
                                newPassword,
                                result.encryptionSalt,
                                result.wrappedVaultKey
                            )
                        } catch (e: Exception) {
                            vaultKeyManager.clearCachedVaultKey()
                            return Result.Error("Password changed but vault re-sync failed: ${e.message}")
                        }
                    }
                    Result.Success(Unit)
                },
                onFailure = {
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
        encryptionVersion: Int,
        wrappedVaultKey: String? = null
    ) {
        SessionManager.setAccessToken(accessToken)
        SessionManager.setRefreshToken(refreshToken)
        SessionManager.setEncryptionSalt(encryptionSalt)
        SessionManager.setUserId(userId)
        SessionManager.setUserEmail(email)
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
