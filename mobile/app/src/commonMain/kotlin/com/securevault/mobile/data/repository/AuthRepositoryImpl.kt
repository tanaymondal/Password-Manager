package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.breach.BreachChecker
import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.PreLoginRequest
import com.securevault.mobile.data.model.RefreshTokenRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.domain.crypto.CryptoEngine
import com.securevault.mobile.domain.model.AuthState
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.TwoFactorInfo
import com.securevault.mobile.domain.model.User
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.LoginResponse
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlin.random.Random

class AuthRepositoryImpl(
    private val api: SecureVaultApi,
    private val cryptoEngine: CryptoEngine,
    private val encryptor: EntryEncryptor,
    private val vaultKeyManager: VaultKeyManager
) : AuthRepository {

    private val _authState = MutableStateFlow(getAuthStateFromStorage())

    override suspend fun register(email: String, password: String): Result<AuthState> {
        return try {
            if (BreachChecker.checkBreach(password, cryptoEngine)) {
                return Result.Error("This password has been exposed in a data breach. Please choose a different password.")
            }

            val authSalt = cryptoEngine.generateSalt()
            val encryptionSalt = cryptoEngine.generateSalt()
            val vaultKey = cryptoEngine.generateVaultKey()
            val authHash = cryptoEngine.generateAuthHash(password, authSalt)
            val kek = cryptoEngine.deriveKek(password, encryptionSalt)
            val wrappedVaultKey = cryptoEngine.wrapVaultKey(vaultKey, kek)
            val deviceId = getOrCreateDeviceId()

            val response = api.register(
                RegisterRequest(email, authHash, authSalt, encryptionSalt, wrappedVaultKey, 2, deviceId)
            )
            response.fold(
                onSuccess = { authResponse ->
                    vaultKeyManager.setCachedVaultKey(vaultKey)
                    saveSession(
                        authResponse.accessToken!!,
                        authResponse.refreshToken!!,
                        authResponse.encryptionSalt!!,
                        authResponse.userId!!,
                        authResponse.email!!,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
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

    override suspend fun login(email: String, password: String): Result<LoginResponse> {
        return try {
            val preloginResult = api.prelogin(PreLoginRequest(email))
            val authSalt = preloginResult.getOrNull()?.authSalt ?: email
            val authHash = cryptoEngine.generateAuthHash(password, authSalt)
            val deviceId = getOrCreateDeviceId()
            val response = api.login(LoginRequest(email, authHash, deviceName = "Mobile App", deviceId = deviceId))

            response.fold(
                onSuccess = { authResponse ->
                    if (authResponse.twoFactorRequired) {
                        val info = TwoFactorInfo(
                            userId = authResponse.userId!!,
                            email = authResponse.email!!,
                            challengeId = authResponse.challengeId!!,
                            encryptionSalt = authResponse.encryptionSalt!!,
                            wrappedVaultKey = authResponse.wrappedVaultKey
                        )
                        Result.Success(LoginResponse.TwoFactorRequired(info))
                    } else {
                        val vaultKey = deriveVaultKey(
                            password,
                            authResponse.encryptionSalt!!,
                            authResponse.wrappedVaultKey
                        )
                        if (vaultKey != null) {
                            vaultKeyManager.setCachedVaultKey(vaultKey)
                        }
                        saveSession(
                            authResponse.accessToken!!,
                            authResponse.refreshToken!!,
                            authResponse.encryptionSalt!!,
                            authResponse.userId!!,
                            email,
                            authResponse.encryptionVersion,
                            authResponse.wrappedVaultKey
                        )
                        Result.Success(LoginResponse.Success(getCurrentAuthState()))
                    }
                },
                onFailure = { Result.Error(it.message ?: "Login failed", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Login failed", e)
        }
    }

    override suspend fun verifyTwoFactor(
        email: String,
        challengeId: String,
        code: String,
        password: String
    ): Result<AuthState> {
        return try {
            val response = api.verifyTwoFactor(email, challengeId, code)
            response.fold(
                onSuccess = { authResponse ->
                    val vaultKey = deriveVaultKey(
                        password,
                        authResponse.encryptionSalt!!,
                        authResponse.wrappedVaultKey
                    )
                    if (vaultKey != null) {
                        vaultKeyManager.setCachedVaultKey(vaultKey)
                    }
                    saveSession(
                        authResponse.accessToken!!,
                        authResponse.refreshToken!!,
                        authResponse.encryptionSalt!!,
                        authResponse.userId!!,
                        email,
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
                    )
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
                        authResponse.encryptionVersion,
                        authResponse.wrappedVaultKey
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

            val vaultKey = deriveVaultKey(password, encryptionSalt, wrappedVaultKey)
            if (vaultKey != null) {
                vaultKeyManager.setCachedVaultKey(vaultKey)
            }
            Result.Success(Unit)
        } catch (e: Exception) {
            Result.Error("Failed to unlock vault: ${e.message}")
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

    private fun getOrCreateDeviceId(): String {
        val existing = SessionManager.getDeviceId()
        if (existing.isNotEmpty()) return existing
        val newId = buildString {
            val hex = "0123456789abcdef"
            repeat(32) { append(hex[Random.nextInt(hex.length)]) }
        }
        SessionManager.setDeviceId(newId)
        return newId
    }

    private fun deriveVaultKey(password: String, encryptionSalt: String, wrappedVaultKey: String?): String? {
        if (wrappedVaultKey.isNullOrEmpty()) return null
        val kek = cryptoEngine.deriveKek(password, encryptionSalt)
        return cryptoEngine.unwrapVaultKey(wrappedVaultKey, kek)
    }

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
