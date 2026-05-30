package com.securevault.mobile.data.repository

import com.securevault.mobile.data.repository.ErrorMapper
import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.breach.BreachChecker
import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.PreLoginRequest
import com.securevault.mobile.data.model.RefreshTokenRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.data.model.UpgradeKdfRequest
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

class AuthRepositoryImpl(
    private val api: SecureVaultApi,
    private val cryptoEngine: CryptoEngine,
    private val encryptor: EntryEncryptor,
    private val vaultKeyManager: VaultKeyManager
) : AuthRepository {

    private val _authState = MutableStateFlow(getAuthStateFromStorage())

    override suspend fun register(email: String, password: String): Result<AuthState> {
        return try {
            val cfg = KdfConfigManager.getConfig(api)

            if (BreachChecker.checkBreach(password, cryptoEngine)) {
                return Result.Error("This password has been exposed in a data breach. Please choose a different password.")
            }

            val authSalt = cryptoEngine.generateSalt()
            val encryptionSalt = cryptoEngine.generateSalt()
            val vaultKey = cryptoEngine.generateVaultKey()
            val authHash = cryptoEngine.generateAuthHash(password, authSalt, cfg.kdfIterations, cfg.kdfMemory, cfg.kdfParallelism)
            val kek = cryptoEngine.deriveKek(password, encryptionSalt, cfg.kdfIterations, cfg.kdfMemory, cfg.kdfParallelism)
            val wrappedVaultKey = cryptoEngine.wrapVaultKey(vaultKey, kek)
            val deviceId = getOrCreateDeviceId()

            val response = api.register(
                RegisterRequest(email, authHash, authSalt, encryptionSalt, wrappedVaultKey, cfg.encryptionVersion, deviceId,
                    kdfIterations = cfg.kdfIterations, kdfMemory = cfg.kdfMemory, kdfParallelism = cfg.kdfParallelism)
            )
            response.fold(
                onSuccess = { authResponse ->
                    val accessToken = authResponse.accessToken
                    val refreshToken = authResponse.refreshToken
                    val encSalt = authResponse.encryptionSalt
                    val userId = authResponse.userId
                    val userEmail = authResponse.email
                    if (accessToken == null || refreshToken == null || encSalt == null || userId == null) {
                        return@fold Result.Error("Incomplete registration response from server")
                    }
                    vaultKeyManager.setCachedVaultKey(vaultKey)
                    SessionManager.setAuthSalt(authSalt)
                    saveSession(
                        accessToken = accessToken,
                        refreshToken = refreshToken,
                        encryptionSalt = encSalt,
                        userId = userId,
                        email = userEmail ?: email,
                        encryptionVersion = authResponse.encryptionVersion,
                        wrappedVaultKey = authResponse.wrappedVaultKey,
                        kdfIterations = cfg.kdfIterations,
                        kdfMemory = cfg.kdfMemory,
                        kdfParallelism = cfg.kdfParallelism
                    )
                    Result.Success(getCurrentAuthState())
                },
                onFailure = {
                    SessionManager.clearSession()
                    _authState.value = AuthState.unauthenticated()
                    Result.Error(ErrorMapper.map(it.message, "Token refresh failed"))
                }
            )
        } catch (e: Exception) {
            Result.Error(ErrorMapper.map(e.message, "Token refresh failed"), e)
        }
    }

    override suspend fun login(email: String, password: String): Result<LoginResponse> {
        return try {
            // Fetch fresh server KDF config for upgrade comparison after unlock
            KdfConfigManager.getConfig(api)

            val preloginResult = api.prelogin(PreLoginRequest(email))
            val pre = preloginResult.getOrNull()
            val authSalt = pre?.authSalt ?: email
            val defaultCfg = KdfConfigManager.getCachedOrDefault()
            val kdfIter = pre?.kdfIterations ?: defaultCfg.kdfIterations
            val kdfMem = pre?.kdfMemory ?: defaultCfg.kdfMemory
            val kdfPar = pre?.kdfParallelism ?: defaultCfg.kdfParallelism
            SessionManager.setAuthSalt(authSalt)
            SessionManager.setKdfIterations(kdfIter)
            SessionManager.setKdfMemory(kdfMem)
            SessionManager.setKdfParallelism(kdfPar)
            val authHash = cryptoEngine.generateAuthHash(password, authSalt, kdfIter, kdfMem, kdfPar)
            val deviceId = getOrCreateDeviceId()
            val response = api.login(LoginRequest(email, authHash, deviceName = "Mobile App", deviceId = deviceId))

            response.fold(
                onSuccess = { authResponse ->
                    val userId = authResponse.userId
                    val challengeId = authResponse.challengeId
                    if (userId == null || challengeId == null) {
                        return@fold Result.Error("Incomplete login response from server")
                    }
                    val info = TwoFactorInfo(
                        userId = userId,
                        email = email,
                        challengeId = challengeId,
                        twoFactorMethods = authResponse.twoFactorMethods
                    )
                    Result.Success(LoginResponse.TwoFactorRequired(info))
                },
                onFailure = { Result.Error(ErrorMapper.map(it.message, "Login failed"), it) }
            )
        } catch (e: Exception) {
            Result.Error(ErrorMapper.map(e.message, "Login failed"), e)
        }
    }

    override suspend fun verifyTwoFactor(
        email: String,
        challengeId: String,
        code: String,
        password: String
    ): Result<AuthState> {
        return try {
            // Refresh config for upgrade check after successful 2FA
            KdfConfigManager.getConfig(api)
            val response = api.verifyTwoFactor(email, challengeId, code)
            response.fold(
                onSuccess = { authResponse ->
                    val encSalt = authResponse.encryptionSalt
                    val accessToken = authResponse.accessToken
                    val refreshToken = authResponse.refreshToken
                    val userId = authResponse.userId
                    if (encSalt == null || accessToken == null || refreshToken == null || userId == null) {
                        return@fold Result.Error("Incomplete 2FA verification response from server")
                    }
                    val defaultCfg = KdfConfigManager.getCachedOrDefault()
                    val kdfMem = authResponse.kdfMemory ?: defaultCfg.kdfMemory
                    val vaultKey = deriveVaultKey(
                        password, encSalt, authResponse.wrappedVaultKey,
                        defaultCfg.kdfIterations, kdfMem, defaultCfg.kdfParallelism
                    )
                    if (vaultKey != null) {
                        vaultKeyManager.setCachedVaultKey(vaultKey)
                    }
                    saveSession(
                        accessToken = accessToken,
                        refreshToken = refreshToken,
                        encryptionSalt = encSalt,
                        userId = userId,
                        email = email,
                        encryptionVersion = authResponse.encryptionVersion,
                        wrappedVaultKey = authResponse.wrappedVaultKey,
                        kdfIterations = authResponse.kdfIterations ?: defaultCfg.kdfIterations,
                        kdfMemory = authResponse.kdfMemory ?: defaultCfg.kdfMemory,
                        kdfParallelism = authResponse.kdfParallelism ?: defaultCfg.kdfParallelism
                    )
                    Result.Success(getCurrentAuthState())
                },
                onFailure = { Result.Error(ErrorMapper.map(it.message, "2FA verification failed"), it) }
            )
        } catch (e: Exception) {
            Result.Error(ErrorMapper.map(e.message, "2FA verification failed"), e)
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
                    val accessToken = authResponse.accessToken
                    val newRefreshToken = authResponse.refreshToken
                    val encSalt = authResponse.encryptionSalt
                    val userId = authResponse.userId
                    val userEmail = authResponse.email
                    if (accessToken == null || newRefreshToken == null || encSalt == null || userId == null) {
                        return@fold Result.Error("Incomplete refresh response from server")
                    }
                    saveSession(
                        accessToken = accessToken,
                        refreshToken = newRefreshToken,
                        encryptionSalt = encSalt,
                        userId = userId,
                        email = userEmail ?: SessionManager.getUserEmail(),
                        encryptionVersion = authResponse.encryptionVersion,
                        wrappedVaultKey = authResponse.wrappedVaultKey,
                        kdfIterations = authResponse.kdfIterations,
                        kdfMemory = authResponse.kdfMemory,
                        kdfParallelism = authResponse.kdfParallelism
                    )
                    Result.Success(getCurrentAuthState())
                },
                onFailure = {
                    SessionManager.clearSession()
                    _authState.value = AuthState.unauthenticated()
                    Result.Error(ErrorMapper.map(it.message, "Token refresh failed"))
                }
            )
        } catch (e: Exception) {
            Result.Error(ErrorMapper.map(e.message, "Token refresh failed"), e)
        }
    }

    override suspend fun unlockVault(password: String): Result<Unit> {
        return try {
            val encryptionSalt = SessionManager.getEncryptionSalt()
            val wrappedVaultKey = SessionManager.getWrappedVaultKey()

            if (encryptionSalt.isEmpty() || wrappedVaultKey.isEmpty()) {
                return Result.Error("Vault key material not available. Please login again.")
            }

            val cfg = KdfConfigManager.getConfig(api)
            val currentMemory = SessionManager.getKdfMemory()
            val vaultKey = deriveVaultKey(password, encryptionSalt, wrappedVaultKey, cfg.kdfIterations, currentMemory, cfg.kdfParallelism)
            if (vaultKey != null) {
                vaultKeyManager.setCachedVaultKey(vaultKey)
            }

            // Background KDF parameter upgrade
            if (currentMemory < cfg.kdfMemory) {
                try {
                    val authSalt = SessionManager.getAuthSalt()
                    val newAuthHash = cryptoEngine.generateAuthHash(
                        password, authSalt, cfg.kdfIterations, cfg.kdfMemory, cfg.kdfParallelism
                    )
                    val newKek = cryptoEngine.deriveKek(
                        password, encryptionSalt, cfg.kdfIterations, cfg.kdfMemory, cfg.kdfParallelism
                    )
                    val newWrapped = cryptoEngine.wrapVaultKey(vaultKey ?: return@let, newKek)
                    api.upgradeKdf(UpgradeKdfRequest(
                        authHash = newAuthHash,
                        wrappedVaultKey = newWrapped,
                        kdfIterations = cfg.kdfIterations,
                        kdfMemory = cfg.kdfMemory,
                        kdfParallelism = cfg.kdfParallelism
                    )).onSuccess {
                        SessionManager.setKdfIterations(cfg.kdfIterations)
                        SessionManager.setKdfMemory(cfg.kdfMemory)
                        SessionManager.setKdfParallelism(cfg.kdfParallelism)
                    }
                } catch (_: Exception) {
                    // Background upgrade failure is non-fatal
                }
            }

            Result.Success(Unit)
        } catch (e: Exception) {
            Result.Error(ErrorMapper.map(e.message, "Failed to unlock vault"))
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
        val newId = cryptoEngine.generateSecureDeviceId()
        SessionManager.setDeviceId(newId)
        return newId
    }

    private fun deriveVaultKey(password: String, encryptionSalt: String, wrappedVaultKey: String?,
                               iterations: Int = KdfConfigManager.getCachedOrDefault().kdfIterations,
                               memory: Int = KdfConfigManager.getCachedOrDefault().kdfMemory,
                               parallelism: Int = KdfConfigManager.getCachedOrDefault().kdfParallelism): String? {
        if (wrappedVaultKey.isNullOrEmpty()) return null
        val kek = cryptoEngine.deriveKek(password, encryptionSalt, iterations, memory, parallelism)
        return cryptoEngine.unwrapVaultKey(wrappedVaultKey, kek)
    }

    private fun saveSession(
        accessToken: String,
        refreshToken: String,
        encryptionSalt: String,
        userId: String,
        email: String,
        encryptionVersion: Int,
        wrappedVaultKey: String? = null,
        kdfIterations: Int? = null,
        kdfMemory: Int? = null,
        kdfParallelism: Int? = null
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
        SessionManager.setKdfIterations(kdfIterations ?: KdfConfigManager.getCachedOrDefault().kdfIterations)
        SessionManager.setKdfMemory(kdfMemory ?: KdfConfigManager.getCachedOrDefault().kdfMemory)
        SessionManager.setKdfParallelism(kdfParallelism ?: KdfConfigManager.getCachedOrDefault().kdfParallelism)
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
