package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.model.KdfConfigResponse

object KdfConfigManager {

    private var cachedConfig: KdfConfigResponse? = null
    private var fetchAttempted = false

    // Hardcoded fallback — used when server is unreachable
    private val fallbackConfig = KdfConfigResponse(
        kdfIterations = 3,
        kdfMemory = 98304,
        kdfParallelism = 4,
        encryptionVersion = 2
    )

    suspend fun getConfig(api: SecureVaultApi): KdfConfigResponse {
        cachedConfig?.let { return it }

        if (!fetchAttempted) {
            fetchAttempted = true
            api.kdfConfig().onSuccess { config ->
                cachedConfig = config
                return config
            }
        }

        return fallbackConfig
    }

    fun getCachedOrDefault(): KdfConfigResponse {
        return cachedConfig ?: fallbackConfig
    }

    fun reset() {
        cachedConfig = null
        fetchAttempted = false
    }
}
