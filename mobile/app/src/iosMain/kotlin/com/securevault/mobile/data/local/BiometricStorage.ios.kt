package com.securevault.mobile.data.local

import com.securevault.mobile.ui.PlatformContext
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSJSONSerialization
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.writeToFile
import platform.LocalAuthentication.*
import platform.Security.SecRandomCopyBytes

@OptIn(ExperimentalForeignApi::class)
actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val BIO_FILE = ".securevault_biometric"
        private const val KEY_VAULT_KEY = "vault_key"
        private const val KEY_FAILURES = "failures"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private var cache: MutableMap<String, String>? = null
    private var authorizedVaultKey: String? = null

    @OptIn(ExperimentalForeignApi::class)
    private fun getStorePath(): String {
        val documentDir = NSFileManager.defaultManager.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = true,
            error = null,
        ) ?: error("Cannot access Documents directory")
        return requireNotNull(documentDir.path) + "/$BIO_FILE"
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun ensureLoaded() {
        if (cache != null) return
        val data = NSData.create(contentsOfFile = getStorePath()) ?: run {
            cache = mutableMapOf(); return
        }
        val obj = NSJSONSerialization.JSONObjectWithData(data, 0u, null) as? Map<*, *>
        @Suppress("UNCHECKED_CAST")
        cache = (obj as? Map<String, String>)?.toMutableMap() ?: mutableMapOf()
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun save() {
        val data = NSJSONSerialization.dataWithJSONObject(cache ?: return, 0u, null) ?: return
        data.writeToFile(getStorePath(), atomically = true)
    }

    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        ensureLoaded()
        return cache?.containsKey(KEY_VAULT_KEY) == true
    }

    actual fun isLockedOut(): Boolean {
        ensureLoaded()
        return (cache?.get(KEY_FAILURES)?.toIntOrNull() ?: 0) >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        ensureLoaded()
        val count = (cache?.get(KEY_FAILURES)?.toIntOrNull() ?: 0) + 1
        cache?.set(KEY_FAILURES, count.toString())
        save()
    }

    actual fun resetFailureCount() {
        ensureLoaded()
        cache?.remove(KEY_FAILURES)
        save()
    }

    actual fun shouldShowBiometricPrompt(): Boolean {
        return isAvailable() && hasEncryptedVaultKey() && !isLockedOut()
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun authenticate(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit
    ) {
        val ctx = LAContext()
        ctx.evaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, title) { success, error ->
            if (success) {
                resetFailureCount()
                authorizedVaultKey = readVaultKey()
                onSuccess()
            } else {
                val errorCode = error?.let { it.code.toLong() } ?: -1L
                when (errorCode) {
                    LAErrorUserCancel, LAErrorSystemCancel, LAErrorAppCancel -> onCancel()
                    LAErrorBiometryLockout, LAErrorTouchIDLockout -> {
                        recordFailure()
                        onError("Biometric locked out. Use your master password.")
                    }
                    else -> {
                        recordFailure()
                        onError(error?.localizedDescription ?: "Biometric authentication failed")
                    }
                }
            }
        }
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        ensureLoaded()
        cache?.set(KEY_VAULT_KEY, vaultKey)
        save()
        return true
    }

    actual fun retrieveVaultKey(): String? {
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        return readVaultKey()
    }

    actual fun clear() {
        cache = mutableMapOf()
        save()
        authorizedVaultKey = null
    }

    private fun readVaultKey(): String? {
        ensureLoaded()
        return cache?.get(KEY_VAULT_KEY)
    }
}
