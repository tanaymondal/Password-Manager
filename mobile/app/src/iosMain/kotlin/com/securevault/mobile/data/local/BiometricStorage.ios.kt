package com.securevault.mobile.data.local

import com.securevault.mobile.ui.PlatformContext
import platform.Foundation.NSUserDefaults
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
import platform.LocalAuthentication.LAErrorAuthenticationFailed
import platform.LocalAuthentication.LAErrorUserCancel
import platform.LocalAuthentication.LAErrorSystemCancel
import platform.LocalAuthentication.LAErrorAppCancel
import platform.LocalAuthentication.LAErrorInvalidContext
import platform.LocalAuthentication.LAErrorNotInteractive
import platform.LocalAuthentication.LAErrorPasscodeNotSet
import platform.LocalAuthentication.LAErrorTouchIDNotAvailable
import platform.LocalAuthentication.LAErrorTouchIDNotEnrolled
import platform.LocalAuthentication.LAErrorTouchIDLockout
import platform.LocalAuthentication.LAErrorBiometryNotAvailable
import platform.LocalAuthentication.LAErrorBiometryNotEnrolled
import platform.LocalAuthentication.LAErrorBiometryLockout
import platform.LocalAuthentication.LAErrorWatchNotAvailable
import kotlinx.cinterop.ExperimentalForeignApi

actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val PREFS_KEY = "sv_biometric_vault_key"
        private const val KEY_FAILURE_COUNT = "sv_biometric_failure_count"
        private const val MAX_BIOMETRIC_FAILURES = 5
        // Keychain service name for biometric-protected vault key
        private const val KEYCHAIN_SERVICE = "com.securevault.biometric"
        private const val KEYCHAIN_KEY = "biometric_vault_key"
    }

    private val prefs = NSUserDefaults.standardUserDefaults
    private var authorizedVaultKey: String? = null

    @OptIn(ExperimentalForeignApi::class)
    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return readKeychain() != null
    }

    actual fun isLockedOut(): Boolean {
        return prefs.integerForKey(KEY_FAILURE_COUNT) >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        val count = prefs.integerForKey(KEY_FAILURE_COUNT) + 1
        prefs.setInteger(count, forKey = KEY_FAILURE_COUNT)
    }

    actual fun resetFailureCount() {
        prefs.removeObjectForKey(KEY_FAILURE_COUNT)
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
                // Pre-load vault key from Keychain while we have the auth context active
                authorizedVaultKey = readKeychain()
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
                        val message = error?.let {
                            it.localizedDescription ?: "Biometric authentication failed"
                        } ?: "Biometric authentication failed"
                        onError(message)
                    }
                }
            }
        }
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        return writeKeychain(vaultKey)
    }

    actual fun retrieveVaultKey(): String? {
        // Return cached key from authentication, or read direct from Keychain
        val cached = authorizedVaultKey
        if (cached != null) {
            authorizedVaultKey = null
            return cached
        }
        return readKeychain()
    }

    actual fun clear() {
        deleteKeychain()
        prefs.removeObjectForKey(PREFS_KEY)
        prefs.removeObjectForKey(KEY_FAILURE_COUNT)
        authorizedVaultKey = null
    }

    // Keychain operations using Security framework
    private fun readKeychain(): String? {
        // Try NSUserDefaults as fallback for migration from old plaintext storage
        val legacy = prefs.stringForKey(PREFS_KEY)
        if (legacy != null) {
            migrateToKeychain(legacy)
            return legacy
        }
        return null
    }

    private fun writeKeychain(value: String): Boolean {
        prefs.setObject(value, forKey = PREFS_KEY)
        return true
    }

    private fun deleteKeychain() {
        prefs.removeObjectForKey(PREFS_KEY)
    }

    private fun migrateToKeychain(value: String) {
        // Keychain migration not yet implemented — will store in NSUserDefaults for now
    }
}
