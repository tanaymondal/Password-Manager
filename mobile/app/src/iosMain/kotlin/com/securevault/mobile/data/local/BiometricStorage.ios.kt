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
    }

    private val prefs = NSUserDefaults.standardUserDefaults

    @OptIn(ExperimentalForeignApi::class)
    actual fun isAvailable(): Boolean {
        val ctx = LAContext()
        return ctx.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null)
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return prefs.stringForKey(PREFS_KEY) != null
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
                        val message = error?.let { it.localizedDescription ?: "Biometric authentication failed" } ?: "Biometric authentication failed"
                        onError(message)
                    }
                }
            }
        }
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        prefs.setObject(vaultKey, forKey = PREFS_KEY)
        return true
    }

    actual fun retrieveVaultKey(): String? {
        return prefs.stringForKey(PREFS_KEY)
    }

    actual fun clear() {
        prefs.removeObjectForKey(PREFS_KEY)
        prefs.removeObjectForKey(KEY_FAILURE_COUNT)
    }
}
