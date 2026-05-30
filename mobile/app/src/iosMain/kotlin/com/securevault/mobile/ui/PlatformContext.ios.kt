package com.securevault.mobile.ui

import androidx.compose.runtime.Composable

actual class PlatformContext

@Composable
actual fun currentPlatformContext(): PlatformContext {
    return PlatformContext()
}
