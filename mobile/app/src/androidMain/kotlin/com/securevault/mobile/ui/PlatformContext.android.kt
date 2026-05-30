package com.securevault.mobile.ui

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

actual class PlatformContext(val androidContext: Context)

@Composable
actual fun currentPlatformContext(): PlatformContext {
    return PlatformContext(LocalContext.current)
}
