package com.securevault.mobile.ui

import androidx.compose.runtime.Composable

expect class PlatformContext

@Composable
expect fun currentPlatformContext(): PlatformContext
