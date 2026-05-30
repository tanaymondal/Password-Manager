package com.securevault.mobile.di

import androidx.compose.runtime.Composable

@Composable
expect inline fun <reified T : Any> koinInject(): T
