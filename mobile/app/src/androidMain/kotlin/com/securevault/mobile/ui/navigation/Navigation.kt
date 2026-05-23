package com.securevault.mobile.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.navigation.toRoute
import com.securevault.mobile.domain.usecase.auth.AuthStateResult
import com.securevault.mobile.domain.usecase.auth.GetAuthStateUseCase
import com.securevault.mobile.ui.screens.auth.LoginScreen
import com.securevault.mobile.ui.screens.auth.RegisterScreen
import com.securevault.mobile.ui.screens.auth.UnlockScreen
import com.securevault.mobile.ui.screens.settings.SettingsScreen
import com.securevault.mobile.ui.screens.settings.SettingsViewModel
import com.securevault.mobile.ui.screens.vault.AddEditEntryScreen
import com.securevault.mobile.ui.screens.vault.AddEditEntryViewModel
import com.securevault.mobile.ui.screens.vault.VaultScreen
import com.securevault.mobile.ui.screens.vault.VaultViewModel
import kotlinx.serialization.Serializable
import org.koin.androidx.compose.koinViewModel

sealed class Screen(val route: String) {
    data object Login : Screen("login")
    data object Register : Screen("register")
    data object Vault : Screen("vault")
    data object AddEntry : Screen("add_entry")
    data object EditEntry : Screen("edit_entry/{entryId}") {
        fun createRoute(entryId: Long) = "edit_entry/$entryId"
    }
    data object Settings : Screen("settings")
    data object Unlock : Screen("unlock")
}

@Serializable
data class EditEntryRoute(val entryId: Long)

@Composable
fun SecureVaultNavHost() {
    val navController = rememberNavController()
    val getAuthStateUseCase = getAuthStateUseCase()
    val startDestination = remember { getAuthStateUseCase() }.let { state ->
        when (state) {
            is AuthStateResult.Authenticated -> Screen.Vault.route
            is AuthStateResult.Unauthenticated -> Screen.Login.route
        }
    }

    NavHost(navController = navController, startDestination = startDestination) {
        composable(Screen.Login.route) {
            LoginScreen(
                onLoginSuccess = {
                    navController.navigate(Screen.Vault.route) {
                        popUpTo(Screen.Login.route) { inclusive = true }
                    }
                },
                onNavigateToRegister = { navController.navigate(Screen.Register.route) }
            )
        }

        composable(Screen.Register.route) {
            RegisterScreen(
                onRegisterSuccess = {
                    navController.navigate(Screen.Vault.route) {
                        popUpTo(Screen.Login.route) { inclusive = true }
                    }
                },
                onNavigateToLogin = { navController.popBackStack() }
            )
        }

        composable(Screen.Unlock.route) {
            UnlockScreen(
                onUnlockSuccess = {
                    navController.navigate(Screen.Vault.route) {
                        popUpTo(Screen.Unlock.route) { inclusive = true }
                    }
                },
                onLogout = {
                    navController.navigate(Screen.Login.route) {
                        popUpTo(0) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.Vault.route) {
            VaultScreen(
                onNavigateToAddEntry = { navController.navigate(Screen.AddEntry.route) },
                onNavigateToEditEntry = { entryId -> navController.navigate(Screen.EditEntry.createRoute(entryId)) },
                onNavigateToSettings = { navController.navigate(Screen.Settings.route) },
                onLogout = { navController.navigate(Screen.Login.route) { popUpTo(Screen.Vault.route) { inclusive = true } } },
                onNavigateToUnlock = { navController.navigate(Screen.Unlock.route) }
            )
        }

        composable(Screen.AddEntry.route) {
            val vaultViewModel: VaultViewModel = koinViewModel()
            AddEditEntryScreen(
                entryId = null,
                onNavigateBack = { navController.popBackStack() },
                onSaveSuccess = { navController.popBackStack() },
                onReload = { vaultViewModel.handleIntent(com.securevault.mobile.ui.screens.vault.VaultIntent.TriggerReload) }
            )
        }

        composable(
            route = Screen.EditEntry.route,
            arguments = listOf(navArgument("entryId") { type = NavType.LongType })
        ) { backStackEntry ->
            val entryId = backStackEntry.arguments?.getLong("entryId") ?: 0L
            val vaultViewModel: VaultViewModel = koinViewModel()
            AddEditEntryScreen(
                entryId = entryId,
                onNavigateBack = { navController.popBackStack() },
                onSaveSuccess = { navController.popBackStack() },
                onReload = { vaultViewModel.handleIntent(com.securevault.mobile.ui.screens.vault.VaultIntent.TriggerReload) }
            )
        }

        composable(Screen.Settings.route) {
            val settingsViewModel: SettingsViewModel = koinViewModel()
            SettingsScreen(
                onNavigateBack = { navController.popBackStack() },
                onLogout = { navController.navigate(Screen.Login.route) { popUpTo(0) { inclusive = true } } },
                viewModel = settingsViewModel
            )
        }
    }
}

@Composable
private fun getAuthStateUseCase(): GetAuthStateUseCase {
    return org.koin.compose.koinInject()
}